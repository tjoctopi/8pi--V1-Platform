"""Boolean-blind SQLi oracle (spec §5 — the canonical propose/verify example).

    "boolean-blind SQLi confirmed only when a known payload pair produces a
     statistically significant differential across N trials, not a one-shot LLM
     guess."

We send a TRUE-condition payload (``' AND '1'='1``) and a FALSE-condition
payload (``' AND '1'='2``) N times each, through the scope-enforced HTTP probe,
and require:

  * each condition to produce a **consistent** response signature (status+size)
    across all trials — no flapping, and
  * the TRUE and FALSE signatures to **differ**.

Only then is the injection confirmed. If boolean-blind shows no differential
(some endpoints are UNION/error-based, not boolean-friendly), it falls back to
an **error/quote differential**: a lone single quote that provokes a SQL error
while a balanced quote does not proves the input is parsed as SQL. Either way it
confirms the vulnerability exists without extracting a single row of data — it
observes only HTTP status and response size (the RoE-safe boundary).
"""

from __future__ import annotations

from typing import Any

from ...schemas.findings import Finding
from ...schemas.tools import ToolProfile
from ..context import VerifyContext
from .base import Oracle, OracleResult

_TRUE_SUFFIX = "' AND '1'='1"
_FALSE_SUFFIX = "' AND '1'='2"


class SqliBooleanBlindOracle(Oracle):
    oracle_id = "sqli_boolean_blind_oracle_v1"

    def __init__(self, trials: int = 6, min_trials: int = 5) -> None:
        if trials < min_trials:
            raise ValueError("trials must be >= min_trials")
        self._trials = trials
        self._min_trials = min_trials

    def handles(self, finding: Finding) -> bool:
        return finding.type.startswith("sqli-boolean-blind")

    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        md = finding.metadata
        param = md.get("param")
        base = str(md.get("base_value", ""))
        if not param:
            return OracleResult(
                passed=False,
                oracle_id=self.oracle_id,
                detail="finding lacks an injection param in metadata",
            )
        true_payload = str(md.get("true_payload", base + _TRUE_SUFFIX))
        false_payload = str(md.get("false_payload", base + _FALSE_SUFFIX))
        base_args = {
            "scheme": md.get("scheme", "http"),
            "port": md.get("port"),
            "path": md.get("path", "/"),
            "method": str(md.get("method", "GET")).upper(),
        }

        true_sigs: list[tuple[int | None, int | None]] = []
        false_sigs: list[tuple[int | None, int | None]] = []
        evidence: list[str] = []

        for _ in range(self._trials):
            t = self._probe(ctx, finding.asset, base_args, {param: true_payload})
            f = self._probe(ctx, finding.asset, base_args, {param: false_payload})
            true_sigs.append((t["parsed"].get("status"), t["parsed"].get("size")))
            false_sigs.append((f["parsed"].get("status"), f["parsed"].get("size")))
            evidence.extend([t["audit_id"], f["audit_id"]])

        true_consistent = len(set(true_sigs)) == 1
        false_consistent = len(set(false_sigs)) == 1
        differential = true_sigs[0] != false_sigs[0]
        passed = (
            len(true_sigs) >= self._min_trials
            and true_consistent
            and false_consistent
            and differential
        )
        # Confidence: fraction of trials whose TRUE sig differs from FALSE sig.
        diffs = sum(1 for t, f in zip(true_sigs, false_sigs, strict=True) if t != f)
        confidence = diffs / len(true_sigs) if true_sigs else 0.0

        if passed:
            return OracleResult(
                passed=True,
                oracle_id=self.oracle_id,
                detail=(
                    f"boolean-blind: true_sig={true_sigs[0]} false_sig={false_sigs[0]} "
                    f"consistent differential across {self._trials} trials"
                ),
                confidence=confidence,
                evidence=tuple(f"raw:{a}" for a in evidence),
                measurements={"technique": "boolean-blind",
                              "true_signature": list(true_sigs[0]),
                              "false_signature": list(false_sigs[0])},
            )

        # Fallback: error/quote differential. Boolean-blind can't tickle every
        # injection (e.g. UNION/error-based endpoints), but a lone single quote
        # that provokes a SQL error — while a balanced quote does not — proves
        # the input is parsed as SQL. We observe only status/size, never data.
        err = self._quote_differential(ctx, finding.asset, base_args, str(param), base)
        evidence.extend(err["evidence"])
        if err["confirmed"]:
            return OracleResult(
                passed=True,
                oracle_id=self.oracle_id,
                detail=err["detail"],
                confidence=0.95,
                evidence=tuple(f"raw:{a}" for a in evidence),
                measurements={"technique": "error-differential", **err["measurements"]},
            )

        return OracleResult(
            passed=False,
            oracle_id=self.oracle_id,
            detail=(
                f"no boolean-blind differential (true={true_sigs[0]} false={false_sigs[0]}) "
                f"and no error/quote differential ({err['detail']})"
            ),
            confidence=confidence,
            evidence=tuple(f"raw:{a}" for a in evidence),
            measurements={"true_signature": list(true_sigs[0]),
                          "false_signature": list(false_sigs[0])},
        )

    def _quote_differential(
        self,
        ctx: VerifyContext,
        target: str,
        base_args: dict[str, Any],
        param: str,
        base: str,
    ) -> dict[str, Any]:
        """Odd single quote → SQL error, balanced quote → OK ⇒ injectable."""

        r_base = self._probe(ctx, target, base_args, {param: base})
        r_odd = self._probe(ctx, target, base_args, {param: base + "'"})
        r_even = self._probe(ctx, target, base_args, {param: base + "''"})
        sb, zb = r_base["parsed"].get("status"), r_base["parsed"].get("size")
        so, zo = r_odd["parsed"].get("status"), r_odd["parsed"].get("size")
        se, ze = r_even["parsed"].get("status"), r_even["parsed"].get("size")
        evidence = [r_base["audit_id"], r_odd["audit_id"], r_even["audit_id"]]

        error_signal = (
            so is not None and sb is not None and se is not None
            and so >= 500 and sb < 500 and se < 500
        )
        # Content signal: the odd quote changes the response and balancing it
        # brings the response back toward baseline (quote is SQL-significant).
        content_signal = zo != zb and ze != zo and zb == ze
        confirmed = bool(error_signal or content_signal)
        signal = (
            "SQL error on odd quote" if error_signal
            else "content differential" if content_signal
            else "no signal"
        )
        return {
            "confirmed": confirmed,
            "evidence": evidence,
            "detail": (
                f"quote differential: base=HTTP{sb}/{zb}B odd-quote=HTTP{so}/{zo}B "
                f"balanced=HTTP{se}/{ze}B ({signal})"
            ),
            "measurements": {"base": [sb, zb], "odd_quote": [so, zo], "balanced": [se, ze]},
        }

    @staticmethod
    def _probe(
        ctx: VerifyContext,
        target: str,
        base_args: dict[str, Any],
        params: dict[str, str],
    ) -> dict[str, Any]:
        # Honour the injection point's HTTP method: a POST/PUT parameter is sent
        # in the request body, a GET parameter in the query string. This lets the
        # same differential logic confirm SQLi in form/JSON body params, not just
        # query params.
        method = str(base_args.get("method", "GET")).upper()
        payload_key = "data" if method in ("POST", "PUT", "PATCH") else "params"
        profile = ToolProfile(args={**base_args, payload_key: params})
        result = ctx.tool_runner.run("http_probe", target, profile)
        return {"parsed": result.parsed, "audit_id": result.audit_id}
