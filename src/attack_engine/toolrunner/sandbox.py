"""Ephemeral, network-scoped tool sandboxes (spec §5 — container isolation).

Every tool runs in an isolated, disposable sandbox so there is no shared blast
radius and nothing touches the corporate network. Three backends:

* :class:`DockerSandbox` — one ephemeral ``--rm`` container per invocation on an
  engagement-scoped Docker network (optionally gVisor-isolated). Production.
* :class:`LocalSandbox`  — runs the tool directly on the host with a timeout.
  **No isolation** — dev/CI convenience only, gated behind explicit config.
* :class:`NoopSandbox`   — never executes; returns a canned failure. Unit tests.

A backend only has to turn an argv into an exit code + captured output. All the
policy (scope, rate, RoE, audit) lives above it in the Tool Runner.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..errors import SandboxError, ToolTimeoutError

if TYPE_CHECKING:
    from ..config import Settings


@dataclass(frozen=True)
class SandboxSpec:
    """Everything needed to launch one sandboxed command."""

    image: str
    argv: list[str]
    timeout_sec: int = 300
    #: Docker network name/mode; ``none`` disables networking entirely.
    network: str = "none"
    env: dict[str, str] = field(default_factory=dict)
    #: Read-only mounts as (source, container_path) — source is a host path or a
    #: docker volume name. Used to supply wordlists / template sets to tools
    #: without loosening the read-only root fs. Always mounted ``:ro``.
    mounts: tuple[tuple[str, str], ...] = ()
    #: Drop ALL Linux capabilities (the hardened default). A few tools genuinely
    #: can't run this way — e.g. the Metasploit framework's Alpine/musl Ruby
    #: interpreter fails to ``execve`` under ``--cap-drop ALL``. Such a tool sets
    #: this False to use Docker's default (already reduced) capability set; every
    #: OTHER control — read-only root, no-new-privileges, tmpfs, network scope,
    #: pids-limit, audit — is unchanged.
    drop_all_caps: bool = True


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_sec: float
    backend: str

    @property
    def combined(self) -> bytes:
        if self.stderr:
            return self.stdout + b"\n---stderr---\n" + self.stderr
        return self.stdout


class Sandbox(ABC):
    name: str = "abstract"

    @abstractmethod
    def run(self, spec: SandboxSpec) -> SandboxResult: ...


class NoopSandbox(Sandbox):
    """Executes nothing. Returns a canned non-zero result. For unit tests."""

    name = "noop"

    def run(self, spec: SandboxSpec) -> SandboxResult:
        return SandboxResult(
            exit_code=127,
            stdout=b"",
            stderr=b"noop sandbox: execution disabled",
            duration_sec=0.0,
            backend=self.name,
        )


class LocalSandbox(Sandbox):
    """Runs the tool binary directly on the host. NO ISOLATION — dev only.

    Argv is executed with ``shell=False`` so there is no shell interpolation.
    Still, this backend gives a tool full host access; never enable it in prod.
    """

    name = "local"

    def run(self, spec: SandboxSpec) -> SandboxResult:
        binary = spec.argv[0] if spec.argv else ""
        if not shutil.which(binary):
            raise SandboxError(f"binary {binary!r} not found on host (LocalSandbox)")
        start = time.monotonic()
        try:
            proc = subprocess.run(
                spec.argv,
                capture_output=True,
                timeout=spec.timeout_sec,
                check=False,
                env={**spec.env} or None,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeoutError(binary, "local", f"timeout after {spec.timeout_sec}s") from exc
        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_sec=time.monotonic() - start,
            backend=self.name,
        )


class DockerSandbox(Sandbox):
    """One ephemeral, network-scoped container per invocation (production).

    Uses ``docker run --rm`` with a locked-down profile: read-only root fs,
    dropped capabilities, no new privileges, and an engagement-scoped network.
    An optional runtime (e.g. ``runsc`` for gVisor) adds kernel isolation.
    """

    name = "docker"

    def __init__(
        self,
        *,
        docker_bin: str = "docker",
        runtime: str | None = None,  # e.g. "runsc" for gVisor
        extra_run_args: list[str] | None = None,
    ) -> None:
        self._docker = docker_bin
        self._runtime = runtime
        self._extra = extra_run_args or []

    def _build_command(self, spec: SandboxSpec) -> list[str]:
        cmd = [
            self._docker, "run", "--rm",
            # Clear any image ENTRYPOINT so every tool image runs our explicit
            # argv (binary first) uniformly, regardless of how it was built.
            "--entrypoint", "",
            "--network", spec.network,
            "--read-only",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            # Read-only root fs, but tools still need scratch space. A capped,
            # noexec tmpfs at /tmp (and HOME pointed there) lets curl/nuclei/ffuf
            # write configs/temp files without loosening the read-only root.
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m,mode=1777",
            "--env", "HOME=/tmp",
        ]
        # Drop every capability by default; a tool that needs the default set
        # (see SandboxSpec.drop_all_caps) opts out — nothing else is loosened.
        if spec.drop_all_caps:
            cmd += ["--cap-drop", "ALL"]
        for source, target in spec.mounts:
            cmd += ["-v", f"{source}:{target}:ro"]  # always read-only
        if self._runtime:
            cmd += ["--runtime", self._runtime]
        for key, val in spec.env.items():
            cmd += ["--env", f"{key}={val}"]
        cmd += self._extra
        cmd.append(spec.image)
        cmd += spec.argv
        return cmd

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not shutil.which(self._docker):
            raise SandboxError(f"{self._docker!r} not found; is Docker installed?")
        command = self._build_command(spec)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                timeout=spec.timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeoutError(
                spec.image, spec.network, f"timeout after {spec.timeout_sec}s"
            ) from exc
        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_sec=time.monotonic() - start,
            backend=self.name,
        )


def build_sandbox(settings: Settings | None = None) -> Sandbox:
    from ..config import SandboxBackend, get_settings

    s: Settings = settings or get_settings()
    if s.sandbox_backend is SandboxBackend.DOCKER:
        return DockerSandbox()
    if s.sandbox_backend is SandboxBackend.LOCAL:
        return LocalSandbox()
    return NoopSandbox()
