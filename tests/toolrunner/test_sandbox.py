"""Sandbox backend tests (no Docker required)."""

from __future__ import annotations

import sys

import pytest

from attack_engine.errors import SandboxError
from attack_engine.toolrunner.sandbox import (
    DockerSandbox,
    LocalSandbox,
    NoopSandbox,
    SandboxSpec,
)


def test_noop_sandbox_never_executes() -> None:
    res = NoopSandbox().run(SandboxSpec(image="x", argv=["nmap", "10.0.4.12"]))
    assert res.exit_code == 127
    assert res.backend == "noop"


class TestLocalSandbox:
    def test_missing_binary_raises(self) -> None:
        with pytest.raises(SandboxError, match="not found"):
            LocalSandbox().run(SandboxSpec(image="x", argv=["definitely-not-a-real-bin"]))

    def test_runs_real_process_and_captures_output(self) -> None:
        # Use the running Python interpreter as a guaranteed-present binary.
        res = LocalSandbox().run(
            SandboxSpec(image="x", argv=[sys.executable, "-c", "print('hello sandbox')"])
        )
        assert res.exit_code == 0
        assert b"hello sandbox" in res.stdout
        assert res.backend == "local"

    def test_nonzero_exit_captured(self) -> None:
        res = LocalSandbox().run(
            SandboxSpec(image="x", argv=[sys.executable, "-c", "import sys; sys.exit(3)"])
        )
        assert res.exit_code == 3


class TestDockerSandbox:
    def test_command_is_locked_down(self) -> None:
        sb = DockerSandbox(runtime="runsc")
        cmd = sb._build_command(
            SandboxSpec(image="attack-engine/nmap", argv=["nmap", "-F", "10.0.4.12"], network="ae-eng1")
        )
        # Hardening flags must be present.
        assert "--rm" in cmd
        assert "--read-only" in cmd
        assert cmd[cmd.index("--network") + 1] == "ae-eng1"
        assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
        assert "no-new-privileges" in cmd
        assert cmd[cmd.index("--runtime") + 1] == "runsc"
        # Image precedes the tool argv.
        assert "attack-engine/nmap" in cmd
        assert cmd[-3:] == ["nmap", "-F", "10.0.4.12"]

    def test_env_passthrough(self) -> None:
        sb = DockerSandbox()
        cmd = sb._build_command(
            SandboxSpec(image="img", argv=["tool"], env={"FOO": "bar"})
        )
        assert "--env" in cmd
        assert "FOO=bar" in cmd
