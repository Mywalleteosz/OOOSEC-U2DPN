from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class SandboxPolicyError(ValueError):
    """Raised when a scanner profile or sandbox input violates policy."""


@dataclass(frozen=True)
class ScannerProfile:
    name: str
    image: str
    command: tuple[str, ...]


_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,250}@sha256:[0-9a-f]{64}$")
_PROFILES = frozenset({"gitleaks", "bandit"})


def validate_pinned_image(image: str) -> str:
    if not isinstance(image, str) or not _IMAGE_RE.fullmatch(image):
        raise SandboxPolicyError("scanner_image_digest_required")
    return image


def scanner_profile(name: str, images: dict[str, str]) -> ScannerProfile:
    """Return one fixed command; API input can never supply image or argv."""
    if name not in _PROFILES:
        raise SandboxPolicyError("scanner_profile_not_allowed")
    image = validate_pinned_image(images.get(name, ""))
    commands = {
        "gitleaks": (
            "detect", "--source", "/src", "--no-git",
            "--report-format", "json", "--report-path", "/dev/stdout",
        ),
        "bandit": ("-r", "/src", "-f", "json", "-q"),
    }
    return ScannerProfile(name=name, image=image, command=commands[name])


def build_docker_argv(
    profile: ScannerProfile,
    source_directory: str | Path,
    cidfile: str | Path,
) -> list[str]:
    """Build a locked-down Docker invocation. Never invokes a shell."""
    if profile.name not in _PROFILES:
        raise SandboxPolicyError("scanner_profile_not_allowed")
    validate_pinned_image(profile.image)
    fixed_commands = {
        "gitleaks": (
            "detect", "--source", "/src", "--no-git",
            "--report-format", "json", "--report-path", "/dev/stdout",
        ),
        "bandit": ("-r", "/src", "-f", "json", "-q"),
    }
    if profile.command != fixed_commands[profile.name]:
        raise SandboxPolicyError("scanner_command_not_allowed")

    source = Path(source_directory)
    if not source.is_absolute() or not source.is_dir() or source.is_symlink():
        raise SandboxPolicyError("source_directory_must_be_absolute_real_directory")
    cid = Path(cidfile)
    if not cid.is_absolute():
        raise SandboxPolicyError("cidfile_must_be_absolute")

    return [
        "docker", "run", "--rm",
        "--cidfile", str(cid),
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", "64",
        "--memory", "256m",
        "--memory-swap", "256m",
        "--cpus", "0.50",
        "--user", "65532:65532",
        "--ulimit", "nofile=64:64",
        "--ulimit", "fsize=10485760:10485760",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--mount", f"type=bind,src={source},dst=/src,readonly",
        "--workdir", "/src",
        "--env", "HOME=/tmp",
        "--env", "TMPDIR=/tmp",
        profile.image,
        *profile.command,
    ]


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    output: bytes


def run_sandbox(
    profile: ScannerProfile,
    source_directory: str | Path,
    *,
    timeout_seconds: int = 60,
    max_output_bytes: int = 2 * 1024 * 1024,
    process_factory: Callable = subprocess.Popen,
    monotonic: Callable = time.monotonic,
) -> SandboxResult:
    """Run a fixed profile with bounded stdout and wall-clock time.

    This is a privileged control-plane operation: the caller needs access to
    the container runtime. The scanner container itself receives no runtime
    socket, credentials, or network.
    """
    if not 1 <= timeout_seconds <= 300:
        raise SandboxPolicyError("sandbox_timeout_out_of_range")
    if not 1024 <= max_output_bytes <= 10 * 1024 * 1024:
        raise SandboxPolicyError("sandbox_output_limit_out_of_range")

    source = Path(source_directory)
    if not source.is_absolute() or not source.is_dir() or source.is_symlink():
        raise SandboxPolicyError("source_directory_must_be_absolute_real_directory")

    with tempfile.TemporaryDirectory(prefix="ooosec-sandbox-") as temp_dir:
        cidfile = Path(temp_dir) / "container.id"
        argv = build_docker_argv(profile, source, cidfile)
        process = process_factory(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
        output = bytearray()
        deadline = monotonic() + timeout_seconds
        selector = selectors.DefaultSelector()
        if process.stdout is None:
            raise SandboxPolicyError("sandbox_stdout_unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)

        try:
            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise SandboxPolicyError("sandbox_timeout")
                events = selector.select(min(remaining, 0.25))
                for key, _ in events:
                    chunk = os.read(key.fd, min(65536, max_output_bytes - len(output) + 1))
                    if chunk:
                        output.extend(chunk)
                        if len(output) > max_output_bytes:
                            raise SandboxPolicyError("sandbox_output_limit")
                    else:
                        selector.unregister(key.fileobj)
                if process.poll() is not None and not selector.get_map():
                    return SandboxResult(process.returncode, bytes(output))
        except Exception:
            try:
                if cidfile.is_file():
                    container_id = cidfile.read_text(encoding="ascii").strip()
                    if re.fullmatch(r"[0-9a-f]{12,64}", container_id):
                        subprocess.run(
                            ["docker", "kill", container_id],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                            check=False,
                            close_fds=True,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
                        )
            except (OSError, subprocess.SubprocessError):
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise
        finally:
            selector.close()
            if process.stdout is not None:
                process.stdout.close()
