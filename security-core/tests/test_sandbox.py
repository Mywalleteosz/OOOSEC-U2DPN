from pathlib import Path
from unittest.mock import Mock

import pytest

from app.sandbox import (
    SandboxPolicyError,
    build_docker_argv,
    run_sandbox,
    scanner_profile,
    validate_pinned_image,
)


GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.24.2@sha256:" + "a" * 64
BANDIT_IMAGE = "ghcr.io/pycqa/bandit:1.8.6@sha256:" + "b" * 64


def test_image_requires_digest():
    assert validate_pinned_image(GITLEAKS_IMAGE) == GITLEAKS_IMAGE
    with pytest.raises(SandboxPolicyError, match="digest_required"):
        validate_pinned_image("gitleaks:latest")


def test_only_fixed_profiles_are_available():
    profile = scanner_profile("bandit", {"bandit": BANDIT_IMAGE})
    assert profile.command == ("-r", "/src", "-f", "json", "-q")
    with pytest.raises(SandboxPolicyError, match="not_allowed"):
        scanner_profile("custom", {})


def test_missing_image_digest_fails_closed():
    with pytest.raises(SandboxPolicyError, match="digest_required"):
        scanner_profile("gitleaks", {})


def test_docker_argv_enforces_isolation(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    profile = scanner_profile("gitleaks", {"gitleaks": GITLEAKS_IMAGE})
    argv = build_docker_argv(profile, source, tmp_path / "cid")
    assert argv[0:2] == ["docker", "run"]
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in argv
    assert "--pids-limit" in argv
    assert "--memory" in argv
    assert "--cpus" in argv
    assert "--user" in argv
    assert any(item.endswith(",readonly") for item in argv)
    assert not any("docker.sock" in item for item in argv)
    assert profile.image in argv


def test_source_directory_must_be_absolute_real_directory(tmp_path):
    profile = scanner_profile("bandit", {"bandit": BANDIT_IMAGE})
    with pytest.raises(SandboxPolicyError):
        build_docker_argv(profile, Path("relative"), tmp_path / "cid")


def test_cidfile_must_be_absolute(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    profile = scanner_profile("bandit", {"bandit": BANDIT_IMAGE})
    with pytest.raises(SandboxPolicyError, match="cidfile"):
        build_docker_argv(profile, source, "cid")


def test_timeout_and_output_limits_are_bounded(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    profile = scanner_profile("bandit", {"bandit": BANDIT_IMAGE})
    with pytest.raises(SandboxPolicyError, match="timeout"):
        run_sandbox(profile, source, timeout_seconds=0)
    with pytest.raises(SandboxPolicyError, match="output_limit"):
        run_sandbox(profile, source, max_output_bytes=100)


def test_docker_command_never_accepts_user_argv(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    profile = scanner_profile("bandit", {"bandit": BANDIT_IMAGE})
    argv = build_docker_argv(profile, source, tmp_path / "cid")
    assert "sh" not in argv
    assert ";" not in argv
    assert "&&" not in argv


def test_builder_rejects_manually_constructed_arbitrary_profile(tmp_path):
    from app.sandbox import ScannerProfile

    source = tmp_path / "source"
    source.mkdir()
    malicious = ScannerProfile(
        name="bandit",
        image=BANDIT_IMAGE,
        command=("sh", "-c", "touch /tmp/pwned"),
    )
    with pytest.raises(SandboxPolicyError, match="command_not_allowed"):
        build_docker_argv(malicious, source, tmp_path / "cid")
