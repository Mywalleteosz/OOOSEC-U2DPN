from __future__ import annotations

import ipaddress
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "codeload.github.com"})


class SourcePolicyError(ValueError):
    """Raised when a repository URL, address, or archive violates policy."""


def validate_repository_url(value: str) -> str:
    """Return a canonical GitHub repository URL; reject URL ambiguity."""
    if not isinstance(value, str) or not value or len(value) > 300:
        raise SourcePolicyError("invalid_repository_url")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise SourcePolicyError("invalid_repository_url") from exc

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or "\\" in parsed.path
    ):
        raise SourcePolicyError("repository_host_or_url_not_allowed")

    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0] != "" or not parts[1] or not parts[2]:
        raise SourcePolicyError("invalid_repository_path")

    owner, repository = parts[1], parts[2]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        not _OWNER_RE.fullmatch(owner)
        or not _REPO_RE.fullmatch(repository)
        or repository in {".", ".."}
    ):
        raise SourcePolicyError("invalid_repository_path")
    return f"https://github.com/{owner}/{repository}"


def validate_download_url(value: str) -> str:
    """Validate a download/redirect URL against the narrow GitHub host allowlist."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise SourcePolicyError("invalid_download_url") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise SourcePolicyError("download_host_or_url_not_allowed")
    return value


def validate_resolved_addresses(addresses: list[str]) -> tuple[str, ...]:
    """Reject empty, mixed, private, reserved, or otherwise non-public DNS answers."""
    if not addresses:
        raise SourcePolicyError("dns_empty_result")
    parsed_addresses = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise SourcePolicyError("dns_invalid_address") from exc
        if not address.is_global:
            raise SourcePolicyError("dns_non_public_address")
        parsed_addresses.append(address.compressed)
    return tuple(sorted(set(parsed_addresses)))


def _safe_archive_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise SourcePolicyError("archive_invalid_path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SourcePolicyError("archive_path_traversal")
    if path.parts and ":" in path.parts[0]:
        raise SourcePolicyError("archive_invalid_path")
    return path


def _write_member(root: Path, relative: PurePosixPath, source, state: dict, limits: dict) -> None:
    target = root.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise SourcePolicyError("archive_path_escape")
    target.parent.mkdir(parents=True, exist_ok=True)
    remaining = limits["max_total_bytes"] - state["total_bytes"]
    file_limit = min(limits["max_file_bytes"], remaining)
    written = 0
    with target.open("xb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, file_limit - written + 1))
            if not chunk:
                break
            written += len(chunk)
            if written > file_limit:
                raise SourcePolicyError("archive_expanded_size_limit")
            output.write(chunk)
    state["total_bytes"] += written


def extract_source_archive(
    archive_path: str | Path,
    destination: str | Path,
    *,
    max_archive_bytes: int = 25 * 1024 * 1024,
    max_total_bytes: int = 100 * 1024 * 1024,
    max_file_bytes: int = 20 * 1024 * 1024,
    max_files: int = 5000,
    max_path_depth: int = 20,
) -> Path:
    """Safely extract ZIP or gzip-TAR into a new directory with strict quotas."""
    archive = Path(archive_path)
    root = Path(destination)
    limits = {
        "max_total_bytes": max_total_bytes,
        "max_file_bytes": max_file_bytes,
    }
    if archive.stat().st_size > max_archive_bytes:
        raise SourcePolicyError("archive_compressed_size_limit")
    if root.exists():
        raise SourcePolicyError("destination_must_not_exist")
    root.mkdir(parents=True, mode=0o700)
    state = {"total_bytes": 0, "seen": set(), "files": 0}

    def accept_path(name: str, is_directory: bool) -> PurePosixPath:
        relative = _safe_archive_path(name.rstrip("/") if is_directory else name)
        if len(relative.parts) > max_path_depth:
            raise SourcePolicyError("archive_path_depth_limit")
        key = relative.as_posix()
        if key in state["seen"]:
            raise SourcePolicyError("archive_duplicate_path")
        state["seen"].add(key)
        if not is_directory:
            state["files"] += 1
            if state["files"] > max_files:
                raise SourcePolicyError("archive_file_count_limit")
        return relative

    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as bundle:
                for item in bundle.infolist():
                    if item.flag_bits & 0x1:
                        raise SourcePolicyError("archive_encrypted_member")
                    mode = (item.external_attr >> 16) & 0xFFFF
                    file_type = mode & 0o170000
                    is_directory = item.is_dir()
                    if file_type not in (0, 0o100000, 0o040000):
                        raise SourcePolicyError("archive_link_or_special_file")
                    relative = accept_path(item.filename, is_directory)
                    if is_directory:
                        root.joinpath(*relative.parts).mkdir(parents=True, exist_ok=True)
                    else:
                        with bundle.open(item, "r") as source:
                            _write_member(root, relative, source, state, limits)
        else:
            with tarfile.open(archive, mode="r|gz") as bundle:
                for item in bundle:
                    if not (item.isdir() or item.isreg()):
                        raise SourcePolicyError("archive_link_or_special_file")
                    relative = accept_path(item.name, item.isdir())
                    target = root.joinpath(*relative.parts)
                    if item.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        source = bundle.extractfile(item)
                        if source is None:
                            raise SourcePolicyError("archive_member_unreadable")
                        with source:
                            _write_member(root, relative, source, state, limits)
        return root
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
