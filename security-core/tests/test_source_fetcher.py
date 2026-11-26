import io
import tarfile
import zipfile

import pytest

from app.source_fetcher import (
    SourcePolicyError,
    extract_source_archive,
    validate_download_url,
    validate_repository_url,
    validate_resolved_addresses,
)


def test_repository_url_is_canonicalized():
    assert validate_repository_url("https://github.com/Example/Project.git") == (
        "https://github.com/Example/Project"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/repo",
        "https://github.com.evil.test/example/repo",
        "https://user@github.com/example/repo",
        "https://github.com:8443/example/repo",
        "https://github.com/example/repo?next=//127.0.0.1",
        "https://github.com/example/%2e%2e",
        "https://github.com/example/repo/tree/main",
        "https://github.com/example/../repo",
    ],
)
def test_repository_url_rejects_ambiguous_targets(url):
    with pytest.raises(SourcePolicyError):
        validate_repository_url(url)


def test_download_redirect_allows_only_github_hosts():
    assert validate_download_url("https://codeload.github.com/example/repo/zip/abc")
    with pytest.raises(SourcePolicyError):
        validate_download_url("https://127.0.0.1/archive.zip")
    with pytest.raises(SourcePolicyError):
        validate_download_url("https://github.com.evil.test/archive.zip")


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["10.0.0.1"], ["::1"], ["8.8.8.8", "192.168.1.1"]])
def test_dns_rejects_non_public_or_mixed_answers(addresses):
    with pytest.raises(SourcePolicyError):
        validate_resolved_addresses(addresses)


def test_dns_accepts_public_addresses():
    assert validate_resolved_addresses(["8.8.8.8"]) == ("8.8.8.8",)


def _zip(path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)


def test_zip_extracts_regular_files(tmp_path):
    archive = tmp_path / "source.zip"
    _zip(archive, [("repo/README.md", b"safe")])
    output = extract_source_archive(archive, tmp_path / "out")
    assert (output / "repo/README.md").read_bytes() == b"safe"


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "repo\\..\\escape.txt"])
def test_zip_rejects_traversal(tmp_path, name):
    archive = tmp_path / "bad.zip"
    _zip(archive, [(name, b"bad")])
    with pytest.raises(SourcePolicyError):
        extract_source_archive(archive, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_zip_rejects_dot_segment(tmp_path):
    archive = tmp_path / "dot.zip"
    _zip(archive, [("repo/./file.txt", b"bad")])
    with pytest.raises(SourcePolicyError, match="path_traversal"):
        extract_source_archive(archive, tmp_path / "out")


def test_zip_rejects_duplicate_paths(tmp_path):
    archive = tmp_path / "duplicate.zip"
    _zip(archive, [("repo/a.txt", b"one"), ("repo/a.txt", b"two")])
    with pytest.raises(SourcePolicyError, match="duplicate"):
        extract_source_archive(archive, tmp_path / "out")


def test_zip_rejects_expansion_limit(tmp_path):
    archive = tmp_path / "large.zip"
    _zip(archive, [("repo/large.txt", b"x" * 100)])
    with pytest.raises(SourcePolicyError, match="expanded_size"):
        extract_source_archive(archive, tmp_path / "out", max_file_bytes=10)


def test_zip_rejects_symlink(tmp_path):
    archive = tmp_path / "link.zip"
    info = zipfile.ZipInfo("repo/link")
    info.create_system = 3
    info.external_attr = (0o120777 << 16)
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(info, "target")
    with pytest.raises(SourcePolicyError, match="link_or_special"):
        extract_source_archive(archive, tmp_path / "out")


def test_tar_rejects_symbolic_link(tmp_path):
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("repo/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        bundle.addfile(info)
    with pytest.raises(SourcePolicyError, match="link_or_special"):
        extract_source_archive(archive, tmp_path / "out")


def test_tar_extracts_regular_file(tmp_path):
    archive = tmp_path / "source.tar.gz"
    data = b"hello"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("repo/hello.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    output = extract_source_archive(archive, tmp_path / "out")
    assert (output / "repo/hello.txt").read_bytes() == data


def test_archive_file_count_limit(tmp_path):
    archive = tmp_path / "many.zip"
    _zip(archive, [("a.txt", b"a"), ("b.txt", b"b")])
    with pytest.raises(SourcePolicyError, match="file_count"):
        extract_source_archive(archive, tmp_path / "out", max_files=1)
