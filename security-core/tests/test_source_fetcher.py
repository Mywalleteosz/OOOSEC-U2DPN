import io
import tarfile
import zipfile

import pytest

from app.source_fetcher import (
    SourcePolicyError,
    fetch_repository_archive,
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



class _FakeResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self._body = body
        self._offset = 0
        self._headers = headers or {}

    def getheader(self, name):
        return self._headers.get(name)

    def read(self, size):
        chunk = self._body[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self):
        pass


class _FakeConnection:
    def __init__(self, host, port, address, timeout, response, calls):
        self._response = response
        calls.append((host, port, address, timeout))

    def request(self, method, path, headers):
        assert method == "GET"
        assert path.endswith("/" + COMMIT_SHA)
        assert headers["Connection"] == "close"

    def getresponse(self):
        return self._response

    def close(self):
        pass


COMMIT_SHA = "a" * 40


def _fake_factory_for(responses, calls):
    def factory(host, port, address, timeout):
        return _FakeConnection(host, port, address, timeout, responses.pop(0), calls)
    return factory


def _public_resolver(host, port):
    assert host in {"codeload.github.com", "github.com"}
    assert port == 443
    return ("93.184.216.34",)


def test_fetch_uses_pinned_ip_and_returns_commit_archive(tmp_path):
    calls = []
    body = b"archive-content"
    result = fetch_repository_archive(
        "https://github.com/example/repo", COMMIT_SHA, tmp_path / "repo.zip",
        resolver=_public_resolver,
        connection_factory=_fake_factory_for(
            [_FakeResponse(200, body, {"Content-Length": str(len(body))})], calls),
    )
    assert result.read_bytes() == body
    assert calls == [("codeload.github.com", 443, "93.184.216.34", 10.0)]


def test_fetch_revalidates_redirect_host(tmp_path):
    calls = []
    with pytest.raises(SourcePolicyError, match="download_host"):
        fetch_repository_archive(
            "https://github.com/example/repo", COMMIT_SHA, tmp_path / "repo.zip",
            resolver=_public_resolver,
            connection_factory=_fake_factory_for(
                [_FakeResponse(302, headers={"Location": "https://127.0.0.1/private.zip"})], calls),
        )
    assert len(calls) == 1
    assert not (tmp_path / "repo.zip").exists()


def test_fetch_rejects_non_immutable_ref(tmp_path):
    with pytest.raises(SourcePolicyError, match="commit_sha"):
        fetch_repository_archive(
            "https://github.com/example/repo", "main", tmp_path / "repo.zip",
            resolver=_public_resolver,
        )


def test_fetch_enforces_streamed_size_limit(tmp_path):
    calls = []
    with pytest.raises(SourcePolicyError, match="size_limit"):
        fetch_repository_archive(
            "https://github.com/example/repo", COMMIT_SHA, tmp_path / "repo.zip",
            max_archive_bytes=5, resolver=_public_resolver,
            connection_factory=_fake_factory_for([_FakeResponse(200, b"123456", {})], calls),
        )
    assert not (tmp_path / "repo.zip").exists()


def test_fetch_revalidates_and_pins_each_redirect(tmp_path):
    calls = []
    result = fetch_repository_archive(
        "https://github.com/example/repo", COMMIT_SHA, tmp_path / "repo.zip",
        resolver=_public_resolver,
        connection_factory=_fake_factory_for([
            _FakeResponse(302, headers={"Location": "https://codeload.github.com/example/repo/archive.zip"}),
            _FakeResponse(200, b"archive", {"Content-Length": "7"}),
        ], calls),
    )
    assert result.read_bytes() == b"archive"
    assert len(calls) == 2
    assert all(call[2] == "93.184.216.34" for call in calls)
