import json

import pytest

from app.result_collector import CollectorError, collect_findings, parse_bandit, parse_gitleaks

COMMIT = "a" * 40


def encoded(value):
    return json.dumps(value).encode()


def test_gitleaks_secret_material_is_never_returned():
    raw_secret = "ghp_SUPER_SECRET_VALUE"
    result = parse_gitleaks(encoded([{
        "RuleID": "github-pat",
        "File": "src/config.py",
        "StartLine": 12,
        "StartColumn": 3,
        "Secret": raw_secret,
        "Match": "token = " + raw_secret,
        "Fingerprint": "untrusted-fingerprint",
    }]), scanner_version="8.24.2", commit_sha=COMMIT)
    assert len(result) == 1
    rendered = json.dumps(result[0])
    assert raw_secret not in rendered
    assert "Match" not in rendered
    assert result[0]["severity"] == "high"
    assert result[0]["path"] == "src/config.py"
    assert len(result[0]["fingerprint"]) == 64


def test_bandit_source_and_issue_text_are_not_returned():
    source = "password = 'super-secret'"
    result = parse_bandit(encoded({"results": [{
        "test_id": "B105",
        "filename": "app/settings.py",
        "line_number": 7,
        "issue_severity": "HIGH",
        "issue_text": source,
        "code": source,
    }]}), scanner_version="1.8.6", commit_sha=COMMIT)
    assert source not in json.dumps(result)
    assert result[0]["severity"] == "high"
    assert result[0]["rule_id"] == "B105"


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret", "src/../secret", "src\\secret", "src//secret", "src/./secret"])
def test_rejects_unsafe_paths(path):
    output = encoded([{"RuleID": "rule", "File": path, "StartLine": 1}])
    with pytest.raises(CollectorError):
        parse_gitleaks(output, scanner_version="1.0", commit_sha=COMMIT)


def test_rejects_invalid_json_and_duplicate_keys():
    with pytest.raises(CollectorError, match="invalid_scanner_json"):
        parse_gitleaks(b"{broken", scanner_version="1.0", commit_sha=COMMIT)
    with pytest.raises(CollectorError, match="duplicate_json_key"):
        parse_gitleaks(b'[{"RuleID":"a","RuleID":"b","File":"x.py"}]', scanner_version="1.0", commit_sha=COMMIT)


def test_rejects_oversized_output_and_finding_count():
    with pytest.raises(CollectorError, match="too_large"):
        parse_gitleaks(b" " * 20, scanner_version="1.0", commit_sha=COMMIT, max_output_bytes=10)
    with pytest.raises(CollectorError):
        parse_gitleaks(encoded([{"RuleID": "r", "File": "a.py"}] * 2),
                       scanner_version="1.0", commit_sha=COMMIT, max_findings=1)


def test_rejects_bad_metadata_severity_and_unknown_scanner():
    with pytest.raises(CollectorError, match="invalid_scan_metadata"):
        parse_gitleaks(b"[]", scanner_version="latest!", commit_sha=COMMIT)
    with pytest.raises(CollectorError, match="invalid_severity"):
        parse_bandit(encoded({"results": [{"test_id": "B1", "filename": "a.py",
                    "issue_severity": "CRITICAL", "line_number": 1}]}),
                    scanner_version="1.0", commit_sha=COMMIT)
    with pytest.raises(CollectorError, match="not_allowed"):
        collect_findings("custom", b"[]", scanner_version="1.0", commit_sha=COMMIT)


def test_empty_scanner_results_are_valid():
    assert parse_gitleaks(b"[]", scanner_version="8.24.2", commit_sha=COMMIT) == []
    assert parse_bandit(b'{"results":[]}', scanner_version="1.8.6", commit_sha=COMMIT) == []
