from pathlib import Path

from gitforensics import __version__
from gitforensics.detectors import get_default_detectors
from gitforensics.security import SecurityLimits


def test_readme_version_sync() -> None:
    """Test package version in README.md matches __version__."""
    readme_path = Path(__file__).parents[2] / "README.md"
    content = readme_path.read_text(encoding="utf-8")
    assert f"v{__version__}" in content or f"{__version__}" in content


def test_no_em_dashes_in_readme() -> None:
    """Test that README.md contains zero em dash or en dash characters."""
    readme_path = Path(__file__).parents[2] / "README.md"
    content = readme_path.read_text(encoding="utf-8")
    assert "—" not in content
    assert "–" not in content


def test_rule_ids_synchronization() -> None:
    """Test that all 16 rule IDs are present in README.md and get_default_detectors."""

    readme_path = Path(__file__).parents[2] / "README.md"
    rules_path = Path(__file__).parents[2] / "docs" / "RULES.md"
    readme_text = readme_path.read_text(encoding="utf-8")
    rules_text = rules_path.read_text(encoding="utf-8")

    detectors = get_default_detectors()
    registered_ids = {d.get_rule_id() for d in detectors}
    assert len(registered_ids) == 16

    expected_ids = {f"GF{i:03d}" for i in range(1, 17)}
    assert registered_ids == expected_ids

    for rule_id in expected_ids:
        assert rule_id in readme_text, f"Rule ID {rule_id} missing from README.md"
        assert rule_id in rules_text, f"Rule ID {rule_id} missing from docs/RULES.md"


def test_security_limits_documentation_sync() -> None:
    """Test default SecurityLimits values match documented CLI defaults."""
    limits = SecurityLimits()
    assert limits.max_commits == 50_000
    assert limits.max_tags == 10_000
    assert limits.max_git_stdout_bytes == 64 * 1024 * 1024
    assert limits.max_workflow_file_bytes == 500_000
    assert limits.max_workflow_files == 100
    assert limits.max_api_response_bytes == 8 * 1024 * 1024
    assert limits.max_api_pages == 20
    assert limits.max_releases == 2_000
    assert limits.max_release_assets == 5_000
    assert limits.max_attestation_payload_bytes == 1 * 1024 * 1024
    assert limits.max_findings == 2_000
    assert limits.max_evidence_string_chars == 512
    assert limits.max_evidence_items == 50
    assert limits.max_metadata_chars == 16_384
    assert limits.max_diff_entries == 1_000_000


def test_exit_codes_documentation_sync() -> None:
    """Test exit codes 0 through 5 are accurately described in README.md."""
    readme_path = Path(__file__).parents[2] / "README.md"
    content = readme_path.read_text(encoding="utf-8")
    for code in ("0", "1", "2", "3", "4", "5"):
        assert f"`{code}`:" in content or f"`{code}` :" in content
