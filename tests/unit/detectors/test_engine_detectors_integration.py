"""Integration tests for engine, registry, exception isolation, and signatures."""

from pathlib import Path

from gitforensics.detectors import get_default_detectors
from gitforensics.detectors.base import BaseDetector
from gitforensics.engine import run_analysis
from gitforensics.git import RepositoryExtractor, parse_repository_input
from gitforensics.models import DetectorResult, RepositoryContext, SignatureStatus
from tests.helpers.git_fixtures import add_commit, create_dummy_repo


class BrokenFailingDetector(BaseDetector):
    """Synthetic detector that intentionally raises an unhandled exception."""

    def get_rule_id(self) -> str:
        return "GF999"

    def analyze(self, context: RepositoryContext) -> DetectorResult:
        raise RuntimeError("Synthetic detector crash!")


def test_registry_registers_all_ten_detectors() -> None:
    """Test get_default_detectors returns all 16 registered detectors."""
    detectors = get_default_detectors()
    assert len(detectors) == 16
    rule_ids = {d.get_rule_id() for d in detectors}
    expected_ids = {
        "GF001",
        "GF002",
        "GF003",
        "GF004",
        "GF005",
        "GF006",
        "GF007",
        "GF008",
        "GF009",
        "GF010",
        "GF011",
        "GF012",
        "GF013",
        "GF014",
        "GF015",
        "GF016",
    }
    assert rule_ids == expected_ids


def test_detector_exception_isolation(tmp_path: Path) -> None:
    """Test that a failing detector does not crash the engine or stop other detectors."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Test commit")

    repo_input = parse_repository_input(str(tmp_path))
    detectors: list[BaseDetector] = [BrokenFailingDetector()] + get_default_detectors()
    report, _ = run_analysis(repo_input, detectors=detectors)

    # Engine completed successfully despite BrokenFailingDetector crash
    assert report is not None


def test_local_repository_unsigned_signature_extraction_integration(tmp_path: Path) -> None:
    """Integration test: extract unsigned commit status from actual local repository."""
    create_dummy_repo(tmp_path)
    add_commit(tmp_path, message="Local test commit")

    repo_input = parse_repository_input(str(tmp_path))
    history = RepositoryExtractor().extract(repo_input)

    assert len(history.commits) == 1
    c = history.commits[0]
    assert c.signature_status == SignatureStatus.UNSIGNED
