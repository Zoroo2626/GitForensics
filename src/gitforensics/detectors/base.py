"""Base class and interface for anomaly detectors."""

from abc import ABC, abstractmethod

from gitforensics.models import DetectorResult, RepositoryContext


class BaseDetector(ABC):
    """Abstract base class for all GitForensics detectors."""

    @abstractmethod
    def get_rule_id(self) -> str:
        """Returns a stable, unique rule ID (e.g., 'GF001')."""
        pass

    @abstractmethod
    def analyze(self, context: RepositoryContext) -> DetectorResult:
        """Analyzes the repository context and returns a DetectorResult."""
        pass
