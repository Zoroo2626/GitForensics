"""Project specific exception classes for GitForensics."""


class GitForensicsError(Exception):
    """Base exception class for GitForensics."""

    exit_code: int = 1


class CLIArgumentError(GitForensicsError):
    """Raised when invalid CLI arguments or options are provided."""

    exit_code: int = 2


class OutputWriteError(GitForensicsError):
    """Raised when writing the report output file fails."""

    exit_code: int = 2


class RepositoryNotFoundError(GitForensicsError):
    """Raised when the repository path or URL is invalid, non-existent, or inaccessible."""

    exit_code: int = 3


class InvalidGitRepositoryError(GitForensicsError):
    """Raised when a directory is not a valid Git repository."""

    exit_code: int = 3


class GitCommandError(GitForensicsError):
    """Raised when a Git command subprocess execution fails."""

    exit_code: int = 3

    def __init__(
        self,
        message: str,
        command: list[str] | None = None,
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.command = command or []
        self.returncode = returncode
        self.stderr = stderr


class GitTimeoutError(GitForensicsError):
    """Raised when a Git command subprocess times out."""

    exit_code: int = 3


class GitOutputLimitError(GitForensicsError):
    """Raised when a Git process exceeds its bounded stdout/stderr allowance."""

    exit_code: int = 3


class GitCloneError(GitForensicsError):
    """Raised when cloning a remote repository fails."""

    exit_code: int = 3


class MalformedGitOutputError(GitForensicsError):
    """Raised when Git command output cannot be parsed."""

    exit_code: int = 3


class TemporaryCleanupError(GitForensicsError):
    """Raised when sensitive cloned repository data cannot be removed."""

    exit_code: int = 1


class NetworkError(GitForensicsError):
    """Raised when a network-dependent GitHub API request fails."""

    exit_code: int = 4


class GitHubAPIError(NetworkError):
    """Base exception for GitHub REST API errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimitError(GitHubAPIError):
    """Raised when GitHub API rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        reset_timestamp: int | None = None,
        status_code: int | None = 429,
    ) -> None:
        super().__init__(message, status_code=status_code)
        self.reset_timestamp = reset_timestamp


class GitHubNotFoundError(GitHubAPIError):
    """Raised when a GitHub repository or resource is not found (HTTP 404)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=404)


class GitHubAuthError(GitHubAPIError):
    """Raised when GitHub API authentication fails (HTTP 401/403)."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message, status_code=status_code)


class GitHubNetworkError(NetworkError):
    """Raised when a low-level HTTP network or connection error occurs."""

    pass


class GitHubResponseLimitError(GitHubAPIError):
    """Raised when an API response or pagination sequence exceeds configured limits."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=None)


class MalformedGitHubResponseError(GitHubAPIError):
    """Raised when a required GitHub API payload has an invalid schema."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=None)


class ThresholdBreachedError(GitForensicsError):
    """Raised when analysis findings breach the specified --fail-on severity threshold."""

    exit_code: int = 5


class NotImplementedAnalysisError(GitForensicsError):
    """Raised when analysis functionality is invoked before implementation."""

    exit_code: int = 1
