"""configlint.ssh — SCNG SSH client for network device interaction."""

from .client import SSHClient, SSHClientConfig, LegacySSHSupport

__all__ = ["SSHClient", "SSHClientConfig", "LegacySSHSupport"]
