"""
configlint.collector — SSH-based config collection for policy auditing.

Lighter than driftwatch's collector — no baselines, no diffs, no storage.
SSH in → collect config → scrub → return clean text for policy checks.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .models import (
    Device, Platform, PLATFORM_COMMANDS,
)
from .ssh import SSHClient, SSHClientConfig
from .scrubber import ConfigScrubber

logger = logging.getLogger(__name__)


class Collector:
    """
    Collect configs from devices for policy auditing.

    Args:
        scrubber: ConfigScrubber for noise removal.
        username: SSH username.
        password: SSH password (optional if using keys).
        key_file: Path to SSH private key (optional).
        key_passphrase: Passphrase for SSH key (optional).
        max_workers: Max concurrent SSH sessions.
        legacy_mode: Enable legacy SSH algorithms.
    """

    def __init__(
        self,
        scrubber: ConfigScrubber,
        username: str,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        max_workers: int = 10,
        legacy_mode: bool = True,
    ):
        self.scrubber = scrubber
        self.username = username
        self.password = password
        self.key_file = key_file
        self.key_passphrase = key_passphrase
        self.max_workers = max_workers
        self.legacy_mode = legacy_mode

    def collect_device(
        self, device: Device, command: Optional[str] = None,
    ) -> tuple[str, str]:
        """
        Collect output from a single device.

        When command is None (default), collects the platform config command
        and runs it through the scrubber. When command is provided, runs that
        command and returns raw output (stripped of envelope only — no config
        scrubbing, no Juniper sort).

        Flow (mirrors pybgpwatch engine._connect_sync):
          1. Build SSHClientConfig
          2. Connect (with retry on failure using fresh client + legacy_mode)
          3. find_prompt → set_expect_prompt
          4. Platform-specific pagination disable
          5. Arista: enable escalation if needed
          6. Collect output → scrub (config only) → strip envelope

        Returns:
            Tuple of (cleaned_output, error_string).
            On success error is empty. On failure output is empty.
        """
        cmds = PLATFORM_COMMANDS[device.platform]
        is_config = command is None
        run_cmd = cmds["config"] if is_config else command
        client = None

        try:
            ssh_cfg = SSHClientConfig(
                host=device.host,
                username=self.username,
                password=self.password,
                key_file=self.key_file,
                key_passphrase=self.key_passphrase,
                port=device.port,
                timeout=60,
                shell_timeout=60.0,
                inter_command_time=2.0,
                expect_prompt_timeout=90000,
                prompt_count=2,
                legacy_mode=self.legacy_mode,
            )

            # ── Connect with retry (engine pattern) ──────────────
            client = SSHClient(ssh_cfg)
            logger.info(f"{device.hostname}: connecting to {device.host}:{device.port} "
                        f"(user={self.username}, legacy={self.legacy_mode})")

            try:
                client.connect()
            except Exception as e:
                logger.warning(f"{device.hostname}: connect failed ({e}), "
                               f"retrying with fresh client + legacy_mode=True")
                # Discard the failed client entirely
                try:
                    client.disconnect()
                except Exception:
                    pass

                # Brand new SSHClient — fresh paramiko internals
                retry_cfg = SSHClientConfig(
                    host=ssh_cfg.host,
                    username=ssh_cfg.username,
                    password=ssh_cfg.password,
                    key_file=ssh_cfg.key_file,
                    key_passphrase=ssh_cfg.key_passphrase,
                    port=ssh_cfg.port,
                    timeout=ssh_cfg.timeout,
                    shell_timeout=ssh_cfg.shell_timeout,
                    inter_command_time=ssh_cfg.inter_command_time,
                    expect_prompt_timeout=ssh_cfg.expect_prompt_timeout,
                    prompt_count=ssh_cfg.prompt_count,
                    legacy_mode=True,
                )
                client = SSHClient(retry_cfg)
                client.connect()
                logger.info(f"{device.hostname}: connected on retry (legacy)")

            logger.info(f"{device.hostname}: SSH connected")

            # ── Prompt detection ─────────────────────────────────
            prompt = client.find_prompt()
            client.set_expect_prompt(prompt)
            logger.info(f"{device.hostname}: prompt → {prompt!r}")

            # ── Platform-specific pagination disable ─────────────
            pag_cmd = cmds["pagination"]
            logger.debug(f"{device.hostname}: sending '{pag_cmd}'")
            client.execute_command(pag_cmd)
            logger.info(f"{device.hostname}: pagination disabled")

            # ── Arista: escalate to privileged mode if needed ────
            if prompt.endswith(">") and device.platform == Platform.ARISTA:
                logger.debug(f"{device.hostname}: in user mode, sending 'enable'")
                client._shell.send("enable\n")
                time.sleep(1)
                client._shell.send("\n")
                time.sleep(0.5)
                prompt = client.find_prompt()
                client.set_expect_prompt(prompt)
                logger.info(f"{device.hostname}: post-enable prompt → {prompt!r}")
                if not prompt.endswith("#"):
                    raise RuntimeError(
                        f"Failed to enter privileged mode (prompt={prompt!r})"
                    )

            # ── Collect output ────────────────────────────────────
            logger.debug(f"{device.hostname}: running '{run_cmd}'")
            raw_output = client.execute_command(run_cmd)
            logger.info(f"{device.hostname}: raw output {len(raw_output)} chars, "
                        f"{len(raw_output.splitlines())} lines")

            # ── Disconnect ───────────────────────────────────────
            client.disconnect()
            client = None

            # ── Scrub + strip ────────────────────────────────────
            if is_config:
                # Config collection: full scrub (noise filters + Juniper sort)
                cleaned = self.scrubber.scrub(raw_output, device.platform)
            else:
                # Operational command: strip empty lines only, no config scrubbing
                cleaned = "\n".join(
                    line for line in raw_output.splitlines() if line.strip()
                ) + "\n"

            cleaned = _strip_command_envelope(cleaned, run_cmd, prompt)

            logger.info(
                f"{device.hostname}: collected {len(cleaned.splitlines())} clean lines"
            )
            return cleaned, ""

        except Exception as e:
            logger.error(f"{device.hostname}: collection failed: {e}")
            return "", str(e)

        finally:
            # Ensure connection is closed even on unexpected errors
            if client is not None:
                try:
                    client.disconnect()
                except Exception:
                    pass

    def collect_all(
        self,
        devices: list[Device],
        callback=None,
    ) -> dict[str, tuple[str, str]]:
        """
        Collect configs from multiple devices concurrently.

        Args:
            devices: List of devices.
            callback: Optional callable(hostname, config, error).

        Returns:
            Dict of hostname → (config, error).
        """
        results: dict[str, tuple[str, str]] = {}
        workers = min(self.max_workers, len(devices))

        logger.info(f"Collecting from {len(devices)} devices ({workers} workers)")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.collect_device, dev): dev
                for dev in devices
            }

            for future in as_completed(futures):
                dev = futures[future]
                config, error = future.result()
                results[dev.hostname] = (config, error)
                if callback:
                    callback(dev.hostname, config, error)

        return results

    def collect_command(
        self,
        devices: list[Device],
        command_map: dict[str, str],
        callback=None,
    ) -> dict[str, tuple[str, str]]:
        """
        Run an operational command across devices concurrently.

        Args:
            devices: List of devices.
            command_map: Platform value → show command string.
                Devices whose platform isn't in the map are skipped.
            callback: Optional callable(hostname, output, error).

        Returns:
            Dict of hostname → (output, error).
        """
        # Filter to devices whose platform has a command
        eligible = [d for d in devices if d.platform.value in command_map]
        if not eligible:
            return {}

        results: dict[str, tuple[str, str]] = {}
        workers = min(self.max_workers, len(eligible))

        logger.info(
            f"Collecting operational data from {len(eligible)} devices "
            f"({workers} workers)"
        )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    self.collect_device, dev,
                    command=command_map[dev.platform.value],
                ): dev
                for dev in eligible
            }

            for future in as_completed(futures):
                dev = futures[future]
                output, error = future.result()
                results[dev.hostname] = (output, error)
                if callback:
                    callback(dev.hostname, output, error)

        return results


def _strip_command_envelope(text: str, command: str, prompt: str) -> str:
    """
    Remove command echo and trailing prompt from command output.

    Same logic as driftwatch — when you execute 'show running-config',
    output includes the command echo and a trailing prompt.
    """
    lines = text.splitlines()
    cleaned = []

    for line in lines:
        stripped_line = line.strip()
        # Skip command echo
        if stripped_line == command.strip():
            continue
        # Skip lines that are just the prompt
        if prompt and stripped_line == prompt.strip():
            continue
        # Skip prompt-tail lines
        if prompt and stripped_line.endswith(prompt.strip()) and len(stripped_line) <= len(prompt) + 5:
            continue
        cleaned.append(line)

    return "\n".join(cleaned) + "\n" if cleaned else ""