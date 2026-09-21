"""Run another datasource's CLI on a remote machine.

`CommandRunner` (in the abstract package) is the seam: a CLI datasource asks its
runner to start a process, find a binary or read a file, and never learns where
that happened. This is the implementation that answers "on another machine", and
it lives here because everything it needs — argv construction, host-key handling,
the askpass machinery, connection multiplexing — is already in this package. The
Claude and Grok datasources depend on the interface alone and know nothing about
SSH.

What makes this practical rather than merely possible is **multiplexing**. An agent
turn is not one command: the datasource looks for the CLI, checks whether it is
logged in, then runs it. Three round trips of TCP and authentication per turn would
be unusable, so every command here rides one shared connection opened on first use
and kept for the life of the runner. The second and third commands cost a round
trip each and nothing more.

Two things are genuinely harder remotely than locally and are handled explicitly:

- **Finding the CLI.** Agent CLIs install under nvm, `~/.local/bin`,
  `~/.npm-global` — and a non-interactive ssh command gets none of those, because
  the shell's rc file returns early when not interactive. Every command therefore
  runs through a login shell with the usual locations added to PATH.
- **Attachments.** A file the operator attached lives on the machine running the
  service, and a remote CLI cannot open it. `upload` copies it into a temporary
  directory on the far side and returns the path there; `cleanup` removes it.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import threading
import uuid

from brainboost_data_source_logger_package.BBLogger import BBLogger
from subjective_abstract_data_source_package import CommandRunner

# Where agent CLIs actually install, in the order ssh would find them if the
# remote shell had run its rc file. Prepended to PATH for every command.
REMOTE_PATH_PREFIXES = (
    "$HOME/.npm-global/bin",
    "$HOME/.local/bin",
    "$HOME/bin",
)
# Sourced when present, because nvm puts node — and therefore most agent CLIs —
# somewhere no fixed path can name.
NVM_SETUP = '[ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1'


class SshCommandRunner(CommandRunner):
    """Runs a datasource's commands on the far side of one multiplexed connection."""

    is_remote = True

    def __init__(self, datasource, *, label: str = ""):
        """`datasource` is a configured SubjectiveSshDataSource: it owns the argv,
        the credentials and the host-key policy, and this borrows them rather than
        reimplementing any of it."""
        self._datasource = datasource
        self.location = label or f"{datasource.host}"
        self._lock = threading.RLock()
        self._materials: dict | None = None
        self._release = None
        self._control_path = ""
        self._uploads: list[str] = []
        self._remote_temp = ""

    # -- the shared connection ---------------------------------------------------

    def _prepare(self) -> dict:
        with self._lock:
            if self._materials is None:
                self._materials, self._release = self._datasource._open_materials()
                # One socket for the life of the runner. Opened by the first
                # command, reused by every command after it.
                self._control_path = os.path.join(
                    self._datasource._control_dir(), f"agent-{uuid.uuid4().hex[:12]}.sock"
                )
            return self._materials

    def _argv(self, remote_command: str) -> list[str]:
        materials = self._prepare()
        ssh_path = self._datasource._find_ssh() or "ssh"
        argv = [ssh_path, *self._datasource._port_argv()]
        for option in self._datasource._ssh_options(materials, multiplex=False):
            argv += ["-o", option]
        argv += [
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._control_path}",
            "-o", "ControlPersist=300",
        ]
        if materials.get("identity_file"):
            argv += ["-i", materials["identity_file"]]
        elif self._datasource.auth_method == self._datasource.AUTH_KEY_PATH and self._datasource.private_key_path:
            argv += ["-i", os.path.expanduser(self._datasource.private_key_path)]
        argv.append(self._datasource._target())
        # One already-quoted argument: ssh re-joins several with plain spaces and
        # hands the result to the remote shell, which would re-parse it.
        argv.append(shlex.join(["bash", "-lc", remote_command]))
        return argv

    def _wrap(self, argv: list[str], cwd: str = "") -> str:
        """The command as the remote login shell should see it.

        PATH is extended and nvm sourced because a non-interactive shell gets
        neither: the rc file that sets them up returns early when not interactive,
        which is why `codex` is "not found" over ssh but present in a terminal.
        """
        prefix = ":".join(REMOTE_PATH_PREFIXES)
        setup = f'export PATH="{prefix}:$PATH"; {NVM_SETUP}; '
        if cwd:
            setup += f"cd {shlex.quote(cwd)} || exit 127; "
        return setup + shlex.join(argv)

    # -- CommandRunner -----------------------------------------------------------

    def popen(self, argv: list[str], *, env: dict | None = None, cwd: str = "") -> subprocess.Popen:
        return subprocess.Popen(
            self._argv(self._wrap(argv, cwd)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=self._datasource._build_environment(self._prepare()),
            # Killing this group takes down the local ssh. The remote CLI then sees
            # its connection close, which is the same signal a dropped terminal
            # gives it — the closest thing to a local cancel without a pty.
            start_new_session=True,
        )

    def run(
        self, argv: list[str], *, timeout: float, env: dict | None = None, cwd: str = ""
    ) -> subprocess.CompletedProcess:
        process = self.popen(argv, env=env, cwd=cwd)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout or "", stderr or "")

    def which(self, name: str, candidates: tuple[str, ...] = ()) -> str | None:
        """Ask the remote shell where the CLI is.

        One command rather than a probe per candidate: each probe is a round trip,
        and `command -v` after the same PATH setup answers exactly the question the
        local implementation answers with `shutil.which`.
        """
        probes = " ".join(
            f'[ -x {shlex.quote(candidate)} ] && {{ printf "%s" {shlex.quote(candidate)}; exit 0; }};'
            for candidate in candidates
        )
        script = f'{probes} command -v {shlex.quote(name)} 2>/dev/null || true'
        try:
            completed = self.run(["sh", "-c", script], timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            BBLogger.log(f"[SshCommandRunner] Could not look for {name}: {error}")
            return None
        found = (completed.stdout or "").strip().splitlines()
        return found[-1].strip() if found and found[-1].strip() else None

    def is_file(self, path: str) -> bool:
        try:
            completed = self.run(["sh", "-c", f'test -f {shlex.quote(path)}'], timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    def upload(self, local_path: str) -> str:
        """Copy an attachment to the remote host and return its path there."""
        with self._lock:
            if not self._remote_temp:
                made = self.run(
                    ["sh", "-c", 'd=$(mktemp -d -t subjective-attach-XXXXXX) && printf "%s" "$d"'],
                    timeout=30,
                )
                self._remote_temp = (made.stdout or "").strip()
                if not self._remote_temp:
                    raise OSError("Could not make a temporary directory on the remote host.")

        name = os.path.basename(local_path) or "attachment"
        remote_path = f"{self._remote_temp}/{uuid.uuid4().hex[:8]}-{name}"
        # scp over the same multiplexed connection, so this costs no new handshake.
        materials = self._prepare()
        scp = [
            "scp", "-q",
            "-o", f"ControlPath={self._control_path}",
            *(["-P", str(self._datasource.port)] if self._datasource._port_explicit else []),
            local_path,
            f"{self._datasource._target()}:{remote_path}",
        ]
        completed = subprocess.run(
            scp, capture_output=True, text=True, timeout=300,
            env=self._datasource._build_environment(materials),
        )
        if completed.returncode != 0:
            raise OSError(f"Could not copy the attachment: {(completed.stderr or '').strip()[:200]}")
        with self._lock:
            self._uploads.append(remote_path)
        return remote_path

    def cleanup(self) -> None:
        with self._lock:
            uploads, self._uploads = self._uploads, []
            temp, self._remote_temp = self._remote_temp, ""
            control, self._control_path = self._control_path, ""
            release, self._release = self._release, None
            self._materials = None
        if temp:
            try:
                # Best effort: the directory is mktemp'd and the host reaps /tmp.
                subprocess.run(
                    self._argv(f"rm -rf {shlex.quote(temp)}"),
                    capture_output=True, timeout=30,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if control:
            try:
                subprocess.run(
                    [self._datasource._find_ssh() or "ssh", "-o", f"ControlPath={control}",
                     "-O", "exit", self._datasource._target()],
                    capture_output=True, timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if release is not None:
            try:
                release()
            except Exception as error:  # noqa: BLE001
                BBLogger.log(f"[SshCommandRunner] Releasing session secrets failed: {error}")
