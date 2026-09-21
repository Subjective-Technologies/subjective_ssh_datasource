"""Subjective v2 on-demand datasource: chat with any computer over SSH.

Same contract as the CLI datasources next to it (``run(request) -> dict``), but the
"agent" on the other end is a shell rather than an LLM: a turn's prompt is executed as
a command on the remote host and its stdout/stderr/exit code come back as the reply.

Transport is the OpenSSH client, not a Python SSH library. Three reasons:

- no new runtime dependency — ``ssh`` is already present everywhere this service runs;
- host-key verification, ``known_hosts``, ciphers and agent forwarding are OpenSSH's,
  not a reimplementation of them here;
- cancellation works exactly like the sibling datasources: the child runs in its own
  process group and ``cancel()`` signals the group.

Two details carry security weight and are deliberate:

- **Remote argv is joined here, not by ssh.** ``ssh host a b c`` re-joins the trailing
  arguments with plain spaces and hands the result to the remote shell, so anything
  this module interpolates (the working directory, the sentinel) would be re-parsed
  remotely. The remote command is therefore built as an argv list and collapsed with
  ``shlex.join`` into a single already-quoted trailing argument.
- **The prompt is intentionally arbitrary.** Unlike a filter value, the user's text
  *is* the command to run; quoting it would defeat the datasource. Everything around
  it is quoted, the command itself is not. Treat a configured connection as equivalent
  to handing out a shell on that host, and gate it at the connection layer.

Secrets (password, key passphrase, key content) never enter argv, the environment of
anything but the askpass helper, log lines, or the result dict.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from brainboost_data_source_logger_package.BBLogger import BBLogger
from subjective_abstract_data_source_package import SubjectiveDataSource


class SubjectiveSshDataSource(SubjectiveDataSource):
    """On-demand, resumable shell-over-SSH datasource."""

    AUTH_AGENT = "agent"
    AUTH_KEY_PATH = "private_key_path"
    AUTH_KEY_CONTENT = "private_key_content"
    AUTH_PASSWORD = "password"
    AUTH_METHODS = (AUTH_AGENT, AUTH_KEY_PATH, AUTH_KEY_CONTENT, AUTH_PASSWORD)

    HOST_KEY_STRICT = "strict"
    HOST_KEY_ACCEPT_NEW = "accept-new"
    HOST_KEY_OFF = "off"
    HOST_KEY_POLICIES = (HOST_KEY_STRICT, HOST_KEY_ACCEPT_NEW, HOST_KEY_OFF)
    _STRICT_OPTION = {
        HOST_KEY_STRICT: "yes",
        HOST_KEY_ACCEPT_NEW: "accept-new",
        HOST_KEY_OFF: "no",
    }

    # Marks the end of a turn's stdout. Carries the exit code and the shell's working
    # directory after the command ran, which is how `cd` survives into the next turn.
    # Random-free on purpose: it is matched anchored to a line and stripped before the
    # reply is shown, and a fixed marker keeps transcripts diffable.
    SENTINEL = "__SUBJECTIVE_SSH_END__"
    _SENTINEL_RE = re.compile(
        rf"^{SENTINEL}:(?P<code>-?\d+):(?P<cwd>.*)$", re.MULTILINE
    )

    MAX_OUTPUT_CHARS = 200_000
    DEFAULT_CONNECT_TIMEOUT = 15
    DEFAULT_COMMAND_TIMEOUT = 600
    # How long a multiplexed connection stays open after the last turn, so a chat does
    # not pay a TCP + auth handshake per message.
    DEFAULT_PERSIST_SECONDS = 600

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        connection = self._connection or {}

        # In-flight turn, for cancel(). datasources.run builds a fresh instance per
        # turn, so this is one process at a time, not a registry.
        self._active_process: subprocess.Popen | None = None
        self._cancelled = False
        self._process_lock = threading.Lock()
        self._lock = threading.RLock()

        self.host = str(connection.get("host") or "").strip()
        self.port = self._coerce_int(connection.get("port"), 22, minimum=1)
        # Whether to pass -p at all. `host` may be an alias whose ~/.ssh/config entry
        # sets Port; passing a defaulted -p 22 would silently override it.
        self._port_explicit = bool(str(connection.get("port") or "").strip())
        self.username = str(connection.get("username") or "").strip()

        auth_method = str(connection.get("auth_method") or self.AUTH_AGENT).strip()
        self.auth_method = (
            auth_method if auth_method in self.AUTH_METHODS else self.AUTH_AGENT
        )
        # Secrets: held on the instance, never logged and never returned.
        self._password = str(connection.get("password") or "")
        self._private_key_content = str(connection.get("private_key_content") or "")
        self._key_passphrase = str(connection.get("key_passphrase") or "")
        self.private_key_path = str(connection.get("private_key_path") or "").strip()

        self.known_hosts_path = str(connection.get("known_hosts_path") or "").strip()
        self.host_key_fingerprint = str(
            connection.get("host_key_fingerprint") or ""
        ).strip()
        # How much to trust an unfamiliar host key. Three positions, because the two
        # the boolean offered are the wrong two: `yes` cannot connect to a machine
        # this account has never met (and refusing every first connection makes the
        # feature unusable), while `no` accepts a *changed* key, which is the one
        # case that actually indicates an attack. `accept-new` takes an unknown key
        # and pins it, and still refuses a changed one.
        policy = str(connection.get("host_key_policy") or "").strip()
        if policy not in self.HOST_KEY_POLICIES:
            # The boolean this replaced, still honoured for connections that set it.
            legacy = connection.get("strict_host_key_checking")
            policy = (
                self.HOST_KEY_STRICT if self._coerce_bool(legacy)
                else self.HOST_KEY_OFF if legacy is not None
                else self.HOST_KEY_ACCEPT_NEW
            )
        self.host_key_policy = policy

        self.working_directory = str(connection.get("working_directory") or "").strip()
        self.connect_timeout = self._coerce_int(
            connection.get("connect_timeout"), self.DEFAULT_CONNECT_TIMEOUT, minimum=1
        )
        self.command_timeout = self._coerce_int(
            connection.get("command_timeout", connection.get("timeout")),
            self.DEFAULT_COMMAND_TIMEOUT,
            minimum=1,
        )
        self.shell = str(connection.get("shell") or "bash").strip() or "bash"
        self.login_shell = self._coerce_bool(connection.get("login_shell", True))
        self.persistent_session = self._coerce_bool(
            connection.get("persistent_session", True)
        )
        self.persist_seconds = self._coerce_int(
            connection.get("persist_seconds"),
            self.DEFAULT_PERSIST_SECONDS,
            minimum=0,
        )
        self.configured_ssh_path = str(connection.get("ssh_path") or "").strip()
        # Only meaningful for a terminal session; see open_pty.
        self.term = str(connection.get("term") or "").strip()

        self.session_id = str(connection.get("session_id") or "") or None
        # Working directory as of the last turn, so `cd` carries forward. Seeded from
        # the connection and then replaced by whatever the sentinel reports.
        self.cwd = self.working_directory

        self._ssh_path: str | None = None

    # ------------------------------------------------------------------ schemas

    @classmethod
    def connection_schema(cls) -> dict:
        return {
            "host": {
                "type": "text",
                "label": "Host",
                "required": True,
                "placeholder": "server.example.com",
                "description": (
                    "Hostname, IP address, or a Host alias from ~/.ssh/config "
                    "(which then supplies the account, port and key)."
                ),
            },
            "port": {
                "type": "number",
                "label": "Port",
                "required": False,
                "default": 22,
            },
            "username": {
                "type": "text",
                "label": "Username",
                "required": False,
                "placeholder": "deploy",
                "description": (
                    "Remote account the commands run as. Leave blank to let "
                    "~/.ssh/config decide, as the ssh command would."
                ),
            },
            "auth_method": {
                "type": "select",
                "label": "Authentication",
                "required": True,
                "default": cls.AUTH_AGENT,
                "options": list(cls.AUTH_METHODS),
                "description": (
                    "agent: use the running ssh-agent and default keys. "
                    "private_key_path: a key file on this machine. "
                    "private_key_content: a key pasted here, written to a private "
                    "temporary file for the duration of a turn. "
                    "password: password authentication."
                ),
            },
            "password": {
                "type": "password",
                "label": "Password",
                "required": False,
                "description": (
                    "Used only when Authentication is password. Handed to ssh through "
                    "an askpass helper, never through argv or the environment."
                ),
            },
            "private_key_path": {
                "type": "file_path",
                "label": "Private Key Path",
                "required": False,
                "placeholder": "~/.ssh/id_ed25519",
                "description": "Used only when Authentication is private_key_path.",
            },
            "private_key_content": {
                "type": "password",
                "label": "Private Key",
                "required": False,
                "description": (
                    "PEM/OpenSSH private key text. Used only when Authentication is "
                    "private_key_content. Written to a 0600 temporary file for the "
                    "duration of a turn and removed afterwards."
                ),
            },
            "key_passphrase": {
                "type": "password",
                "label": "Key Passphrase",
                "required": False,
                "description": "Passphrase for an encrypted private key, if any.",
            },
            "known_hosts_path": {
                "type": "file_path",
                "label": "Known Hosts File",
                "required": False,
                "placeholder": "~/.ssh/known_hosts",
                "description": "Overrides the default known_hosts used for verification.",
            },
            "host_key_fingerprint": {
                "type": "text",
                "label": "Host Key Fingerprint",
                "required": False,
                "placeholder": "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "description": (
                    "Pin the host key. When set, the host key is scanned and compared "
                    "before every connection and a mismatch aborts the turn."
                ),
            },
            "host_key_policy": {
                "type": "select",
                "label": "Host Key Checking",
                "required": False,
                "default": cls.HOST_KEY_ACCEPT_NEW,
                "options": list(cls.HOST_KEY_POLICIES),
                "description": (
                    "accept-new: trust a machine's key the first time and refuse it "
                    "if it ever changes. strict: refuse anything not already in "
                    "known_hosts, so a new machine must be added there first. "
                    "off: verify nothing — only for a host you reach over a network "
                    "you already trust."
                ),
            },
            "working_directory": {
                "type": "text",
                "label": "Working Directory",
                "required": False,
                "placeholder": "/srv/app",
                "description": "Directory the first command runs in. Blank uses the login directory.",
            },
            "shell": {
                "type": "text",
                "label": "Remote Shell",
                "required": False,
                "default": "bash",
            },
            "login_shell": {
                "type": "checkbox",
                "label": "Login Shell",
                "default": True,
                "description": "Run commands through a login shell so profile files are sourced.",
            },
            "persistent_session": {
                "type": "checkbox",
                "label": "Persistent Session",
                "default": True,
                "description": (
                    "Reuse one multiplexed connection across turns instead of "
                    "reconnecting and re-authenticating for every message."
                ),
            },
            "persist_seconds": {
                "type": "number",
                "label": "Session Idle Timeout (s)",
                "required": False,
                "default": cls.DEFAULT_PERSIST_SECONDS,
            },
            "connect_timeout": {
                "type": "number",
                "label": "Connect Timeout (s)",
                "required": False,
                "default": cls.DEFAULT_CONNECT_TIMEOUT,
            },
            "command_timeout": {
                "type": "number",
                "label": "Command Timeout (s)",
                "required": False,
                "default": cls.DEFAULT_COMMAND_TIMEOUT,
            },
            "term": {
                "type": "text",
                "label": "Terminal Type",
                "required": False,
                "placeholder": "xterm-256color",
                "description": (
                    "TERM for interactive terminal sessions. Blank uses "
                    "xterm-256color; ignored by the command-at-a-time paths."
                ),
            },
            "ssh_path": {
                "type": "file_path",
                "label": "ssh Binary Path",
                "required": False,
                "description": "Optional override. PATH is searched when blank.",
            },
        }

    @classmethod
    def request_schema(cls) -> dict:
        return {
            "prompt": {
                "type": "textarea",
                "label": "Command",
                "required": False,
                "description": "Executed verbatim on the remote host.",
            },
            "cwd": {
                "type": "text",
                "label": "Working Directory",
                "required": False,
                "description": "Overrides the directory carried over from the previous turn.",
            },
            "session_id": {"type": "text", "label": "Session ID", "required": False},
            "new_session": {
                "type": "checkbox",
                "label": "Start New Session",
                "default": False,
            },
            "timeout": {"type": "number", "label": "Command Timeout (s)", "required": False},
            "action": {
                "type": "select",
                "label": "Action",
                "options": ["status", "send", "reset_session"],
                "default": "status",
            },
        }

    @classmethod
    def output_schema(cls) -> dict:
        return {
            "success": {"type": "bool", "label": "Success"},
            "status": {"type": "text", "label": "Status"},
            "response": {"type": "textarea", "label": "Response"},
            "session_id": {"type": "text", "label": "Session ID"},
            "error": {"type": "text", "label": "Error"},
            "exit_code": {"type": "number", "label": "Exit Code"},
            "stdout": {"type": "textarea", "label": "Stdout"},
            "stderr": {"type": "textarea", "label": "Stderr"},
            "cwd": {"type": "text", "label": "Working Directory"},
            "host": {"type": "text", "label": "Host"},
            "truncated": {"type": "bool", "label": "Output Truncated"},
            "events": {"type": "*", "label": "Events"},
            "usage": {"type": "*", "label": "Usage"},
        }

    @classmethod
    def icon(cls) -> str:
        icon_path = os.path.join(os.path.dirname(__file__), "icon.svg")
        try:
            with open(icon_path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return ""

    # ------------------------------------------------------------------ contract

    def supports_chat(self) -> bool:
        return True

    def run(self, request: dict) -> dict:
        request = request or {}
        action = str(request.get("action") or "status")
        prompt = request.get("prompt") or request.get("message")

        if action == "reset_session":
            self.reset_session()
            return self._status_result("ready")
        if action == "send" or prompt:
            payload = dict(request)
            payload["content"] = prompt or ""
            return self.handle_message(payload, files=request.get("files"))
        return self.get_status()

    def get_status(self) -> dict:
        """Report reachability without running anything the operator did not ask for."""
        ssh_path = self._find_ssh()
        if not ssh_path:
            return self._status_result(
                "not_installed",
                error="The ssh client was not found. Install OpenSSH or configure ssh_path.",
            )

        missing = self._missing_configuration()
        if missing:
            return self._status_result(
                "configuration_required",
                error="Incomplete connection: " + ", ".join(missing) + ".",
            )

        pinned = self._verify_pinned_fingerprint()
        if pinned is not None:
            return pinned

        # `true` is the cheapest command that still proves auth and shell access.
        probe = self._execute("true", timeout=max(self.connect_timeout + 5, 10))
        if probe["status"] == "completed":
            return self._status_result("ready")
        return self._status_result(probe["status"], error=probe.get("error") or "")

    def authentication_instructions(self) -> dict:
        """Never launch an interactive login invisibly — tell the operator what to run."""
        target = self._target() or "user@host"
        return {
            "status": "authentication_required",
            "login_command": f"ssh-copy-id -p {self.port} {target}",
            "message": (
                "SSH rejected the configured credentials. Install a key with "
                "ssh-copy-id from a visible terminal, add the key to ssh-agent, or "
                "correct the password/key in the connection."
            ),
        }

    def reset_session(self) -> None:
        """Drop the multiplexed connection and forget the session and directory."""
        with self._lock:
            self._close_master()
            self.session_id = None
            self.cwd = self.working_directory

    def handle_message(self, message: Any, files: list | None = None) -> dict:
        """Run one command on the remote host and return its output as the reply."""
        with self._lock:
            normalized = self._normalize_message(message, files)
            command = normalized["command"].strip()

            if normalized["new_session"]:
                self.reset_session()
            if normalized["session_id"]:
                self.session_id = normalized["session_id"]
            if normalized["cwd"]:
                self.cwd = normalized["cwd"]
            if not self.session_id:
                self.session_id = secrets.token_hex(8)

            if not command:
                return self._error_result("invalid_request", "No command was provided.")

            ssh_path = self._find_ssh()
            if not ssh_path:
                return self._error_result(
                    "not_installed",
                    "The ssh client was not found. Install OpenSSH or configure ssh_path.",
                )
            missing = self._missing_configuration()
            if missing:
                return self._error_result(
                    "configuration_required",
                    "Incomplete connection: " + ", ".join(missing) + ".",
                )

            pinned = self._verify_pinned_fingerprint()
            if pinned is not None:
                return self._error_result(pinned["status"], pinned["error"])

            return self._execute(command, timeout=normalized["timeout"])

    def cancel(self) -> bool:
        """Stop the in-flight turn. Called from another thread.

        Latches, so a cancel arriving between handle_message() and the spawn still
        takes effect instead of being lost.
        """
        with self._process_lock:
            self._cancelled = True
            process = self._active_process
        if process is None or process.poll() is not None:
            return False
        BBLogger.log("[SubjectiveSshDataSource] Cancelling SSH turn")
        self._signal_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._signal_group(process, signal.SIGKILL)
        return True

    # ------------------------------------------------------------------ execution

    def _execute(self, command: str, *, timeout: int) -> dict:
        """Run one remote command. Secrets live only inside the askpass scratch dir."""
        with self._askpass_materials() as materials:
            argv = self._build_argv(command, materials)
            environment = self._build_environment(materials)
            try:
                with self._process_lock:
                    if self._cancelled:
                        return self._error_result(
                            "cancelled", "Stopped before ssh started."
                        )
                    process = subprocess.Popen(
                        argv,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        errors="replace",
                        env=environment,
                        # Own process group, so cancel() takes ssh and anything it
                        # spawned down together.
                        start_new_session=True,
                    )
                    self._active_process = process
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._signal_group(process, signal.SIGKILL)
                    stdout, stderr = process.communicate()
                    BBLogger.log(
                        f"[SubjectiveSshDataSource] Turn timed out after {timeout}s "
                        f"host={self.host}"
                    )
                    return self._error_result(
                        "timeout", f"The command timed out after {timeout} seconds."
                    )
                finally:
                    with self._process_lock:
                        self._active_process = None
            except OSError as error:
                BBLogger.log(f"[SubjectiveSshDataSource] Failed to start ssh: {error}")
                return self._error_result("execution_error", str(error))

        if self._cancelled:
            return self._error_result("cancelled", "Stopped by the operator.")

        return self._build_result(
            stdout or "", stderr or "", process.returncode, command
        )

    def _build_result(
        self, stdout: str, stderr: str, ssh_returncode: int, command: str
    ) -> dict:
        """Split the sentinel off stdout and decide whether ssh or the command failed."""
        body, exit_code, cwd = self._split_sentinel(stdout)

        if exit_code is None:
            # No sentinel: the remote shell never ran the command, so this is an ssh
            # failure (auth, host key, DNS, refused) rather than a command failure.
            status = self._classify_error(stderr or body)
            BBLogger.log(
                f"[SubjectiveSshDataSource] ssh failed host={self.host} "
                f"exit={ssh_returncode} status={status}"
            )
            result = self._error_result(
                status,
                (stderr or body).strip()
                or f"ssh exited with code {ssh_returncode} without running the command.",
            )
            result["exit_code"] = ssh_returncode
            result["stderr"] = self._truncate(stderr)[0]
            return result

        if cwd:
            self.cwd = cwd

        body, body_truncated = self._truncate(body)
        stderr_text, stderr_truncated = self._truncate(stderr)
        truncated = body_truncated or stderr_truncated

        BBLogger.log(
            f"[SubjectiveSshDataSource] Command completed host={self.host} "
            f"session={self.session_id or '-'} exit={exit_code}"
        )
        return {
            "success": exit_code == 0,
            # The command ran and reported for itself; a non-zero exit is a result,
            # not a datasource failure, and must not be reported as one.
            "status": "completed" if exit_code == 0 else "command_failed",
            "response": self._format_response(body, stderr_text, exit_code),
            "session_id": self.session_id or "",
            "error": "" if exit_code == 0 else f"Command exited with code {exit_code}.",
            "exit_code": exit_code,
            "stdout": body,
            "stderr": stderr_text,
            "cwd": self.cwd or "",
            "host": self.host,
            "truncated": truncated,
            "command": command,
            "events": [],
            "usage": {},
        }

    def _build_argv(self, command: str, materials: dict) -> list[str]:
        ssh_path = self._find_ssh() or "ssh"
        argv = [ssh_path, *self._port_argv()]
        for option in self._ssh_options(materials):
            argv += ["-o", option]
        if materials.get("identity_file"):
            argv += ["-i", materials["identity_file"]]
        elif self.auth_method == self.AUTH_KEY_PATH and self.private_key_path:
            argv += ["-i", os.path.expanduser(self.private_key_path)]
        argv.append(self._target())
        # One already-quoted trailing argument: ssh re-joins several with plain spaces
        # and hands the result to the remote shell, which would re-parse anything
        # interpolated below.
        argv.append(shlex.join(self._remote_argv(command)))
        return argv

    def _remote_argv(self, command: str) -> list[str]:
        shell_flags = "-lc" if self.login_shell else "-c"
        return [self.shell, shell_flags, self._remote_script(command)]

    def _remote_script(self, command: str) -> str:
        """Wrap the command so the exit code and resulting directory come back.

        `command` is interpolated unquoted on purpose — running the operator's text as
        a command is the whole feature. Everything this method adds around it is
        quoted.

        The sentinel is written from an EXIT trap rather than from a line after the
        command, because a command may legitimately end the shell (`exit 3`, `exec`),
        which would skip a trailing line and leave the turn looking like an ssh
        failure. For the same reason the command runs in the main shell and not a
        subshell: a subshell would contain `exit`, but it would also throw away the
        `cd` this datasource carries into the next turn.
        """
        sentinel = shlex.quote(self.SENTINEL)
        prologue = ""
        if self.cwd:
            # A missing directory must not silently run the command somewhere else.
            quoted_cwd = shlex.quote(self.cwd)
            prologue = (
                f"cd {quoted_cwd} || {{ "
                f'printf "subjective-ssh: cannot enter %s\\n" {quoted_cwd} >&2; '
                f"exit 1; }}\n"
            )
        return (
            "__subjective_report() {\n"
            "  __subjective_rc=$?\n"
            # $(pwd) runs a command and would overwrite $?, so capture it first.
            f'  printf "\\n%s:%s:%s\\n" {sentinel} "$__subjective_rc" "$(pwd)"\n'
            "}\n"
            "trap __subjective_report EXIT\n"
            f"{prologue}"
            f"{command}\n"
        )

    def _ssh_options(
        self, materials: dict, *, multiplex: bool = True, pty: bool = False
    ) -> list[str]:
        options = [
            f"ConnectTimeout={self.connect_timeout}",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=3",
            # `force` is the option form of -tt: ask for a remote pty even though
            # ssh's own stdin is a pty we created rather than a real terminal.
            # Otherwise nothing is interactive here and a tty is only a liability.
            "RequestTTY=force" if pty else "RequestTTY=no",
            f"StrictHostKeyChecking={self._STRICT_OPTION[self.host_key_policy]}",
        ]
        if self.username:
            options.append(f"User={self.username}")

        known_hosts = materials.get("known_hosts") or (
            os.path.expanduser(self.known_hosts_path) if self.known_hosts_path else ""
        )
        if known_hosts:
            options.append(f"UserKnownHostsFile={known_hosts}")
        elif self.host_key_policy == self.HOST_KEY_OFF:
            # Nothing is being verified, so nothing should be recorded either:
            # writing a key that was never checked would make the next connection
            # look verified when it is not.
            options.append("UserKnownHostsFile=/dev/null")

        if materials.get("askpass"):
            # BatchMode would suppress the prompt the helper exists to answer.
            options.append("BatchMode=no")
            options.append("NumberOfPasswordPrompts=1")
            if self.auth_method == self.AUTH_PASSWORD:
                options.append("PreferredAuthentications=password,keyboard-interactive")
                options.append("PubkeyAuthentication=no")
        else:
            # Without a helper there is nobody to answer a prompt, so fail fast
            # instead of hanging until the command timeout.
            options.append("BatchMode=yes")

        if self.auth_method in (self.AUTH_KEY_PATH, self.AUTH_KEY_CONTENT):
            options.append("IdentitiesOnly=yes")

        # A shell session holds its own connection for its whole life, so a
        # ControlMaster would only leave a socket behind outliving it.
        if multiplex and self.persistent_session and self.session_id:
            options.append("ControlMaster=auto")
            options.append(f"ControlPath={self._control_path()}")
            options.append(f"ControlPersist={self.persist_seconds}")
        return options

    def _build_environment(self, materials: dict) -> dict[str, str]:
        environment = dict(os.environ)
        if materials.get("askpass"):
            environment["SSH_ASKPASS"] = materials["askpass"]
            # OpenSSH 8.4+: use the helper even with a tty attached and no DISPLAY.
            environment["SSH_ASKPASS_REQUIRE"] = "force"
        else:
            # A stale helper inherited from the parent must not answer our prompts.
            environment.pop("SSH_ASKPASS", None)
            environment.pop("SSH_ASKPASS_REQUIRE", None)
        return environment

    # ------------------------------------------------------------------ secrets

    class _Materials:
        """Context manager yielding per-turn secret files, removed on the way out."""

        def __init__(self, owner: "SubjectiveSshDataSource"):
            self._owner = owner
            self._directory: str | None = None

        def __enter__(self) -> dict:
            owner = self._owner
            materials: dict[str, str] = {}
            secret = owner._prompt_secret()
            needs_key_file = (
                owner.auth_method == owner.AUTH_KEY_CONTENT
                and bool(owner._private_key_content)
            )
            if not secret and not needs_key_file:
                return materials

            # 0700 directory: the secret files inside are only ever readable by this
            # uid, which is the same boundary ~/.ssh relies on.
            self._directory = tempfile.mkdtemp(prefix="subjective-ssh-")
            os.chmod(self._directory, stat.S_IRWXU)
            base = Path(self._directory)

            if needs_key_file:
                key_file = base / "id_key"
                key_text = owner._private_key_content
                if not key_text.endswith("\n"):
                    key_text += "\n"
                key_file.write_text(key_text, encoding="utf-8")
                key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
                materials["identity_file"] = str(key_file)

            if secret:
                secret_file = base / "secret"
                secret_file.write_text(secret, encoding="utf-8")
                secret_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
                askpass = base / "askpass"
                # The helper reads the secret from a private file rather than taking
                # it from the environment, so it is not exposed to unrelated children.
                askpass.write_text(
                    "#!/bin/sh\n"
                    f"cat {shlex.quote(str(secret_file))}\n",
                    encoding="utf-8",
                )
                askpass.chmod(stat.S_IRWXU)
                materials["askpass"] = str(askpass)
            return materials

        def __exit__(self, *exc_info) -> None:
            if self._directory:
                shutil.rmtree(self._directory, ignore_errors=True)
                self._directory = None

    def _askpass_materials(self) -> "SubjectiveSshDataSource._Materials":
        return self._Materials(self)

    def _open_materials(self) -> tuple[dict, Callable[[], None]]:
        """Secret files for something longer than one command, with its own release.

        A terminal session outlives any single command and ssh may re-authenticate on
        a dropped connection, so the files cannot be torn down when the first command
        returns. The caller owns the returned release and must call it.
        """
        manager = self._askpass_materials()
        materials = manager.__enter__()
        return materials, lambda: manager.__exit__(None, None, None)

    def _prompt_secret(self) -> str:
        """The secret ssh will prompt for, if any."""
        if self.auth_method == self.AUTH_PASSWORD:
            return self._password
        if self.auth_method in (self.AUTH_KEY_PATH, self.AUTH_KEY_CONTENT):
            return self._key_passphrase
        return ""

    # ------------------------------------------------------------------ host keys

    def _verify_pinned_fingerprint(self) -> dict | None:
        """Compare the live host key against the pin. Returns None when it matches."""
        if not self.host_key_fingerprint:
            return None
        observed, error = self._scan_host_fingerprints()
        if error:
            return self._status_result("unreachable", error=error)
        expected = self._normalize_fingerprint(self.host_key_fingerprint)
        if expected in observed:
            return None
        BBLogger.log(
            f"[SubjectiveSshDataSource] Host key mismatch host={self.host}:{self.port}"
        )
        return self._status_result(
            "host_key_mismatch",
            error=(
                f"The host key of {self.host}:{self.port} does not match the pinned "
                "fingerprint. Refusing to connect."
            ),
        )

    def _scan_host_fingerprints(self) -> tuple[set[str], str]:
        keyscan = shutil.which("ssh-keyscan")
        keygen = shutil.which("ssh-keygen")
        if not keyscan or not keygen:
            return set(), "ssh-keyscan and ssh-keygen are required to pin a host key."
        try:
            scanned = subprocess.run(
                [keyscan, "-T", str(self.connect_timeout), "-p", str(self.port), self.host],
                capture_output=True,
                text=True,
                timeout=self.connect_timeout + 5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return set(), f"Could not read the host key: {error}"
        if not (scanned.stdout or "").strip():
            return set(), (
                f"No host key was returned by {self.host}:{self.port}: "
                f"{(scanned.stderr or '').strip()[:300]}"
            )
        try:
            printed = subprocess.run(
                [keygen, "-lf", "-"],
                input=scanned.stdout,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return set(), f"Could not fingerprint the host key: {error}"
        fingerprints = set()
        for line in (printed.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                fingerprints.add(self._normalize_fingerprint(parts[1]))
        return fingerprints, ""

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        """Compare fingerprints without tripping over formatting differences."""
        text = str(value or "").strip()
        if text.upper().startswith(("SHA256:", "MD5:")):
            prefix, _, rest = text.partition(":")
            return f"{prefix.upper()}:{rest.strip()}"
        # A bare hex/base64 body: assume SHA256, the only format ssh-keygen prints now.
        return f"SHA256:{text}"

    # ------------------------------------------------------------------ sessions

    def open_shell(self, *, on_event: Callable[[dict], None] | None = None):
        """Open a long-lived remote shell for a terminal session.

        The one-shot `run()` path answers a pipeline turn: one command, one result.
        This is the interactive path behind the WebSocket terminal — one shell that
        survives many commands, so `cd`, `export` and an activated virtualenv persist,
        and output streams out as it is produced instead of arriving all at once.

        Raises LookupError when ssh is missing or the connection is incomplete, and
        ValueError when a pinned host key does not match. Both are refusals to
        connect, and both must reach the operator before a socket is opened.
        """
        from ssh_shell import SshShellSession, remote_shell_argv

        if not self._find_ssh():
            raise LookupError(
                "The ssh client was not found. Install OpenSSH or configure ssh_path."
            )
        missing = self._missing_configuration()
        if missing:
            raise LookupError("Incomplete connection: " + ", ".join(missing) + ".")
        pinned = self._verify_pinned_fingerprint()
        if pinned is not None:
            raise ValueError(pinned["error"])

        materials, release = self._open_materials()
        try:
            argv = self._build_shell_argv(materials)
            environment = self._build_environment(materials)
        except Exception:
            release()
            raise
        argv.append(shlex.join(remote_shell_argv(self.shell, self.login_shell)))
        BBLogger.log(
            f"[SubjectiveSshDataSource] Opening shell session host={self.host}:{self.port}"
        )
        return SshShellSession(
            argv,
            environment,
            release=release,
            shell=self.shell,
            on_event=on_event,
        )

    def open_pty(
        self,
        *,
        cols: int = 0,
        rows: int = 0,
        term: str = "",
        on_event: Callable[[dict], None] | None = None,
    ):
        """Open an interactive terminal on the remote host.

        The third shape, after `run()` (one command, one result) and `open_shell()`
        (a stream of framed commands). Here the remote gets a real tty, so `claude`
        and `codex` with no arguments, `top`, `vim` and `sudo` prompts all work — and
        in exchange there are no exit codes, no `cwd` and no stream separation,
        because a terminal has no command boundary to report. See ssh_pty.

        Raises LookupError when ssh is missing or the connection is incomplete, and
        ValueError when a pinned host key does not match.
        """
        from ssh_pty import (
            DEFAULT_COLS,
            DEFAULT_ROWS,
            DEFAULT_TERM,
            SshPtySession,
            remote_login_argv,
        )

        if not self._find_ssh():
            raise LookupError(
                "The ssh client was not found. Install OpenSSH or configure ssh_path."
            )
        missing = self._missing_configuration()
        if missing:
            raise LookupError("Incomplete connection: " + ", ".join(missing) + ".")
        pinned = self._verify_pinned_fingerprint()
        if pinned is not None:
            raise ValueError(pinned["error"])

        materials, release = self._open_materials()
        try:
            argv = self._build_pty_argv(materials)
        except Exception:
            release()
            raise
        argv += remote_login_argv(self.cwd, self.shell)
        BBLogger.log(
            f"[SubjectiveSshDataSource] Opening pty session host={self.host}:{self.port}"
        )
        return SshPtySession(
            argv,
            self._build_environment(materials),
            release=release,
            cols=cols or DEFAULT_COLS,
            rows=rows or DEFAULT_ROWS,
            term=term or self.term or DEFAULT_TERM,
            on_event=on_event,
        )

    def _build_pty_argv(self, materials: dict) -> list[str]:
        """ssh argv for a terminal session, without the trailing remote command."""
        ssh_path = self._find_ssh() or "ssh"
        argv = [ssh_path, *self._port_argv()]
        for option in self._ssh_options(materials, multiplex=False, pty=True):
            argv += ["-o", option]
        if materials.get("identity_file"):
            argv += ["-i", materials["identity_file"]]
        elif self.auth_method == self.AUTH_KEY_PATH and self.private_key_path:
            argv += ["-i", os.path.expanduser(self.private_key_path)]
        argv.append(self._target())
        return argv

    def _build_shell_argv(self, materials: dict) -> list[str]:
        """ssh argv for a session, without the trailing remote command."""
        ssh_path = self._find_ssh() or "ssh"
        argv = [ssh_path, *self._port_argv()]
        for option in self._ssh_options(materials, multiplex=False):
            argv += ["-o", option]
        if materials.get("identity_file"):
            argv += ["-i", materials["identity_file"]]
        elif self.auth_method == self.AUTH_KEY_PATH and self.private_key_path:
            argv += ["-i", os.path.expanduser(self.private_key_path)]
        argv.append(self._target())
        return argv

    def _control_dir(self) -> str:
        """Private directory for multiplexing sockets. Shared with SshCommandRunner,
        which opens one socket for a whole agent turn rather than per command."""
        base = Path(
            os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        ) / f"subjective-ssh-{os.getuid()}"
        base.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
        return str(base)

    def _control_path(self) -> str:
        """Socket for the multiplexed session.

        Hashed rather than composed from host/user: the path has a hard length limit
        (sockaddr_un), and a long hostname or workspace would silently break
        multiplexing instead of failing loudly.
        """
        digest = hashlib.sha256(
            f"{self.username}@{self.host}:{self.port}/{self.session_id}".encode()
        ).hexdigest()[:16]
        return str(Path(self._control_dir()) / f"{digest}.sock")

    def _close_master(self) -> None:
        if not (self.persistent_session and self.session_id):
            return
        path = self._control_path()
        if not os.path.exists(path):
            return
        ssh_path = self._find_ssh()
        if ssh_path:
            try:
                subprocess.run(
                    [ssh_path, "-o", f"ControlPath={path}", "-O", "exit", self._target()],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            os.unlink(path)
        except OSError:
            pass

    # ------------------------------------------------------------------ helpers

    def _target(self) -> str:
        return f"{self.username}@{self.host}" if self.username else self.host

    def _port_argv(self) -> list[str]:
        return ["-p", str(self.port)] if self._port_explicit else []

    def _missing_configuration(self) -> list[str]:
        """Fields without which a connection cannot be attempted at all.

        `username` is deliberately not one of them: `host` may be an alias in the
        operator's ~/.ssh/config, which is where the account, port, key and options
        for it are already written. Requiring a username here would reject the
        shortest and most common way to name a machine.
        """
        missing = []
        if not self.host:
            missing.append("host")
        if self.auth_method == self.AUTH_PASSWORD and not self._password:
            missing.append("password")
        if self.auth_method == self.AUTH_KEY_PATH:
            if not self.private_key_path:
                missing.append("private_key_path")
            elif not os.path.isfile(os.path.expanduser(self.private_key_path)):
                missing.append(f"private_key_path ({self.private_key_path} does not exist)")
        if self.auth_method == self.AUTH_KEY_CONTENT and not self._private_key_content:
            missing.append("private_key_content")
        return missing

    def _find_ssh(self) -> str | None:
        if self._ssh_path:
            return self._ssh_path
        candidate = (
            os.path.expanduser(self.configured_ssh_path)
            if self.configured_ssh_path
            else shutil.which("ssh")
        )
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            self._ssh_path = candidate
            return candidate
        return None

    @classmethod
    def _split_sentinel(cls, stdout: str) -> tuple[str, int | None, str]:
        """Return (output without the sentinel, exit code, remote cwd).

        The last match wins: the command's own output may legitimately contain a line
        that looks like the sentinel, and only the shell writes one after it.
        """
        matches = list(cls._SENTINEL_RE.finditer(stdout or ""))
        if not matches:
            return stdout or "", None, ""
        last = matches[-1]
        body = (stdout[: last.start()]).rstrip("\n")
        try:
            code = int(last.group("code"))
        except ValueError:
            code = None
        return body, code, last.group("cwd").strip()

    @classmethod
    def _truncate(cls, text: str) -> tuple[str, bool]:
        text = text or ""
        if len(text) <= cls.MAX_OUTPUT_CHARS:
            return text, False
        kept = text[: cls.MAX_OUTPUT_CHARS]
        return (
            kept + f"\n… output truncated at {cls.MAX_OUTPUT_CHARS} characters.",
            True,
        )

    @staticmethod
    def _format_response(stdout: str, stderr: str, exit_code: int) -> str:
        """One readable reply for the chat, keeping the streams distinguishable."""
        parts = []
        if stdout.strip():
            parts.append(stdout.rstrip())
        if stderr.strip():
            parts.append("stderr:\n" + stderr.rstrip())
        if not parts:
            parts.append(
                "(no output)" if exit_code == 0 else f"(no output, exit code {exit_code})"
            )
        elif exit_code != 0:
            parts.append(f"(exit code {exit_code})")
        return "\n\n".join(parts)

    def _normalize_message(self, message: Any, files: list | None) -> dict:
        """Accept the several shapes a turn arrives in across callers."""
        command = ""
        cwd = ""
        session_id = ""
        new_session = False
        timeout = self.command_timeout

        if isinstance(message, dict):
            command = str(
                message.get("content")
                or message.get("prompt")
                or message.get("message")
                or message.get("command")
                or ""
            )
            cwd = str(message.get("cwd") or message.get("working_directory") or "").strip()
            session_id = str(message.get("session_id") or "").strip()
            new_session = self._coerce_bool(message.get("new_session", False))
            timeout = self._coerce_int(
                message.get("timeout", self.command_timeout),
                self.command_timeout,
                minimum=1,
            )
        else:
            command = str(message or "")

        # Files have no meaning for a shell turn; note them rather than dropping them
        # silently, so an operator who attaches one sees why nothing happened.
        if files:
            BBLogger.log(
                f"[SubjectiveSshDataSource] Ignoring {len(files)} attachment(s): "
                "this datasource executes commands and does not upload files."
            )
        return {
            "command": command,
            "cwd": cwd,
            "session_id": session_id,
            "new_session": new_session,
            "timeout": timeout,
        }

    @staticmethod
    def _classify_error(error_text: str) -> str:
        lowered = (error_text or "").lower()
        if "host key verification failed" in lowered or "remote host identification has changed" in lowered:
            return "host_key_mismatch"
        if "permission denied" in lowered or "too many authentication failures" in lowered:
            return "authentication_required"
        if "could not resolve hostname" in lowered or "name or service not known" in lowered:
            return "host_not_found"
        if (
            "connection refused" in lowered
            or "connection timed out" in lowered
            or "no route to host" in lowered
            or "network is unreachable" in lowered
            or "connection closed" in lowered
        ):
            return "unreachable"
        if "operation timed out" in lowered:
            return "timeout"
        return "execution_error"

    def _status_result(self, status: str, *, error: str = "") -> dict:
        return {
            "success": status == "ready",
            "status": status,
            "response": "",
            "session_id": self.session_id or "",
            "error": error,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "cwd": self.cwd or "",
            "host": self.host,
            "truncated": False,
            "provider": "ssh",
            "ssh_path": self._find_ssh() or "",
            "events": [],
            "usage": {},
        }

    def _error_result(self, status: str, error: str) -> dict:
        return {
            "success": False,
            "status": status,
            "response": "",
            "session_id": self.session_id or "",
            "error": error,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "cwd": self.cwd or "",
            "host": self.host,
            "truncated": False,
            "events": [],
            "usage": {},
        }

    @staticmethod
    def _signal_group(process: subprocess.Popen, sig: int) -> None:
        """Signal the whole group: ssh spawns children, and orphaning them leaves the
        remote command running with nobody reading its output."""
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill() if sig == signal.SIGKILL else process.terminate()
            except OSError:
                pass

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _coerce_int(value: Any, default: int, *, minimum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, parsed)
