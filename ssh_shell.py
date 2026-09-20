"""A persistent remote shell over one SSH connection, streamed rather than batched.

`SubjectiveSshDataSource.run()` answers one command per call: connect (or reuse a
multiplexed connection), run, collect, return. That is the right shape for a pipeline
turn and the wrong shape for a terminal — every command pays a round trip, nothing
appears until the command finishes, and shell state does not survive between calls
beyond the working directory this package threads through by hand.

This module is the other shape: `ssh … bash -s` with stdin held open, so one shell
lives for the whole session. Commands are written to it and output is pumped out as it
arrives. Shell state — variables, functions, `cd`, `export`, activated virtualenvs —
persists because it is genuinely the same shell.

**Framing.** stdout and stderr are separate pipes with no ordering guarantee between
them, so a command's end is marked on *both*: the shell prints a sentinel carrying the
exit code and `pwd` to stdout and a matching one to stderr, and a command is only
reported finished once both have been seen. Without the stderr sentinel, a command
whose diagnostics arrive late would have them attributed to the next command.

Framing is not a trust boundary. A command that writes the marker to both streams can
fake a command boundary — but anyone reaching this code already runs arbitrary
commands on the far side, so there is nothing to defend. Requiring both streams is
there to stop it happening *by accident*, which output containing the marker on one
stream otherwise would.

**Not a terminal.** There is no pty, so interactive programs (`top`, `vim`, a `sudo`
password prompt) will not work: the remote side sees a pipe and behaves accordingly.
Each command's stdin is `/dev/null`, which is what keeps a program like `cat` from
eating the sentinel lines and wedging the session. A pty mode belongs here later; it
needs a local pty pair and `ssh -tt`, and it changes the output from text into a byte
stream the client must render with a terminal emulator.
"""
from __future__ import annotations

import os
import queue
import shlex
import signal
import subprocess
import threading
import time
from typing import Any, Callable

from brainboost_data_source_logger_package.BBLogger import BBLogger


class SshShellSession:
    """One long-lived remote shell. Thread-safe for one writer and one reader."""

    # Distinct from the one-shot datasource's sentinel: this one also marks stderr, and
    # the two must never be mistaken for each other in a transcript.
    SENTINEL = "__SUBJECTIVE_SSH_SHELL__"
    # How long to wait for the shell to exit politely before signalling its group.
    CLOSE_GRACE_SECONDS = 3

    def __init__(
        self,
        argv: list[str],
        environment: dict[str, str],
        *,
        release: Callable[[], None] | None = None,
        shell: str = "bash",
        on_event: Callable[[dict], None] | None = None,
    ):
        self._argv = argv
        self._environment = environment
        # Frees the per-session secret files. Held for the life of the session rather
        # than per command, because ssh may re-authenticate on a dropped connection.
        self._release = release
        self._shell = shell
        self._on_event = on_event

        self._process: subprocess.Popen | None = None
        self._events: queue.Queue[dict] = queue.Queue()
        self._readers: list[threading.Thread] = []
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = False
        # Set when the stdout sentinel has been seen but stderr's has not, and vice
        # versa; the command is finished when both have landed.
        self._pending_exit: dict | None = None
        self._stdout_done = False
        self._stderr_done = False
        self.cwd = ""
        self.started_at = 0.0
        # One held-back blank line per stream. See `_consume`.
        self._held: dict[str, str] = {}
        # Events are queued until a consumer attaches a callback; see `attach`. Held
        # across the swap so an event cannot be delivered twice or dropped.
        self._emit_lock = threading.Lock()
        self._queue_events = True

    # ------------------------------------------------------------------ lifecycle

    def start(self, *, timeout: float = 30.0) -> dict:
        """Open the connection and wait for the shell to prove it is alive.

        Returns the first `ready` event, or an `error` event if the shell never came
        up. Never raises for an ordinary connection failure: a bad host is a normal
        outcome for an operator typing a target, and it reads better as an event.
        """
        with self._state_lock:
            if self._process is not None:
                raise RuntimeError("This session has already been started.")
            try:
                self._process = subprocess.Popen(
                    self._argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Bytes, not text: output may be binary or partial UTF-8 at a chunk
                    # boundary, and decoding is the consumer's business.
                    bufsize=0,
                    env=self._environment,
                    # Own process group, so close() takes ssh and its children together.
                    start_new_session=True,
                )
            except OSError as error:
                self._release_materials()
                return {"type": "error", "error": f"Could not start ssh: {error}"}
            self.started_at = time.time()

        self._readers = [
            threading.Thread(
                target=self._pump, args=("stdout", self._process.stdout), daemon=True
            ),
            threading.Thread(
                target=self._pump, args=("stderr", self._process.stderr), daemon=True
            ),
        ]
        for reader in self._readers:
            reader.start()

        # A probe rather than an assumption: ssh exits non-zero long after Popen
        # succeeds (auth, host key, DNS), and the operator needs that as a failure to
        # connect, not as a silent session that answers nothing.
        probe = self.send_command(":")
        if not probe:
            return {"type": "error", "error": "Could not write to the remote shell."}
        deadline = time.time() + timeout
        transcript: list[str] = []
        while time.time() < deadline:
            event = self.next_event(timeout=deadline - time.time())
            if event is None:
                continue
            if event["type"] == "exit":
                return {"type": "ready", "cwd": self.cwd}
            if event["type"] == "closed":
                detail = "".join(transcript).strip()
                return {
                    "type": "error",
                    "error": detail or "The SSH connection closed before the shell started.",
                    "exit_code": event.get("code"),
                }
            if event["type"] == "output":
                # Keep ssh's own diagnostics: they say *why* the connection failed.
                transcript.append(event.get("data", ""))
        self.close()
        return {"type": "error", "error": f"The remote shell did not respond within {timeout:g}s."}

    def close(self) -> None:
        """End the session. Safe to call repeatedly and from any thread."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
        if process is None:
            self._release_materials()
            return
        try:
            if process.stdin and not process.stdin.closed:
                # Closing stdin is how a shell is asked to leave; signalling is the
                # fallback for one wedged inside a command.
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=self.CLOSE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._signal_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=self.CLOSE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                self._signal_group(process, signal.SIGKILL)
        self._release_materials()

    @property
    def alive(self) -> bool:
        with self._state_lock:
            if self._closed or self._process is None:
                return False
            return self._process.poll() is None

    # ------------------------------------------------------------------ commands

    def send_command(self, command: str) -> bool:
        """Queue one command. Returns False when the shell is no longer writable."""
        process = self._process
        if process is None or process.stdin is None or not self.alive:
            return False
        payload = self._wrap(command).encode("utf-8", "replace")
        with self._write_lock:
            try:
                process.stdin.write(payload)
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                return False
        return True

    def interrupt(self) -> bool:
        """Ctrl-C the remote command.

        Signals the local ssh process group. Without a pty there is no way to deliver
        SIGINT to the remote foreground job, so this tears down the connection and with
        it the remote shell; the caller should treat the session as finished. Faithful
        interruption needs the pty mode described in this module's docstring.
        """
        with self._state_lock:
            process = self._process
        if process is None or process.poll() is not None:
            return False
        self._signal_group(process, signal.SIGINT)
        return True

    def _wrap(self, command: str) -> str:
        """Bracket a command so its end, exit code and directory are unambiguous.

        The braces are a group, not a subshell, so `cd` and `export` still affect the
        session. `</dev/null` applies to the group: a command that reads stdin would
        otherwise consume the sentinel lines below it and wedge the session.
        """
        sentinel = shlex.quote(self.SENTINEL)
        # Each sentinel is prefixed with a newline so that it always starts a line,
        # even when the command's last write had no trailing newline (`printf abc`).
        # The blank line this adds when output *did* end cleanly is taken back out by
        # the pump — see `_consume`.
        return (
            "{\n"
            f"{command}\n"
            "} </dev/null\n"
            "__subjective_rc=$?\n"
            f'printf "\\n%s:%s:%s\\n" {sentinel} "$__subjective_rc" "$(pwd)"\n'
            f'printf "\\n%s\\n" {sentinel} >&2\n'
        )

    # ------------------------------------------------------------------ events

    def next_event(self, timeout: float | None = None) -> dict | None:
        """Pop one event, or None if none arrived within `timeout`.

        Events: `{"type": "output", "stream": "stdout"|"stderr", "data": str}`,
        `{"type": "exit", "code": int, "cwd": str}`, `{"type": "closed", "code": int}`.
        """
        try:
            return self._events.get(timeout=timeout) if timeout else self._events.get_nowait()
        except queue.Empty:
            return None

    def attach(self, on_event: Callable[[dict], None]) -> None:
        """Deliver events to `on_event` from now on instead of queueing them.

        `start()` consumes events from the internal queue to detect the shell coming
        up. A live consumer — the WebSocket terminal — wants them pushed instead, and
        wants the queue to stop growing behind it. The swap and the flush happen under
        the emit lock, so each event is delivered exactly once and in order.
        """
        with self._emit_lock:
            self._on_event = on_event
            self._queue_events = False
            pending = []
            while True:
                try:
                    pending.append(self._events.get_nowait())
                except queue.Empty:
                    break
        for event in pending:
            self._deliver(event)

    def _emit(self, event: dict) -> None:
        with self._emit_lock:
            if self._queue_events:
                self._events.put(event)
            callback = self._on_event
        if callback is not None:
            self._deliver(event, callback)

    def _deliver(self, event: dict, callback: Callable[[dict], None] | None = None) -> None:
        callback = callback or self._on_event
        if callback is None:
            return
        try:
            callback(event)
        except Exception as error:  # noqa: BLE001 — a bad callback must not kill the pump
            BBLogger.log(f"[SshShellSession] Event callback failed: {error}")

    def _pump(self, stream_name: str, stream) -> None:
        """Read one pipe, split the sentinel out of it, and emit the rest as output."""
        buffered = ""
        try:
            while True:
                chunk = stream.read(4096) if stream else b""
                if not chunk:
                    break
                buffered += chunk.decode("utf-8", "replace")
                buffered = self._consume(stream_name, buffered)
        except (OSError, ValueError):
            pass
        finally:
            held = self._held.pop(stream_name, None)
            if held is not None:
                self._emit({"type": "output", "stream": stream_name, "data": held})
            if buffered:
                self._emit({"type": "output", "stream": stream_name, "data": buffered})
            self._finish(stream_name)

    def _consume(self, stream_name: str, buffered: str) -> str:
        """Emit whole lines, turning sentinel lines into completion state.

        Anything after the last newline is kept: a sentinel split across two reads must
        not be emitted as output, and partial lines of real output are better held for
        a moment than shown twice.
        """
        while True:
            newline = buffered.find("\n")
            if newline < 0:
                # Hold back a possible partial sentinel; release ordinary text promptly
                # so long-running output is not stuck waiting for its newline.
                if buffered and not self.SENTINEL.startswith(buffered[: len(self.SENTINEL)]):
                    held = self._held.pop(stream_name, None)
                    if held is not None:
                        self._emit({"type": "output", "stream": stream_name, "data": held})
                    self._emit({"type": "output", "stream": stream_name, "data": buffered})
                    return ""
                return buffered
            line, buffered = buffered[:newline], buffered[newline + 1:]
            if line.startswith(self.SENTINEL):
                # Drop the blank line the sentinel's own leading newline produced.
                # Any blank line genuinely printed by the command was already flushed
                # by the line that followed it, so only ours can still be held here.
                self._held.pop(stream_name, None)
                self._mark_done(stream_name, line)
                continue
            if line == "":
                # Might be ours; decided when the next line arrives.
                held = self._held.get(stream_name)
                if held is not None:
                    self._emit({"type": "output", "stream": stream_name, "data": held})
                self._held[stream_name] = "\n"
                continue
            held = self._held.pop(stream_name, None)
            if held is not None:
                self._emit({"type": "output", "stream": stream_name, "data": held})
            self._emit({"type": "output", "stream": stream_name, "data": line + "\n"})

    def _mark_done(self, stream_name: str, line: str) -> None:
        """Record one stream's end-of-command marker; report when both have landed."""
        with self._state_lock:
            if stream_name == "stdout":
                parts = line.split(":", 2)
                code = 0
                if len(parts) >= 2:
                    try:
                        code = int(parts[1])
                    except ValueError:
                        code = 0
                if len(parts) >= 3 and parts[2].strip():
                    self.cwd = parts[2].strip()
                self._pending_exit = {"type": "exit", "code": code, "cwd": self.cwd}
                self._stdout_done = True
            else:
                self._stderr_done = True
            ready = self._stdout_done and self._stderr_done and self._pending_exit
            if not ready:
                return
            event = self._pending_exit
            self._pending_exit = None
            self._stdout_done = False
            self._stderr_done = False
        self._emit(event)

    def _finish(self, stream_name: str) -> None:
        """One pipe reached EOF: the shell is gone once both have."""
        with self._state_lock:
            if stream_name == "stdout":
                self._stdout_eof = True
            else:
                self._stderr_eof = True
            if not (getattr(self, "_stdout_eof", False) and getattr(self, "_stderr_eof", False)):
                return
            process = self._process
        code = process.wait() if process is not None else None
        self._emit({"type": "closed", "code": code})

    # ------------------------------------------------------------------ helpers

    def _release_materials(self) -> None:
        release, self._release = self._release, None
        if release is not None:
            try:
                release()
            except Exception as error:  # noqa: BLE001
                BBLogger.log(f"[SshShellSession] Releasing session secrets failed: {error}")

    @staticmethod
    def _signal_group(process: subprocess.Popen, sig: int) -> None:
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill() if sig == signal.SIGKILL else process.terminate()
            except OSError:
                pass


def remote_shell_argv(shell: str, login_shell: bool) -> list[str]:
    """The remote side of a session: a shell reading commands from stdin.

    `-s` is what makes the shell read stdin while still accepting `-l`; plain `-l`
    alone would give an interactive shell that expects a terminal.
    """
    flags = "-ls" if login_shell else "-s"
    return [shell, flags]
