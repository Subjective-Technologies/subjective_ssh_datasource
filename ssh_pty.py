"""A real terminal on the far side: `ssh -tt` driven through a local pty pair.

`ssh_shell.SshShellSession` runs commands and frames each one with a sentinel, which
is what gives the caller exit codes, stream separation and a tracked working
directory. The price is that the remote sees pipes, so anything that asks
`isatty(stdin)` — `claude` and `codex` without arguments, `top`, `vim`, a `sudo`
password prompt — refuses to run or falls back to a non-interactive mode.

This module pays the opposite price. The remote gets a genuine tty, every interactive
program works, Ctrl-C reaches the foreground job through the terminal rather than
killing the connection — and all framing is gone. A terminal stream has no
machine-readable command boundary: the shell's prompt is the only marker and it is
cosmetic, and a sentinel cannot be injected because the tty would echo it back to the
user. So there are no `exit` events and no `cwd` here, only bytes.

Two mechanisms are doing the work, and both are needed:

- **`-tt`** forces a pty on the *remote* side even though ssh's own stdin is not a
  terminal. Without it the remote is still pipes and nothing is gained.
- **A local pty pair** gives ssh a controlling terminal of its own. That is what makes
  resizing possible: setting the window size on the master makes the kernel deliver
  SIGWINCH to ssh, which forwards a window-change request to the remote, which
  re-flows whatever is drawing there. With ssh's stdin on a pipe instead, the remote
  terminal is stuck at 0x0 and full-screen programs draw nothing usable.

Output is decoded incrementally. A read can land in the middle of a UTF-8 sequence or
an escape sequence, and decoding each chunk independently would corrupt the first and
a naive line-splitter would break the second — so the decoder carries state across
reads and chunks are passed through whole, boundaries and all.
"""
from __future__ import annotations

import codecs
import errno
import fcntl
import os
import pty
import signal
import struct
import subprocess
import termios
import threading
import time
from typing import Callable

from brainboost_data_source_logger_package.BBLogger import BBLogger

DEFAULT_COLS = 120
DEFAULT_ROWS = 32
# ssh forwards TERM from its own environment, and a service process usually has none —
# which leaves the remote saying "TERM environment variable not set" and every curses
# program drawing badly or refusing to start. xterm-256color is what the browser
# terminal emulator this feeds actually implements.
DEFAULT_TERM = "xterm-256color"
# Terminals are chatty; a read this size keeps a full-screen redraw to a few frames.
READ_SIZE = 65536


class SshPtySession:
    """One interactive terminal on a remote host. Thread-safe."""

    CLOSE_GRACE_SECONDS = 3
    # ETX. Sent into the pty, so the remote tty driver turns it into SIGINT for the
    # foreground process group — the real Ctrl-C, not a connection teardown.
    INTERRUPT = "\x03"

    def __init__(
        self,
        argv: list[str],
        environment: dict[str, str],
        *,
        release: Callable[[], None] | None = None,
        cols: int = DEFAULT_COLS,
        rows: int = DEFAULT_ROWS,
        term: str = DEFAULT_TERM,
        on_event: Callable[[dict], None] | None = None,
    ):
        self._argv = argv
        self._environment = dict(environment)
        self._environment["TERM"] = term or DEFAULT_TERM
        self.term = self._environment["TERM"]
        self._release = release
        self._on_event = on_event
        self.cols = max(1, int(cols or DEFAULT_COLS))
        self.rows = max(1, int(rows or DEFAULT_ROWS))

        self._process: subprocess.Popen | None = None
        self._master: int | None = None
        self._reader: threading.Thread | None = None
        self._state_lock = threading.RLock()
        self._closed = False
        self.started_at = 0.0

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> dict:
        """Spawn ssh attached to a fresh pty. Returns `ready`, or `error`.

        Unlike the command session there is nothing to probe: a terminal has no
        request/response, so a failure to connect shows up as ssh's message on the
        stream followed by `closed`. The caller surfaces both to the user.
        """
        with self._state_lock:
            if self._process is not None:
                raise RuntimeError("This session has already been started.")
            master, slave = pty.openpty()
            # Size it before the child execs, so the remote never sees a 0x0 terminal
            # and full-screen programs draw correctly from their first frame.
            _set_winsize(master, self.rows, self.cols)
            try:
                self._process = subprocess.Popen(
                    self._argv,
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=self._environment,
                    # New session plus TIOCSCTTY below: ssh must own this tty for the
                    # kernel to deliver SIGWINCH to it on resize.
                    start_new_session=True,
                    preexec_fn=_become_session_leader_of_tty,
                    close_fds=True,
                )
            except OSError as error:
                os.close(master)
                os.close(slave)
                self._release_materials()
                return {"type": "error", "error": f"Could not start ssh: {error}"}
            finally:
                # The child holds its own copy; keeping ours open would stop the read
                # side from ever seeing EOF when the child exits.
                try:
                    os.close(slave)
                except OSError:
                    pass
            self._master = master
            self.started_at = time.time()

        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        return {"type": "ready", "cols": self.cols, "rows": self.rows, "term": self.term}

    def close(self) -> None:
        """End the session. Safe to call repeatedly and from any thread."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
            master = self._master
            self._master = None

        if process is not None and process.poll() is None:
            # Closing the master sends SIGHUP to the remote's session through ssh,
            # which is how a terminal normally ends. Signals are the fallback.
            try:
                if master is not None:
                    os.close(master)
                    master = None
            except OSError:
                pass
            try:
                process.wait(timeout=self.CLOSE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                _signal_group(process, signal.SIGTERM)
                try:
                    process.wait(timeout=self.CLOSE_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    _signal_group(process, signal.SIGKILL)
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        self._release_materials()

    @property
    def alive(self) -> bool:
        with self._state_lock:
            if self._closed or self._process is None:
                return False
            return self._process.poll() is None

    # ------------------------------------------------------------------ terminal io

    def write(self, data: str) -> bool:
        """Send keystrokes. Returns False once the terminal is gone.

        This is raw input, not a command: no newline is added and nothing is quoted.
        The remote tty does the echoing, line editing and signal generation, which is
        the whole point of running with one.
        """
        with self._state_lock:
            master = self._master
        if master is None or not self.alive:
            return False
        payload = data.encode("utf-8", "replace")
        while payload:
            try:
                written = os.write(master, payload)
            except (BrokenPipeError, OSError):
                return False
            payload = payload[written:]
        return True

    def interrupt(self) -> bool:
        """Ctrl-C, delivered through the terminal to the remote foreground job."""
        return self.write(self.INTERRUPT)

    def resize(self, cols: int, rows: int) -> bool:
        """Re-flow the remote terminal to a new window size.

        Setting the size on the master makes the kernel signal SIGWINCH to ssh, which
        forwards a window-change to the remote; the remote tty then signals whatever
        is running there. Without the local pty there would be nothing to signal.
        """
        cols = max(1, int(cols or 0))
        rows = max(1, int(rows or 0))
        with self._state_lock:
            master = self._master
            if master is None:
                return False
            self.cols, self.rows = cols, rows
        try:
            _set_winsize(master, rows, cols)
        except OSError:
            return False
        return True

    # ------------------------------------------------------------------ events

    def _pump(self) -> None:
        """Read the terminal until it ends, emitting chunks as they arrive."""
        # Stateful across reads: a chunk can end mid-UTF-8-sequence, and decoding each
        # one independently would turn that into replacement characters.
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            with self._state_lock:
                master = self._master
            if master is None:
                break
            try:
                chunk = os.read(master, READ_SIZE)
            except OSError as error:
                # EIO here is how Linux reports "the other end of the pty is gone",
                # i.e. an ordinary exit, not a failure.
                if error.errno not in (errno.EIO, errno.EBADF):
                    BBLogger.log(f"[SshPtySession] Terminal read failed: {error}")
                break
            if not chunk:
                break
            text = decoder.decode(chunk)
            if text:
                self._emit({"type": "data", "data": text})
        tail = decoder.decode(b"", final=True)
        if tail:
            self._emit({"type": "data", "data": tail})
        self._finish()

    def _finish(self) -> None:
        with self._state_lock:
            process = self._process
        code = None
        if process is not None:
            try:
                code = process.wait(timeout=self.CLOSE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                code = None
        self._emit({"type": "closed", "code": code})

    def _emit(self, event: dict) -> None:
        callback = self._on_event
        if callback is None:
            return
        try:
            callback(event)
        except Exception as error:  # noqa: BLE001 — a bad callback must not kill the pump
            BBLogger.log(f"[SshPtySession] Event callback failed: {error}")

    def attach(self, on_event: Callable[[dict], None]) -> None:
        """Set the consumer. Unlike the command session there is no queue to flush:
        a terminal's backlog is only useful to something already rendering it."""
        self._on_event = on_event

    # ------------------------------------------------------------------ helpers

    def _release_materials(self) -> None:
        release, self._release = self._release, None
        if release is not None:
            try:
                release()
            except Exception as error:  # noqa: BLE001
                BBLogger.log(f"[SshPtySession] Releasing session secrets failed: {error}")


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    """struct winsize is {rows, cols, xpixel, ypixel} — rows first, not cols."""
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _become_session_leader_of_tty() -> None:
    """Make the inherited pty slave the child's controlling terminal.

    `start_new_session=True` already calls setsid(), but a session leader only picks
    up a controlling terminal when it *opens* a tty — and this child inherits fd 0
    rather than opening one. Without the explicit TIOCSCTTY, ssh has no controlling
    terminal, never receives SIGWINCH, and the remote terminal stays at whatever size
    it started with for the life of the session.
    """
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        # Not fatal: everything except resizing still works, and failing the spawn
        # over it would be worse than a terminal that cannot be re-flowed.
        pass


def _signal_group(process: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(os.getpgid(process.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill() if sig == signal.SIGKILL else process.terminate()
        except OSError:
            pass


def remote_login_argv(working_directory: str, shell: str) -> list[str]:
    """What to run on the far side.

    With no command at all, ssh -tt starts the account's own login shell, which is the
    truest terminal and picks up the user's real environment. A working directory
    needs a command, so `exec` is used to replace it rather than nesting a second
    shell inside the login one.
    """
    if not working_directory:
        return []
    quoted = working_directory.replace("'", "'\\''")
    return [f"cd '{quoted}' && exec {shell} -l"]
