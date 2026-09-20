"""Tests for the interactive terminal session.

The fake ssh client execs the remote command locally, so with `-tt` behaviour stubbed
out the child still runs under the real pty this module allocates. That makes the
parts worth pinning — a genuine tty on the child's stdin, a propagated window size,
Ctrl-C arriving as SIGINT, incremental UTF-8 decoding — testable without a host.
"""
import os
import queue
import re
import tempfile
import time
import unittest
from pathlib import Path

from SubjectiveSshDataSource import SubjectiveSshDataSource
from ssh_pty import DEFAULT_TERM, SshPtySession, remote_login_argv


# Runs the trailing remote command if there is one, otherwise an interactive-ish
# shell, exactly where the real ssh would put it: on the pty this module allocated.
FAKE_SSH = r"""#!/bin/sh
# Walk the argv the way ssh does: -o/-i/-p take a value, the first bare word is the
# target, anything after it is the remote command. Taking "the last argument" would
# mistake the target for a command whenever there is no command, which is exactly
# the case a login terminal exercises.
target=""
remote=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-i|-p) shift 2 ;;
    -*) shift ;;
    *) if [ -z "$target" ]; then target="$1"; else remote="$1"; fi; shift ;;
  esac
done
if [ -n "$remote" ]; then exec bash --norc --noprofile -c "$remote"; fi
exec bash --norc --noprofile -i
"""


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)


class PtyTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ssh = Path(self.tmp.name) / "fake-ssh"
        self.ssh.write_text(FAKE_SSH, encoding="utf-8")
        self.ssh.chmod(0o755)
        self.events = queue.Queue()

    def session(self, **overrides):
        connection = {"host": "example.test", "ssh_path": str(self.ssh)}
        connection.update(overrides)
        source = SubjectiveSshDataSource(connection=connection)
        session = source.open_pty(cols=100, rows=30, on_event=self.events.put, **{})
        self.addCleanup(session.close)
        ready = session.start()
        self.assertEqual(ready["type"], "ready", ready)
        return session

    def collect(self, seconds=3.0, until=None):
        """Drain the stream for a while, or until `until` appears in it.

        A tty echoes input, so `until` must be a string the *command* cannot contain
        — otherwise the echo of what was typed ends the wait before the command has
        run. The tests below split their markers ("IS_A" "_TTY") for that reason.
        """
        chunks, deadline = [], time.time() + seconds
        while time.time() < deadline:
            try:
                event = self.events.get(timeout=0.1)
            except queue.Empty:
                if until and until in "".join(chunks):
                    break
                continue
            if event["type"] == "data":
                chunks.append(event["data"])
            else:
                chunks.append(f"<{event['type']}:{event.get('code')}>")
            if until and until in "".join(chunks):
                break
        return "".join(chunks)


class TerminalTests(PtyTestCase):
    def test_the_child_gets_a_real_tty(self):
        """The whole point: without this, claude and codex refuse to run."""
        session = self.session()
        session.write('test -t 0 && echo "IS_A""_TTY" || echo "NOT_A""_TTY"\n')
        self.assertIn("IS_A_TTY", strip_ansi(self.collect(8, until="IS_A_TTY")))

    def test_the_window_size_reaches_the_terminal(self):
        session = self.session()
        session.write("stty size\n")
        self.assertIn("30 100", strip_ansi(self.collect(8, until="30 100")))

    def test_resizing_re_flows_the_terminal(self):
        """Needs the local pty: this is what delivers SIGWINCH to the child."""
        session = self.session()
        self.collect(1.0)
        self.assertTrue(session.resize(80, 24))
        session.write("stty size\n")
        self.assertIn("24 80", strip_ansi(self.collect(8, until="24 80")))

    def test_term_is_set_so_curses_programs_work(self):
        """ssh forwards TERM from its own environment, and a service has none."""
        session = self.session()
        session.write('echo "TERM=$TERM"\n')
        self.assertIn(
            f"TERM={DEFAULT_TERM}",
            strip_ansi(self.collect(8, until=f"TERM={DEFAULT_TERM}")),
        )

    def test_an_explicit_term_is_honoured(self):
        source = SubjectiveSshDataSource(
            connection={"host": "h", "ssh_path": str(self.ssh), "term": "vt100"}
        )
        session = source.open_pty(on_event=self.events.put)
        self.addCleanup(session.close)
        self.assertEqual(session.start()["term"], "vt100")

    def test_interrupt_signals_the_remote_job_instead_of_dropping_the_connection(self):
        session = self.session()
        self.collect(1.0)
        session.write('sleep 30; echo "SHOULD_NOT""_PRINT"\n')
        time.sleep(1.0)
        self.assertTrue(session.interrupt())
        transcript = strip_ansi(self.collect(4))
        self.assertNotIn("SHOULD_NOT_PRINT", transcript)
        # The session itself survived, unlike the command mode's interrupt.
        self.assertTrue(session.alive)
        session.write('echo "STILL""_HERE"\n')
        self.assertIn("STILL_HERE", strip_ansi(self.collect(8, until="STILL_HERE")))

    def test_the_terminal_echoes_input_because_the_tty_does(self):
        """Echo comes from the remote tty, not from this code — proof it is a tty."""
        session = self.session()
        session.write("echo marker-echo-check\n")
        # No `until` here: the point is to see both the echo and the output, so the
        # wait must not stop at the first of them.
        transcript = strip_ansi(self.collect(3))
        self.assertGreaterEqual(transcript.count("marker-echo-check"), 2)

    def test_multibyte_output_split_across_reads_is_not_corrupted(self):
        session = self.session()
        session.write("printf 'héllo wörld ✓\\n'\n")
        transcript = strip_ansi(self.collect(3))
        # Twice: the tty's echo and the command's own output, both decoded intact.
        self.assertGreaterEqual(transcript.count("héllo wörld ✓"), 2)

    def test_closing_ends_the_session(self):
        session = self.session()
        self.collect(1.0)
        session.close()
        self.assertFalse(session.alive)
        self.assertFalse(session.write("echo nope\n"))

    def test_closing_is_idempotent(self):
        session = self.session()
        session.close()
        session.close()
        self.assertFalse(session.alive)

    def test_exiting_the_shell_emits_closed(self):
        session = self.session()
        self.collect(1.0)
        session.write("exit 5\n")
        self.assertIn("<closed:", self.collect(8, until="<closed:"))


class ArgvTests(unittest.TestCase):
    def test_a_terminal_session_asks_for_a_remote_pty(self):
        """-tt in option form: without it the remote is still pipes."""
        source = SubjectiveSshDataSource(connection={"host": "h"})
        self.assertIn("RequestTTY=force", source._ssh_options({}, pty=True))

    def test_the_command_path_still_refuses_a_tty(self):
        source = SubjectiveSshDataSource(connection={"host": "h"})
        self.assertIn("RequestTTY=no", source._ssh_options({}))

    def test_no_remote_command_means_the_accounts_own_login_shell(self):
        self.assertEqual(remote_login_argv("", "bash"), [])

    def test_a_working_directory_execs_rather_than_nesting_a_shell(self):
        argv = remote_login_argv("/srv/app", "bash")
        self.assertEqual(argv, ["cd '/srv/app' && exec bash -l"])

    def test_a_quote_in_the_working_directory_cannot_break_out(self):
        argv = remote_login_argv("/srv/it's", "bash")
        self.assertEqual(argv, ["cd '/srv/it'\\''s' && exec bash -l"])

    def test_a_terminal_session_leaves_no_control_socket(self):
        source = SubjectiveSshDataSource(connection={"host": "h", "session_id": "abc"})
        options = source._ssh_options({}, multiplex=False, pty=True)
        self.assertFalse([o for o in options if o.startswith("ControlMaster")])

    def test_an_incomplete_connection_refuses_to_open(self):
        source = SubjectiveSshDataSource(connection={})
        with self.assertRaises(LookupError):
            source.open_pty()


class SecretTests(PtyTestCase):
    def test_session_secrets_are_removed_when_the_terminal_closes(self):
        source = SubjectiveSshDataSource(
            connection={
                "host": "example.test",
                "ssh_path": str(self.ssh),
                "auth_method": "password",
                "password": "hunter2",
            }
        )
        session = source.open_pty(on_event=self.events.put)
        askpass = Path(session._environment["SSH_ASKPASS"])
        self.assertTrue(askpass.exists())
        session.start()
        session.close()
        self.assertFalse(askpass.exists())
        self.assertFalse(askpass.parent.exists())

    def test_the_password_never_reaches_the_command_line(self):
        source = SubjectiveSshDataSource(
            connection={
                "host": "example.test",
                "ssh_path": str(self.ssh),
                "auth_method": "password",
                "password": "hunter2",
            }
        )
        session = source.open_pty(on_event=self.events.put)
        self.addCleanup(session.close)
        self.assertNotIn("hunter2", " ".join(session._argv))


if __name__ == "__main__":
    unittest.main()
