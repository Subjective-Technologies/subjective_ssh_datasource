"""Tests for the persistent shell session.

The fake ssh client runs the remote command locally, so `bash -s` becomes a real
local shell reading real stdin. Everything the session promises — state surviving
between commands, exit codes, stream separation, sentinel framing — is exercised
against an actual shell rather than a mock of one.
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from SubjectiveSshDataSource import SubjectiveSshDataSource
from ssh_shell import SshShellSession, remote_shell_argv


FAKE_SSH = r"""#!/bin/sh
for remote in "$@"; do :; done
eval "$remote"
"""


class ShellTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ssh = Path(self.tmp.name) / "fake-ssh"
        self.ssh.write_text(FAKE_SSH, encoding="utf-8")
        self.ssh.chmod(0o755)

    def session(self, **overrides):
        connection = {
            "host": "example.test",
            "username": "deploy",
            "ssh_path": str(self.ssh),
            # A login shell would source the developer's profile and print whatever it
            # prints into the transcript under test.
            "login_shell": False,
        }
        connection.update(overrides)
        source = SubjectiveSshDataSource(connection=connection)
        session = source.open_shell()
        self.addCleanup(session.close)
        ready = session.start(timeout=20)
        self.assertEqual(ready["type"], "ready", ready)
        return session

    def run_command(self, session, command, timeout=20):
        """Send one command and collect everything up to its exit event."""
        self.assertTrue(session.send_command(command))
        stdout, stderr = [], []
        while True:
            event = session.next_event(timeout=timeout)
            self.assertIsNotNone(event, f"no event for {command!r}")
            if event["type"] == "output":
                (stdout if event["stream"] == "stdout" else stderr).append(event["data"])
            elif event["type"] == "exit":
                return "".join(stdout), "".join(stderr), event
            elif event["type"] == "closed":
                return "".join(stdout), "".join(stderr), event


class SessionTests(ShellTestCase):
    def test_a_command_returns_its_output_and_exit_code(self):
        session = self.session()
        stdout, _, event = self.run_command(session, "echo hello")
        self.assertEqual(stdout, "hello\n")
        self.assertEqual(event["type"], "exit")
        self.assertEqual(event["code"], 0)

    def test_a_failing_command_reports_its_code_without_ending_the_session(self):
        session = self.session()
        _, _, event = self.run_command(session, "false")
        self.assertEqual(event["code"], 1)
        self.assertTrue(session.alive)
        stdout, _, event = self.run_command(session, "echo still-here")
        self.assertEqual(stdout, "still-here\n")
        self.assertEqual(event["code"], 0)

    def test_streams_stay_separate(self):
        session = self.session()
        stdout, stderr, _ = self.run_command(session, "echo out; echo problem >&2")
        self.assertEqual(stdout, "out\n")
        self.assertEqual(stderr, "problem\n")

    def test_the_directory_survives_between_commands(self):
        session = self.session()
        target = Path(self.tmp.name) / "sub"
        target.mkdir()
        _, _, event = self.run_command(session, f"cd {target}")
        self.assertEqual(os.path.realpath(event["cwd"]), os.path.realpath(target))
        stdout, _, _ = self.run_command(session, "pwd")
        self.assertEqual(os.path.realpath(stdout.strip()), os.path.realpath(target))

    def test_shell_state_survives_between_commands(self):
        """The whole point of a session: one shell, not one shell per command."""
        session = self.session()
        self.run_command(session, "FOO=bar; greet() { echo hi-$1; }")
        stdout, _, _ = self.run_command(session, "echo $FOO; greet there")
        self.assertEqual(stdout, "bar\nhi-there\n")

    def test_output_without_a_trailing_newline_is_not_lost(self):
        session = self.session()
        stdout, _, _ = self.run_command(session, "printf no-newline-at-end")
        self.assertEqual(stdout, "no-newline-at-end")

    def test_a_blank_line_the_command_printed_survives(self):
        """The sentinel's own leading newline is removed; the command's is not."""
        session = self.session()
        stdout, _, _ = self.run_command(session, r"printf 'a\n\n'")
        self.assertEqual(stdout, "a\n\n")

    def test_a_command_with_no_output_produces_no_output_events(self):
        session = self.session()
        stdout, stderr, event = self.run_command(session, "true")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(event["code"], 0)

    def test_a_sentinel_printed_on_stdout_alone_does_not_end_the_command(self):
        """Output that looks like the marker must not cut the command short.

        A command *can* forge a boundary by writing the marker to both streams, but
        whoever runs commands here already runs arbitrary code: this is framing, not
        a security boundary. What matters is that it does not happen by accident.
        """
        session = self.session()
        stdout, _, event = self.run_command(
            session, f"echo {SshShellSession.SENTINEL}:0:/spoofed; echo after"
        )
        self.assertIn("after", stdout)
        self.assertEqual(event["type"], "exit")
        self.assertEqual(event["code"], 0)
        self.assertNotEqual(event["cwd"], "/spoofed")

    def test_a_command_reading_stdin_does_not_eat_the_session(self):
        """Without </dev/null, `cat` would swallow the sentinel and wedge the shell."""
        session = self.session()
        stdout, _, event = self.run_command(session, "cat")
        self.assertEqual(stdout, "")
        self.assertEqual(event["code"], 0)
        stdout, _, _ = self.run_command(session, "echo alive")
        self.assertEqual(stdout, "alive\n")

    def test_exiting_the_shell_closes_the_session(self):
        session = self.session()
        _, _, event = self.run_command(session, "exit 7")
        self.assertEqual(event["type"], "closed")
        self.assertEqual(event["code"], 7)
        self.assertFalse(session.alive)
        self.assertFalse(session.send_command("echo nope"))

    def test_closing_is_idempotent_and_ends_the_shell(self):
        session = self.session()
        session.close()
        session.close()
        self.assertFalse(session.alive)


class AttachTests(ShellTestCase):
    def test_attaching_delivers_events_by_callback_instead_of_queue(self):
        session = self.session()
        received = []
        session.attach(received.append)
        session.send_command("echo pushed")
        deadline = 20
        import time as _time

        end = _time.time() + deadline
        while _time.time() < end and not any(e["type"] == "exit" for e in received):
            _time.sleep(0.05)
        kinds = [e["type"] for e in received]
        self.assertIn("exit", kinds)
        self.assertIn("pushed\n", [e.get("data") for e in received if e["type"] == "output"])
        # The queue stops growing once a consumer has attached.
        self.assertIsNone(session.next_event())


class ArgvTests(unittest.TestCase):
    def test_the_remote_side_reads_commands_from_stdin(self):
        """-s is what makes the shell read stdin while still honouring -l."""
        self.assertEqual(remote_shell_argv("bash", False), ["bash", "-s"])
        self.assertEqual(remote_shell_argv("bash", True), ["bash", "-ls"])


class SessionSecretTests(ShellTestCase):
    def test_session_secrets_outlive_a_command_and_die_with_the_session(self):
        """ssh may re-authenticate mid-session, so the askpass files must persist."""
        source = SubjectiveSshDataSource(
            connection={
                "host": "example.test",
                "username": "deploy",
                "ssh_path": str(self.ssh),
                "login_shell": False,
                "auth_method": "password",
                "password": "hunter2",
            }
        )
        session = source.open_shell()
        askpass = Path(session._environment["SSH_ASKPASS"])
        self.assertTrue(askpass.exists())
        self.assertEqual(stat.S_IMODE(askpass.parent.stat().st_mode), 0o700)
        ready = session.start(timeout=20)
        self.assertEqual(ready["type"], "ready", ready)
        # Still present after a command, unlike the one-shot path.
        self.run_command(session, "echo ok")
        self.assertTrue(askpass.exists())
        session.close()
        self.assertFalse(askpass.exists())
        self.assertFalse(askpass.parent.exists())


class FailureTests(ShellTestCase):
    def test_a_connection_that_never_opens_is_reported_as_an_error(self):
        failing = Path(self.tmp.name) / "failing-ssh"
        failing.write_text(
            "#!/bin/sh\necho 'deploy@example.test: Permission denied (publickey).' >&2\nexit 255\n",
            encoding="utf-8",
        )
        failing.chmod(0o755)
        source = SubjectiveSshDataSource(
            connection={"host": "example.test", "username": "deploy", "ssh_path": str(failing)}
        )
        session = source.open_shell()
        self.addCleanup(session.close)
        started = session.start(timeout=20)
        self.assertEqual(started["type"], "error")
        self.assertIn("Permission denied", started["error"])

    def test_an_incomplete_connection_refuses_to_open_at_all(self):
        source = SubjectiveSshDataSource(connection={"ssh_path": str(self.ssh)})
        with self.assertRaises(LookupError) as caught:
            source.open_shell()
        self.assertIn("host", str(caught.exception))

    def test_a_host_alias_needs_no_username(self):
        """`host` may be a ~/.ssh/config alias that already names the account."""
        source = SubjectiveSshDataSource(
            connection={"host": "subjective-agents", "ssh_path": str(self.ssh)}
        )
        self.assertEqual(source._missing_configuration(), [])

    def test_a_defaulted_port_is_not_forced_onto_a_config_alias(self):
        """Passing -p 22 would override a Port set in ~/.ssh/config for the alias."""
        source = SubjectiveSshDataSource(
            connection={"host": "subjective-agents", "ssh_path": str(self.ssh)}
        )
        self.assertNotIn("-p", source._build_shell_argv({}))
        explicit = SubjectiveSshDataSource(
            connection={"host": "h", "port": 2222, "ssh_path": str(self.ssh)}
        )
        argv = explicit._build_shell_argv({})
        self.assertEqual(argv[argv.index("-p") + 1], "2222")

    def test_a_session_does_not_leave_a_control_socket_behind(self):
        """A ControlMaster would outlive the session it was opened for."""
        source = SubjectiveSshDataSource(
            connection={"host": "h", "session_id": "abc", "ssh_path": str(self.ssh)}
        )
        options = source._ssh_options({}, multiplex=False)
        self.assertFalse([o for o in options if o.startswith("ControlMaster")])


if __name__ == "__main__":
    unittest.main()
