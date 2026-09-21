"""Hermetic tests: a fake ssh client stands in for a real host.

The fake evaluates the remote command locally, so the sentinel, exit codes and the
working directory carried between turns are exercised for real rather than mocked.
"""
import os
import shlex
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from SubjectiveSshDataSource import SubjectiveSshDataSource


FAKE_SSH = r"""#!/bin/sh
# Stand-in for the OpenSSH client. Records its argv and environment, answers an
# askpass prompt if one is configured, then runs the remote command locally.
{
  for arg in "$@"; do printf '%s\n' "$arg"; done
} > "$FAKE_SSH_ARGV"
env | grep -E '^(SSH_ASKPASS|SSH_ASKPASS_REQUIRE)=' > "$FAKE_SSH_ENV" || true
if [ -n "$SSH_ASKPASS" ] && [ -x "$SSH_ASKPASS" ]; then
  "$SSH_ASKPASS" > "$FAKE_SSH_SECRET"
fi
if [ -n "$FAKE_SSH_FAIL" ]; then
  printf '%s\n' "$FAKE_SSH_FAIL" >&2
  exit 255
fi
# The remote command is the single last argument, already shell-quoted.
for remote in "$@"; do :; done
eval "$remote"
"""


class SshTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.ssh = base / "fake-ssh"
        self.ssh.write_text(FAKE_SSH, encoding="utf-8")
        self.ssh.chmod(0o755)
        self.argv_log = base / "argv"
        self.env_log = base / "env"
        self.secret_log = base / "secret"
        os.environ["FAKE_SSH_ARGV"] = str(self.argv_log)
        os.environ["FAKE_SSH_ENV"] = str(self.env_log)
        os.environ["FAKE_SSH_SECRET"] = str(self.secret_log)
        os.environ.pop("FAKE_SSH_FAIL", None)
        self.addCleanup(self.tmp.cleanup)
        for key in ("FAKE_SSH_ARGV", "FAKE_SSH_ENV", "FAKE_SSH_SECRET", "FAKE_SSH_FAIL"):
            self.addCleanup(os.environ.pop, key, None)

    def datasource(self, **overrides):
        connection = {
            "host": "example.test",
            "username": "deploy",
            "ssh_path": str(self.ssh),
            # Multiplexing would point a real ControlPath at a host that does not
            # exist; the session tests below turn it back on deliberately.
            "persistent_session": False,
        }
        connection.update(overrides)
        return SubjectiveSshDataSource(connection=connection)

    def recorded_argv(self):
        return self.argv_log.read_text(encoding="utf-8").splitlines()


class SchemaTests(SshTestCase):
    def test_connection_schema_covers_every_documented_field(self):
        schema = SubjectiveSshDataSource.connection_schema()
        for field in (
            "host",
            "port",
            "username",
            "auth_method",
            "password",
            "private_key_path",
            "private_key_content",
            "key_passphrase",
            "known_hosts_path",
            "host_key_fingerprint",
            "working_directory",
            "connect_timeout",
            "command_timeout",
        ):
            self.assertIn(field, schema, field)

    def test_declares_itself_chat_capable(self):
        self.assertTrue(self.datasource().supports_chat())

    def test_output_schema_reports_the_shell_specific_fields(self):
        schema = SubjectiveSshDataSource.output_schema()
        for field in ("exit_code", "stdout", "stderr", "cwd", "host"):
            self.assertIn(field, schema, field)


class SentinelTests(unittest.TestCase):
    def test_parses_exit_code_and_directory(self):
        stdout = f"hello\n{SubjectiveSshDataSource.SENTINEL}:3:/srv/app\n"
        body, code, cwd = SubjectiveSshDataSource._split_sentinel(stdout)
        self.assertEqual(body, "hello")
        self.assertEqual(code, 3)
        self.assertEqual(cwd, "/srv/app")

    def test_output_cannot_spoof_the_sentinel(self):
        """A command printing a lookalike line must not decide the turn's exit code."""
        stdout = (
            f"{SubjectiveSshDataSource.SENTINEL}:0:/spoofed\n"
            f"{SubjectiveSshDataSource.SENTINEL}:7:/real\n"
        )
        body, code, cwd = SubjectiveSshDataSource._split_sentinel(stdout)
        self.assertEqual(code, 7)
        self.assertEqual(cwd, "/real")
        self.assertIn("/spoofed", body)

    def test_missing_sentinel_reports_no_exit_code(self):
        body, code, cwd = SubjectiveSshDataSource._split_sentinel("ssh: connect failed\n")
        self.assertIsNone(code)
        self.assertEqual(cwd, "")
        self.assertEqual(body, "ssh: connect failed\n")


class CommandConstructionTests(SshTestCase):
    def test_remote_command_is_one_already_quoted_argument(self):
        """ssh re-joins several trailing arguments with plain spaces and lets the
        remote shell re-parse the result, so there must be exactly one."""
        source = self.datasource(working_directory="/srv/app")
        argv = source._build_argv("echo hi", {})
        remote = shlex.split(argv[-1])
        self.assertEqual(remote[0], "bash")
        self.assertEqual(remote[1], "-lc")
        self.assertEqual(len(remote), 3)

    def test_working_directory_is_quoted_and_the_command_is_not(self):
        source = self.datasource(working_directory="/srv/my apps; rm -rf /")
        script = source._remote_script("echo $HOME && ls")
        self.assertIn("cd '/srv/my apps; rm -rf /'", script)
        # The prompt is the command: quoting it would defeat the datasource.
        self.assertIn("echo $HOME && ls", script)

    def test_batch_mode_is_forced_when_no_secret_can_answer_a_prompt(self):
        source = self.datasource()
        options = source._ssh_options({})
        self.assertIn("BatchMode=yes", options)

    def test_password_auth_enables_the_prompt_it_can_answer(self):
        source = self.datasource(auth_method="password", password="hunter2")
        options = source._ssh_options({"askpass": "/tmp/askpass"})
        self.assertIn("BatchMode=no", options)
        self.assertIn("PubkeyAuthentication=no", options)

    def test_an_unknown_host_key_is_trusted_once_and_pinned_by_default(self):
        """`yes` cannot reach a machine this account has never met, and refusing every
        first connection makes the feature unusable; `accept-new` still refuses a
        *changed* key, which is the case that actually indicates an attack."""
        self.assertIn("StrictHostKeyChecking=accept-new", self.datasource()._ssh_options({}))

    def test_strict_can_be_asked_for(self):
        source = self.datasource(host_key_policy="strict")
        self.assertIn("StrictHostKeyChecking=yes", source._ssh_options({}))

    def test_checking_can_be_turned_off_entirely(self):
        source = self.datasource(host_key_policy="off")
        options = source._ssh_options({})
        self.assertIn("StrictHostKeyChecking=no", options)
        # Nothing was verified, so nothing is recorded: writing an unchecked key
        # would make the next connection look verified when it is not.
        self.assertIn("UserKnownHostsFile=/dev/null", options)

    def test_the_boolean_this_replaced_is_still_honoured(self):
        """Connections saved before the policy existed carry the old field."""
        self.assertIn(
            "StrictHostKeyChecking=yes",
            self.datasource(strict_host_key_checking=True)._ssh_options({}),
        )
        self.assertIn(
            "StrictHostKeyChecking=no",
            self.datasource(strict_host_key_checking=False)._ssh_options({}),
        )

    def test_an_unknown_policy_falls_back_to_the_safe_default(self):
        source = self.datasource(host_key_policy="whatever")
        self.assertIn("StrictHostKeyChecking=accept-new", source._ssh_options({}))


class ExecutionTests(SshTestCase):
    def test_successful_command_returns_its_output(self):
        result = self.datasource().run({"action": "send", "prompt": "echo hello"})
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"].strip(), "hello")
        self.assertIn("hello", result["response"])

    def test_non_zero_exit_is_a_result_not_a_datasource_failure(self):
        result = self.datasource().run({"action": "send", "prompt": "exit 42"})
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "command_failed")
        self.assertEqual(result["exit_code"], 42)
        self.assertEqual(result["error"], "Command exited with code 42.")

    def test_stderr_is_kept_separate_from_stdout(self):
        result = self.datasource().run(
            {"action": "send", "prompt": "echo out; echo problem >&2"}
        )
        self.assertEqual(result["stdout"].strip(), "out")
        self.assertIn("problem", result["stderr"])
        self.assertIn("stderr:", result["response"])

    def test_working_directory_carries_into_the_next_turn(self):
        source = self.datasource(working_directory=self.tmp.name)
        target = Path(self.tmp.name) / "sub"
        target.mkdir()
        first = source.run({"action": "send", "prompt": "cd sub"})
        self.assertEqual(os.path.realpath(first["cwd"]), os.path.realpath(target))
        second = source.run({"action": "send", "prompt": "pwd"})
        self.assertEqual(
            os.path.realpath(second["stdout"].strip()), os.path.realpath(target)
        )

    def test_a_missing_working_directory_fails_instead_of_running_elsewhere(self):
        source = self.datasource(working_directory="/nonexistent-subjective-test")
        result = source.run({"action": "send", "prompt": "echo should-not-run"})
        self.assertFalse(result["success"])
        self.assertNotIn("should-not-run", result["stdout"])

    def test_ssh_failure_without_a_sentinel_is_classified_from_stderr(self):
        os.environ["FAKE_SSH_FAIL"] = "deploy@example.test: Permission denied (publickey)."
        result = self.datasource().run({"action": "send", "prompt": "whoami"})
        self.assertEqual(result["status"], "authentication_required")
        self.assertFalse(result["success"])

    def test_a_changed_host_key_is_reported_as_such(self):
        os.environ["FAKE_SSH_FAIL"] = "Host key verification failed."
        result = self.datasource().run({"action": "send", "prompt": "whoami"})
        self.assertEqual(result["status"], "host_key_mismatch")

    def test_an_empty_command_is_rejected_before_connecting(self):
        result = self.datasource().run({"action": "send", "prompt": "   "})
        self.assertEqual(result["status"], "invalid_request")
        self.assertFalse(self.argv_log.exists())

    def test_status_probes_the_host(self):
        self.assertEqual(self.datasource().get_status()["status"], "ready")

    def test_output_is_truncated_at_the_cap(self):
        body, truncated = SubjectiveSshDataSource._truncate(
            "x" * (SubjectiveSshDataSource.MAX_OUTPUT_CHARS + 10)
        )
        self.assertTrue(truncated)
        self.assertIn("output truncated", body)


class ConfigurationTests(SshTestCase):
    def test_a_missing_host_is_reported_before_any_connection_attempt(self):
        source = self.datasource(host="")
        result = source.run({"action": "send", "prompt": "uptime"})
        self.assertEqual(result["status"], "configuration_required")
        self.assertIn("host", result["error"])
        self.assertFalse(self.argv_log.exists())

    def test_password_auth_without_a_password_is_reported(self):
        source = self.datasource(auth_method="password")
        self.assertEqual(source.get_status()["status"], "configuration_required")

    def test_a_key_path_that_does_not_exist_is_reported(self):
        source = self.datasource(
            auth_method="private_key_path", private_key_path="/no/such/key"
        )
        status = source.get_status()
        self.assertEqual(status["status"], "configuration_required")
        self.assertIn("private_key_path", status["error"])

    def test_a_missing_ssh_client_is_reported(self):
        source = self.datasource(ssh_path="/no/such/ssh")
        with patch("shutil.which", return_value=None):
            self.assertEqual(source.get_status()["status"], "not_installed")


class SecretTests(SshTestCase):
    def test_the_password_reaches_ssh_only_through_the_askpass_helper(self):
        source = self.datasource(auth_method="password", password="hunter2")
        result = source.run({"action": "send", "prompt": "echo ok"})
        self.assertTrue(result["success"])
        # The helper answered the prompt...
        self.assertEqual(self.secret_log.read_text(encoding="utf-8"), "hunter2")
        # ...and the secret appears in neither the command line nor the result.
        self.assertNotIn("hunter2", "\n".join(self.recorded_argv()))
        self.assertNotIn("hunter2", str(result))

    def test_the_askpass_helper_is_forced_so_no_terminal_is_needed(self):
        source = self.datasource(auth_method="password", password="hunter2")
        source.run({"action": "send", "prompt": "echo ok"})
        recorded = self.env_log.read_text(encoding="utf-8")
        self.assertIn("SSH_ASKPASS_REQUIRE=force", recorded)

    def test_an_inherited_askpass_helper_is_removed_when_unused(self):
        """A helper left in the environment by the parent must not answer our prompts."""
        source = self.datasource()
        with patch.dict(os.environ, {"SSH_ASKPASS": "/inherited/helper"}):
            environment = source._build_environment({})
        self.assertNotIn("SSH_ASKPASS", environment)

    def test_a_pasted_key_is_written_private_and_removed_after_the_turn(self):
        source = self.datasource(
            auth_method="private_key_content",
            private_key_content="-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",
        )
        seen = {}
        with source._askpass_materials() as materials:
            path = Path(materials["identity_file"])
            seen["path"] = path
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertFalse(seen["path"].exists())
        self.assertFalse(seen["path"].parent.exists())

    def test_secret_files_are_removed_even_when_the_turn_raises(self):
        source = self.datasource(auth_method="password", password="hunter2")
        directory = None
        with self.assertRaises(RuntimeError):
            with source._askpass_materials() as materials:
                directory = Path(materials["askpass"]).parent
                raise RuntimeError("turn blew up")
        self.assertFalse(directory.exists())

    def test_agent_auth_creates_no_secret_files_at_all(self):
        with self.datasource()._askpass_materials() as materials:
            self.assertEqual(materials, {})


class FingerprintTests(unittest.TestCase):
    def test_a_bare_fingerprint_is_read_as_sha256(self):
        self.assertEqual(
            SubjectiveSshDataSource._normalize_fingerprint("abc123"), "SHA256:abc123"
        )

    def test_the_algorithm_prefix_is_compared_case_insensitively(self):
        self.assertEqual(
            SubjectiveSshDataSource._normalize_fingerprint("sha256:abc123"),
            SubjectiveSshDataSource._normalize_fingerprint("SHA256:abc123"),
        )

    def test_a_mismatched_pin_refuses_to_connect(self):
        source = SubjectiveSshDataSource(
            connection={
                "host": "example.test",
                "username": "deploy",
                "host_key_fingerprint": "SHA256:expected",
            }
        )
        with patch.object(
            source, "_scan_host_fingerprints", return_value=({"SHA256:actual"}, "")
        ):
            outcome = source._verify_pinned_fingerprint()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome["status"], "host_key_mismatch")

    def test_a_matching_pin_allows_the_connection(self):
        source = SubjectiveSshDataSource(
            connection={
                "host": "example.test",
                "username": "deploy",
                "host_key_fingerprint": "SHA256:expected",
            }
        )
        with patch.object(
            source, "_scan_host_fingerprints", return_value=({"SHA256:expected"}, "")
        ):
            self.assertIsNone(source._verify_pinned_fingerprint())


class FakePopen:
    """Stands in for the ssh child where the real one would have to hang or time out."""

    def __init__(self, *, timeout=False, hangs=False, returncode=0):
        self._timeout = timeout
        self._hangs = hangs
        self.returncode = returncode
        self.pid = 4242
        self.started = threading.Event()
        self.released = threading.Event()
        self.signalled = []

    def communicate(self, timeout=None):
        if self._timeout:
            self._timeout = False
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=timeout or 0)
        if self._hangs:
            self.started.set()
            self.released.wait(timeout=10)
        return "", ""

    def poll(self):
        return None if (self._hangs and not self.released.is_set()) else self.returncode

    def wait(self, timeout=None):
        self.released.set()
        return self.returncode

    def kill(self):
        self.signalled.append("kill")
        self.released.set()

    def terminate(self):
        self.signalled.append("terminate")
        self.released.set()


class CancellationTests(SshTestCase):
    def test_a_timeout_is_reported_rather_than_hanging(self):
        source = self.datasource(command_timeout=1)
        with patch("subprocess.Popen", return_value=FakePopen(timeout=True)):
            result = source.run({"action": "send", "prompt": "sleep 60"})
        self.assertEqual(result["status"], "timeout")
        self.assertIn("timed out", result["error"])

    def test_cancel_stops_an_in_flight_turn(self):
        source = self.datasource()
        process = FakePopen(hangs=True)
        outcome = {}

        def turn():
            with patch("subprocess.Popen", return_value=process):
                outcome["result"] = source.run({"action": "send", "prompt": "sleep 60"})

        worker = threading.Thread(target=turn)
        worker.start()
        self.assertTrue(process.started.wait(timeout=5))
        self.assertTrue(source.cancel())
        worker.join(timeout=10)
        self.assertEqual(outcome["result"]["status"], "cancelled")

    def test_a_cancel_arriving_before_the_spawn_is_not_lost(self):
        """cancel() latches, so the gap between handle_message and Popen is covered."""
        source = self.datasource()
        source.cancel()
        result = source.run({"action": "send", "prompt": "echo hi"})
        self.assertEqual(result["status"], "cancelled")
        self.assertFalse(self.argv_log.exists())


if __name__ == "__main__":
    unittest.main()
