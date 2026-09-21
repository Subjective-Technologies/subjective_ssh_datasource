"""The runner that puts another datasource's CLI on a remote machine.

The interface is in the abstract package and the CLI datasources depend only on
that; this is the implementation that answers "somewhere else". What is worth
pinning is the part that is easy to get wrong and invisible when it is: the remote
command is one quoted argument, the connection is shared, and a non-interactive
shell is given the PATH it otherwise lacks.
"""
import shlex
import tempfile
import unittest
from pathlib import Path

from SubjectiveSshDataSource import SubjectiveSshDataSource
from ssh_runner import NVM_SETUP, REMOTE_PATH_PREFIXES, SshCommandRunner

FAKE_SSH = r"""#!/bin/sh
target=""
remote=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-i|-p) shift 2 ;;
    -*) shift ;;
    *) if [ -z "$target" ]; then target="$1"; else remote="$1"; fi; shift ;;
  esac
done
exec /bin/sh -c "$remote"
"""


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ssh = Path(self.tmp.name) / "fake-ssh"
        self.ssh.write_text(FAKE_SSH, encoding="utf-8")
        self.ssh.chmod(0o755)
        source = SubjectiveSshDataSource(
            connection={"host": "example.test", "ssh_path": str(self.ssh)}
        )
        self.runner = SshCommandRunner(source, label="example.test")
        self.addCleanup(self.runner.cleanup)


class ArgvTests(RunnerTestCase):
    def test_the_remote_command_is_a_single_quoted_argument(self):
        """ssh re-joins several trailing arguments with plain spaces and lets the
        remote shell re-parse them."""
        argv = self.runner._argv("echo hi")
        remote = shlex.split(argv[-1])
        self.assertEqual(remote[:2], ["bash", "-lc"])
        self.assertEqual(len(remote), 3)

    def test_every_command_rides_one_shared_connection(self):
        """An agent turn is three commands — find the CLI, check the login, run it.
        Three handshakes per turn would make this unusable."""
        first = self.runner._argv("true")
        second = self.runner._argv("true")
        paths = [item for item in first if item.startswith("ControlPath=")]
        self.assertEqual(len(paths), 1)
        self.assertIn("ControlMaster=auto", first)
        # The same socket, so the second command reuses the first's connection.
        self.assertEqual(paths, [item for item in second if item.startswith("ControlPath=")])

    def test_the_remote_shell_is_given_the_path_it_otherwise_lacks(self):
        """A non-interactive shell returns before its rc file sets these up, which
        is exactly why `codex` is "not found" over ssh but present in a terminal."""
        wrapped = self.runner._wrap(["codex", "--version"])
        for prefix in REMOTE_PATH_PREFIXES:
            self.assertIn(prefix, wrapped)
        self.assertIn(NVM_SETUP, wrapped)
        self.assertIn("codex --version", wrapped)

    def test_a_working_directory_is_quoted(self):
        """A path with a quote or a space in it must not become extra arguments."""
        wrapped = self.runner._wrap(["true"], cwd="/srv/it's here")
        self.assertIn(f"cd {shlex.quote(chr(47) + 'srv/' + chr(105) + chr(116) + chr(39) + 's here')}", wrapped)

    def test_a_missing_working_directory_stops_the_command(self):
        """Running the agent in the wrong directory is worse than not running it."""
        self.assertIn("|| exit 127", self.runner._wrap(["true"], cwd="/srv/app"))


class ExecutionTests(RunnerTestCase):
    def test_it_runs_things(self):
        completed = self.runner.run(["echo", "remote-hello"], timeout=30)
        self.assertEqual(completed.returncode, 0)
        self.assertIn("remote-hello", completed.stdout)

    def test_it_reports_a_missing_file(self):
        self.assertFalse(self.runner.is_file("/definitely/not/here"))
        self.assertTrue(self.runner.is_file("/etc/hostname"))

    def test_which_prefers_a_candidate_path_over_the_search(self):
        """A datasource knows where its CLI installs; PATH is the fallback."""
        candidate = Path(self.tmp.name) / "pretend-cli"
        candidate.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        candidate.chmod(0o755)
        self.assertEqual(self.runner.which("pretend-cli", (str(candidate),)), str(candidate))

    def test_which_falls_back_to_the_path(self):
        self.assertTrue((self.runner.which("sh") or "").endswith("/sh"))

    def test_which_reports_nothing_for_a_binary_that_is_not_there(self):
        self.assertIsNone(self.runner.which("no-such-binary-anywhere", ()))

    def test_it_announces_that_it_is_remote(self):
        """Datasources use this to skip work that only makes sense locally."""
        self.assertTrue(self.runner.is_remote)
        self.assertEqual(self.runner.location, "example.test")


if __name__ == "__main__":
    unittest.main()
