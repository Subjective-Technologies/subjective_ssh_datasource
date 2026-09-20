# subjective_ssh_datasource

Subjective v2 on-demand datasource that turns a DevAgents chat into a shell on any
machine reachable over SSH. A turn's prompt is executed verbatim on the remote host;
the reply is the command's stdout, stderr and exit code.

It implements the same contract as the CLI datasources beside it
(`subjective_codex_datasource`, `subjective_claude_cli_datasource`,
`subjective_grok_cli_datasource`), so `subjective_devagents_fastapi` loads and calls it
in-process with no special casing:

```python
SubjectiveSshDataSource(connection={...}).run({"action": "send", "prompt": "uptime"})
```

## Security

**A configured connection is equivalent to handing out a shell on that host.** The
prompt is interpolated into the remote command unquoted — that is the feature, not an
oversight. Access control belongs at the connection layer: who may create a connection,
and which host and remote account it names.

What the datasource does guarantee:

- **Remote argv is joined here.** `ssh host a b c` re-joins trailing arguments with
  plain spaces and hands the result to the remote shell. Everything this package
  interpolates around the prompt (working directory, sentinel) is `shlex.quote`d and
  the whole remote command is collapsed with `shlex.join` into a single argument.
- **Secrets never reach argv, the environment, logs or results.** A password or key
  passphrase is written to a `0600` file inside a `0700` temporary directory and read
  by a generated `SSH_ASKPASS` helper; a pasted private key is written to a `0600` file
  for the duration of the turn. The directory is removed when the turn ends, including
  on failure.
- **Host-key verification is on by default.** `StrictHostKeyChecking=yes`. Setting
  `host_key_fingerprint` pins the key: it is scanned and compared before every
  connection and a mismatch aborts before any authentication attempt.
- **No hidden interactive login.** Without a secret to supply, ssh runs with
  `BatchMode=yes` so it fails fast instead of blocking on a prompt nobody can answer.
  `authentication_instructions()` returns a login command for the operator to run in a
  visible terminal.

## Behaviour

| Action | Effect |
|---|---|
| `status` | Checks the ssh client, the connection fields and the pinned host key, then runs `true` on the host. Returns `ready`, `not_installed`, `configuration_required`, `authentication_required`, `host_not_found`, `host_key_mismatch`, `unreachable` or `execution_error`. |
| `send` | Runs the prompt on the host and returns its output. |
| `reset_session` | Closes the multiplexed connection and forgets the session and working directory. |

### Sessions and working directory

With `persistent_session` on (the default), turns for one `session_id` share a single
OpenSSH `ControlMaster` connection, so only the first message pays the TCP and
authentication handshake. `ControlPersist` (`persist_seconds`) decides how long an idle
connection lingers.

`cd` survives between turns. Each remote command is followed by a sentinel line
carrying the exit code and `pwd`; the datasource strips it from the reply and returns
the directory as `cwd`, which the caller passes back on the next turn. The last
sentinel in the output wins, so a command that prints a lookalike line cannot spoof it.

### Exit codes

A non-zero exit is a *result*, not a datasource failure: `status` is `command_failed`,
`success` is `false`, and stdout/stderr/exit_code are all populated. A failure with no
sentinel means the command never ran (auth, host key, DNS, refused) and is classified
from ssh's stderr instead.

## Connection fields

`host`, `port`, `username`, `auth_method` (`agent` | `private_key_path` |
`private_key_content` | `password`), `password`, `private_key_path`,
`private_key_content`, `key_passphrase`, `known_hosts_path`, `host_key_fingerprint`,
`strict_host_key_checking`, `working_directory`, `shell`, `login_shell`,
`persistent_session`, `persist_seconds`, `connect_timeout`, `command_timeout`,
`ssh_path`.

## Requirements

OpenSSH 8.4 or newer on the machine running the datasource — `SSH_ASKPASS_REQUIRE=force`
is what lets password and passphrase authentication work without a terminal. `ssh-keyscan`
and `ssh-keygen` are needed only when pinning a fingerprint. No Python SSH library.

## Tests

```bash
python -m pytest tests -q
```

The suite is hermetic: it drives a fake ssh client that evaluates the remote command
locally, so the sentinel, exit codes and the working directory carried between turns
are exercised for real without contacting a host.
