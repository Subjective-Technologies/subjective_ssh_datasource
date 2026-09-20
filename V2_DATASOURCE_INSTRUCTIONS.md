<!-- Agent workflow is not this file. Read /subjective/AGENTS.md then /subjective/workflow/AGENTS.md. Class contract: libs/dependencies/subjective-abstract-data-source-package/AGENTS.md. This copy is plugin-local authoring notes. -->

# V2 Datasource Instructions

This package implements a Subjective v2 on-demand chat datasource. Unlike its siblings,
the thing on the other end is a shell, not an LLM CLI.

## Required class methods

- `connection_schema()` — durable connection fields (no `connection_name`)
- `request_schema()` — per-request inputs
- `output_schema()` — fields returned by `run()`
- `icon()` — classmethod that reads `icon.svg`
- `run(request)` — executes status / send / reset_session

## Safety rules

- Never launch interactive login invisibly. Return `authentication_instructions()` with
  a visible login command instead.
- Never put a secret in argv, in the environment of anything but the askpass helper, in
  a log line, or in the result dict.
- Keep `StrictHostKeyChecking=yes` the default. Turning it off is an explicit operator
  choice, and pinning `host_key_fingerprint` is the stronger option to offer first.
- Quote everything interpolated around the prompt. The prompt itself is deliberately
  unquoted — it *is* the command — so nothing else may be.
- Build the remote command as an argv list and `shlex.join` it into one trailing
  argument. `ssh` re-joins several trailing arguments with plain spaces and the remote
  shell re-parses the result.

## SSH mapping

- Turn: `ssh -p PORT -o … user@host "<shell> -lc '<script>'"`
- Script: optional `cd`, the command, then a sentinel line carrying `$?` and `$(pwd)`
- Session: `ControlMaster=auto` + `ControlPath=<hashed socket>` + `ControlPersist`
- Reset: `ssh -O exit` against the control socket
- Password / passphrase: generated `SSH_ASKPASS` helper with `SSH_ASKPASS_REQUIRE=force`
- Host-key pin: `ssh-keyscan` piped through `ssh-keygen -lf -`, compared before connecting

Canonical architecture doc (when present in tree):
`com_subjective_architecture_docs/architecture/older/27_v2_datasource_authoring_instructions.md`
