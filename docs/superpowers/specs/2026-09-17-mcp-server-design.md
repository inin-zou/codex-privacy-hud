# Wire the MCP server, and stop the block message promising what no surface does

**Status:** Design · **Date:** 2026-09-17 · **Builds on:** [#38](https://github.com/inin-zou/codex-privacy-hud/issues/38), [#40](https://github.com/inin-zou/codex-privacy-hud/issues/40), [#36](https://github.com/inin-zou/codex-privacy-hud/issues/36)

## The problem

A sweep of what this project promises against what it does found user-facing copy telling people to take actions nothing implements:

1. **The block message.** `engine.BLOCK_TEMPLATE` ends `Run $privacy to review, minimize, or allow once.` `$privacy` offers neither minimize nor allow once. `mcp_tools.allow_once` exists; its only caller is `mcp/server.py`, which Codex never loads.
2. **The MCP server.** `README.md:108` says installing the plugin "gives Codex … the MCP server", and `architecture.md` §9 says it is "declared in `plugin.json`". `.codex-plugin/plugin.json` has never had an `mcpServers` key in any commit, and `install.sh` never installs the `[mcp]` extra.

Both trace to the uncommitted 2026-09-03 implementation plan. Its Task 13 lists `Modify: .codex-plugin/plugin.json — declare the MCP server`, a step skipped without review noticing; the block copy is in that plan verbatim. Review checked the code against the brief, and the defect was in the brief.

Design turned up a third, of #38's kind:

3. **`allow_dest`.** `apply_policy` accepts it, writes a row, and the server returns `{"applied": True}`. The engine never reads it: it compares `rule_type` against exactly `mask`, `block_path` and `block_command`. `apply_policy`'s own docstring calls a rule the engine cannot match worse than an error. `2026-09-03-decisions.md:280` records it as a placeholder ("untouched because nothing mints it yet"). It is latent today only because the server is not wired.

## What this is not

- **Not a consent flow.** `allow_once` is not exposed (decision 1), and the block message stops offering it. A consent flow that works is its own design; see *Deferred*.
- **Not `minimize`.** No surface offers it; the copy stops naming it.
- **Not subagent tracking**, which the same sweep found records nothing (`SubagentStart` is observed with `text=""`). Separate.
- **Not the audit polluting its own ledger** (see *Found in design, out of scope*). Verified pre-existing; this work neither causes nor worsens it.

## Decisions

### 1. A model-callable tool must not be able to loosen protection

An MCP tool is called by the model. Every tool the server exposes is one the model can call on its own, subject only to Codex's per-tool approval — which a user can set to approve automatically, and which `permission_mode = bypassPermissions` skips.

So the server exposes a tool only if calling it cannot weaken what the plugin enforces:

| Tool | Exposed | Why |
|---|---|---|
| `privacy.get_session_summary` | yes | read-only |
| `privacy.list_exposures` | yes | read-only |
| `privacy.get_exposure_detail` | yes | read-only |
| `privacy.read_guard_status` | yes | read-only |
| `privacy.update_policy` | yes | tighten-only once `allow_dest` is withdrawn (decision 2); no path removes a rule (limit 13). Its selectors are a data type, a path or a program name — never a value — so the call carries no secret |
| `privacy.allow_once` | **no** | mints a token that unblocks the call it names |
| `privacy.read_guard_set` | **no** | can turn the read guard off |
| `privacy.hud_toggle` | **no** | can hide the indicator |

The withheld three stay where they are reachable today. `read_guard_set` and `hud_toggle` are behind `$privacy read|hud on|off`, which a user types. `allow_once` stays in `mcp_tools`, with no surface.

**`allow_once` could not have worked through MCP anyway.** Reproduced on this branch: to mint a matching token it must carry the blocked call's full `tool_input`. The only default block is a credential on egress, so that `tool_input` holds the credential. An MCP call is egress (`codex.is_mcp_tool`), and the plugin has no exemption for its own tools — so the `allow_once` call is itself denied, with a message telling the user to allow once. The only situation the copy appears in is the one situation the remedy cannot reach.

This is not a claim that the model cannot disable the plugin. It runs a shell with the user's permissions and can write `settings.json` directly; a hook-based guard in the model's own trust domain does not defend against a model set on disabling it. The rule is narrower: the plugin does not *hand* the model a sanctioned switch. A helpful agent that gets blocked reaches for the documented remedy, and would set `reviewed=True` to finish the user's task — which `allow_once`'s docstring already admits it cannot verify.

### 2. Withdraw `allow_dest`

`apply_policy` refuses it the way it refuses `block_source` (#38), with its own message. A row an older ledger holds decides nothing, as it already does. The `ledger.py` schema comment and `architecture.md` stop listing it.

### 3. The server re-executes itself under the pinned interpreter

Codex constrains a plugin MCP server's `command` to a bare executable name on the host `PATH`, or a `./` path inside the plugin root. `${PLUGIN_ROOT}` is rejected there — unlike `hooks.json`, where `$PLUGIN_ROOT` expands. The plugin's Python lives in `~/.local/share/codex-privacy-hud/venv/`: outside the plugin root, not on `PATH`.

So the manifest runs host `python3`, and `mcp/server.py` must reach the venv interpreter before it imports anything from the package. Today it imports `privacy_hud` at module top, and under host `python3` it dies on that line.

It does what `hooks/handler.py` already does to spawn the daemon: read `$PLUGIN_DATA/runtime.json` (Codex injects `PLUGIN_DATA` into the server's environment), apply the same checks, take `python` and `pythonpath`, and `os.execve` itself under that interpreter.

- **Why re-exec, not `sys.path`.** `mcp` depends on `pydantic`, whose core is a compiled extension built for the venv interpreter's version. Host `python3` importing it from the venv's `site-packages` is a binary mismatch waiting for the two versions to differ.
- **Why restate the receipt checks rather than import them.** In `handler.py` they are inlined in `_spawn_daemon`, on the path every tool call runs; extracting them would change the hook client for this feature's sake. The repo's precedent for a fact two stdlib-only ends must share is to restate it and pin both copies with one test (`EGRESS_EVENTS`, the socket name). This follows it.
- **A re-exec guard.** An environment marker is set before `execve`. An entry that finds it already set does not re-exec again; it returns, and the process goes on to start the server. It must not exit: the marker is set in the *child*, so the child is exactly the process that finds it set, and a guard that exited there would mean the re-exec'd interpreter exits immediately and the server never runs. The guard's job is to stop a second `execve`, not to stop the program.
- **stdout is the protocol.** Stdio MCP speaks JSON-RPC on stdout. The launcher writes nothing there on any path. Every failure goes to stderr with a non-zero exit.

### 4. The manifest

Inline object form, one server:

```json
"mcpServers": {
  "privacy-hud": { "command": "python3", "args": ["./mcp/server.py"], "cwd": "." }
}
```

Inline rather than a `.mcp.json` file: declaring both lets one silently overwrite the other. Named `privacy-hud` so it cannot collide with a server the user already has.

The shape follows OpenAI's own bundled `sites` plugin, installed on this machine in the same `.codex-plugin/plugin.json` layout, and the field names were read from the 0.154.0 binary's `AgentPluginMcpServer` parser. The plugin manifest's stdio object takes only `command`, `args`, `env` and `cwd`; `config.toml`'s `[mcp_servers.*]` fields (`startup_timeout_sec`, `enabled`, …) do not apply here.

### 5. Install the extra

`install.sh` installs `privacy-hud[detectors,mcp]`. That install runs before the model prompt, so a user who declines the model still gets the server.

`mcp` is already on `test_network_isolation`'s `ALLOWED_DISTRIBUTIONS`, and `mcp/server.py` is outside the AST allowlist's `src/` + `hooks/` scope by design. No I2 change.

### 6. The doctor proves it loads

Codex warns and ignores a manifest `mcpServers` value it cannot use, and a server that fails at launch leaves the plugin loaded with hooks and skills intact. Nothing inside Codex shows the difference — the same silent shape as the hooks trust gate that bit this project before.

So `privacy-hud-doctor` gains a check that launches the server the way Codex does — host `python3`, `cwd` the installed plugin copy, `PLUGIN_ROOT` and `PLUGIN_DATA` set — completes an MCP `initialize` and `tools/list` over stdio within a timeout, and passes only if the listed tools are **exactly** decision 1's five.

That last clause makes the doctor the runtime half of decision 1: a regression that exposes `allow_once` fails a check a user runs, not only a unit test.

### 7. The copy

`BLOCK_TEMPLATE`'s last line becomes `Run $privacy to review.`

`ORIGIN_BLOCK_TEMPLATE` drops `allow once does not override it.` The sentence is true, but with no surface offering allow once it names a feature as if the user had it. What remains — `A source rule you wrote for this session denies this call. The rule ends with the session.` — is still the whole story.

`REWRITE_TEMPLATE`'s `Run $privacy to review or adjust policy.` stays. It was traced, not assumed: `$privacy` step 3 starts the local audit UI, whose "Protect future occurrences" writes a `mask` rule. `READ_BLOCK_TEMPLATE` and `READ_NOTICE_TEMPLATE` name `$privacy read off` and `$privacy read on`, which exist.

### 8. Keep the class from coming back

Two layers, because only half of it is mechanical.

- **A test.** Every `*_TEMPLATE` in `engine.py` is scanned for `$privacy <word>`; each `<word>` must be a subcommand `skills/privacy/SKILL.md` documents. It catches a named subcommand that does not exist. It does **not** catch prose: "minimize" was a verb, not a subcommand, and no pattern reads what a sentence promises.
- **A rule, for the prose.** `.claude/CLAUDE.md` §5 gains one: every action user-facing copy tells a user to take is traced, before merge, to the surface that performs it — traced through the actual call, not inferred from a function existing. The final whole-branch review prompt checks it by name.

## Error handling

- No `PLUGIN_DATA`, no receipt, a receipt failing the checks, or an interpreter that is not executable: one line to stderr naming the problem — an exception class or a fixed phrase, never a payload (I1) — and a non-zero exit. Codex marks the server failed; the doctor says why.
- `mcp` not importable under the pinned interpreter: the existing lazy import's message, to stderr.
- Re-exec guard already set: fall through and serve, rather than `execve` again. This is the normal path in the child, not an error — a receipt naming an interpreter that re-enters this file is what the marker prevents looping on, and the loop is broken by not re-execing, not by exiting. `test_it_does_not_re_exec_twice` asserts the recorded interpreter's payload is absent, not that stdout is empty, for that reason: with the marker set stdout is the server's own JSON-RPC channel.

## Testing

TDD throughout.

1. **Tool surface.** The server's registered tool names equal exactly decision 1's five, pinned as a set, so adding one is a visible diff with this spec behind it.
2. **`allow_dest` refused**, with its message.
3. **The self-block, pinned.** An MCP `PreToolUse` whose `tool_input` carries a credential is denied. This is the reason `allow_once` is not exposed; if it ever stops holding, decision 1's reasoning is revisited rather than the test deleted.
4. **Launcher**, with a fake receipt: re-execs under the recorded interpreter with `PYTHONPATH` prepended; refuses a group- or world-writable receipt; refuses a non-executable interpreter; does not re-exec twice; writes nothing to stdout on any failure path.
5. **Receipt checks agree.** The launcher's restated checks and `handler.py`'s, pinned by one test.
6. **Doctor.** Passes against a server exposing the five; fails on a missing manifest key, a launch failure, and a differing tool set.
7. **Copy.** Decision 8's subcommand test.

Every new test is run once against a deliberately broken implementation before it is committed. This repo has shipped three tests this month that passed against the defect they were written for.

## Docs

- `README.md` / `README.zh-CN.md`: the MCP sentence becomes true, naming the five tools and decision 1's rule.
- `architecture.md` §9 and `PRD.md` §7.5: the tool list shrinks to five, with decision 1's rule stated.
- **zh-CN prose is written by Codex**, per house practice. The zh-CN read-guard section and limit 14 changed in #42 were written inline, against that practice, and are rewritten by Codex here. The `codex` MCP tool is failing to connect in this environment, so this goes through `codex exec`.
- Version `0.7.0`: user-visible MCP tools. `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` and `pyproject.toml` move together.

## Found in design, out of scope

**Reading the audit raises the disclosure budget.** Verified on this branch by running `$privacy`'s real step-2 calls through the hook path: after one real read of `.env`, the budget is 42%; running `$privacy` once adds a row `('exposed', 'path', 'python', 'model_context')` and the budget reads 43%. The `.env` in the audit's SOURCE column matches tier 0. Later runs dedupe into that row, so it happens once per session, not per run.

It is pre-existing through `$privacy`'s Bash, and the MCP path adds nothing: `source` is not in the dedupe key, so both surfaces land in the same row. I7's last verification did not see it because that session had no exposures, and an empty audit names no source. It is an I3 question — re-naming a file is detection, not disclosure — and gets its own issue.

## Verified live, or not

The doctor check proves the launcher starts and exposes the right tools. It does not prove Codex reads the manifest key: that needs a live session with the plugin reinstalled (Codex's cache holds 0.5.0). It goes with the I7 re-audit and the `PreToolUse` `systemMessage` check, which need the same session.

## Deferred

- **A consent flow that works.** A deny records a short id against its `args_hash` — tokens already store only the hash (I1). Consent references the id, so the secret never rides in the consent call, which removes the self-block. It is given in the local UI, which the model cannot operate, which removes the model-consent problem. The UI refuses `allow once` today only because the ledger holds no `tool_input`, and an id removes that reason too.
- **`minimize`.**

## Build order

| Step | Change | Verified by |
|---|---|---|
| 1 | Withdraw `allow_dest`; `BLOCK_TEMPLATE` and `ORIGIN_BLOCK_TEMPLATE` copy; subcommand test | unit tests |
| 2 | Launcher re-exec; receipt-check parity test | unit tests |
| 3 | Server exposes the five; tool-surface and self-block tests | unit tests |
| 4 | Manifest; install extra; version 0.7.0 | `test_versions`, `test_install_sh` |
| 5 | Doctor check | unit tests; run against the real venv |
| 6 | CLAUDE.md §5 rule; docs; zh-CN via Codex | review |
