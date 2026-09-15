# Codex Privacy HUD

![Codex's own status line, under the composer, with the plugin's Privacy item beside the model and working directory](docs/images/banner.png)

[![CI](https://github.com/inin-zou/codex-privacy-hud/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/inin-zou/codex-privacy-hud/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/inin-zou/codex-privacy-hud)](LICENSE)
[![Stars](https://img.shields.io/github/stars/inin-zou/codex-privacy-hud)](https://github.com/inin-zou/codex-privacy-hud/stargazers)

English | [简体中文](README.zh-CN.md)

> Trace your privacy disclosure the same way you already trace your token usage — live, in every conversation.

> **See what your agent knows. Control where it goes.**

A local-first Codex plugin that maintains a live **disclosure ledger** for every Codex session, minimizes sensitive context **before** tool execution, and lets you inspect exactly what data reached the model, subagents, MCP tools, or external services.

Detection runs on your own machine, via [`openai/privacy-filter`](https://huggingface.co/openai/privacy-filter) loaded locally through `transformers` — no prompt, file, or secret is ever sent anywhere to be scanned. The plugin makes no outbound network calls at all; the only socket it opens is a local one to its own daemon on `127.0.0.1`.

```text
Token HUD:    How much context has been consumed?
Privacy HUD:  How much sensitive context has been disclosed?
```

![The Codex Privacy HUD user journey — from the ambient disclosure bar through the session audit, exposure detail, and minimizing a payload before it reaches an external tool](docs/images/user-journey-mockup.png)

**Before you rely on it:** the start of a session is not monitored while the model loads, hosted tools bypass hooks, and detection is heuristic. The HUD marks a session whose record has a known hole rather than showing it as a clean 0%, but it cannot tell you what it missed. Read the [known limits](#known-limits).

---

- [News](#news)
- [Install](#install)
- [What you see](#what-you-see)
- [How it works](#how-it-works)
- [Known limits](#known-limits)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Installing by hand](#installing-by-hand)
- [Documentation](#documentation)
- [License](#license)

## News

- 2026-09-15: patched Codex 0.154.0 builds for `aarch64-apple-darwin` and `x86_64-apple-darwin` are published on the GitHub release `codex-0.154.0-hud` and on the rolling `latest`. `install.sh` finds them.
- 2026-09-15: the `privacy` status-line item now renders inside a patched Codex, and the macOS install is one command.
- 2026-09-05: verified by hand against Codex CLI 0.153.0 that running the plugin on its own development session yields zero exposures (zero events, budget 0.0/120.0). It is **not** an automated test: it needs a live Codex session, which CI has neither the binary nor the network for.

## Install

Verified end-to-end against a real Codex CLI install on 0.145.0 and 0.153.0.

### Before you start

- **macOS** on Apple Silicon or Intel. (Linux and Windows are not packaged; see [Installing by hand](#installing-by-hand) for the fallback pane.)
- **Codex CLI** already installed and signed in — `codex --version` prints something like `codex-cli 0.154.0`. The installer needs that number to pick the matching patched build.
- **Python 3.11 or newer** on your `PATH` (`python3 --version`). On a Mac without one: `brew install python@3.12`.
- About **3 GB of disk** if you want name and address detection (that is the size of the `openai/privacy-filter` weights), and a few minutes.

### Run it

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh
```

The script asks exactly one question — whether to download the detection
model. Everything else is automatic. This is what it does, in the order it
prints:

| step | what happens | where it lands |
|---|---|---|
| 1 | Finds your `codex`, reads its version, checks `python3 >= 3.11` | — |
| 2 | Creates a private virtualenv and installs the plugin package into it (a few minutes; this pulls `torch` and `transformers`) | `~/.local/share/codex-privacy-hud/venv/` |
| 3 | **Asks** before downloading the `openai/privacy-filter` weights (~2.8 GB, from Hugging Face, once). Answer `y` for full detection. Answer `n` and you still get credential and path detection, but **names and addresses go undetected** — `privacy-hud-doctor` will say so. | `~/.cache/huggingface/hub/` |
| 4 | Installs the plugin into Codex (`codex plugin marketplace add` + `codex plugin add`) | Codex's plugin directory |
| 5 | Records which Python interpreter the daemon must run in | `~/.codex/plugins/data/codex-privacy-hud-…/runtime.json` |
| 6 | Downloads the patched Codex build for **your exact version**, verifies its SHA-256, unpacks it, and links your official `codex-code-mode-host` beside it (the tarball carries only `codex`; Code Mode needs that sibling, and the official one of the same version is the right one) | `~/.local/share/codex-privacy-hud/<version>/` |
| 7 | Writes a small forwarder named `codex` and, if needed, adds `~/.local/bin` to your shell `PATH` | `~/.local/bin/codex` |
| 8 | Adds `privacy` to `[tui].status_line` in your Codex config, creating the key with Codex's defaults if you never set one | `~/.codex/config.toml` |
| 9 | Runs `privacy-hud-doctor` and prints its table — every line should read `OK` or `WARN`, never `FAIL` | — |

The binary CI publishes is **unsigned and unnotarized**; the installer removes
the quarantine attribute itself, and the SHA-256 it verifies protects against
a corrupted download, not against a compromised release.

Flags: `--yes` answers the model question with yes; `--no-model` skips the
download without asking. Both are useful for scripted installs, and the
script needs one of them when there is no terminal to ask on.

Steps 2, 3, and 6 are the **only network access anything here ever causes**:
the package, the weights, and the patched build, all downloaded by the
installer, once, before any Codex session exists. The runtime itself never
goes online: it sets `HF_HUB_OFFLINE=1` before importing `transformers` and
opens no socket except its own on `127.0.0.1`.

### Plugin only, from the Codex CLI

The plugin itself installs like any other Codex plugin, with nothing to
clone:

```bash
codex plugin marketplace add inin-zou/codex-privacy-hud
codex plugin add codex-privacy-hud@codex-privacy-hud
```

The first command clones this repository into Codex's marketplace store;
the second copies it into the plugin cache,
`~/.codex/plugins/cache/codex-privacy-hud/codex-privacy-hud/<version>/`.
That gives Codex the `$privacy` skill, the hooks, and the MCP server, and
it puts `install.sh` on your machine, but it does not run it: the daemon's
Python environment, the detection model, and the patched Codex build are
still missing, so every hook answers
`Privacy HUD unavailable — disclosure unverified` and `$privacy` reports no
daemon. From here:

1. Run `codex`. Codex 0.154 opens with **Hooks need review** for the
   plugin's eight hooks; choose **Trust all and continue**. Nothing from
   the plugin runs before that.
2. Send any message. The first turn shows a one-line reminder with the
   installer's path in the plugin cache:
   `sh ~/.codex/plugins/cache/codex-privacy-hud/codex-privacy-hud/<version>/install.sh --yes`.
   Paste it into the session and let Codex run it (Codex asks before it
   writes outside the working directory), or run it in another terminal.
   It is the same script as the one-liner above and is safe to run over an
   existing plugin install; `--yes` downloads the model without asking,
   `--no-model` skips it.
3. Restart Codex so the patched build and the status item are picked up.

[docs/installing-by-hand.md](docs/installing-by-hand.md) has every step
the script performs, if you would rather do them yourself.

### First launch

Open a new terminal (so the `PATH` change is picked up) and run `codex`.
The status line looks unchanged at first: Codex fires its `SessionStart`
hook with the first turn, not at boot, so nothing reaches the daemon until
you send a message. After your first prompt the item appears under the
composer next to the usual ones, as in the [screenshot below](#what-you-see):

```text
Privacy ░░░░░░░░░░  0% · gpt-5.4 · ~/proj · Context 96% left
```

It is 0% until something sensitive crosses into model context; the number
moves as files, prompts, and tool arguments do. (On a machine where the
daemon is not yet running, that first prompt also starts it, which takes
about seven seconds to load the model — the reply to that first hook says
`Privacy HUD unavailable — disclosure unverified`, the item shows up a
moment later, and that load window is unmonitored: see
[Known limits](#known-limits).) Then:

- `/statusline` — Codex's own picker; tick or untick `privacy` to add or
  remove the item for good. It is saved in `config.toml`.
- `$privacy hud off` / `$privacy hud on` — hide or show it for now, without
  touching your config. `$privacy hud status` tells you which of
  `absent | stale | hidden | shown` it is in.
- `$privacy` — the full session audit (Level 2).

## What you see

**Level 1 — Ambient.** One item in Codex's own status line, under the composer:

```text
gpt-5.4 · ~/proj · Privacy ███░░░░░░░ 28% ⚠2
```

Real output from a live Codex 0.154 session running the patched build (not a mockup): one prompt containing a street address, and the `Privacy` item under the composer already at 5%, beside Codex's own model and directory items:

![A Codex session: one prompt containing a street address, the model's reply, and the plugin's `Privacy` item under the composer at 5% disclosure, next to Codex's own model and directory items](docs/images/status-line-patched.png)

Stock Codex has no plugin-owned status item, so this needs a Codex build
with a small patch (`patches/privacy-status-line.patch`, one added item,
nothing else). `install.sh` fetches that build for your exact Codex version
and places it beside your official binary — it never modifies the official
one — and `codex` then resolves to the patched build only while the versions
match. Toggle the item with `/statusline` inside Codex, or hide it for now
with `$privacy hud off`. Without a matching build, the fallback is a
companion pane: `privacy-hud-ambient --watch` in a second terminal.

The pane draws the same line in three forms. The ordinary one:

```text
PRIVACY  Disclosure ███░░░░░░░ 30%  ›
```

And, when the ledger's account of the session has a known hole, a form that says so instead of reporting a clean number:

```text
PRIVACY  Disclosure ░░░░░░░░░░  0% ⚠unverified ›
```

Below 28 columns the word does not fit and the line becomes `⚠ 0%`, the warning glyph taking the band dot's place, so truncation can never leave a bare percentage behind.

**Level 2 — Session audit** (`$privacy`). Summary tiles and a tabbed table of every flow:

```text
SENSITIVE DATA        SOURCE           DESTINATION      STATUS
Customer email ×12    support.log      model context    [EXPOSED]
Full name ×1          user prompt      model context    [EXPOSED]
Repository path ×4    tool input       GitHub MCP       [EXPOSED]
API credential ×1     .env             none             [PREVENTED]
```

Tabs: `Exposed` · `Prevented` · `All events`.

**Level 3 — Exposure detail.** One flow, its masked evidence, and forward-looking remedies (`Protect future occurrences`, `Block this source`). Never an undo — already disclosed data cannot be recalled.

## How it works

### The problem

Coding agents read your filesystem, run shell commands, call MCP servers, and spawn subagents on your behalf, and you cannot find out:

- Which of your files' contents actually entered the model context?
- Did that GitHub MCP call carry a customer email in its arguments?
- Did the subagent inherit the `.env` you read twenty minutes ago?
- Did that `curl` pipe your support log to an external host?

Secret scanners are pre-commit, not pre-inference. DLP products are server-side and require shipping the very data you want to protect. Permission prompts are about *capability*, not *content*.

### Detection is not disclosure

The distinction the product is built on:

| Event | Counts toward the disclosure budget |
|---|---|
| A local scanner detects an email in a file | **No** |
| File content enters model context | **Yes** |
| Data is passed to a subagent | **Yes** — new destination |
| Arguments sent to an MCP tool | **Yes** |
| A shell command sends data to an external host | **Yes** |
| Content redacted or blocked before send | **No** — counted as *prevented* |

So the audit shows **flows**, not findings:

```text
support.log → main agent → GitHub MCP
```

### The ledger

```mermaid
flowchart TD
    A["Codex lifecycle hooks"] --> B["Local privacy engine"]
    B --> C["Session disclosure ledger"]
    C --> D["Compact HUD"]
    C --> E["Interactive audit UI"]
    B --> F["Allow, rewrite, or block"]
```

The ledger is **event-sourced from hook boundaries**, never by asking a model what is in context. Every byte that can enter model context from your machine passes through a small set of chokepoints — `UserPromptSubmit`, `PostToolUse`, `SubagentStart`, `PreToolUse` — which together form a cut of the data-flow graph. We observe the transactions and reconstruct the balance.

There is **no second LLM call to audit the first one.** That would re-transmit the sensitive data being audited, cost a round trip per turn, and produce a non-deterministic ledger. See `architecture.md` §3.

### Privacy of the privacy tool

- Detection runs **entirely locally**. No content is sent anywhere for classification.
- The ledger stores **metadata only** — types, counts, sources, destinations, timestamps, masked exemplars. There is no `content` column, no `prompt` column, no `raw_value` column. The schema *is* the guarantee.
- Value identity uses a session-scoped salted HMAC held in memory and destroyed at session end, so cross-session correlation is impossible by construction.
- No telemetry. No analytics. No network calls except `127.0.0.1`.
- Running Privacy HUD on its own development session must yield zero exposures.

### What the forwarder is, and what it is not

Your official `codex` binary is **never modified, moved, or replaced.**
`~/.local/bin/codex` is a ten-line shell script: it finds the official
binary on your `PATH`, asks it for its version, and runs the patched build
of that same version if one is installed — otherwise it runs the official
binary unchanged. Upgrade Codex with `brew` or `npm` and the forwarder simply
falls through to the new official version until a matching patched build
exists; nothing breaks, you just lose the status-line item in the meantime.

If the installer prints a block starting with `!! PATH:`, another `codex`
comes earlier on your `PATH` than `~/.local/bin`. Put the line it shows
first in your shell rc file and open a new shell, or the status item will
never appear.

## Known limits

Stated up front, because a privacy tool that overclaims is worse than none:

1. **The start of a session is unmonitored.** **Whatever is disclosed in those first seconds is not in the ledger, and no later reading can say what it was.** ([details](docs/known-limits.md#1-the-start-of-a-session-is-unmonitored))
2. **"Unverified" marks the gaps it can see, and there are gaps it cannot.** So `⚠unverified` means "the ledger holds evidence of a hole"; its absence means "nothing on record contradicts a complete account", which is a weaker claim than "complete" and must not be read as the stronger one. ([details](docs/known-limits.md#2-unverified-marks-the-gaps-it-can-see-and-there-are-gaps-it-cannot))
3. **Hosted tools bypass hooks.** WebSearch and similar do not trigger local function-tool hook paths. ([details](docs/known-limits.md#3-hosted-tools-bypass-hooks))
4. **No `ask` decision in Codex hooks.** Interactive consent is a deny → review → one-shot-token → retry loop rather than a modal. ([details](docs/known-limits.md#4-no-ask-decision-in-codex-hooks))
5. **The status-line item lives in a separately built Codex — never in your official one.** **The plugin never modifies your official Codex binary.** ([details](docs/known-limits.md#5-the-status-line-item-lives-in-a-separately-built-codex--never-in-your-official-one))
6. **A command that reads a file itself is not inspected.** The engine scans the *text of a tool call*, not what that call will read at runtime. ([details](docs/known-limits.md#6-a-command-that-reads-a-file-itself-is-not-inspected))
7. **Detection is heuristic.** A determined adversary can encode around regex and NER. ([details](docs/known-limits.md#7-detection-is-heuristic))
8. **Which session is being shown is inferred, not read — and the audit says so when it cannot be sure.** The fallback pane carries no such marker; pin it with `--session-id` when it matters. ([details](docs/known-limits.md#8-which-session-is-being-shown-is-inferred-not-read--and-the-audit-says-so-when-it-cannot-be-sure))
9. **Nothing recalls disclosed data.** Ever. ([details](docs/known-limits.md#9-nothing-recalls-disclosed-data))

## Configuration

| knob | what it does |
|---|---|
| `/statusline` inside Codex | Ticks or unticks the `privacy` item for good. The choice is saved in `config.toml`. |
| `$privacy hud on\|off\|status` | Hides or shows the item for now, without touching your config. `status` prints `absent`, `stale`, `hidden`, or `shown`. |
| `[tui].status_line` in `~/.codex/config.toml` | The list of status-line items Codex renders. The installer adds `"privacy"` to it. |
| `install.sh --yes` / `--no-model` / `--release-base-url URL` / `--uninstall` / `--purge` | `--yes` answers the model question with yes, `--no-model` skips the download, `--release-base-url` fetches the patched build from somewhere other than this repository's GitHub releases, `--uninstall` removes what the installer created, `--purge` also removes the ledger and the weights. |
| `PRIVACY_HUD_NO_SPAWN=1` | Turns daemon auto-start off entirely, for a sandbox where the spawn cannot succeed. |
| `privacy-hud-ambient --watch [N]` / `--once` / `--session-id <id>` | Runs the fallback pane: redraw every N seconds, print one line and exit, or pin the pane to one session. |

## Troubleshooting

- **`no patched build published for codex <ver> yet`** — there is no
  release for your Codex version. Everything else installed; the status
  item will appear once a build for that version is published (rerun the
  installer then). Until then the fallback pane works:
  `~/.local/share/codex-privacy-hud/venv/bin/privacy-hud-ambient --watch`
  in a second terminal.
- **The status line shows no `privacy` item after upgrading Codex** — the
  forwarder found no patched build for the new version and ran your official
  binary unchanged, so nothing broke and the item is simply gone for now.
  Rerun the installer once a build for that version is published.
- **`!! config.toml: …`** — your `config.toml` has a `[tui]` table or a
  `status_line` key in a shape the installer will not edit blind. It changed
  nothing; add `"privacy"` to `[tui].status_line` yourself, using the line
  it prints.
- **Doctor shows `FAIL`** — read its fix line; it names the exact command.
  `privacy-hud-doctor --check-model` goes further and loads the detector
  for real.
- To start over: run the [uninstaller](#uninstall), then install again.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh -s -- --uninstall
```

Removes exactly what the installer created (listed in
`~/.local/share/codex-privacy-hud/manifest.json`) and restores `codex` to
the official binary. Your disclosure ledger and the model weights stay
unless you add `--purge`. The plugin itself is removed separately with
`codex plugin remove codex-privacy-hud`.

## Installing by hand

You want this if there is no `install.sh` for your platform, if you are on Linux, or if you are repairing a broken install. Every step the installer performs is written out in [docs/installing-by-hand.md](docs/installing-by-hand.md).

## Documentation

| doc | what it covers | read it when |
|---|---|---|
| [`docs/installing-by-hand.md`](docs/installing-by-hand.md) | Each install step run by hand, the `privacy-hud-setup` and `privacy-hud-doctor` commands, and the fallback pane. | You cannot use `install.sh`, or you want to control each step. |
| [`docs/known-limits.md`](docs/known-limits.md) | The nine limits in full, with the measurements behind them. | You are deciding how far to trust a number the HUD shows. |
| [`patches/README.md`](patches/README.md) | The one-item Codex status-line patch and how to regenerate it against a new tag. | You want to audit or rebuild the patched Codex binary. |
| [`.claude/docs/architecture.md`](.claude/docs/architecture.md) | Component map, process model, ledger schema, hook dispatch, and the consent loop. | You are working on the plugin itself. |

## License

[MIT](LICENSE).
