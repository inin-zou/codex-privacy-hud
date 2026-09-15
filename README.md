# Codex Privacy HUD

[![CI](https://github.com/inin-zou/codex-privacy-hud/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/inin-zou/codex-privacy-hud/actions/workflows/ci.yml)

> Trace your privacy disclosure the same way you already trace your token usage — live, in every conversation.

> **See what your agent knows. Control where it goes.**

A local-first Codex plugin that maintains a live **disclosure ledger** for every Codex session, minimizes sensitive context **before** tool execution, and lets you inspect exactly what data reached the model, subagents, MCP tools, or external services.

Detection runs on your own machine, via [`openai/privacy-filter`](https://huggingface.co/openai/privacy-filter) loaded locally through `transformers` — no prompt, file, or secret is ever sent anywhere to be scanned. The plugin makes no outbound network calls at all; the only socket it opens is a local one to its own daemon on `127.0.0.1`.

```text
Token HUD:    How much context has been consumed?
Privacy HUD:  How much sensitive context has been disclosed?
```

![The Codex Privacy HUD user journey — from the ambient disclosure bar through the session audit, exposure detail, and minimizing a payload before it reaches an external tool](docs/images/user-journey-mockup.png)

**Before you rely on it,** read the [known limits](#known-limits). The most important one: the start of a session is **not monitored** while the model loads. The HUD marks a session whose record has a known hole (`⚠unverified`) rather than showing it as a clean 0%, but it cannot tell you what it missed. Hosted tools bypass local hooks, and detection is heuristic. A privacy tool that overclaims is worse than none, so those limits are stated in full rather than in a footnote.

---

## The problem

Coding agents read your filesystem, run shell commands, call MCP servers, and spawn subagents on your behalf. You can find out how much of your context window is used. You cannot find out:

- Which of your files' contents actually entered the model context?
- Did that GitHub MCP call carry a customer email in its arguments?
- Did the subagent inherit the `.env` you read twenty minutes ago?
- Did that `curl` pipe your support log to an external host?

Secret scanners are pre-commit, not pre-inference. DLP products are server-side and require shipping the very data you want to protect. Permission prompts are about *capability*, not *content*.

## What it does

```text
PRIVACY  Disclosure ███░░░░░░░ 28%  ›
```

**Level 1 — Ambient.** One item in Codex's own status line, under the composer:

```text
gpt-5.4 · ~/proj · Privacy ███░░░░░░░ 28% ⚠2
```

Stock Codex has no plugin-owned status item, so this needs a Codex build
with a small patch (`patches/privacy-status-line.patch`, one added item,
nothing else). `install.sh` fetches that build for your exact Codex version
and places it beside your official binary — it never modifies the official
one — and `codex` then resolves to the patched build only while the versions
match. Toggle the item with `/statusline` inside Codex, or hide it for now
with `$privacy hud off`. Without a matching build, the fallback is a
companion pane: `privacy-hud-ambient --watch` in a second terminal.

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

## Detection is not disclosure

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

## How it works

```mermaid
flowchart TD
    A["Codex lifecycle hooks"] --> B["Local privacy engine"]
    B --> C["Session disclosure ledger"]
    C --> D["Compact HUD"]
    C --> E["Interactive audit UI"]
    B --> F["Allow, rewrite, or block"]
```

The ledger is **event-sourced from hook boundaries**, never by asking a model what is in context. Every byte that can enter model context passes through a small set of chokepoints — `UserPromptSubmit`, `PostToolUse`, `SubagentStart`, `PreToolUse` — which together form a cut of the data-flow graph. We observe the transactions and reconstruct the balance.

There is **no second LLM call to audit the first one.** That would re-transmit the sensitive data being audited, cost a round trip per turn, and produce a non-deterministic ledger. See `architecture.md` §3.

## Privacy of the privacy tool

- Detection runs **entirely locally**. No content is sent anywhere for classification.
- The ledger stores **metadata only** — types, counts, sources, destinations, timestamps, masked exemplars. There is no `content` column, no `prompt` column, no `raw_value` column. The schema *is* the guarantee.
- Value identity uses a session-scoped salted HMAC held in memory and destroyed at session end, so cross-session correlation is impossible by construction.
- No telemetry. No analytics. No network calls except `127.0.0.1`.
- Running Privacy HUD on its own development session must yield zero exposures. Verified by hand on 2026-09-05 against Codex CLI 0.153.0 — zero events, budget 0.0/120.0. It is **not** an automated test: it needs a live Codex session, which CI has neither the binary nor the network for.

## Using it in Codex

Verified end-to-end against a real Codex CLI install on 0.145.0 and 0.153.0.

### Install (macOS, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh
```

It creates a private virtualenv, asks before downloading the ~2.8 GB
detection model (the only network access the plugin ever causes; the
runtime itself is offline), installs the plugin into Codex, records the
interpreter, fetches the patched Codex build matching `codex --version`,
and runs `privacy-hud-doctor`. `--yes` skips the question, `--no-model`
skips the weights (names and addresses then go undetected; doctor says so).

> **Status as of 2026-09-15 — read before running this.** No release has
> been published yet, and the patched Codex build has never been executed
> end to end. `install.sh` will therefore reach step 6, find no matching
> build, print "no patched build published for codex `<ver>` yet", and fall
> back to the ambient pane — everything else installs and works, but there
> is no status-line item until the first CI release lands. When it does,
> the binary it publishes is **unsigned and unnotarized**; the installer
> removes the quarantine attribute itself, and the SHA-256 it verifies
> protects against a corrupted or truncated download, not against a
> compromised release. Delete this note once a release exists and has been
> run.

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh -s -- --uninstall
```

Removes exactly what the installer created (listed in
`~/.local/share/codex-privacy-hud/manifest.json`) and restores `codex` to
the official binary. Your disclosure ledger and the model weights stay
unless you add `--purge`. The plugin itself is removed separately with
`codex plugin remove codex-privacy-hud`.

### Installing by hand

The one-command installer above runs the steps below itself. Read this
section to see or control each one — installing the plugin, recording the
interpreter, or running only the fallback pane without a patched Codex
build.

#### Prerequisites

Tier 3 detection (person, address, date, account number — the categories no regex can shape-match) runs the `openai/privacy-filter` model locally. It is not optional equipment: without it the engine still runs, but only tiers 0–2, which means credentials and paths are still caught and **names and addresses are not**.

- **Python 3.11+** (developed and verified on 3.12).
- **`transformers >= 5.16`.** Earlier versions fail with `does not recognize this architecture` — the `openai_privacy_filter` model type was not yet known to them. This is a real wall, not a warning.
- **`torch >= 2.5`** (what `transformers` 5.16 itself requires). Note that torch is one of *transformers'* optional extras, so installing `transformers` alone leaves you with no torch and a silently disabled tier 3 — the `[detectors]` extra below names both. If `torchvision` / `torchaudio` are also installed, they must be built against the same torch, or importing the pipeline dies with `operator torchvision::nms does not exist`.

> **Use a dedicated virtualenv.** Upgrading torch inside a shared environment is how you break every other ML package in it — during development this took out `vllm`, `facenet-pytorch`, and `sentence-transformers` in one command. Isolate this install.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[detectors]"
```

**Then fetch the model weights (~2.8 GB).** Download only the files the pipeline actually loads — the full repo is ~17 GB because it also ships ONNX export variants and a duplicate `original/` checkpoint, neither of which this project ever touches:

```bash
python3 -c "
from huggingface_hub import snapshot_download
snapshot_download('openai/privacy-filter', allow_patterns=[
    'config.json', 'model.safetensors', 'tokenizer.json',
    'tokenizer_config.json', 'viterbi_calibration.json'])
"
```

That exact file set is verified sufficient. Everything afterwards runs offline: the plugin sets `HF_HUB_OFFLINE=1` before importing `transformers`, so nothing reaches the network once the weights are on disk (Global Constraint I2).

All three prerequisites fail quietly rather than loudly — an old `transformers`, a missing torch and absent weights all leave you with a running engine that is simply blind to names and addresses. `privacy-hud-doctor` (below) checks each of them by version and by file, and `privacy-hud-doctor --check-model` goes further and constructs the detector to read its real availability.

**Keep the environment you just built.** Step 2 below records *this* interpreter as the one the daemon runs in, and the recording is done by running a command from inside it. Nothing else needs to know where it is afterwards.

**1. Install the plugin.** `codex plugin marketplace add` takes `owner/repo`, so no clone is needed for this half:

```bash
codex plugin marketplace add inin-zou/codex-privacy-hud
codex plugin add codex-privacy-hud@codex-privacy-hud
```

From a local checkout instead (what you want if you are editing the plugin — note that Codex installs a *copy*, so re-run these after changing anything under `hooks/`):

```bash
codex plugin marketplace add /path/to/codex-privacy-hud --json
codex plugin add codex-privacy-hud@codex-privacy-hud --json
```

The manifest lives at `.claude-plugin/plugin.json` (not `.codex-plugin/` — the OpenAI docs describe that path, but real Codex CLI does not recognize it; `codex plugin marketplace add` fails outright against it. `.claude-plugin/` is what Codex actually loads, confirmed by installing both ways. See `.claude/docs/architecture.md` §7 for the divergence.)

**2. Run the setup step once — from the environment that has `transformers` and `torch`.** This is the whole of the daemon's configuration. It records which Python interpreter the daemon must run in, into the plugin-data directory Codex assigns, and after that Codex's hooks start the daemon themselves.

```bash
source .venv/bin/activate            # the env from Prerequisites, whatever it is
privacy-hud-setup                    # or: PYTHONPATH=src python3 -m privacy_hud.runtime
```

```text
privacy-hud setup

  interpreter    ~/.venvs/privacy-hud/bin/python3
  transformers   5.16.1
  torch          2.14.0
  plugin data    ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud

  recorded       ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud/runtime.json
```

**Why an interpreter has to be recorded at all, and why from that shell.** Codex runs `hooks/handler.py` through its `#!/usr/bin/env python3` shebang against Codex's own minimal `PATH` — typically a *system* Python with no `transformers` in it. A daemon started from that interpreter would come up, bind its socket, answer every health check, and detect no names or addresses at all, with nothing anywhere saying so. So the interpreter is recorded once from a process that demonstrably has the stack, and `privacy-hud-setup` **refuses to record one that cannot import `transformers` and `torch`** rather than pinning a blind daemon. (`--allow-degraded` records it anyway if tiers 0–2 are what you want; it says so in the output and in `privacy-hud-doctor`.)

You do not need to know what `PLUGIN_DATA` is, find it, or export it: setup reads the directory Codex assigned from Codex's own state, and the hook that later starts the daemon passes it its own value — so the daemon and the hooks cannot end up pointed at different directories, which used to be this project's most expensive misconfiguration. (`--plugin-data DIR` overrides it for a scratch setup.)

**What the first tool call of a session now costs.** The daemon loads ~2.8 GB of model weights *before* it binds its socket — about seven seconds. The hook that starts it does not wait for it, and neither do the hooks that fire during the load: they get the same answer as a missing daemon (fail open on ingress with an "unverified" note, fail closed on egress). **The first few seconds of a session are unmonitored, and disclosures in that window are not recorded.** After that the daemon stays up for as long as *any* Codex session is open and exits five minutes after the last one closes; the next session's first hook starts a new one and pays the load again.

**How long the daemon stays up, exactly.** One daemon serves every concurrent Codex session, so it counts them rather than watching a clock: `SessionStart` adds a session, `SessionEnd` removes it, and any other hook event counts as that session's keep-alive. While at least one session is open it will not exit no matter how long you leave it idle — an interactive session where nothing has run for half an hour is a person reading a diff, not a session that is over, and taking the daemon away there would put the session back through the unmonitored cold-start window mid-flight. Five minutes after the last session ends, it exits. Two fallbacks bound it if `SessionEnd` never arrives (Codex crashed, was `kill -9`'d, the terminal closed): a session with no hook event for four hours stops counting, and four hours with no connection of any kind exits the daemon regardless of the count. So a leaked session reference costs at most four hours of a resident process, not an unbounded one — and leaving a Codex window open overnight will outlive its daemon, with the next morning's first hook paying one seven-second restart.

**Starting one by hand still works** and is the way to have a daemon up *before* the session — worth it if you want the ambient HUD in step 3 to have something to read immediately, or you are debugging:

```bash
export PLUGIN_DATA=~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud
PYTHONPATH=src python3 -m privacy_hud.daemon &
```

Start Codex within five minutes of it: a hand-started daemon that no session ever connects to is indistinguishable from one whose last session ended, and it exits on the same grace.

Only one daemon can own the socket: whichever starts first wins an exclusive lock and any other exits immediately without disturbing it, so a hand-started daemon and an auto-started one cannot fight or clobber each other's socket.

To turn auto-start off entirely (a sandboxed box where the spawn cannot succeed and paying a fork on every hook is worse than having no HUD), set `PRIVACY_HUD_NO_SPAWN=1` in the environment Codex runs in.

**Check the whole setup in one shot — `privacy-hud-doctor`.** Every moving part above fails *silently*, and they all look identical from the outside: nothing happens. A setup step that was never run, so no hook will start a daemon. A recorded interpreter that has since been deleted along with its virtualenv. A `PLUGIN_DATA` a hand-started daemon and the hook client disagree on. Model weights that were never downloaded, so tier 3 reports `available = False` and person/address detection quietly stops. A `transformers` older than 5.16, or a `transformers` with no torch beside it. A stale copy of the plugin in Codex's cache, because Codex installs a *copy* and your edited `hooks/handler.py` is not what runs. One command tells you which of those it is:

```bash
export PLUGIN_DATA=~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud
privacy-hud-doctor            # or: PYTHONPATH=src python3 -m privacy_hud.doctor
```

```text
privacy-hud doctor

  [ OK ] Python               3.12.10 (requires >= 3.11)
  [ OK ] PLUGIN_DATA          ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud
  [ OK ] Ledger               6 sessions, 44 events recorded
  [ OK ] Runtime pin          ~/.venvs/privacy-hud/bin/python3 (1.4s import probe)
  [ OK ] Daemon               responsive (4 ms round trip)
  [ OK ] Detector deps        transformers 5.16.1, torch 2.14.0
  [ OK ] Tier 3 model         weights present on disk (not loaded)
  [ OK ] Plugin install       installed, version 0.1.0, matches this checkout

Summary: 8 ok, 0 warning(s), 0 failure(s).
Setup is healthy.
```

The daemon check is a real round trip, not a look at the socket file — a unix socket outlives the process that bound it, so a stale one and a running daemon are indistinguishable until something connects. The `Runtime pin` check is a real import in a real subprocess of the recorded interpreter (~1.4 s), for the same reason: "`transformers` is installed there" and "`transformers` imports there" are different claims, and this project has hit the gap between them (a torch/torchvision mismatch surfacing as `operator torchvision::nms does not exist`). A missing or stale pin is a `[FAIL]`, never a quiet fallback to some other Python. Every failing check prints what to do about it.

`Daemon` reporting `[WARN] not running` between sessions is the correct state of a healthy setup, not a fault — the daemon exits once your last session ends, and the next hook starts it. It is a `[FAIL]` only when there is no pin, because then nothing will.

Note that the doctor and the daemon need not be the same interpreter any more. Run `privacy-hud-doctor` from anywhere; where its own `transformers` view differs from the daemon's, the report says so rather than passing one off as the other.

**Exit code 0 when the setup is usable, 1 only when something is genuinely broken.** Degraded-but-working is a warning, not a failure: with no model weights the engine still runs tiers 0–2, so that is reported as `[WARN]` with the consequence spelled out — *names and addresses will not be detected* — and the command still exits 0, which is what makes it usable in a setup script. `[FAIL]` is reserved for states where nothing this plugin promises can happen at all: no runtime pin, so nothing will ever start a daemon; a recorded interpreter that is gone or cannot import the package; a daemon that is listening and not answering; no `PLUGIN_DATA`; no installed plugin; an interpreter below the floor.

It reads the ledger read-only and never creates it, and it reports counts, versions, timestamps and the paths of its own machinery — never a prompt, a file, a detected value, or anything from a session. `--check-model` swaps the cheap on-disk weights check for actually constructing the tier 3 detector (~2.8 GB, about 7 s); by default it says the weights are present and that it did not load them, rather than claiming to know.

**3. Optional — start the fallback Level 1 HUD in a second terminal pane.** If `install.sh` (or the forwarder) found a patched Codex build matching your version, the `privacy` item already lives in Codex's own status line and you can skip this step. Otherwise this is the fallback: a separate process, not a Codex status item, that reads `$PLUGIN_DATA/hud/<session_id>.json` — the same snapshot file (contract A) the patched binary itself reads — and redraws one line in place, so give it its own pane or split beside the pane running Codex. It only moves while a daemon is up and has written that file: with no daemon running, or before the file exists, the HUD shows nothing. Codex's first tool call starts the daemon — but if you want the pane live before that, start the daemon by hand as shown in step 2. It never reports 0% for a session that is simply unmonitored.

```bash
export PLUGIN_DATA=~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud
PYTHONPATH=src python3 -m privacy_hud.ambient --watch
```

```text
PRIVACY  Disclosure ███░░░░░░░ 30%  ›
```

`--watch` redraws every 2 seconds; `--watch N` sets the interval. With no flags (or `--once`) it prints a single line and exits, which is what you want from a shell prompt or another status bar. `--session-id <id>` pins the pane to one session and skips resolution entirely. Without it, *which* session the line is about is resolved the same way `$privacy` resolves it — by asking the daemon — but only about once every 30 seconds, not on every redraw: see known limit 8 for both halves of that trade. If the package is installed, the same entry point is available as `privacy-hud-ambient`.

`--once` is also the quickest way to confirm the whole stack is live: if it prints a line, the daemon is up and the snapshot file is readable. If it prints nothing, nothing has been recorded yet — and `privacy-hud-doctor` is what tells you *why* not.

A third form appears when the ledger's account of the session has a known hole:

```text
PRIVACY  Disclosure ░░░░░░░░░░  0% ⚠unverified ›
```

Read this as *"the ledger holds 0%, and the ledger is not a complete record of this session"* — not as a clean session. It is what you get when the daemon cold-started after the session began, when it was replaced mid-session, or when hook calls were answered while nothing was listening. `$privacy` names which of those it was. Below 28 columns the word does not fit and the line becomes `⚠ 0%`, the warning glyph taking the band dot's place rather than trailing the number, so truncation can never leave a bare percentage behind. See known limit 2 for what this marker does and does not catch.

**4. Use Codex normally.** The plugin's hooks (`hooks/hooks.json`) fire on every `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SubagentStart`/`Stop`, and `SessionEnd` — no per-command action needed. The first hook of the session starts the daemon if nothing is listening; that hook and the ones during the ~7 s model load are answered without detection.

**5. Run `$privacy` at any point** to see the session audit — the ASCII table always works; it also starts a local browser UI at a `127.0.0.1` URL it prints (never a link to anything else).

Real output from a live Codex session (not a mockup) — a fresh session with nothing yet disclosed, and the same audit after a few turns that sent addresses, names, URLs, and a credential to the model:

![`$privacy` rendering a fresh session's audit table — 0% disclosure, nothing exposed yet](docs/images/dashboard-empty.png)

![`$privacy` rendering the same session a few turns later — 100% disclosure, 12 exposed items across address, person, URL, and credential](docs/images/dashboard-exposed.png)

**6. When a call is blocked**, Codex surfaces the reason via `systemMessage`. Run `$privacy` to review the exposure, then choose to minimize and retry, allow once, or leave it blocked — see [`design.md` §8](.claude/docs/design.md) for the full consent flow.

**7. Uninstall the plugin itself.** (If you used the one-command installer, run [`install.sh --uninstall`](#uninstall) instead — it also removes the patched Codex build and the forwarder. This step only removes the plugin; also stop any daemon still running — an auto-started one exits by itself five minutes after your last Codex session ends — and the ambient HUD from step 3 if you started it):

```bash
codex plugin remove codex-privacy-hud@codex-privacy-hud
codex plugin marketplace remove codex-privacy-hud
```

## Known limits

Stated up front, because a privacy tool that overclaims is worse than none:

1. **The start of a session is unmonitored.** The daemon starts itself now (`architecture.md`'s lazy auto-spawn, built), but it loads ~2.8 GB of model weights before it binds its socket — about seven seconds. The hook that starts it does not wait, and the hooks that fire during the load get the same answer as a missing daemon: fail open on ingress with an "unverified" note, fail closed on egress. **Whatever is disclosed in those first seconds is not in the ledger, and no later reading can say what it was.** The ledger does now know that *something* is missing — see limit 2 — but knowing a gap exists is not knowing what fell into it, and nothing recovers the difference. Measured: a `codex exec` one-shot that finished in 8.2 s from a cold start recorded *nothing at all* — the daemon it started was still loading when the session ended, so for short non-interactive runs this is not "the first few seconds" but the whole session. An interactive session is a different story, since typing the first prompt already outlasts the load. Starting a daemon by hand before the session (step 2) is the only way to close that window. It reopens whenever the daemon exits and a later hook has to start a new one — which now happens five minutes after your last session ends, rather than in the middle of a session that merely went quiet for half an hour.

   The same lifetime has one consequence at upgrade time: **upgrading the plugin while an older daemon is still running leaves the status item silent until that daemon exits** — about five minutes after its last session ends — because the running daemon is the only writer of the snapshot file and it is still the old code; restart Codex, or wait it out.

   The other half of the trade: auto-start works only if `privacy-hud-setup` has recorded an interpreter that can load the model. It refuses to record one that cannot, and with no recorded interpreter no daemon is started at all — deliberately, since guessing one produces a daemon that detects nothing while looking healthy. `privacy-hud-doctor` is the detector for both states: it round-trips the socket, and it re-imports the recorded interpreter's stack.
2. **"Unverified" marks the gaps it can see, and there are gaps it cannot.** A session whose record has a known hole renders `⚠unverified` on the ambient line and carries a `⚠ Session record incomplete` banner in the `$privacy` audit, instead of the clean `0%` that used to stand in for both "nothing was disclosed" and "nothing was recorded". Four things are recorded evidence and are detected: a session the ledger has no row for at all; a session whose beginning the daemon never saw (it cold-started late, or replaced one that died mid-session); a daemon replaced during a session; and hook calls that reached no daemon at all, which the daemon learns from the spawn-attempt latch the hook client leaves behind.

   What is **not** detectable, and is not marked: a gap in the middle of a session while one daemon stayed up throughout. A hook Codex never fired, a hook whose 2 s client timeout expired against a busy daemon, a hosted tool that bypassed hooks (limit 3) — each of those leaves no trace anywhere, by construction, and no heuristic here guesses at one. So `⚠unverified` means "the ledger holds evidence of a hole"; its absence means "nothing on record contradicts a complete account", which is a weaker claim than "complete" and must not be read as the stronger one. The marker also does not appear if `PLUGIN_DATA` is unwritable or auto-spawn is off (`PRIVACY_HUD_NO_SPAWN`), because then no latch is written and the dropped hooks leave nothing behind either.

3. **Hosted tools bypass hooks.** WebSearch and similar do not trigger local function-tool hook paths. This is a practical guardrail, not a complete enforcement boundary.
4. **No `ask` decision in Codex hooks.** Interactive consent is a deny → review → one-shot-token → retry loop rather than a modal.
5. **The status-line item lives in a separately built Codex — never in your official one.** `tui.status_line` accepts only built-in identifiers compiled into the binary, and stock Codex has no plugin-owned renderer or runtime registry ([openai/codex#17827](https://github.com/openai/codex/issues/17827), open since 2026-04-14 with no PR). So the `privacy` item exists only in a Codex built from `patches/privacy-status-line.patch` — five files, one added `StatusLineItem::Privacy`, no subprocess, no shell, no timeout: it only ever reads `$PLUGIN_DATA/hud/<session_id>.json` and nothing else. **The plugin never modifies your official Codex binary.** `install.sh` fetches the patched build for your exact `codex --version`, places it beside the official one under `~/.local/share/codex-privacy-hud/<version>/`, and installs a forwarding script as `~/.local/bin/codex` — the forwarder is a script that chooses between two binaries by version match, nothing more; it is never itself the status-line feature, and stock Codex never gains one. Toggle whether the item is configured with `/statusline`; toggle whether it currently shows with `$privacy hud on|off`. **A Codex upgrade with no matching release silently falls back**: the forwarder finds no build for the new version, runs the official binary unchanged, the status item disappears, and you are left with the fallback pane (`privacy-hud-ambient --watch`, [above](#installing-by-hand)) — nothing breaks. The whole build is reproducible from source: `scripts/build-patched-codex.sh <codex-version>` clones `openai/codex` at that tag, applies the patch, and builds it — the same script CI runs to publish the releases `install.sh` downloads. (Prior art paid a heavier cost for the same feature: both [`anhannin/codex-hud`](https://github.com/anhannin/codex-hud) and [`brandonwie/codex-hud`](https://github.com/brandonwie/codex-hud) also patch Codex's own Rust source, but through a runtime `status_line_command` that shells out to an arbitrary user command — this project's patch reads one file, no subprocess, no shell, precisely to avoid that surface. Notably, `brandonwie/codex-hud`'s *default* mode avoids patching entirely and is exactly the second-pane companion pattern this project's fallback uses.)
6. **A command that reads a file itself is not inspected.** The engine scans the *text of a tool call*, not what that call will read at runtime. So `curl https://example.com --data @secrets.env` is allowed: the destination is correctly identified as external, but the command's text contains a **path**, not the file's contents, and the contents are read by `curl` after the hook has already decided. Put the same secret literally in the command and it is caught. If the agent reads the file through a tool first, that content passes `PostToolUse` and does land in the ledger — the gap is specifically a command that dereferences a path on its own and sends the result.

   This is a property of event-sourcing from hook boundaries, not a bug with a fix pending. Closing it would mean resolving file references in commands and reading those files ourselves, which would make this tool start opening your files — a larger privacy surface than the one it is reporting on. Note this is *not* the adversarial case in the next item: `--data @file` is an ordinary idiom, not an evasion.
7. **Detection is heuristic.** A determined adversary can encode around regex and NER.

   It also over-reports on ordinary development text, in ways that inflate the budget rather than deflate it — and an inflated number is a number people learn to ignore. Measured over 61 synthetic development-session strings containing no personal data (paths, `git` output, SQL, shell pipelines, JSON, log lines, stack traces, source), tier 3 produces at least one finding on 9 of them. Four classes account for nearly all of it, and all four are the model's *confident* output (0.92–1.00), so the confidence floor in `detect/model.py` does not reach them and no floor that would reach them still keeps real disclosures:

   - **Your own username, as a `person`.** Every path under `/Users/<you>` or `/home/<you>` scores ~1.00 as a person name. Suppressing entity spans inside filesystem paths would also silence `/Users/<someone-else>/Downloads/patient-intake-2026.csv`, which is a row you want.
   - **Log and database timestamps, as a `date`.** `2026-09-05T18:53:02` scores 1.00, and so does a real date of birth in the same shape — the model does not distinguish them, and neither can we without dropping the one that matters. `date` carries the lowest severity in the matrix (2.0), which is the only thing that keeps this cheap.
   - **Identifier-shaped and size-shaped numbers**, as `person`, `account`, `address`, or `credential`: container image IDs, UUIDs, digests, `SEQ=00194427`, the byte counts in `ls -l` output. A UUID scores 0.978 as a secret while a genuine database password scores 0.949, so this one is provably not separable by confidence.
   - **Capitalized words in structured data**, as a `person`: `"tool_name": "Bash"` scores 1.00.

   Read a `person` or `date` row on a `Bash` source with that in mind: the exemplar column is there so you can tell at a glance which findings are yours and which are the machine's.
8. **Which session is being shown is inferred, not read — and both surfaces say so when they cannot be sure.** Codex exposes no session id to a skill, so the session to audit is worked out rather than read: the daemon knows which session fired a hook most recently, and running `$privacy` itself fires one (the skill runs bash, which is a `PreToolUse` in the session you typed in), so the asking session is the most recently active one. Two consequences. With **two sessions active in the same few seconds** the signal cannot separate them — the audit names the other active session in a line above the table instead of picking one silently, its header reads `Most recently active session` rather than `Current session`, and `$privacy <session id>` audits a specific one. With **no daemon to ask**, it falls back to the most recently started session in the ledger and labels it as that, in both the note and the table header, rather than as yours; a session with no daemon is also not being recorded (limit 1), so that is the state in which the numbers mean least.

   The ambient line (limit 5) resolves the same way, so the pane beside your window and the audit typed into it name the same session. It does so on a slower clock — once when it starts and roughly every 30 s after, not on every two-second redraw — because that resolution asks the daemon over the socket the hooks use, and because a HUD that changed which session it was reporting on between redraws would be unreadable. Two things follow. A session that starts right after a re-resolution can take up to half a minute to appear in the pane. And the ambient line carries **no marker for session ambiguity at all**: at 52 columns there is no honest room for one, and the `⚠unverified` glyph is not available for it — that marker means the session's *record* has a known hole (limit 2), and one glyph cannot mean two things. If you need certainty about which session a pane is showing, pin it with `privacy-hud-ambient --session-id <id>`, or ask `$privacy`, which has the room to explain itself.
9. **Nothing recalls disclosed data.** Ever.

## Documentation

| Doc | Contents |
|---|---|
| [`.claude/docs/PRD.md`](.claude/docs/PRD.md) | Problem, disclosure model, budget formula, scope, success criteria |
| [`.claude/docs/design.md`](.claude/docs/design.md) | Three-level UX, visual language, copy rules, consent flow |
| [`.claude/docs/architecture.md`](.claude/docs/architecture.md) | Process model, context accounting, schema, enforcement, testing |

## Prior art

- [`jarrodwatts/claude-hud`](https://github.com/jarrodwatts/claude-hud) — the token HUD for Claude Code that inspired the ambient layer.

## References

- [Codex Hooks](https://learn.chatgpt.com/docs/hooks) · [Build plugins](https://learn.chatgpt.com/docs/build-plugins) · [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) · [App Server](https://learn.chatgpt.com/docs/app-server)
