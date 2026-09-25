# Installing by hand

The [one-command installer](../README.md#install) runs the steps below itself. Read this page to see or control each one — installing the plugin, recording the interpreter, or running only the fallback pane without a patched Codex build.

Privacy HUD 0.10.0 retains snapshot version 2. New sessions observed from a genuine SessionStart use version-2 accounting; existing sessions and late attachments retain legacy accounting. Snapshot-v2 readers accept version 1 as explicitly legacy and version 2 with nullable accounting fields. Older snapshot-v1-only readers reject version 2 and show no Privacy item. Matching Codex version numbers do not establish snapshot compatibility.

The snapshot-v2 patched Codex builds for 0.154.0, 0.155.0, and 0.155.1 were re-released on 2026-09-22. An earlier installation of one of those versions may still contain the older reader. Updating the plugin does not replace that binary. No additional patched-Codex release is required solely for Privacy HUD 0.10.0.

The native Privacy item displays accounting snapshots; it does not verify runtime alignment. Before repair, an old daemon may continue refreshing a legacy reading. Use the bundled doctor command to check alignment. The bundled ambient launcher reports runtime failure instead of displaying a percentage.

Privacy HUD loads Python code from the selected plugin bundle. The recorded Python environment supplies dependencies. Run $privacy repair to obtain the exact recovery command for another terminal. Explicit installation may download dependencies and model weights; runtime checks and offline repair do not.

The active ledger is $PLUGIN_DATA/ledger/active.db after repair. $PLUGIN_DATA/ledger.db is a directory that fences the historical pathname. Do not replace it with a file or symlink. Repair preserves the accounting generation and recorded values; it does not activate version-2 accounting. The selected daemon activates accounting only when it receives a genuine SessionStart for an absent session.

Generation 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch. Unsupported or altered schemas are preserved and refused. No downgrade migration is provided.

Runtime mismatches produce an unverified warning on ingress and a denial for outbound calls the hook cannot verify. These are plugin decisions, not confirmation of host enforcement. Monitoring gaps and lost in-memory detection state cannot be reconstructed. Open version-2 sessions whose accounting keys were lost remain unavailable for the rest of those sessions.

```bash
PRIVACY_HUD_BUNDLE='/absolute/path/to/installed/0.10.0/plugin'
PRIVACY_HUD_DATA='/absolute/path/to/plugin/data'

python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" doctor

python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" repair --print-command

python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" ambient --watch
```

Privacy HUD 0.7.1 does not alter the schema of a valid prepared generation-5401 ledger during initialization: `events` already contains `source_kind`. It can nevertheless open the historical ledger pathname without participating in the selected runtime's handshake or writer lease. On a prepared ledger, historical session and coverage writes can succeed even though legacy event recording fails against the new `events` layout. On a generation-0 ledger, historical event writes remain possible, and initialization adds `source_kind` only when that column is absent. Explicit repair therefore quiesces legacy users, preserves the ledger at `$PLUGIN_DATA/ledger/active.db`, and replaces `$PLUGIN_DATA/ledger.db` with a directory fence that prevents subsequent historical-path opens. The fence does not revoke already-open connections or protect against same-user code deliberately opening the active pathname.

## Prerequisites

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
HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 HF_DATASETS_OFFLINE=0 HF_HUB_DISABLE_TELEMETRY=1 python3 -c "
from huggingface_hub import snapshot_download
snapshot_download('openai/privacy-filter', allow_patterns=[
    'config.json', 'model.safetensors', 'tokenizer.json',
    'tokenizer_config.json', 'viterbi_calibration.json'])
"
```

That exact file set is verified sufficient. The variables in front of the command turn the offline flags off for that one command only. Installation downloads packages and the patched Codex build; model weights are downloaded only through the explicit model-download step. Runtime, setup probes and doctor checks enforce offline mode regardless of inherited environment values and never download missing weights.

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

The plugin manifest is `.codex-plugin/plugin.json` and the marketplace manifest is `.agents/plugins/marketplace.json`, the two paths Codex looks at first. (Codex also accepts the Claude Code layout, `.claude-plugin/`, as a fallback; this project used it until 2026-09-15. An earlier note here said Codex rejected `.codex-plugin/`: that was Codex 0.145 given a `.codex-plugin/plugin.json` with no marketplace manifest beside it, and the error was about the missing marketplace file. With both files in place, Codex 0.154 installs this layout; see `.claude/docs/architecture.md` §7.)

**How every command below is run (0.8.0).** Privacy HUD loads its Python code from the selected plugin bundle, so each command goes through that bundle's own bootstrap rather than through a console script on your `PATH` or a `PYTHONPATH=src` import. Set these two once for the shell you are working in:

```sh
# Set these to the exact installed bundle and its data directory.
PRIVACY_HUD_BUNDLE='/absolute/path/to/installed/plugin'
PRIVACY_HUD_DATA='/absolute/path/to/plugin/data'
```

`install.sh` also writes wrappers under `~/.local/share/codex-privacy-hud/bin/` that do exactly this with those two values already filled in, which is why the installed setup needs no environment variable at all. A developer checkout is a bundle like any other: point `PRIVACY_HUD_BUNDLE` at the checkout explicitly and give it an isolated `PRIVACY_HUD_DATA`, so a scratch run cannot reach the data directory Codex assigns.

**2. Run the setup step once — from the environment that has `transformers` and `torch`.** This is the whole of the daemon's configuration. It records which Python interpreter the daemon must run in, into the plugin-data directory Codex assigns, and after that Codex's hooks start the daemon themselves.

```bash
source .venv/bin/activate            # the env from Prerequisites, whatever it is
python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" setup --python "$(command -v python3)"
```

```text
privacy-hud setup

  interpreter    ~/.venvs/privacy-hud/bin/python3
  transformers   5.16.1
  torch          2.14.0
  plugin data    ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud

  recorded       ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud/runtime.json
```

**Why an interpreter has to be recorded at all, and why from that shell.** Codex runs `hooks/handler.py` through its `#!/usr/bin/env python3` shebang against Codex's own minimal `PATH` — typically a *system* Python with no `transformers` in it. A daemon started from that interpreter would come up, bind its socket, answer every health check, and detect no names or addresses at all, with nothing anywhere saying so. So the interpreter is recorded once from a process that demonstrably has the stack, and `setup` **refuses to record one that cannot import `transformers` and `torch`** rather than pinning a blind daemon. (`--allow-degraded` records it anyway if tiers 0–2 are what you want; it says so in the output and in `privacy-hud-doctor`.)

You do not need to know what `PLUGIN_DATA` is, find it, or export it: setup reads the directory Codex assigned from Codex's own state, and the hook that later starts the daemon passes it its own value — so the daemon and the hooks cannot end up pointed at different directories, which used to be this project's most expensive misconfiguration. (`--plugin-data DIR` overrides it for a scratch setup.)

**What the first tool call of a session now costs.** The daemon loads ~2.8 GB of model weights *before* it binds its socket — about seven seconds. The hook that starts it does not wait for it, and neither do the hooks that fire during the load: they get the same answer as a missing daemon (fail open on ingress with an "unverified" note, fail closed on egress). **The first few seconds of a session are unmonitored, and disclosures in that window are not recorded.** After that the daemon stays up for as long as *any* Codex session is open and exits five minutes after the last one closes; the next session's first hook starts a new one and pays the load again.

**How long the daemon stays up, exactly.** One daemon serves every concurrent Codex session, so it counts them rather than watching a clock: `SessionStart` adds a session, `SessionEnd` removes it, and any other hook event counts as that session's keep-alive. While at least one session is open it will not exit no matter how long you leave it idle — an interactive session where nothing has run for half an hour is a person reading a diff, not a session that is over, and taking the daemon away there would put the session back through the unmonitored cold-start window mid-flight. Five minutes after the last session ends, it exits. Two fallbacks bound it if `SessionEnd` never arrives (Codex crashed, was `kill -9`'d, the terminal closed): a session with no hook event for four hours stops counting, and four hours with no connection of any kind exits the daemon regardless of the count. So a leaked session reference costs at most four hours of a resident process, not an unbounded one — and leaving a Codex window open overnight will outlive its daemon, with the next morning's first hook paying one seven-second restart.

**Starting one by hand still works** and is the way to have a daemon up *before* the session — worth it if you want the ambient HUD in step 3 to have something to read immediately, or you are debugging:

```bash
python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" daemon &
```

Start Codex within five minutes of it: a hand-started daemon that no session ever connects to is indistinguishable from one whose last session ended, and it exits on the same grace.

Only one daemon can own the socket: whichever starts first wins an exclusive lock and any other exits immediately without disturbing it, so a hand-started daemon and an auto-started one cannot fight or clobber each other's socket.

To turn auto-start off entirely (a sandboxed box where the spawn cannot succeed and paying a fork on every hook is worse than having no HUD), set `PRIVACY_HUD_NO_SPAWN=1` in the environment Codex runs in.

**Check the whole setup in one shot — `privacy-hud-doctor`.** Every moving part above fails *silently*, and they all look identical from the outside: nothing happens. A setup step that was never run, so no hook will start a daemon. A recorded interpreter that has since been deleted along with its virtualenv. A `PLUGIN_DATA` a hand-started daemon and the hook client disagree on. Model weights that were never downloaded, so tier 3 reports `available = False` and person/address detection quietly stops. A `transformers` older than 5.16, or a `transformers` with no torch beside it. A stale copy of the plugin in Codex's cache, because Codex installs a *copy* and your edited `hooks/handler.py` is not what runs. One command tells you which of those it is:

```bash
python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" doctor
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
  [ OK ] Plugin install       installed, version 0.3.0, matches this checkout

Summary: 8 ok, 0 warning(s), 0 failure(s).
Setup is healthy.
```

The daemon check is a real round trip, not a look at the socket file — a unix socket outlives the process that bound it, so a stale one and a running daemon are indistinguishable until something connects. The `Runtime pin` check is a real import in a real subprocess of the recorded interpreter (~1.4 s), for the same reason: "`transformers` is installed there" and "`transformers` imports there" are different claims, and this project has hit the gap between them (a torch/torchvision mismatch surfacing as `operator torchvision::nms does not exist`). A missing or stale pin is a `[FAIL]`, never a quiet fallback to some other Python. Every failing check prints what to do about it.

`Daemon` reporting `[WARN] not running` between sessions is the correct state of a healthy setup, not a fault — the daemon exits once your last session ends, and the next hook starts it. It is a `[FAIL]` only when there is no pin, because then nothing will.

Note that the doctor and the daemon need not be the same interpreter any more. Run the bundled `doctor` from anywhere; where its own `transformers` view differs from the daemon's, the report says so rather than passing one off as the other.

Starting with version 0.7.5, the MCP check validates the five-tool list and calls `privacy.get_session_summary` with the synthetic session ID `__privacy_hud_doctor_probe__`. It requires a valid summary response; tool discovery alone is insufficient. In 0.7.8 the MCP reader opens an existing ledger without initialization or migration. The probe adds no session, policy, event or coverage rows and normally returns the unrecorded variant with `percent=null`. A successful read confirms that the MCP ledger-read path responds; it does not establish that monitoring is working.

**Exit code 0 when the setup is usable, 1 only when something is genuinely broken.** Degraded-but-working is a warning, not a failure: with no model weights the engine still runs tiers 0–2, so that is reported as `[WARN]` with the consequence spelled out — *names and addresses will not be detected* — and the command still exits 0, which is what makes it usable in a setup script. `[FAIL]` is reserved for states where nothing this plugin promises can happen at all: no runtime pin, so nothing will ever start a daemon; a recorded interpreter that is gone or cannot import the package; a daemon that is listening and not answering; no `PLUGIN_DATA`; no installed plugin; an interpreter below the floor.

It reads the ledger read-only and never creates it, and it reports counts, versions, timestamps and the paths of its own machinery — never a prompt, a file, a detected value, or anything from a session. `--check-model` swaps the cheap on-disk weights check for actually constructing the tier 3 detector (~2.8 GB, about 7 s); by default it says the weights are present and that it did not load them, rather than claiming to know.

**3. Optional — start the fallback Level 1 HUD in a second terminal pane.** If `install.sh` (or the forwarder) found a snapshot-v2-compatible patched Codex build matching your version, the `privacy` item already lives in Codex's own status line and you can skip this step. Otherwise this is the fallback: a separate process, not a Codex status item, that reads `$PLUGIN_DATA/hud/<session_id>.json` — the same snapshot file (contract A) the patched binary itself reads — and redraws one line in place, so give it its own pane or split beside the pane running Codex. It only moves while a daemon is up and has written that file: with no daemon running, or before the file exists, the HUD shows nothing. Codex's first tool call starts the daemon — but if you want the pane live before that, start the daemon by hand as shown in step 2. It never reports 0% for a session that is simply unmonitored.

```bash
python3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \
  --plugin-data "$PRIVACY_HUD_DATA" ambient --watch
```

```text
Privacy legacy 30%
```

`--watch` redraws every 2 seconds; `--watch N` sets the interval. With no flags (or `--once`) it prints a single line and exits, which is what you want from a shell prompt or another status bar. `--session-id <id>` pins the pane to one session and skips resolution entirely. Without it, *which* session the line is about is resolved the same way `$privacy` resolves it — by asking the daemon — but only about once every 30 seconds, not on every redraw: see known limit 8 for both halves of that trade. The installer writes the same command as `~/.local/share/codex-privacy-hud/bin/privacy-hud-ambient`.

`--once` checks what the snapshot reader can display. A line is not proof that the whole stack is live. Silence can mean a missing, malformed, stale, or hidden snapshot, unresolved session selection, or insufficient width; it does not establish an empty ledger. Use `privacy-hud-doctor` to investigate runtime availability.

A recorded legacy session with known coverage gaps can show:

```text
Privacy legacy 0% ⚠unverified
```

This is a legacy zero with incomplete coverage, not proof of no disclosure. An explicitly unrecorded session shows `Privacy —% · No session on record`. Daemon-reported gaps without a resolved session show `Privacy —% · unattributed hook gaps`. The pane selects complete width candidates, retaining `legacy` beside legacy percentages and a warning for incomplete coverage; it renders nothing if none fits. See known limit 2.

**4. Use Codex normally.** The plugin's hooks (`hooks/hooks.json`) fire on every `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SubagentStart`/`Stop`, and `SessionEnd` — no per-command action needed. The first hook of the session starts the daemon if nothing is listening; that hook and the ones during the ~7 s model load are answered without detection.

**5. Run `$privacy` at any point** to see the session audit — the ASCII table always works; it also starts a local browser UI at a `127.0.0.1` URL it prints (never a link to anything else).

**6. When Privacy HUD issues a denial or returns rewritten input**, its `systemMessage` describes that decision and directs you to `$privacy` to review the ledger. Host enforcement or application of rewritten input is not confirmed. Neither “minimize and retry” nor “allow once” is an available user action; [`design.md` §8](../.claude/docs/design.md) records an unbuilt consent proposal. The current rewrite message is `PRIVACY HUD returned rewritten input`.

**7. Uninstall the plugin itself.** (If you used the one-command installer, run [`install.sh --uninstall`](../README.md#uninstall) instead — it also removes the patched Codex build and the forwarder. This step only removes the plugin; also stop any daemon still running — an auto-started one exits by itself five minutes after your last Codex session ends — and the ambient HUD from step 3 if you started it):

```bash
codex plugin remove codex-privacy-hud@codex-privacy-hud
codex plugin marketplace remove codex-privacy-hud
```
