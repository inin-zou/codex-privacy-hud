# The self-audit, and what it is allowed to prove

`CLAUDE.md`'s I7 used to say: *running Privacy HUD on this repo's own
development session must produce zero exposures.*

That was false. Three read-only source-review sessions, measured on
2026-09-21 during the SDK 2.x reinstall, recorded **88%, 100% and 100%** of
the disclosure budget. Nothing left the machine — I2 held, and the failure
is detection and accounting rather than disclosure — but the invariant every
agent reads before working in this repository was contradicted by the tool's
own output, and it stayed that way for sixteen days, because the measurement
was written in a commit message and nothing automated could reach it.

## Why the claim was not fixable as written

"Zero exposures on a development session" cannot be tested, and not for a
practical reason. Sessions differ. A session that reads a file containing a
real street address *should* record an exposure — that is the product
working. So "zero" is only meaningful against **stated inputs**, which is
why the corpus is committed rather than described, and why the two halves
are labelled rather than counted.

Two fixes were available and both are wrong:

- **Exempt this repository.** A privacy tool whose own files are invisible
  to it is a tool with a blind spot shaped exactly like the place a
  contributor works.
- **Raise the budget cap.** The number would drop below 100% without a
  single detection improving.

## What replaced it

`tests/fixtures/self_audit/` holds the corpus, and `tests/test_self_audit.py`
runs it.

**`clean.json` — 20 clean entries.** Ordinary development text: paths, `git`
output, SQL, shell pipelines, JSON payloads, log lines, a stack trace,
source, and prose from this repository's own documents. None of it contains
personal data, a credential, or a sensitive file path. The correct number of
findings is zero, so every finding is a false positive and the test needs no
judgement call. The tolerance is **zero**, deliberately: a baseline above it
would be a way to keep a known false positive without deciding anything
about it.

**`planted.json` — 12 planted entries.** Synthetic values planted on
purpose, each labelled with the tier expected to find it: three credentials
(tier 1), three sensitive paths (tier 0), and six values only the model can
find — email, person, phone and three addresses (tier 3). Every value is
invented or a public landmark. The tier-3 half skips when the weights are
not on the machine, which is CI.

## What the corpus found on its first run

Three of the twelve planted values are not detected. They are marked
`known_gap` in the fixture and asserted as **strict** expected failures, so
closing one turns the suite red and forces the entry to be promoted — a
non-strict marker would let a fixed detector sit behind a stale "we do not
catch this" note, which is the drift this repository keeps finding in other
forms.

| entry | what happens |
|---|---|
| `cred-03` | `SecretDetector` has no GitHub token pattern, so `ghp_` + 36 characters is not matched by shape, and its entropy does not trip the generic rule. A token pasted into a shell command crosses a boundary unrecorded. |
| `address-01` | `1600 Pennsylvania Avenue NW, Washington` returns **nothing at all**. The model appears to read a landmark address as an organisation. Confident silence is the worst failure mode a privacy tool has. |
| `address-03` | `42 Rue de Rivoli, 75001 Paris` is found and **fragmented** into `42`, `Rue de Rivoli` and `75001`, so no single finding carries the address. Task 12 masks on these offsets, which makes a fragmented span a masking hole as well as a reporting one — the same class as the BIOES splitting `detect/model.py` documents, surviving on a non-English street line. |

`address-03` is also why the tier-3 assertion compares the **value** and not
just the data type. A first version compared type sets, and three `address`
findings satisfied "an address was found" while none of them was the
address.

One entry carries a `note` rather than a gap: `path-03` expects the finding
value `.pem`, not `server.pem`, because the detector reports the pattern it
matched rather than the file it matched in. That is issue #44 and known
limit 18, recorded here so the corpus states what the tool does rather than
what it should do.

Both directions matter. A detector that stops seeing planted credentials has
failed at the only job that matters. A detector that fires on
`SELECT COUNT(*) FROM events` has failed differently and more quietly: an
inflated budget is a number people learn to ignore, and then the real one
arrives and they ignore that too. Known limit 7 already documents this
happening — 9 of 61 clean strings produced a finding in an earlier
measurement, all of them the model's *confident* output.

## What a green run does not prove

The test exercises the detector stack directly. It says nothing about hooks,
the daemon, the ledger, or what a live Codex session does — and the 88%
came from a live session, not from a detector in isolation. Between a clean
detector run and a clean session sit at least:

- **the accounting**, which charges every distinct value at full price
  because the sublinear formula is never called with `n > 1`
  (issue #47 item 3);
- **the dedupe key**, which can collapse or invert outcomes
  (issues #43 and #44);
- **the boundary taxonomy**, where an allowed call is recorded as `exposed`
  before permission returns (#47 item 8).

So the honest reading of a green run is *"the detectors behave on these
inputs"*, and nothing wider. Closing the gap between that and the session
number is the work those issues describe.

## What is deliberately not in the corpus

Text that mentions `.env`, `id_rsa` or `~/.aws` **in passing** — a log line
naming a path the session never read. Whether flagging that is correct
depends on a question this repository has not answered (does the ledger
record what was read, or what was mentioned?), and burying that decision
inside a fixture would settle it without anyone noticing. It belongs in the
accounting work, not here.

## Re-running the session-level check

Still by hand: it needs a live Codex session, which CI has neither the
binary nor the network for. Note that a cold daemon invalidates the result —
the session goes unrecorded rather than clean (known limit 1), and the two
look identical in the ledger. Record what you measured **here**, not in a
commit message.
