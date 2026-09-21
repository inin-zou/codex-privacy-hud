# The self-audit, and what it is allowed to prove

`CLAUDE.md`'s I7 used to say: *running Privacy HUD on this repo's own
development session must produce zero exposures.*

That was false. Three read-only source-review sessions, measured on
2026-09-21 during the SDK 2.x reinstall, recorded **88%, 100% and 100%** of
the disclosure budget.

**What that does and does not establish.** It establishes that the tool
contradicted its own stated invariant. It does **not** establish that those
sessions were harmless: this project counts model context as B1, a boundary
that leaves the machine, so "read-only" is not a synonym for "disclosed
nothing". Whether those numbers were detector error, accounting inflation,
or real crossings is exactly what is unseparated today — and separating them
is the work, not a detail. An earlier draft of this page asserted "nothing
left the machine"; that was a claim about Codex's behaviour made from a fact
about the plugin's, and review removed it.

The provenance is also thinner than it should be. The figures come from a
commit message (`abd3321`) with no session ids or receipts attached, so they
are a recorded report rather than something a reader can re-derive. Record
future runs **here**, with enough detail to check them.

## Why the claim was not fixable as written

It was not unfalsifiable — one counterexample disproves it, and one arrived.
It was an **invalid requirement**: sessions differ, and a session that reads
a file containing a real street address *should* record an exposure. That is
the product working. A rule demanding otherwise asks a correct tool to fail.

So "zero" is only meaningful against **stated inputs**, which is why the
corpus is committed rather than described, and why both halves are labelled
rather than counted.

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
purpose, each labelled with the tier expected to find it: three
credential-shaped strings (tier 1), three sensitive paths (tier 0), and six
values only the model can find — email, person, phone and three addresses
(tier 3). Every value is invented or a public landmark. The tier-3 half
skips when the weights are not on the machine, which is CI.

**Both halves run through both tiers.** That sounds obvious and was not: the
first version of this suite ran only the cheap detectors over the clean
corpus and reported green, while two of its own entries fired on the model.
A false-positive corpus that never runs the detector producing the false
positives is not a weaker check — it is a check of nothing, wearing the
green tick of a real one. Review found it by running the model itself.

## What the corpus found on its first run

Three of the twelve planted values are not detected. They are marked
`known_gap` in the fixture and asserted as **strict** expected failures, so
closing one turns the suite red and forces the entry to be promoted — a
non-strict marker would let a fixed detector sit behind a stale "we do not
catch this" note, which is the drift this repository keeps finding in other
forms.

| entry | what happens |
|---|---|
| `json-01` (clean) | The model reads the JSON string value `"Bash"` as a **person**, confidently. Known limit 7's class, and the confidence floor cannot reach it without dropping real disclosures first. |
| `log-01` (clean) | A log timestamp scores as a **date**, indistinguishable from a date of birth in the same shape. Also known limit 7. |
| `address-01` | `1600 Pennsylvania Avenue NW, Washington` returns **nothing at all**. Confident silence is the worst failure mode a privacy tool has. Why it happens is not established — an earlier draft asserted the model reads a landmark as an organisation, which was a guess. |
| `address-03` | `42 Rue de Rivoli, 75001 Paris` is found and **fragmented** into `42`, `Rue de Rivoli` and `75001`, so no single finding carries the street line — the BIOES class `detect/model.py` documents, surviving on a non-English address. Not a masking hole: passing all three findings through `minimize_text` does replace all three spans. What is lost is the reported value. |

**One entry in that table was wrong and is worth keeping as a record.**
`cred-03` was committed claiming `SecretDetector` has no GitHub token
pattern. It has one — `ghp_[A-Za-z0-9]{36}` in `secrets.py` — and the
fixture carried **38** suffix characters while its own note said 36. The
accompanying entropy explanation was invented: the token's Shannon entropy
is ~5.25, well above the 3.5 threshold. Review caught it before an issue was
filed against a defect that does not exist. A corpus can manufacture a false
gap as easily as it can find a real one, and the difference is whether
someone checks the detector rather than the fixture.

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
