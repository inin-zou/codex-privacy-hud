# src/privacy_hud/runtime_messages.py
"""Fixed user-facing text for runtime failures (#66).

Every string here is copied from the #66 contract. Nothing here is built
from an exception message, a path the plugin did not choose, or hook
content; the only substitutions are a release string and a repair command
from `runtime_repair.format_repair_command`.

`scripts/runtime.py` and `hooks/handler.py` must be able to print these
when the package cannot be imported, so they restate the ones they use and
`tests/test_runtime_messages.py` pins the copies to this module.
"""
from __future__ import annotations

#: Doctor, and any bootstrap command that finds no usable selected runtime.
RUNTIME_SETUP_FAIL = (
    "[FAIL] Runtime setup\n"
    "No usable Privacy HUD runtime is configured.\n"
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "Installation may download dependencies and model weights."
)

REPAIR_FAILED = (
    "Privacy HUD runtime repair did not complete.\n"
    "Existing ledger files were preserved. Activation may be incomplete.\n"
    "Run this command in another terminal:\n"
    "  {repair_command}"
)

#: `repair --print-command`, and `$privacy repair`.
REPAIR_COMMAND_OUTPUT = (
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "This command may download dependencies and model weights.\n"
    "It does not install or replace a patched Codex binary."
)

#: MCP bootstrap failure: stderr only, exit 1, stdout left empty.
MCP_BOOTSTRAP_REFUSAL = (
    "privacy-hud mcp: runtime setup is incompatible; no ledger was opened.\n"
    "Run in another terminal:\n"
    "  {repair_command}"
)

#: Daemon refusal before any writable ledger open.
DAEMON_STARTUP_REFUSAL = (
    "privacy-hud daemon: runtime identity or ledger compatibility check "
    "failed; no writable ledger was opened.\n"
    "Run the repair command reported by the current plugin's doctor."
)

#: Ambient launcher, in place of a percentage.
AMBIENT_RUNTIME_MISMATCH = "Privacy — runtime mismatch"

#: Hook replies (#66), restated by `hooks/handler.py`. The payload was not
#: checked by a compatible daemon: a warning on ingress, a denial on egress.
#: Neither claims host enforcement.
INGRESS_REFUSAL = (
    "Privacy HUD runtime mismatch — this event was not checked by a "
    "compatible daemon.\n"
    "Run $privacy repair to get the recovery command."
)
EGRESS_REFUSAL = (
    "Privacy HUD issued a denial because no compatible daemon could verify "
    "this outbound call.\n"
    "Run $privacy repair to get the recovery command."
)
STARTING_INGRESS = "Privacy HUD is starting — this event is unverified."
STARTING_EGRESS = (
    "Privacy HUD issued a denial because the daemon is still starting.\n"
    "Retry after startup completes."
)

#: A policy mutation refused before anything was sent or written: the MCP
#: tool and the local browser's `/api/policy`. "No policy rule was saved"
#: is a fact in this branch and only in this branch — the refusal happens
#: before the write, so nothing about the outcome is unknown.
POLICY_PREFLIGHT_REFUSAL = (
    "Privacy HUD runtime mismatch. No policy rule was saved."
)

#: Explicit repair, after the selected daemon answered a handshake and not
#: before. The second line has a fresh-installation variant below: there
#: were no records to preserve, and saying there were would be a claim
#: about a ledger nobody wrote.
REPAIR_SUCCESS = (
    "Privacy HUD {release} is running from the selected plugin bundle.\n"
    "Existing ledger records were preserved.\n"
    "Restart Codex to reload its hooks and MCP server.\n"
    "Monitoring gaps and lost in-memory detection state cannot be "
    "reconstructed."
)
REPAIR_SUCCESS_FRESH = (
    "Privacy HUD {release} is running from the selected plugin bundle.\n"
    "The active ledger location is configured.\n"
    "Restart Codex to reload its hooks and MCP server.\n"
    "Monitoring gaps and lost in-memory detection state cannot be "
    "reconstructed."
)

#: Printed separately from success, always. A daemon that matches the
#: selected build says nothing about whether the deep-scan detector
#: loaded, and a user who reads one sentence as the other has been told
#: their session is covered when it is not (I3/§5).
MODEL_DEGRADED = (
    "Deep-scan detection is unavailable. Runtime alignment does not "
    "establish detector availability."
)

#: A ledger this build cannot write. Preserved and refused, never
#: repaired: there is no downgrade migration and no automatic rewrite of
#: history (CLAUDE.md §4).
LEDGER_UNSUPPORTED = (
    "Privacy HUD cannot safely use this ledger.\n"
    "Its schema is unsupported or does not match its recorded version.\n"
    "Existing files were preserved. No automatic ledger repair was "
    "attempted."
)

#: Something may still hold the old ledger, or the question could not be
#: asked at all. Both are the same answer to the user: the transition did
#: not happen and nothing was moved.
UNKNOWN_HOLDER = (
    "Privacy HUD could not verify that all legacy ledger users have "
    "stopped.\n"
    "The storage transition was not completed. Existing files were "
    "preserved.\n"
    "Close other Privacy HUD processes and retry the repair command."
)

#: A policy mutation whose reply never came back. The request reached the
#: daemon; what happened to it there is not knowable from here, so this
#: says exactly that and offers no action -- 0.8.0 has no surface that
#: lists a session's saved rules for a user to check against (§D's
#: action-free alternative, adopted).
POLICY_OUTCOME_UNKNOWN = (
    "Privacy HUD could not confirm whether the policy rule was saved. "
    "The request was not retried."
)

#: Shown above history when the runtime does not match. History is still
#: readable -- it is a record, not a claim about now -- and the two
#: sentences say which parts of the product are not working.
AUDIT_RUNTIME_MISMATCH = (
    "Privacy HUD runtime mismatch. Historical records may still be "
    "viewed.\n"
    "Monitoring is unverified, and policy changes are unavailable."
)

#: Doctor's runtime-alignment failure. The daemon release is printed only
#: when it came back inside a validated protocol reply; anything else is
#: `unknown`, because a release string from an unvalidated peer is a
#: string that peer chose (I1).
DOCTOR_RUNTIME_MISMATCH = (
    "[FAIL] Runtime alignment\n"
    "The selected plugin and Privacy HUD runtime do not match.\n"
    "Plugin: {plugin_release}\n"
    "Daemon: {daemon_release_or_unknown}\n"
    "Monitoring is unverified. Policy changes are unavailable.\n"
    "Run this command in another terminal:\n"
    "  {repair_command}"
)

#: What doctor prints when the daemon release could not be established
#: from validated protocol data.
UNKNOWN_DAEMON_RELEASE = "unknown"

#: Doctor's runtime-source success. Provenance, not a distribution
#: version: the question is which tree the running code was read from.
DOCTOR_RUNTIME_SOURCE_OK = (
    "[ OK ] Runtime source\n"
    "Privacy HUD {release} is loaded from the selected plugin bundle."
)

#: Appended to the line above only where an older distribution was
#: actually found in the dependency environment. Never asserted blind:
#: saying an absent package is being bypassed is a claim about a machine
#: nobody looked at.
DOCTOR_OLD_DISTRIBUTION_UNUSED = (
    "The older privacy-hud distribution in the dependency environment is "
    "not used."
)

#: Doctor's runtime-alignment success, after a matching hello and nothing
#: less. Alignment is one fact; detector availability and storage validity
#: are separate checks and this sentence does not speak for them.
DOCTOR_RUNTIME_ALIGNMENT_OK = (
    "[ OK ] Runtime alignment\n"
    "The daemon matches the selected build and activation epoch."
)

#: The native Codex status item is drawn by the installed binary, which
#: this plugin neither ships nor replaces. A matching Codex version does
#: not establish that its reader understands snapshot v2 (§A).
DOCTOR_NATIVE_UNVERIFIED = (
    "[WARN] Native HUD compatibility\n"
    "The installed Codex binary has not been verified as a snapshot-v2 "
    "reader.\n"
    "A matching Codex version is not proof of snapshot compatibility.\n"
    "Run the bundled ambient command in another terminal:\n"
    "  {ambient_command}"
)

#: The ambient pane at a width that cannot hold the line above. Still not
#: a number: an unverified runtime has no reading to show, and a narrow
#: pane is not a reason to invent one.
AMBIENT_NARROW_FALLBACK = "Privacy unverified"
