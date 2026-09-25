"""#54 Phase 4 (0.9.0): the release contract and its exact copy.

The strings below pin astra's §C text as amended by the owner-approved
0.9.0 scope: shell-derived accounting file identities remain unresolved,
and #44 remains open. The Chinese copy is pinned verbatim too. The
documents are compared with their hard wrapping removed, so a paragraph
compares as the sentences it is. Historical screenshots, captions, dates
and CHANGELOG entries are preserved; only the current contract changes.
"""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

from privacy_hud import hud_snapshot, ledger_schema
from privacy_hud import runtime_contract as contract
from privacy_hud.matrix.loader import load_matrix

REPO = Path(__file__).resolve().parents[1]
RELEASE = contract.RELEASE

#: The CHANGELOG below the 0.9.0 section, exactly as 0.8.3 published it.
PRIOR_CHANGELOG_SHA256 = (
    "c3b39aa9446983dd31af355ab01dcf5ca9f9be558485fa56310a0ef1aefadf2f")

CONTRACT_DOCS = (".claude/docs/PRD.md", ".claude/docs/design.md",
                 ".claude/docs/architecture.md")
INSTALL_DOCS = ("README.md", "docs/installing-by-hand.md",
                "patches/README.md",
                "docs/superpowers/specs/"
                "2026-09-15-patched-codex-status-line-design.md")

CONTRACT_BLOCK = '**Current contract — #54 Phase 4 and #44 guard-target audit (0.10.0).**\n\nNew sessions observed from a genuine SessionStart use evidence-based accounting. Existing sessions and sessions attached after their start retain legacy accounting. Observations, finding outcomes, disclosure identities, and charges are separate. Current hooks do not confirm model-context admission, transmission, or host application of interventions; unresolved evidence withholds the percentage. Historical records remain unchanged. Recipient identity does not establish delivery, inherited subagent content, or causal multi-hop flows. All shell-derived accounting file identities remain unresolved in 0.9.0, including ordinary `cat .env` reads. Observation-local opaque subjects preserve separate events without establishing distinct files or naming the denied file. #43 is addressed for new version-2 sessions only; legacy sessions and historical rows retain their limitations. Version 0.10.0 adds separate guard-target metadata for newly recorded, keyed version-2 local shell read-guard denials. A random session-scoped target ID and fixed rule ID describe the path representation evaluated by Privacy HUD. "Same evaluated target as event #N" means exact equality of that evaluated representation, including existing home collapse; it does not mean the same filesystem object. The matching HMAC map exists only in daemon memory. SessionEnd discards it, and key loss disables new target correlation for that session. Stored IDs, rule metadata and prior links remain. No candidate path, command, basename or suffix is stored. Execution file subjects and accounting counts are unchanged. Guard-target writes are optional. When an ordinary write failure is contained by its savepoint, the observation and denial evidence still commit, but that row has no guard-target metadata and seeds no new link. Delivery retries do not backfill it. No failure text or extra coverage/scan-gap record is persisted. Failure of the core transaction or its commit remains outside this guarantee. #44 remains open for filesystem identity and independently recognizable historical filenames.\n\nRuntime selection, writer ownership, read-only readers, daemon policy RPC, and the fenced ledger layout remain required. Accounting activation runs under the daemon\'s current writer lease and does not change the runtime activation epoch. Generation 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch. Snapshot version remains 2; the native HUD does not authenticate runtime alignment.'

README_INTRO = 'A local-first Codex plugin that records hook observations in a session ledger and can return denials or rewritten input before tool execution.\n\nNew sessions observed from a genuine SessionStart use evidence-based accounting: confirmed points, distinct disclosures, confirmed recipients, and denials issued. A percentage is shown only when the recorded evidence supports it. Current hooks do not confirm model-context admission, transmission, or host application of a denial or rewrite, so a session may show zero confirmed points alongside unresolved actions and an unavailable percentage. Zero confirmed points does not mean no disclosure occurred.\n\nExisting sessions and sessions attached after their start retain their legacy permitted-crossing score and its limitations. Historical rows are preserved without backfill or rescoring. An unrecorded session has no percentage or numeric counts.\n\nRecipient identity is separate from boundary category. Supported, unambiguous MCP names and simple network commands can identify intended recipients; ambiguous identities remain unresolved. This does not establish delivery, downstream forwarding, or what a subagent inherited.\n\nDetection runs locally; the plugin sends no prompt, file, or secret to a remote scanner. Runtime communication is limited to Unix-domain sockets and the local browser UI on 127.0.0.1.'

RELEASE_SENTENCE = 'Version 0.10.0 activates evidence-based accounting for new sessions observed from a genuine SessionStart, using the selected runtime and fenced ledger introduced in 0.8.0. Existing and late-attached sessions retain legacy accounting; historical records are not backfilled or rescored.'

README_ZH_INTRO = 'Codex Privacy HUD 是一个本地优先的 Codex 插件。它把收到的 hook 观测记录在会话账本中，并可在工具执行前返回拒绝决定或改写后的输入。\n\n只有在收到真正的 SessionStart 时首次建立记录的新会话，才使用基于证据的新版记账。摘要显示已确认披露分数、不同披露数、已确认接收方数，以及插件发出的拒绝次数。只有记录中的证据足以支持计算时，才显示百分比。当前 hook 无法确认内容是否进入模型上下文、数据是否完成传输，或宿主是否执行了拒绝或改写。因此，会话可能同时显示已确认披露分数为 0、结果尚未确定的操作，以及不可用的百分比。已确认披露分数为 0，不代表没有发生披露。\n\n已有会话，以及开始后才被插件接入的会话，继续使用旧版许可跨界评分，并保留其原有限制。历史记录原样保留，不补造证据，也不重新计分。没有会话记录时，不显示百分比或数字统计。\n\n接收方身份与边界类别分开记录。受支持且没有歧义的 MCP 名称和简单网络命令，可以标识预期接收方；无法确定的身份保留为未解析状态。这不能证明实际送达、后续转发，也不能说明子智能体继承了哪些内容。\n\n检测在本机执行；插件不会把提示词、文件或秘密信息发送到远程扫描服务。运行时通信仅使用 Unix 域套接字，以及绑定到 127.0.0.1 的本地浏览器界面。'

RELEASE_SENTENCE_ZH = '0.10.0 为收到真正 SessionStart 的新会话启用基于证据的记账，并继续使用 0.8.0 引入的运行时选择机制和隔离后的账本。已有会话和开始后才接入的会话仍采用旧版记账；历史记录不会被回填或重新计分。'

LIMIT_17 = 'This limitation remains for legacy-accounted sessions and historical rows. Legacy deduplication can merge a later denial into an earlier row with a different outcome. Those records are preserved without reconstruction or rescoring.\n\nNew-accounting sessions append independent observations and finding outcomes. An earlier permission or disclosure does not suppress a later denial, and a later denial does not subtract an earlier charge. The summary counts denials issued by action, including actions with no findings.\n\nA denial issued by Privacy HUD is not confirmation that the host enforced it. Current hooks leave that outcome unresolved.'

LIMIT_18 = 'Legacy-accounted sessions and historical rows can still merge files matching one detector pattern. Version-2 accounting removes that pattern-based merging, but does not identify which filesystem object a shell-read denial concerned.\n\nVersion 0.10.0 adds separate guard-target metadata for newly recorded, keyed version-2 local shell read-guard denials. A random session-scoped target ID and fixed rule ID describe the path representation evaluated by Privacy HUD. "Same evaluated target as event #N" means exact equality of that evaluated representation, including existing home collapse; it does not mean the same filesystem object. The matching HMAC map exists only in daemon memory. SessionEnd discards it, and key loss disables new target correlation for that session. Stored IDs, rule metadata and prior links remain. No candidate path, command, basename or suffix is stored. Execution file subjects and accounting counts are unchanged. Guard-target writes are optional. When an ordinary write failure is contained by its savepoint, the observation and denial evidence still commit, but that row has no guard-target metadata and seeds no new link. Delivery retries do not backfill it. No failure text or extra coverage/scan-gap record is persisted. Failure of the core transaction or its commit remains outside this guarantee.\n\nAll shell-derived accounting file identities remain unresolved, including ordinary `cat .env` reads. Command text does not attest the executable, shell expansion, inherited environment, or program configuration. Separate observations retain separate unresolved file subjects. Equal guard-target IDs establish equal evaluated representations only; different IDs do not establish different filesystem objects. The audit does not recover historical filenames or prove file contents.\n\nThe HUD counts denials issued by action, not confirmed stopped reads. Guard-target metadata neither resolves an accounting subject nor changes unresolved counts, disclosures, charges, denials enforced, or reads stopped. Legacy history, network-file denials, non-shell calls, permitted reads, keyless observations and late observations after SessionEnd receive no new guard-target metadata. Existing supported structured-input parser behavior is unchanged; it is not evidence of a native Codex file-read hook. #44 remains open for filesystem identity and independently recognizable historical filenames.'

README_LIMITS_17_18 = '17. Legacy rows can still collapse different outcomes. New accounting appends independent outcome evidence and counts denials issued by action. Historical rows are not reconstructed, and issued denials do not establish host enforcement.\n\n18. Legacy rows can still merge files matching one pattern. Newly recorded, keyed version-2 local shell read-guard denials carry separate opaque guard-target IDs, fixed rules and same-evaluated-target links. These identify the path representation evaluated by Privacy HUD, not a filesystem object or historical filename. Matching ends with SessionEnd or key loss; existing links remain. Shell execution file identities and host enforcement remain unresolved, and accounting counts are unchanged. #44 remains open for filesystem identity and independently recognizable historical filenames. Guard-target writes are optional. When an ordinary write failure is contained by its savepoint, the observation and denial evidence still commit, but that row has no guard-target metadata and seeds no new link. Delivery retries do not backfill it. No failure text or extra coverage/scan-gap record is persisted. Failure of the core transaction or its commit remains outside this guarantee.'

README_LIMITS_17_18_ZH = '17. 旧版记录仍可能合并不同结果。新版记账会追加独立的结果证据，并按操作统计发出的拒绝。历史记录不会重建，发出拒绝也不能证明宿主执行了拒绝。\n\n18. 旧版记录仍可能合并匹配同一模式的文件。新记录的、仍持有会话密钥的新版本地 shell 读取防护拒绝记录，带有独立的不透明防护目标 ID、固定规则和相同评估目标关联。这些元数据标识的是 Privacy HUD 实际评估的路径表示，不是文件系统对象，也不能还原历史文件名。SessionEnd 或密钥丢失后停止建立新的匹配关联；既有关联仍保留。shell 执行文件身份和宿主是否执行拒绝仍未确认，各项记账统计保持不变。#44 仍保持开放，后续需要解决文件系统身份和可独立辨认的历史文件名问题。防护目标元数据的写入是可选步骤。如果保存点成功隔离了一般写入异常，观察记录和拒绝证据仍会提交，但该行的 guard_target 为 null，也不会成为新关联的起点。重复投递不会补写这些元数据。不保存异常文本，也不额外写入覆盖记录或扫描缺口记录。核心事务或其提交失败不在此保证范围内。'

INSTALL_BLOCK = 'Privacy HUD 0.10.0 retains snapshot version 2. New sessions observed from a genuine SessionStart use version-2 accounting; existing sessions and late attachments retain legacy accounting. Snapshot-v2 readers accept version 1 as explicitly legacy and version 2 with nullable accounting fields. Older snapshot-v1-only readers reject version 2 and show no Privacy item. Matching Codex version numbers do not establish snapshot compatibility.\n\nThe snapshot-v2 patched Codex builds for 0.154.0, 0.155.0, and 0.155.1 were re-released on 2026-09-22. An earlier installation of one of those versions may still contain the older reader. Updating the plugin does not replace that binary. No additional patched-Codex release is required solely for Privacy HUD 0.10.0.\n\nThe native Privacy item displays accounting snapshots; it does not verify runtime alignment. Before repair, an old daemon may continue refreshing a legacy reading. Use the bundled doctor command to check alignment. The bundled ambient launcher reports runtime failure instead of displaying a percentage.\n\nPrivacy HUD loads Python code from the selected plugin bundle. The recorded Python environment supplies dependencies. Run $privacy repair to obtain the exact recovery command for another terminal. Explicit installation may download dependencies and model weights; runtime checks and offline repair do not.\n\nThe active ledger is $PLUGIN_DATA/ledger/active.db after repair. $PLUGIN_DATA/ledger.db is a directory that fences the historical pathname. Do not replace it with a file or symlink. Repair preserves the accounting generation and recorded values; it does not activate version-2 accounting. The selected daemon activates accounting only when it receives a genuine SessionStart for an absent session.\n\nGeneration 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch. Unsupported or altered schemas are preserved and refused. No downgrade migration is provided.\n\nRuntime mismatches produce an unverified warning on ingress and a denial for outbound calls the hook cannot verify. These are plugin decisions, not confirmation of host enforcement. Monitoring gaps and lost in-memory detection state cannot be reconstructed. Open version-2 sessions whose accounting keys were lost remain unavailable for the rest of those sessions.'

INSTALL_BLOCK_ZH = 'Privacy HUD 0.10.0 继续使用 snapshot v2。收到真正 SessionStart 的新会话采用新版记账；已有会话和开始后才接入的会话仍采用旧版记账。支持 v2 的读取器会将 v1 明确标为旧版，并支持 v2 中可为空的记账字段。仅支持 snapshot v1 的旧读取器会拒绝 v2，不显示 Privacy 状态项。Codex 版本号相同并不代表快照兼容。\n\n支持 snapshot v2 的 Codex 0.154.0、0.155.0 和 0.155.1 补丁构建已于 2026-09-22 重新发布。此前安装的同版本二进制文件可能仍包含旧读取器。更新插件不会替换该二进制文件；仅发布 Privacy HUD 0.10.0 不需要再次发布 Codex 补丁构建。\n\n原生 Privacy 状态项只显示记账快照，不验证运行时是否一致。修复之前，旧守护进程可能仍在刷新旧版读数。请使用插件内置启动器的 doctor 命令检查一致性。独立 ambient 启动器在运行时检查失败时显示错误，不显示百分比。\n\nPrivacy HUD 从所选插件包加载 Python 代码，已记录的 Python 环境只提供依赖。运行 $privacy repair 可获取在另一个终端执行的完整修复命令。显式安装可能下载依赖和模型权重；运行时检查和离线修复不会下载。\n\n修复后的当前账本位于 $PLUGIN_DATA/ledger/active.db。$PLUGIN_DATA/ledger.db 是用于隔离旧路径的目录，请勿将其替换为文件或符号链接。修复保留账本代次和已记录的值，不启用新版记账。只有所选守护进程收到尚无记录会话的真正 SessionStart 时，才会启用新版记账。\n\n账本代次 5402 需要 Privacy HUD 0.9.0 引入的已启用记账实现。运行中的客户端还必须与所选运行时构建及激活纪元一致。结构不受支持或被改动的账本会被保留并拒绝使用。本项目不提供降级迁移。\n\n运行时不匹配时，入站事件继续执行并显示未经验证的提示；对于 hook 无法验证的出站调用，插件会返回拒绝决定。这些决定不能证明宿主实际执行了干预。监测空档和丢失的内存检测状态无法恢复。尚未结束的新版会话如果丢失记账密钥，其记账会在该会话余下时间保持不可用。'

COMMANDS = 'PRIVACY_HUD_BUNDLE=\'/absolute/path/to/installed/0.10.0/plugin\'\nPRIVACY_HUD_DATA=\'/absolute/path/to/plugin/data\'\n\npython3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \\\n  --plugin-data "$PRIVACY_HUD_DATA" doctor\n\npython3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \\\n  --plugin-data "$PRIVACY_HUD_DATA" repair --print-command\n\npython3 "$PRIVACY_HUD_BUNDLE/scripts/runtime.py" \\\n  --plugin-data "$PRIVACY_HUD_DATA" ambient --watch'

GENERATIONS = '- 0: legacy storage.\n- 5401: prepared storage. Legacy sessions retain their accounting;\n  the private synthetic constructor exercises V2 without activation.\n- 5402: activated storage. Genuine starts for absent sessions use V2;\n  existing sessions and late attachments retain their own accounting.\n  Generation 5402 requires the activated-accounting implementation\n  introduced in Privacy HUD 0.9.0. A live client must also match the\n  selected runtime build and activation epoch.'

OWNERSHIP_PROSE = "Readers open existing ledgers read-only, without initialization, migration, or activation. Browser and MCP policy actions use the matching daemon's policy RPC. The daemon remains the sole production ledger writer."

CHANGELOG_090 = "## 0.9.0\n\n- Activate evidence-based accounting only for new sessions observed from a genuine SessionStart. Existing sessions and late attachments retain legacy accounting.\n- Record delivered observations, finding outcomes, intended recipient identities, and first charged disclosures separately. Preserve historical rows and scores without backfill or rescoring.\n- Distinguish issued denials and rewrites from confirmed host enforcement. Current hooks do not confirm crossing or enforcement; unresolved evidence withholds the percentage.\n- Integrate version-2 accounting with the HUD, ambient pane, audit, event detail, session receipt, local browser, and MCP presentation.\n- Discard session accounting keys at end and make open-session accounting unavailable after key loss. Identity-hash erasure retains opaque IDs and accounting joins.\n- Activate generation 5402 under the selected daemon's writer lease. Preserve receipt v2, socket protocol 2, the activation epoch contract, read-only readers, daemon policy RPC, and the fenced ledger layout.\n- Support generation-preserving repair of activated ledgers while retaining verified daemon stop and quiescence checks.\n- Narrow known limit 17: #43 is addressed for new version-2 sessions only; legacy sessions and historical rows retain their limitations. Narrow known limit 18 to record pattern-merging and action-counting improvements, while #44 remains open for supported guard-target identity and I1-safe audit display. All shell-derived accounting file identities remain unresolved, including ordinary `cat .env` reads; opaque subject IDs do not identify distinct files. 0.10.0 is a proposed target for the remaining #44 work, not a release commitment.\n- Retain snapshot version 2 and compatibility with the published snapshot-v2 patched Codex builds. No downgrade migration is provided.\n\nGeneration 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch.\n\nRefs #54, #43, #44, #47."

SKILL_DESCRIPTION = 'Open the Privacy HUD session audit — inspect confirmed disclosure evidence, issued interventions, unresolved actions, and separately labelled legacy accounting for the selected session.'

SKILL_SUMMARY = "The summary distinguishes new accounting, legacy accounting, and an\nunrecorded session. New accounting shows confirmed points, distinct\ndisclosures and recipients, issued interventions, and unresolved actions.\nIts percentage is unavailable when the required evidence is incomplete.\nZero confirmed points with unresolved actions does not mean no disclosure\noccurred. Legacy accounting retains its explicit legacy labels. An\nunrecorded session has no numeric score or counts. Print the renderer's\naccounting note and unavailable reasons; never substitute zero."

SKILL_SESSION = 'An argument after $privacy is a session ID. It is not a flow or event ID.'

SKILL_DETAIL = "If the user asks for an event from the selected session, use that row's id\nas EVENT_ID in the detail command. $privacy <id> alone selects a session;\nit does not select an event."

SKILL_SETUP = 'Privacy HUD 0.10.0 writes snapshot version 2. The native Privacy item requires\na patched Codex build containing the snapshot-v2 reader. Matching Codex\nversions and successful plugin installation do not establish that\ncompatibility. Until the installed build is verified, run the bundled\nambient launcher in a separate terminal pane.'

SKILL_AMBIENT = 'python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \\\n  ambient --watch'

ANALOGY = 'Privacy HUD:  What is confirmed, and what remains unresolved?'

ANALOGY_ZH = 'Privacy HUD：哪些事实已确认，哪些结果仍未确定？'

WHAT_YOU_SEE = 'For a new session whose outcomes remain unresolved:\n\nPrivacy —% · 3 unresolved · 2 denials issued\n\nThe native Privacy item is available only in a snapshot-v2-compatible patched Codex build. The ambient pane provides the fallback.\n\nThe audit shows confirmed points, distinct disclosures, confirmed recipients, and denials issued. It also shows unresolved actions and why a percentage is unavailable. The compact HUD omits points; open $privacy for the full accounting explanation.\n\nTabs are Confirmed crossings, Interventions, and All finding events. Rows describe evidence at one observation point. Repeated exposure events can share one charged disclosure. Actions without findings are included in the summary.\n\nDetail shows the subject, intended or evidenced recipient, outcome evidence, occurrences, and contribution charged at that event. Opaque file labels distinguish subject records without storing sensitive path components. For shell reads, these records have unresolved file identities: different IDs do not prove different files, and repeated observations of one path can receive different IDs. The audit shows `local file` and `file <opaque-id>`, without the filename or a suffix. These labels cannot be used as source-rule selectors.\n\nVersion 0.10.0 adds separate guard-target metadata for newly recorded, keyed version-2 local shell read-guard denials. A random session-scoped target ID and fixed rule ID describe the path representation evaluated by Privacy HUD. "Same evaluated target as event #N" means exact equality of that evaluated representation, including existing home collapse; it does not mean the same filesystem object. The matching HMAC map exists only in daemon memory. SessionEnd discards it, and key loss disables new target correlation for that session. Stored IDs, rule metadata and prior links remain. No candidate path, command, basename or suffix is stored. Execution file subjects and accounting counts are unchanged. Guard-target writes are optional. When an ordinary write failure is contained by its savepoint, the observation and denial evidence still commit, but that row has no guard-target metadata and seeds no new link. Delivery retries do not backfill it. No failure text or extra coverage/scan-gap record is persisted. Failure of the core transaction or its commit remains outside this guarantee.\n\nLegacy sessions retain their explicit legacy labels and tab meanings. Unrecorded sessions have no numeric accounting.'

WHAT_YOU_SEE_ZH = '对于操作结果尚未确定的新会话，HUD 可能显示：\n\nPrivacy —% · 3 unresolved · 2 denials issued\n\n原生 Privacy 状态项只在支持 snapshot v2 的 Codex 补丁版构建中提供；独立的 ambient 窗格可作为替代。\n\n审计页显示已确认披露分数、不同披露数、已确认接收方数和发出的拒绝次数，并说明结果尚未确定的操作以及百分比不可用的原因。紧凑 HUD 不显示分数；运行 $privacy 可查看完整说明。\n\n三个标签页分别是 Confirmed crossings、Interventions 和 All finding events。每行描述一个观察时点的证据。多次确认的跨越可以对应同一个已计分披露；没有检测结果的操作仍计入摘要。\n\n详情显示主体、预期或有送达证据的接收方、结果证据、匹配次数，以及该行新增的分数。不透明文件标签用于区分主体记录，避免保存敏感路径片段。对于 shell 读取，文件身份始终未解析：不同 ID 不能证明是不同文件，对同一路径的多次观察也可能得到不同 ID。审计中显示 `local file` 和 `file <opaque-id>`，不显示文件名或后缀。这些标签不能用作来源规则的选择条件。\n\n0.10.0 为新记录的、仍持有会话密钥的新版本地 shell 读取防护拒绝记录，增加独立的防护目标元数据。随机生成的会话内目标 ID 和固定规则 ID 描述的是 Privacy HUD 实际评估的路径表示。“Same evaluated target as event #N”表示评估后的路径表示完全相同，包括现有的主目录折叠处理；这不表示它们是同一个文件系统对象。用于匹配的 HMAC 映射只存在于守护进程内存中。SessionEnd 会丢弃该映射；会话密钥丢失后，该会话不再建立新的目标关联。已保存的 ID、规则元数据和既有关联仍会保留。不保存候选路径、命令、文件名或后缀。执行文件主体及各项记账统计保持不变。防护目标元数据的写入是可选步骤。如果保存点成功隔离了一般写入异常，观察记录和拒绝证据仍会提交，但该行的 guard_target 为 null，也不会成为新关联的起点。重复投递不会补写这些元数据。不保存异常文本，也不额外写入覆盖记录或扫描缺口记录。核心事务或其提交失败不在此保证范围内。\n\n旧版会话继续使用显式旧版标签和原有标签页含义。没有会话记录时，不显示数字统计。'

EVIDENCE_TABLE = '| Observation | V2 accounting |\n|---|---|\n| Local scanner finding | Detection; zero points |\n| Permission to attempt a crossing | Permission; zero points |\n| Privacy HUD issues a denial | Denial issued; zero points |\n| Privacy HUD returns rewritten input | Rewrite issued; zero points; application unresolved |\n| Evidence identifies a subject crossing to a concrete recipient | First distinct disclosure is charged |\n| Evidence identifies a subject excluded by an applied rewrite | Prevention for that subject; zero points |\n| Observed persistence | Retention; zero points |\n| Supported explicit delegation pre-hook | B2 observation; finding recipients unresolved; no confirmed disclosure charge |'

EVIDENCE_TABLE_ZH = '| 观察到的事实 | 新版记账 |\n|---|---|\n| 本地扫描发现敏感内容 | 检测记录；零分 |\n| 允许尝试跨越边界 | 允许记录；零分 |\n| Privacy HUD 发出拒绝 | 已发出拒绝；零分 |\n| Privacy HUD 返回改写后的输入 | 已发出改写；零分；是否应用仍未确认 |\n| 证据确认某个主体跨越边界并到达具体接收方 | 首次不同披露计分 |\n| 证据确认宿主应用改写，且某个主体未包含在发送内容中 | 仅该主体记为已防止；零分 |\n| 观察到持久化 | 留存记录；零分 |\n| 受支持的显式委派执行前 hook | B2 观测；检测结果的接收方身份未解析；不增加已确认披露分数 |'

EVIDENCE_FOLLOW = 'The audit contains finding events with explicit outcome evidence. Observations also record actions with no findings. Disclosure identities and charges are separate from event rows. Source-to-recipient associations do not reconstruct causal multi-hop flows.'

EVIDENCE_FOLLOW_ZH = '审计页展示带有明确结果证据的检测事件；观察记录也包括没有检测结果的操作。披露身份和计分与事件行分开保存。来源与接收方的关联不能还原因果上的多跳传播链。'

READ_GUARD = 'The guard remains limited to recognized shell reads and is off by default. Template-file exemptions remain. All shell-derived accounting file identities remain unresolved, including ordinary `cat .env` reads. Separate observations retain separate unresolved file subjects; they do not establish which files were read. The extracted path remains available to the guard and its immediate denial message, but the audit does not name that file. A denial request is not proof that the host stopped the read.\n\nVersion 0.10.0 adds separate guard-target metadata for newly recorded, keyed version-2 local shell read-guard denials. A random session-scoped target ID and fixed rule ID describe the path representation evaluated by Privacy HUD. "Same evaluated target as event #N" means exact equality of that evaluated representation, including existing home collapse; it does not mean the same filesystem object. The matching HMAC map exists only in daemon memory. SessionEnd discards it, and key loss disables new target correlation for that session. Stored IDs, rule metadata and prior links remain. No candidate path, command, basename or suffix is stored. Execution file subjects and accounting counts are unchanged. Guard-target writes are optional. When an ordinary write failure is contained by its savepoint, the observation and denial evidence still commit, but that row has no guard-target metadata and seeds no new link. Delivery retries do not backfill it. No failure text or extra coverage/scan-gap record is persisted. Failure of the core transaction or its commit remains outside this guarantee.'

READ_GUARD_ZH = '读取防护仍只处理能够识别的 shell 读取，默认关闭，并继续豁免模板文件。所有从 shell 命令推断的记账文件身份均保持未解析，包括普通的 `cat .env` 读取。不同观察保留各自未解析的文件主体，但这不能证明实际读取了哪些文件。提取出的路径仍用于防护判断和即时拒绝消息，审计记录却不显示该文件名。发出拒绝请求不能证明宿主已经停止读取。\n\n0.10.0 为新记录的、仍持有会话密钥的新版本地 shell 读取防护拒绝记录，增加独立的防护目标元数据。随机生成的会话内目标 ID 和固定规则 ID 描述的是 Privacy HUD 实际评估的路径表示。“Same evaluated target as event #N”表示评估后的路径表示完全相同，包括现有的主目录折叠处理；这不表示它们是同一个文件系统对象。用于匹配的 HMAC 映射只存在于守护进程内存中。SessionEnd 会丢弃该映射；会话密钥丢失后，该会话不再建立新的目标关联。已保存的 ID、规则元数据和既有关联仍会保留。不保存候选路径、命令、文件名或后缀。执行文件主体及各项记账统计保持不变。防护目标元数据的写入是可选步骤。如果保存点成功隔离了一般写入异常，观察记录和拒绝证据仍会提交，但该行的 guard_target 为 null，也不会成为新关联的起点。重复投递不会补写这些元数据。不保存异常文本，也不额外写入覆盖记录或扫描缺口记录。核心事务或其提交失败不在此保证范围内。'

COMPLETENESS = "The ledger records delivered local hooks; it does not reconstruct the model's complete context. Missing hooks, hosted tools, discarded results, and unconfirmed host outcomes remain outside what those observations establish. Accounting keeps that uncertainty explicit instead of charging an assumed crossing."

COMPLETENESS_ZH = '账本记录实际收到的本地 hook，不会还原模型的完整上下文。缺失的 hook、托管工具、被丢弃的结果，以及尚未确认的宿主处理结果，都超出了这些观察能够证明的范围。记账会明确保留这种不确定性，而不是假定发生跨越后计分。'

PRIVACY_BULLET_1 = 'New accounting stores allowlisted metadata, opaque identities, and masked examples. Column names alone do not make arbitrary labels safe.'

PRIVACY_BULLET_2 = 'At session end, new-accounting identity hashes are nulled and the matching in-memory key is discarded. Opaque IDs and accounting joins remain. This is logical erasure, not secure overwriting of SQLite pages, WAL files, backups, swap, or Python memory; other metadata can still correlate records.'

PRIVACY_BULLET_1_ZH = '新版记账只保存经过允许列表限制的元数据、不透明身份和遮盖后的示例。仅仅没有内容字段，并不能保证任意标签都是安全的。'

PRIVACY_BULLET_2_ZH = '会话结束时，新版记账的身份哈希会被置空，对应的内存密钥也会被丢弃；不透明 ID 和记账关联仍保留。这是逻辑擦除，不是对 SQLite 页面、WAL 文件、备份、交换空间或 Python 内存的安全覆写；其他元数据仍可能关联记录。'

LIMIT_20 = 'Legacy accounting groups destinations by boundary category.\n\nNew accounting separates boundary category from recipient identity. Supported, unambiguous MCP namespaces identify intended server configurations; multiple tools in one namespace share a recipient. A narrow parser identifies the intended endpoint of supported simple network commands. Ambiguous names, unsupported command forms, dynamic destinations, and unknown recipients remain unresolved.\n\nExplicit delegation observations use the B2 subagent category, but their intended recipient identities remain unresolved, including when a target argument is present. This release does not correlate those identities with spawn results or lifecycle events. Intended identity does not prove transmission, backend identity, downstream forwarding, subagent inheritance, or continuity across unobserved configuration changes. Current hooks do not supply the crossing receipts needed to turn those intentions into confirmed disclosures.'

LIMIT_21_PARAGRAPH = "Legacy scan gaps remain session-level records without an event link. New accounting also records the gap on its observation, including observations with no findings; finding-event detail carries that observation's gap reason. A gap does not establish whether a particular value crossed a boundary."

LEDGER_DOCSTRING = '"""Versioned session accounting and legacy ledger access.\n\nNew sessions observed from a genuine SessionStart use version-2 accounting.\nExisting sessions and late attachments retain legacy accounting.\n\nObservations, finding events and first disclosures are separate records.\nOnly a new chargeable disclosure increases a version-2 score. Profiles\nand session caps are frozen; historical records are not rescored.\n\nIdentity inputs are hashed before persistence. Persisted metadata uses\nexplicit allowlists and opaque labels. SessionEnd erases matching hashes\nwhile retaining opaque identities and accounting joins. Key destruction\nbelongs to daemon lifecycle handling; this is logical erasure, not a\nsecure-deletion guarantee.\n\nReaders never initialize, migrate or activate a ledger.\n"""'

FLOOR = 'Generation 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch.'

README_LIMIT_20 = '20. Concrete recipients are identified only where the hook and supported parser provide an unambiguous identity. Other recipients remain unresolved. Identity alone does not establish delivery or forwarding.'

README_LIMIT_20_ZH = '20. 只有 hook 和受支持的解析器提供明确身份时，才区分具体接收方。其他接收方保留为未解析状态。知道身份本身不能证明数据已送达或继续转发。'

def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _flowed(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _has(relative: str, text: str) -> bool:
    return _flowed(text) in _flowed(_read(relative))


def _paragraphs(text: str) -> list[str]:
    return [p for p in text.split("\n\n") if p.strip()]


# --------------------------------------------------------------------- #
# versions
# --------------------------------------------------------------------- #

def test_phase4_versions_match_the_current_release():
    plugin = json.loads(_read(".codex-plugin/plugin.json"))
    marketplace = json.loads(_read(".agents/plugins/marketplace.json"))
    project = tomllib.loads(_read("pyproject.toml"))
    assert plugin["version"] == RELEASE
    assert [p["version"] for p in marketplace["plugins"]
            if p["name"] == plugin["name"]] == [RELEASE]
    assert project["project"]["version"] == RELEASE
    assert contract.RELEASE == RELEASE
    assert json.loads(_read(contract.MANIFEST_NAME))["release"] == RELEASE


def test_phase4_wire_and_matrix_versions_remain_unchanged():
    """Regression gate: nothing on the wire, in the schema generations or
    in the scoring inputs moves with the release."""
    assert ledger_schema.PREPARED_VERSION == 5401
    assert ledger_schema.ACTIVATED_VERSION == 5402
    assert hud_snapshot.SNAPSHOT_VERSION == 2
    assert hud_snapshot.DAEMON_MARKER_VERSION == 1
    assert contract.PROTOCOL_VERSION == 2
    assert contract.RECEIPT_VERSION == 2
    assert contract.STORAGE_GENERATION == 1
    assert contract.MANIFEST_FORMAT == 1
    assert contract.READABLE_SCHEMAS == contract.WRITABLE_SCHEMAS == \
        (0, 5401, 5402)
    matrix = load_matrix()
    assert matrix.version == "1"
    assert matrix.budget_cap == 120.0


# --------------------------------------------------------------------- #
# the documents
# --------------------------------------------------------------------- #

def test_phase4_contract_blocks_match_verbatim():
    for relative in CONTRACT_DOCS:
        text = _read(relative)
        assert text.count(CONTRACT_BLOCK) == 1, relative
        lines = text.split("\n")
        assert lines[0].startswith("# Codex Privacy HUD"), relative
        assert lines[2].startswith("**Status:**"), relative
        assert lines[4] == CONTRACT_BLOCK.split("\n")[0], relative
        assert "Current contract — #54 Phase 3" not in text, relative
    assert _read(".claude/docs/design.md").split(CONTRACT_BLOCK, 1)[1] \
        .lstrip("\n").startswith("This document covers product and "
                                 "interaction design")
    assert _has(".claude/docs/architecture.md", OWNERSHIP_PROSE)


def test_phase4_readme_introductions_match_verbatim():
    english, chinese = _read("README.md"), _read("README.zh-CN.md")
    for paragraph in _paragraphs(README_INTRO) + [RELEASE_SENTENCE,
                                                   ANALOGY]:
        assert english.count(paragraph) == 1, paragraph[:60]
    for paragraph in _paragraphs(README_ZH_INTRO) + [RELEASE_SENTENCE_ZH,
                                                      ANALOGY_ZH]:
        assert chinese.count(paragraph) == 1, paragraph[:30]
    assert "Version 0.8.1 includes the new accounting core" not in english
    assert "0.8.1 已包含新的记账核心" not in chinese
    assert "What does this session's legacy accounting record?" \
        not in english + chinese


def test_phase4_copy_catalog_matches_verbatim():
    skill = _read("skills/privacy/SKILL.md")
    assert f"\ndescription: {SKILL_DESCRIPTION}\n" in skill
    for text in (SKILL_SUMMARY, SKILL_SESSION, SKILL_DETAIL, SKILL_SETUP,
                 SKILL_AMBIENT):
        assert _flowed(text) in _flowed(skill), text[:60]
    for text in (WHAT_YOU_SEE, EVIDENCE_TABLE, EVIDENCE_FOLLOW, READ_GUARD,
                 COMPLETENESS, PRIVACY_BULLET_1, PRIVACY_BULLET_2):
        assert _has("README.md", text), text[:60]
    for text in (WHAT_YOU_SEE_ZH, EVIDENCE_TABLE_ZH, EVIDENCE_FOLLOW_ZH,
                 READ_GUARD_ZH, COMPLETENESS_ZH, PRIVACY_BULLET_1_ZH,
                 PRIVACY_BULLET_2_ZH):
        assert _has("README.zh-CN.md", text), text[:30]
    assert "The schema *is* the guarantee." not in _read("README.md")
    assert "cross-session correlation is impossible by construction" \
        not in _read("README.md")
    doc = _read("src/privacy_hud/ledger.py")
    assert doc.startswith(LEDGER_DOCSTRING + "\n")
    assert _flowed(GENERATIONS) in _flowed(
        _read("src/privacy_hud/ledger_schema.py"))


def test_phase4_limits_preserve_anchors_and_legacy_caveats():
    limits = _read("docs/known-limits.md")
    headings = re.findall(r"^## (\d+)\. (.*)$", limits, re.M)
    assert [n for n, _ in headings] == [str(i) for i in range(1, 23)]
    assert dict(headings)["17"] == ("A blocked read can leave a record that "
                                    "says the opposite, in one sequence.")
    assert dict(headings)["18"] == "A blocked read's row does not name the file."
    assert dict(headings)["20"] == ("A destination is a boundary category, "
                                    "not a recipient.")

    def body(number: int) -> str:
        return limits.split(f"\n## {number}. ", 1)[1].split("\n## ", 1)[0]

    assert _flowed(body(17)).endswith(_flowed(LIMIT_17))
    assert _flowed(body(18)).endswith(_flowed(LIMIT_18))
    assert _flowed(body(20)).endswith(_flowed(LIMIT_20))
    assert _flowed(LIMIT_21_PARAGRAPH) in _flowed(body(21))
    assert "Phase 1 does not separate the file subjects" not in limits

    readme, chinese = _read("README.md"), _read("README.zh-CN.md")
    anchors = {17: "#17-a-blocked-read-can-leave-a-record-that-says-the-"
                   "opposite-in-one-sequence",
               18: "#18-a-blocked-reads-row-does-not-name-the-file",
               20: "#20-a-destination-is-a-boundary-category-not-a-recipient"}
    shorts = dict(zip((17, 18), _paragraphs(README_LIMITS_17_18),
                      strict=True))
    shorts[20] = README_LIMIT_20
    shorts_zh = dict(zip((17, 18), _paragraphs(README_LIMITS_17_18_ZH),
                         strict=True))
    shorts_zh[20] = README_LIMIT_20_ZH
    for number, anchor in anchors.items():
        for text, items in ((readme, shorts), (chinese, shorts_zh)):
            line = [ln for ln in text.splitlines()
                    if ln.startswith(f"{number}. ")]
            assert len(line) == 1, number
            assert line[0].startswith(items[number]), number
            assert anchor in line[0], number


def test_phase4_install_notes_name_available_v2_builds():
    for relative in INSTALL_DOCS:
        for paragraph in _paragraphs(INSTALL_BLOCK):
            assert _has(relative, paragraph), (relative, paragraph[:60])
        text = _read(relative)
        assert "Production sessions still use legacy accounting" not in text
        assert "Privacy HUD 0.8.2 retains" not in text
    for paragraph in _paragraphs(INSTALL_BLOCK_ZH):
        assert _has("README.zh-CN.md", paragraph), paragraph[:30]
    spec = _read(INSTALL_DOCS[3])
    assert "Privacy HUD 0.7.8 writes snapshot version 2" not in spec
    assert "Compatible release artifacts have not yet been published" \
        not in spec


def test_phase4_does_not_claim_unbuilt_consent_or_export():
    readme = _flowed(_read("README.md"))
    for sentence in (
            "No shipped surface offers `Allow once`, `Minimize & retry`, a "
            "minimization preview or a consent-token-driven tool retry.",
            "it does not save a Markdown receipt file",
            "It is not an event or flow deep link."):
        assert _flowed(sentence) in readme, sentence
    # The skill names these words only to forbid them (§E allows that).
    for relative in ("README.md", "README.zh-CN.md"):
        # #66's hazard paragraph says what the fence cannot do to other
        # processes' connections; it is not a claim about disclosed data.
        text = _read(relative).replace(
            "does not revoke already-open connections", "").lower()
        for phrase in ("undo", "revoke", "remove from context",
                       "your data is protected", "100% secure"):
            assert phrase not in text, (relative, phrase)


def test_phase4_preserves_issue72_action_contracts():
    """#72's reconciled routes and qualifications survive, and the Phase 4
    session-selection and detail wording joins them rather than replacing
    them."""
    skill = _flowed(_read("skills/privacy/SKILL.md"))
    for text in (
            "`$privacy repair` prints the recovery command for another "
            "terminal.",
            "It is not an event or flow deep link.",
            "The detail command requires both identifiers.",
            SKILL_SESSION, SKILL_DETAIL):
        assert _flowed(text) in skill, text[:60]
    readme = _flowed(_read("README.md"))
    for text in (
            "`$privacy <session_id>` selects a session audit. It is not an "
            "event or flow deep link.",
            "The local audit browser has buttons that POST to "
            "`/api/policy`"):
        assert _flowed(text) in readme, text[:60]


def test_phase4_user_actions_have_executable_routes():
    """Every command the new copy tells a user or agent to run exists."""
    import argparse
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bundled_runtime", REPO / "scripts" / "runtime.py")
    assert spec is not None
    source = (REPO / "scripts" / "runtime.py").read_text(encoding="utf-8")
    commands = re.findall(r"--plugin-data \"[^\"]+\"\s+(?:\\\s+)?([a-z]+)",
                          COMMANDS + "\n" + SKILL_AMBIENT)
    assert sorted(set(commands)) == ["ambient", "doctor", "repair"]
    for command in commands:
        assert f'sub.add_parser("{command}")' in source or \
            f'{command} = sub.add_parser("{command}")' in source, command
    assert "repair --print-command" in COMMANDS
    assert "--print-command" in source
    from privacy_hud import local_ui_server
    assert "/api/policy" in Path(local_ui_server.__file__).read_text(
        encoding="utf-8")
    assert argparse  # the launcher's own parser is argparse-built


def test_phase4_generation_floor_is_exact():
    for relative in (*CONTRACT_DOCS, *INSTALL_DOCS, "CHANGELOG.md",
                     "src/privacy_hud/runtime_contract.py",
                     "src/privacy_hud/ledger_schema.py"):
        flowed = _flowed(_read(relative).replace("#: ", "").replace(
            "#:\n", ""))
        assert _flowed(FLOOR) in flowed, relative
    assert _has("README.zh-CN.md", "账本代次 5402 需要 Privacy HUD 0.9.0 "
                                   "引入的已启用记账实现。")
    for relative in (*CONTRACT_DOCS, *INSTALL_DOCS, "README.zh-CN.md",
                     "CHANGELOG.md", "skills/privacy/SKILL.md"):
        text = _read(relative)
        for stale in ("0.8.0 or newer", "0.9.0 or newer",
                      "Daemons older than 0.8.0",
                      "A daemon of this version refuses it"):
            assert stale not in text, (relative, stale)


def test_phase4_commands_use_selected_bundle_launcher():
    for relative in ("README.md", "docs/installing-by-hand.md"):
        assert _has(relative, COMMANDS), relative
    skill = _read("skills/privacy/SKILL.md")
    assert SKILL_AMBIENT in skill
    assert "bin/privacy-hud-ambient --watch" not in skill
    assert "/absolute/path/to/installed/0.8.2/plugin" not in \
        _read("README.md")


def test_phase4_changelog_preserves_prior_releases():
    text = _read("CHANGELOG.md")
    historical = CHANGELOG_090 + "\n\n"
    assert text.count(historical) == 1
    rest = text.split(historical, 1)[1]
    assert rest.startswith("## 0.8.3\n")
    assert hashlib.sha256(rest.encode()).hexdigest() == PRIOR_CHANGELOG_SHA256
    assert not re.search(
        r"\b(close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved) #\d+",
        CHANGELOG_090, re.I,
    )
