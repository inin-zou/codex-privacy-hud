import { useMemo, useState } from 'react'
import { Icon } from '../components/Icon'
import { Toggle } from '../components/ui'
import { BRAND } from '../data/mock'
import type { Rule } from '../data/types'
import { fmtDate } from '../lib/format'
import { dataLabel, parseRule, targetLabel } from '../store/engine'
import { useStore } from '../store/store'

const SUGGESTIONS = [
  'Never share my health data with social apps',
  'Ask me before Codex shares anything financial',
  'Allow Notion to use my work profile',
  'Block my home address for shopping apps',
]

const AGENT_SUGGESTIONS: { text: string; why: string; rule: Omit<Rule, 'id' | 'createdAt' | 'enabled' | 'createdBy'> }[] = [
  {
    text: 'Ask before sharing identity documents with any app',
    why: 'Airbnb received your passport number under the general travel rule on 29 Aug.',
    rule: { effect: 'ask', data: ['identity'], target: { type: 'category', id: 'travel' }, note: `Suggested by the ${BRAND} agent after a passport share.` },
  },
  {
    text: 'Never share location with social apps',
    why: 'LinkedIn and Instagram both declare Location, and no rule covers it yet.',
    rule: { effect: 'deny', data: ['location'], target: { type: 'category', id: 'social' }, note: `Suggested by the ${BRAND} agent.` },
  },
]

export default function Rules() {
  const { rules, dispatch, addRule } = useStore()
  const [text, setText] = useState('')
  const parsed = useMemo(() => parseRule(text), [text])

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">Rules</h1>
          <p>Write what you want in plain language. {BRAND} turns it into a policy that runs locally, before any request leaves your machine. More specific rules win: app over agent over category over everything.</p>
        </div>
      </div>

      <div className="composer">
        <div className="row" style={{ gap: 8, marginBottom: 10 }} >
          <Icon name="sparkle" size={15} className="muted" />
          <span className="eyebrow">New rule</span>
        </div>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Never share my health data with social apps…"
          rows={2}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey && parsed) { e.preventDefault(); addRule(parsed); setText('') } }}
        />
        <div className="between" style={{ marginTop: 12, alignItems: 'flex-end', gap: 20 }}>
          <div className="grow">
            {parsed ? (
              <div className="preview-rule row" style={{ gap: 12 }}>
                <span className={`effect ${parsed.effect}`}>{parsed.effect}</span>
                <Sentence effect={parsed.effect} data={parsed.data} target={parsed.target} />
              </div>
            ) : text.length > 0 ? (
              <div className="muted" style={{ fontSize: 13.5 }}>Mention what data (address, card, health, repos…) and optionally which app, category or agent.</div>
            ) : (
              <div className="chips">
                {SUGGESTIONS.map(s => <button key={s} className="chip" onClick={() => setText(s)}>{s}</button>)}
              </div>
            )}
          </div>
          <button className="btn" disabled={!parsed} onClick={() => { if (parsed) { addRule(parsed); setText('') } }}>Add rule <span className="kbd" style={{ background: 'rgba(255,255,255,.15)', borderColor: 'transparent', color: '#fff' }}>↵</span></button>
        </div>
      </div>

      <div className="two" style={{ gridTemplateColumns: '1fr 320px' }}>
        <div className="stack">
          <div className="between"><div className="h-sec">Your rules <span className="muted" style={{ fontWeight: 400 }}>· {rules.length}</span></div><span className="muted" style={{ fontSize: 12.5 }}>Evaluated top to bottom by specificity</span></div>
          {rules.map(r => (
            <div className={`rule-card ${r.enabled ? '' : 'off'}`} key={r.id}>
              <span className={`effect ${r.effect}`}>{r.effect}</span>
              <div className="grow">
                <Sentence effect={r.effect} data={r.data} target={r.target} />
                {r.note && <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>{r.note}</div>}
                <div className="row muted" style={{ fontSize: 12, marginTop: 8, gap: 10 }}>
                  <span className="mono">{r.id}</span>
                  <span>·</span>
                  <span className="row" style={{ gap: 5 }}>{r.createdBy === 'agent' ? <><Icon name="sparkle" size={12} />Suggested by the agent</> : <><Icon name="user" size={12} />You</>}</span>
                  <span>·</span>
                  <span>{fmtDate(r.createdAt)}</span>
                  {r.id === 'r-01' && <><span>·</span><span className="row" style={{ gap: 4, color: 'var(--red)' }}><Icon name="lock" size={12} />Always enforced</span></>}
                </div>
              </div>
              <div className="row" style={{ gap: 12 }}>
                <Toggle on={r.enabled} onChange={() => dispatch({ type: 'toggleRule', id: r.id })} />
                <button className="muted" onClick={() => dispatch({ type: 'deleteRule', id: r.id })} aria-label="Delete" disabled={r.id === 'r-01'} style={{ opacity: r.id === 'r-01' ? .3 : 1 }}><Icon name="trash" size={16} /></button>
              </div>
            </div>
          ))}
        </div>

        <div className="stack">
          <div className="h-sec">Suggested by the agent</div>
          {AGENT_SUGGESTIONS.map(s => (
            <div className="card pad" key={s.text} style={{ background: 'var(--bg-2)', border: 0 }}>
              <div className="row" style={{ gap: 8, color: 'var(--ink-3)', fontSize: 12, fontWeight: 600, letterSpacing: '.04em', textTransform: 'uppercase' }}><Icon name="sparkle" size={13} />Suggestion</div>
              <div style={{ fontWeight: 500, marginTop: 8, letterSpacing: '-0.01em' }}>{s.text}</div>
              <div className="sub" style={{ fontSize: 13.5, marginTop: 6 }}>{s.why}</div>
              <button className="btn sm" style={{ marginTop: 12 }} onClick={() => addRule(s.rule, 'agent')}><Icon name="plus" size={13} />Add rule</button>
            </div>
          ))}
          <div className="card pad">
            <div className="h-sec" style={{ fontSize: 14 }}>How rules resolve</div>
            <ol className="sub" style={{ fontSize: 13.5, paddingLeft: 18, margin: '8px 0 0', lineHeight: 1.6 }}>
              <li>Secrets are blocked on every local tool call.</li>
              <li>Most specific target wins: app › agent › category › everything.</li>
              <li>On a tie, the stricter effect wins: never › ask › share.</li>
              <li>No rule? You get asked.</li>
              <li>Data outside an app's declared scopes is flagged as scope creep.</li>
            </ol>
          </div>
        </div>
      </div>
    </>
  )
}

function Sentence({ effect, data, target }: Pick<Rule, 'effect' | 'data' | 'target'>) {
  const verb = { allow: 'Share', ask: 'Ask before sharing', deny: 'Never share' }[effect]
  return <div className="rule-sentence">{verb} <b>{dataLabel(data)}</b> with <b>{targetLabel(target)}</b></div>
}
