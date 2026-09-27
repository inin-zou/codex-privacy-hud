import { useState } from 'react'
import { Icon } from '../components/Icon'
import { AgentBadge, AppAvatar, CategoryTag, DecisionBadge } from '../components/ui'
import { DATA } from '../data/mock'
import { AGENTS, type AgentId, type Decision } from '../data/types'
import { fmtDate, fmtTime } from '../lib/format'
import { useStore } from '../store/store'

type DF = 'all' | Decision
const FILTERS: { id: DF; label: string }[] = [
  { id: 'all', label: 'All' }, { id: 'allowed', label: 'Allowed' }, { id: 'pending', label: 'Pending' }, { id: 'asked', label: 'Asked' }, { id: 'denied', label: 'Denied' }, { id: 'blocked', label: 'Blocked' },
]

export default function Activity() {
  const { events, apps, simulate } = useStore()
  const [f, setF] = useState<DF>('all')
  const [agent, setAgent] = useState<AgentId | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const shown = events.filter(e => (f === 'all' || e.decision === f) && (!agent || e.agent === agent))
  const stopped = events.filter(e => e.decision === 'denied' || e.decision === 'blocked').length

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">Activity</h1>
          <p>Every share request from your agents, with the fields involved, the rule that decided, and what you did. {events.length} requests, {stopped} stopped.</p>
        </div>
        <button className="btn ghost" onClick={simulate}><Icon name="zap" size={15} />Simulate agent request</button>
      </div>

      <div className="between">
        <div className="seg">
          {FILTERS.map(x => <button key={x.id} className={f === x.id ? 'on' : ''} onClick={() => setF(x.id)}>{x.label}</button>)}
        </div>
        <div className="chips">
          {(Object.keys(AGENTS) as AgentId[]).map(a => (
            <button key={a} className={`chip ${agent === a ? 'on' : ''}`} onClick={() => setAgent(agent === a ? null : a)}>{AGENTS[a].label}</button>
          ))}
        </div>
      </div>

      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="list">
          {shown.length === 0 && <div className="empty">No requests match.</div>}
          {shown.map(e => {
            const app = apps.find(a => a.id === e.app)!
            const items = e.fields.map(id => DATA.find(d => d.id === id)!).filter(Boolean)
            const isOpen = open === e.id
            return (
              <div key={e.id} className={e.flagged ? 'flag' : ''}>
                <div className="event" onClick={() => setOpen(isOpen ? null : e.id)}>
                  <div className="time">{fmtTime(e.at)}<br /><span style={{ opacity: .7 }}>{fmtDate(e.at)}</span></div>
                  <AgentBadge agent={e.agent} />
                  <div className="row grow">
                    <AppAvatar app={app} size="sm" />
                    <div className="grow">
                      <div className="trunc" style={{ fontWeight: 500 }}>{app.name} <span className="muted" style={{ fontWeight: 400 }}>· {e.session}</span></div>
                      <div className="ctx trunc">{e.context}</div>
                    </div>
                  </div>
                  <div className="chips" style={{ gap: 4 }}>
                    {items.slice(0, 2).map(d => <span key={d.id} className={`tag ${d.category === 'secrets' ? 'red' : ''}`} style={{ height: 22, fontSize: 11.5 }}>{d.label}</span>)}
                    {items.length > 2 && <span className="tag" style={{ height: 22, fontSize: 11.5 }}>+{items.length - 2}</span>}
                  </div>
                  <div className="between"><DecisionBadge d={e.decision} /><Icon name="chevronDown" size={14} className="muted" style={{ transform: isOpen ? 'rotate(180deg)' : undefined, transition: 'transform .2s' }} /></div>
                </div>
                {isOpen && (
                  <div className="event-detail">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, paddingTop: 16 }}>
                      <div>
                        <div className="eyebrow" style={{ marginBottom: 8 }}>Fields in payload</div>
                        <div className="card">
                          {items.map(d => (
                            <div className="between" key={d.id} style={{ padding: '8px 14px', borderTop: '1px solid var(--line)', fontSize: 13.5 }}>
                              <span className="row" style={{ gap: 8 }}><span style={{ fontWeight: 500 }}>{d.label}</span><span className="mono muted">{d.value}</span></span>
                              <CategoryTag cat={d.category} />
                            </div>
                          ))}
                        </div>
                        <div style={{ marginTop: 14 }}>
                          <div className="eyebrow" style={{ marginBottom: 6 }}>Decision</div>
                          <div style={{ fontSize: 14 }}><DecisionBadge d={e.decision} />{e.ruleId && <span className="muted"> · rule <span className="mono">{e.ruleId}</span></span>}</div>
                          {e.reason && <div className="sub" style={{ fontSize: 13.5, marginTop: 4 }}>{e.reason}</div>}
                        </div>
                      </div>
                      <div>
                        <div className="eyebrow" style={{ marginBottom: 8 }}>Raw request from the plugin</div>
                        <pre className="code" style={{ borderRadius: 12, padding: '14px 16px', fontSize: 12 }}>{JSON.stringify({
                          id: e.id, agent: e.agent, session: e.session, app: app.domain, context: e.context,
                          fields: e.fields, decision: e.decision, rule: e.ruleId ?? null, flagged: !!e.flagged, at: e.at,
                        }, null, 2)}</pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </>
  )
}
