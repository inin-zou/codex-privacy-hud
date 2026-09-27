import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Icon } from '../components/Icon'
import { AgentBadge } from '../components/ui'
import { BRAND, DATA } from '../data/mock'
import { fmtDateTime, timeAgo } from '../lib/format'
import { useStore } from '../store/store'

export default function Alerts() {
  const { alerts, events, apps, dispatch } = useStore()
  const [view, setView] = useState<'open' | 'resolved' | 'all'>('open')
  const shown = alerts.filter(a => view === 'all' || (view === 'open' ? !a.resolved : a.resolved))
  const open = alerts.filter(a => !a.resolved)

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">Alerts</h1>
          <p>{BRAND} raises an alert when a request looks wrong: a secret in a payload, an unverified destination, or an app asking beyond its declared scopes. {open.length} open.</p>
        </div>
        <div className="seg">
          {(['open', 'resolved', 'all'] as const).map(v => <button key={v} className={view === v ? 'on' : ''} onClick={() => setView(v)}>{v[0].toUpperCase() + v.slice(1)}</button>)}
        </div>
      </div>

      <div className="stack" style={{ gap: 14 }}>
        {shown.length === 0 && <div className="card"><div className="empty">Nothing here. Your agents behaved.</div></div>}
        {shown.map(a => {
          const ev = events.find(e => e.id === a.eventId)
          const app = ev && apps.find(x => x.id === ev.app)
          return (
            <div className={`alert-card ${a.severity} ${a.resolved ? 'resolved' : ''}`} key={a.id}>
              <span className={`sev ${a.severity}`} style={a.resolved ? { animation: 'none' } : undefined}><Icon name={a.severity === 'info' ? 'info' : 'alert'} size={18} stroke={2.2} /></span>
              <div>
                <div className="row" style={{ gap: 8, fontSize: 12, marginBottom: 6 }}>
                  <span className={`tag ${a.severity === 'critical' ? 'red' : a.severity === 'warning' ? 'amber' : 'blue'}`}>{a.severity}</span>
                  <span className="muted">{fmtDateTime(a.at)} · {timeAgo(a.at)}</span>
                </div>
                <div style={{ fontWeight: 600, fontSize: 16, letterSpacing: '-0.015em', lineHeight: 1.3 }}>{a.title}</div>
                <p className="sub" style={{ marginTop: 6, fontSize: 14, maxWidth: '70ch' }}>{a.body}</p>
                {ev && app && (
                  <div className="row" style={{ marginTop: 12, gap: 10, fontSize: 13 }}>
                    <AgentBadge agent={ev.agent} />
                    <span className="muted">→ {app.domain}</span>
                    <span className="chips" style={{ gap: 4 }}>
                      {ev.fields.map(id => DATA.find(d => d.id === id)).filter(Boolean).map(d => (
                        <span key={d!.id} className={`tag ${d!.category === 'secrets' ? 'red' : 'outline'}`} style={{ height: 22, fontSize: 11.5 }}>{d!.label}</span>
                      ))}
                    </span>
                    <Link to="/app/activity" className="row muted" style={{ gap: 4, marginLeft: 'auto' }}>Open in activity <Icon name="arrowUpRight" size={13} /></Link>
                  </div>
                )}
                {a.severity === 'critical' && !a.resolved && (
                  <div className="row" style={{ marginTop: 14, gap: 8 }}>
                    <button className="btn danger sm"><Icon name="key" size={13} />Rotate the key</button>
                    <button className="btn ghost sm" onClick={() => dispatch({ type: 'toggleApp', id: ev?.app ?? '' })}>Block {app?.name ?? 'app'} for good</button>
                  </div>
                )}
              </div>
              <div>
                {a.resolved
                  ? <span className="tag green"><Icon name="check" size={11} stroke={2.5} />Resolved</span>
                  : <button className="btn soft sm" onClick={() => dispatch({ type: 'resolveAlert', id: a.id })}><Icon name="check" size={13} />Resolve</button>}
              </div>
            </div>
          )
        })}
      </div>
    </>
  )
}
