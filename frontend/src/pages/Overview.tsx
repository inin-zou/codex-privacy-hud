import { Link } from 'react-router-dom'
import { Icon } from '../components/Icon'
import { AgentBadge, AppAvatar, DecisionBadge, Stat } from '../components/ui'
import { BRAND, DATA, SOURCES, USER } from '../data/mock'
import { AGENTS, type AgentId } from '../data/types'
import { timeAgo } from '../lib/format'
import { useStore } from '../store/store'

export default function Overview() {
  const { apps, rules, events, alerts, unresolved, simulate } = useStore()
  const connected = apps.filter(a => a.connected).length
  const stopped = events.filter(e => e.decision === 'denied' || e.decision === 'blocked').length
  const fromAgents = DATA.filter(d => SOURCES.find(s => s.id === d.source)?.kind !== 'website' && SOURCES.find(s => s.id === d.source)?.kind !== 'browser').length
  const byAgent = (Object.keys(AGENTS) as AgentId[]).map(a => ({ a, n: events.filter(e => e.agent === a).length })).sort((x, y) => y.n - x.n)
  const max = Math.max(...byAgent.map(b => b.n), 1)
  const hour = new Date().getHours()
  const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">{greet}, {USER.name.split(' ')[0]}.</h1>
          <p>Here is what agents and apps did with your data. Last plugin sync {timeAgo(SOURCES.find(s => s.id === 'chrome')!.lastSync)}.</p>
        </div>
        <button className="btn ghost" onClick={simulate}><Icon name="zap" size={15} />Simulate a request</button>
      </div>

      <div className="stats">
        <Stat label="Data points known" value={DATA.length} delta={`${fromAgents} came from agent sessions`} />
        <Stat label="Connected apps" value={connected} delta={`of ${apps.length} in the catalogue`} />
        <Stat label="Active rules" value={rules.filter(r => r.enabled).length} delta={`${rules.filter(r => r.createdBy === 'agent').length} suggested by the agent`} />
        <Stat label="Requests · 7 days" value={events.length} delta={`${stopped} stopped`} tone={stopped ? 'red' : undefined} />
      </div>

      <div className="two">
        <div className="card">
          <div className="between" style={{ padding: '16px 18px', borderBottom: '1px solid var(--line)' }}>
            <div className="h-sec">Recent activity</div>
            <Link to="/app/activity" className="row muted" style={{ fontSize: 13, gap: 4 }}>All activity <Icon name="chevronRight" size={14} /></Link>
          </div>
          <div className="list">
            {events.slice(0, 7).map(e => {
              const app = apps.find(a => a.id === e.app)!
              return (
                <Link to="/app/activity" className={`item clickable ${e.flagged ? 'flag' : ''}`} key={e.id}>
                  <AgentBadge agent={e.agent} compact />
                  <AppAvatar app={app} size="sm" />
                  <div className="grow">
                    <div className="t trunc">{AGENTS[e.agent].label} → {app.name}</div>
                    <div className="s trunc">{e.context} · {e.fields.length} field{e.fields.length > 1 ? 's' : ''}</div>
                  </div>
                  <DecisionBadge d={e.decision} />
                  <span className="mono muted" style={{ width: 72, textAlign: 'right' }}>{timeAgo(e.at)}</span>
                </Link>
              )
            })}
          </div>
        </div>

        <div className="stack" style={{ gap: 20 }}>
          <div className="card">
            <div className="between" style={{ padding: '16px 18px', borderBottom: '1px solid var(--line)' }}>
              <div className="h-sec">Needs attention</div>
              <Link to="/app/alerts" className="row muted" style={{ fontSize: 13, gap: 4 }}>{unresolved.length} open <Icon name="chevronRight" size={14} /></Link>
            </div>
            <div className="list">
              {unresolved.length === 0 && <div className="empty">All clear.</div>}
              {unresolved.slice(0, 3).map(a => (
                <Link to="/app/alerts" className="item clickable" key={a.id} style={{ alignItems: 'flex-start' }}>
                  <span className={`sev ${a.severity}`} style={{ width: 30, height: 30, borderRadius: 9, animation: 'none' }}><Icon name={a.severity === 'info' ? 'info' : 'alert'} size={15} stroke={2.2} /></span>
                  <div className="grow">
                    <div className="t" style={{ fontSize: 14, lineHeight: 1.35 }}>{a.title}</div>
                    <div className="s">{timeAgo(a.at)}</div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
          <div className="card pad">
            <div className="h-sec" style={{ marginBottom: 14 }}>Who asks the most</div>
            <div className="stack" style={{ gap: 12 }}>
              {byAgent.map(b => (
                <div key={b.a}>
                  <div className="between" style={{ fontSize: 13.5, marginBottom: 6 }}>
                    <AgentBadge agent={b.a} />
                    <span className="mono muted">{b.n} requests</span>
                  </div>
                  <div className="bar"><i style={{ width: `${(b.n / max) * 100}%` }} /></div>
                </div>
              ))}
            </div>
          </div>
          <div className="card pad" style={{ background: 'var(--ink)', color: '#fff', border: 0 }}>
            <div className="row" style={{ gap: 8, color: '#a5a5b5', fontSize: 12, fontWeight: 600, letterSpacing: '.04em', textTransform: 'uppercase' }}><Icon name="sparkle" size={13} />{BRAND} agent</div>
            <p style={{ marginTop: 10, fontSize: 15, lineHeight: 1.5 }}>
              You have no rule for <b>identity documents</b> yet. Airbnb received your passport number last week under the general travel rule. Want me to require approval for it?
            </p>
            <Link to="/app/rules" className="btn" style={{ marginTop: 14, background: '#fff', color: 'var(--ink)', borderColor: '#fff' }}>Review suggestion</Link>
          </div>
        </div>
      </div>
      <div className="muted" style={{ fontSize: 12.5 }}>{alerts.filter(a => a.resolved).length} alerts resolved this month.</div>
    </>
  )
}
