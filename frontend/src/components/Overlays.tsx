import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Icon } from './Icon'
import { AgentBadge, AppAvatar, CategoryTag, Sens, Toggle, TrustTag } from './ui'
import { useStore } from '../store/store'
import { BRAND, DATA } from '../data/mock'
import { DATA_CATEGORIES } from '../data/types'
import { explainApp } from '../store/engine'

export function Overlays() {
  return <><ConsentPrompt /><Takeover /><AppDrawer /><Toasts /></>
}

function ConsentPrompt() {
  const { pending, apps, dispatch } = useStore()
  if (!pending) return null
  const { scenario, evaluation } = pending
  const app = apps.find(a => a.id === scenario.app)!
  const asking = evaluation.fields.filter(f => f.effect === 'ask').length
  return (
    <div className="overlay">
      <div className="modal" role="dialog" aria-modal>
        <div className="head">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <AgentBadge agent={scenario.agent} />
            <span className="tag"><Icon name="clock" size={11} />Waiting for you</span>
          </div>
          <h2 style={{ fontSize: 24, marginTop: 18, lineHeight: 1.15 }}>
            Share with {app.name}?
          </h2>
          <p className="sub" style={{ marginTop: 8 }}>
            Session <span className="mono">{scenario.session}</span> · {scenario.context}
          </p>
        </div>
        <div className="body">
          <div className="row" style={{ marginBottom: 12 }}>
            <AppAvatar app={app} size="sm" />
            <div className="grow">
              <div style={{ fontWeight: 500 }}>{app.name}</div>
              <div className="muted" style={{ fontSize: 12.5 }}>{app.domain}</div>
            </div>
            <TrustTag trust={app.trust} />
          </div>
          <div className="card" style={{ padding: '4px 16px' }}>
            {evaluation.fields.map(f => (
              <div className="consent-row" key={f.item.id}>
                <div className="grow">
                  <div className="row" style={{ gap: 8 }}>
                    <span style={{ fontWeight: 500 }}>{f.item.label}</span>
                    <span className="mono muted">{f.item.value}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>{f.reason}</div>
                </div>
                {f.effect === 'allow' && <span className="tag green"><Icon name="check" size={11} stroke={2.5} />{f.ruleId}</span>}
                {f.effect === 'ask' && <span className="tag amber">Needs approval</span>}
                {f.effect === 'deny' && <span className="tag red"><Icon name="x" size={11} stroke={2.5} />{f.ruleId}</span>}
              </div>
            ))}
          </div>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
            {asking} field{asking > 1 ? 's' : ''} need{asking > 1 ? '' : 's'} your approval. Nothing has been sent yet. Your decision is logged in Activity.
          </p>
        </div>
        <div className="foot">
          <button className="btn ghost" onClick={() => dispatch({ type: 'resolvePending', decision: 'deny' })}>Deny</button>
          <button className="btn soft" onClick={() => dispatch({ type: 'resolvePending', decision: 'allow' })}>Allow once</button>
          <button className="btn" onClick={() => dispatch({ type: 'resolvePending', decision: 'always' })}>Always allow for {app.name}</button>
        </div>
      </div>
    </div>
  )
}

function Takeover() {
  const { criticalTakeover, events, apps, dispatch } = useStore()
  const nav = useNavigate()
  if (!criticalTakeover) return null
  const ev = events.find(e => e.id === criticalTakeover.eventId)
  const app = ev && apps.find(a => a.id === ev.app)
  return (
    <div className="overlay" style={{ background: 'rgba(120,10,14,.5)' }}>
      <div className="modal critical" role="alertdialog" aria-modal>
        <div className="head">
          <div className="row" style={{ gap: 16 }}>
            <div className="big-x"><Icon name="alert" size={28} stroke={2.2} /></div>
            <div>
              <div className="eyebrow" style={{ color: 'var(--red)' }}>Blocked before leaving your machine</div>
              <h2 style={{ fontSize: 22, marginTop: 4, lineHeight: 1.2 }}>{criticalTakeover.title}</h2>
            </div>
          </div>
        </div>
        <div className="body">
          <p className="sub">{criticalTakeover.body}</p>
          {ev && app && (
            <div className="card soft" style={{ padding: 14, marginTop: 16 }}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 10 }}>
                <AgentBadge agent={ev.agent} />
                <span className="muted" style={{ fontSize: 13 }}>→ {app.domain}</span>
              </div>
              {ev.fields.map(id => DATA.find(d => d.id === id)).filter(Boolean).map(d => (
                <div className="between" key={d!.id} style={{ padding: '6px 0', borderTop: '1px solid var(--line)' }}>
                  <span className="row" style={{ gap: 8 }}><span className="mono">{d!.label}</span><CategoryTag cat={d!.category} /></span>
                  <Sens level={d!.sensitivity} />
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="foot">
          <button className="btn ghost" onClick={() => dispatch({ type: 'dismissTakeover' })}>Dismiss</button>
          <button className="btn danger" onClick={() => { dispatch({ type: 'dismissTakeover' }); nav('/app/alerts') }}>Review alert</button>
        </div>
      </div>
    </div>
  )
}

function AppDrawer() {
  const { drawerApp, apps, rules, dispatch } = useStore()
  const app = apps.find(a => a.id === drawerApp)
  useEffect(() => {
    if (!app) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') dispatch({ type: 'drawer', id: null }) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [app, dispatch])
  if (!app) return null
  const ex = explainApp(app, rules)
  return (
    <>
      <div className="overlay" style={{ background: 'rgba(13,13,13,.2)', backdropFilter: 'none' }} onClick={() => dispatch({ type: 'drawer', id: null })} />
      <aside className="drawer">
        <div className="dh">
          <AppAvatar app={app} />
          <div className="grow">
            <div style={{ fontWeight: 600 }}>{app.name}</div>
            <div className="muted" style={{ fontSize: 12.5 }}>{app.domain}</div>
          </div>
          <TrustTag trust={app.trust} />
          <button className="bell" style={{ width: 34, height: 34 }} onClick={() => dispatch({ type: 'drawer', id: null })} aria-label="Close"><Icon name="x" size={16} /></button>
        </div>
        <div className="db">
          <div className="explain">
            <div className="who"><Icon name="sparkle" size={13} />Explained by the {BRAND} agent</div>
            {ex.text}
          </div>
          <div>
            <div className="h-sec" style={{ marginBottom: 10 }}>Declared scopes</div>
            <div className="card">
              <div className="list">
                {ex.rows.length === 0 && <div className="empty">This app declares no scopes.</div>}
                {ex.rows.map(r => (
                  <div className="item" key={r.cat}>
                    <div className="grow">
                      <div className="t">{DATA_CATEGORIES[r.cat].label}</div>
                      <div className="s">{DATA_CATEGORIES[r.cat].hint}</div>
                    </div>
                    <span className={`scope ${r.effect}`}>{r.effect === 'allow' ? 'Shared' : r.effect === 'ask' ? 'Ask me' : 'Never'}{r.rule && <span className="mono" style={{ fontSize: 11 }}>{r.rule.id}</span>}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="card pad between">
            <div>
              <div style={{ fontWeight: 500 }}>Connected</div>
              <div className="muted" style={{ fontSize: 12.5 }}>{app.connected ? `${app.requests} requests so far` : 'Agents cannot share anything until connected'}</div>
            </div>
            <Toggle on={app.connected} onChange={() => dispatch({ type: 'toggleApp', id: app.id })} green />
          </div>
        </div>
      </aside>
    </>
  )
}

function Toasts() {
  const { toasts, dispatch } = useStore()
  useEffect(() => {
    if (!toasts.length) return
    const t = setTimeout(() => dispatch({ type: 'untoast', id: toasts[0].id }), 3600)
    return () => clearTimeout(t)
  }, [toasts, dispatch])
  if (!toasts.length) return null
  return (
    <div className="toasts">
      {toasts.map(t => (
        <div className="toast" key={t.id}>
          <span style={{ width: 8, height: 8, borderRadius: 4, background: t.tone === 'ok' ? 'var(--green)' : t.tone === 'bad' ? 'var(--red)' : '#fff', flex: 'none' }} />
          <div><div>{t.title}</div>{t.sub && <div className="s">{t.sub}</div>}</div>
        </div>
      ))}
    </div>
  )
}
