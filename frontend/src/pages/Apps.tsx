import { useState } from 'react'
import { Icon } from '../components/Icon'
import { AppAvatar, CAT_ICON, Toggle, TrustTag } from '../components/ui'
import { APP_CATEGORIES } from '../data/mock'
import { DATA_CATEGORIES, type AppCategoryId } from '../data/types'
import { timeAgo } from '../lib/format'
import { matchRule } from '../store/engine'
import { useStore } from '../store/store'

export default function Apps() {
  const { apps, rules, dispatch } = useStore()
  const [cat, setCat] = useState<AppCategoryId | null>(null)
  const [onlyConnected, setOnlyConnected] = useState(false)
  const shown = apps.filter(a => (!cat || a.category === cat) && (!onlyConnected || a.connected))

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">Applications</h1>
          <p>Every app declares the scopes it needs. Your rules decide what each one actually receives, and the agent can explain the outcome in one paragraph.</p>
        </div>
        <label className="row" style={{ gap: 10, fontSize: 14, fontWeight: 500 }}>
          Connected only <Toggle on={onlyConnected} onChange={() => setOnlyConnected(v => !v)} />
        </label>
      </div>

      <div className="cat-grid">
        {APP_CATEGORIES.map(c => {
          const n = apps.filter(a => a.category === c.id).length
          const on = apps.filter(a => a.category === c.id && a.connected).length
          return (
            <button key={c.id} className={`cat ${cat === c.id ? 'on' : ''}`} onClick={() => setCat(cat === c.id ? null : c.id)}>
              <span className="ic"><Icon name={CAT_ICON[c.id]} size={16} /></span>
              <span>
                <div className="n">{c.label}</div>
                <div className="c">{on} connected · {n} apps</div>
              </span>
            </button>
          )
        })}
      </div>

      <div className="between">
        <div className="h-sec">{cat ? APP_CATEGORIES.find(c => c.id === cat)!.label : 'All apps'} <span className="muted" style={{ fontWeight: 400 }}>· {shown.length}</span></div>
        <div className="row muted" style={{ fontSize: 12.5, gap: 14 }}>
          <span className="row" style={{ gap: 6 }}><i className="scope allow" style={{ width: 10, height: 10, padding: 0 }} />Shared</span>
          <span className="row" style={{ gap: 6 }}><i className="scope ask" style={{ width: 10, height: 10, padding: 0 }} />Ask me</span>
          <span className="row" style={{ gap: 6 }}><i className="scope deny" style={{ width: 10, height: 10, padding: 0 }} />Never</span>
        </div>
      </div>

      <div className="app-grid">
        {shown.map(app => (
          <div className="app-card" key={app.id} style={app.trust === 'unknown' ? { borderColor: 'rgba(229,72,77,.35)' } : undefined}>
            <div className="row">
              <AppAvatar app={app} />
              <div className="grow">
                <div className="row" style={{ gap: 8 }}><span style={{ fontWeight: 600 }}>{app.name}</span><TrustTag trust={app.trust} /></div>
                <div className="muted" style={{ fontSize: 12.5 }}>{app.domain} · {APP_CATEGORIES.find(c => c.id === app.category)!.label}</div>
              </div>
              <Toggle on={app.connected} onChange={() => dispatch({ type: 'toggleApp', id: app.id })} green />
            </div>
            <div className="desc">{app.blurb}</div>
            <div className="scopes">
              {app.scopes.length === 0 && <span className="muted" style={{ fontSize: 13 }}>No declared scopes. Any request is flagged.</span>}
              {app.scopes.map(s => {
                const r = matchRule(s, app, null, rules)
                const eff = r?.effect ?? 'ask'
                return <button key={s} className={`scope ${eff}`} onClick={() => dispatch({ type: 'drawer', id: app.id })} title={r ? `Rule ${r.id}` : 'No rule yet — you will be asked'}>{DATA_CATEGORIES[s].label}</button>
              })}
            </div>
            <div className="between" style={{ marginTop: 'auto', paddingTop: 4 }}>
              <span className="muted" style={{ fontSize: 12.5 }}>{app.lastAccess ? `Last access ${timeAgo(app.lastAccess)} · ${app.requests} requests` : 'Never accessed'}</span>
              <button className="btn soft sm" onClick={() => dispatch({ type: 'drawer', id: app.id })}><Icon name="sparkle" size={13} />Explain</button>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}
