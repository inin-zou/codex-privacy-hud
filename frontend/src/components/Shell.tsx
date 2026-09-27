import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Icon, type IconName } from './Icon'
import { BRAND, USER } from '../data/mock'
import { useStore } from '../store/store'
import { Overlays } from './Overlays'

const NAV: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: '/app', label: 'Overview', icon: 'grid', end: true },
  { to: '/app/data', label: 'My data', icon: 'database' },
  { to: '/app/apps', label: 'Applications', icon: 'layers' },
  { to: '/app/rules', label: 'Rules', icon: 'sliders' },
  { to: '/app/activity', label: 'Activity', icon: 'activity' },
  { to: '/app/alerts', label: 'Alerts', icon: 'bell' },
]

export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <span className="brand-mark" style={{ width: size, height: size, borderRadius: size * 0.29 }}>
      <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="7.5" stroke="#fff" strokeWidth="2.4" />
        <circle cx="12" cy="12" r="2.6" fill="#10a37f" />
      </svg>
    </span>
  )
}

export function Shell() {
  const { unresolved, simulate, alerts, events } = useStore()
  const loc = useLocation()
  const nav = useNavigate()
  const title = NAV.find(n => n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to))?.label ?? 'Overview'
  const critical = alerts.find(a => a.severity === 'critical' && !a.resolved)
  const pendingCount = events.filter(e => e.decision === 'pending').length

  return (
    <div className="shell">
      <aside className="side">
        <NavLink to="/" className="brand"><BrandMark />{BRAND}</NavLink>
        <div className="eyebrow nav-label">Workspace</div>
        {NAV.map(n => (
          <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => `navi ${isActive ? 'active' : ''}`}>
            <Icon name={n.icon} size={17} />
            {n.label}
            {n.to === '/app/alerts' && unresolved.length > 0 && <span className="count red">{unresolved.length}</span>}
            {n.to === '/app/activity' && pendingCount > 0 && <span className="count">{pendingCount} pending</span>}
          </NavLink>
        ))}
        <div className="eyebrow nav-label">Plugins</div>
        <div className="navi" style={{ cursor: 'default' }}><span className="agent"><span className="ic codex">CX</span></span>Codex <span className="count" style={{ color: 'var(--green)' }}>● live</span></div>
        <div className="navi" style={{ cursor: 'default' }}><span className="agent"><span className="ic claude">CC</span></span>Claude Code <span className="count" style={{ color: 'var(--green)' }}>● live</span></div>
        <div className="navi" style={{ cursor: 'default' }}><span className="agent"><span className="ic chatgpt">GP</span></span>ChatGPT agent <span className="count">idle</span></div>
        <div className="me">
          <div className="avatar sm" style={{ background: 'linear-gradient(135deg,#10a37f,#0d0d0d)' }}>{USER.name.split(' ').map(w => w[0]).join('')}</div>
          <div className="grow">
            <div style={{ fontWeight: 500, fontSize: 13.5 }}>{USER.name}</div>
            <div className="muted" style={{ fontSize: 12 }}>{USER.plan} plan</div>
          </div>
          <Icon name="logout" size={16} className="muted" />
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="crumb">{BRAND} <Icon name="chevronRight" size={14} /> <b>{title}</b></div>
          <div className="grow" />
          <div className="field" style={{ width: 260, height: 36 }}>
            <Icon name="search" size={15} className="muted" />
            <input placeholder="Search data, apps, rules…" />
            <span className="kbd">⌘K</span>
          </div>
          <button className="btn" onClick={simulate}><Icon name="zap" size={15} stroke={2.2} />Simulate agent request</button>
          <button className="bell" onClick={() => nav('/app/alerts')} aria-label="Alerts">
            <Icon name="bell" size={17} />
            {unresolved.length > 0 && <span className="n">{unresolved.length}</span>}
          </button>
        </header>

        <main className="content">
          {critical && (
            <div className="banner critical">
              <span className="pulse" />
              <div className="grow"><b>Critical.</b> {critical.title}</div>
              <button className="btn" onClick={() => nav('/app/alerts')}>Review</button>
            </div>
          )}
          <Outlet />
        </main>
      </div>
      <Overlays />
    </div>
  )
}
