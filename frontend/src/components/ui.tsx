import { Icon, type IconName } from './Icon'
import { AGENTS, DATA_CATEGORIES, type AgentId, type App, type AppCategoryId, type DataCategory, type Decision, type Sensitivity, type Source } from '../data/types'

export function AppAvatar({ app, size = '' }: { app: App; size?: '' | 'sm' | 'lg' }) {
  const initials = app.name.replace(/\.[a-z]+$/i, '').split(/[\s-]/).map(w => w[0]).join('').slice(0, 2).toUpperCase()
  return <div className={`avatar ${size}`} style={{ background: app.color }}>{initials}</div>
}

export function AgentBadge({ agent, compact = false }: { agent: AgentId; compact?: boolean }) {
  const a = AGENTS[agent]
  return (
    <span className="agent">
      <span className={`ic ${a.cls}`}>{a.short}</span>
      {!compact && a.label}
    </span>
  )
}

export function DecisionBadge({ d }: { d: Decision }) {
  const label: Record<Decision, string> = { allowed: 'Allowed', denied: 'Denied', asked: 'Asked', blocked: 'Blocked', pending: 'Awaiting you' }
  return <span className={`decision ${d}`}><i />{label[d]}</span>
}

export function Toggle({ on, onChange, green }: { on: boolean; onChange: () => void; green?: boolean }) {
  return <button type="button" role="switch" aria-checked={on} className={`toggle ${on ? 'on' : ''} ${green ? 'green' : ''}`} onClick={onChange} />
}

export function CategoryTag({ cat }: { cat: DataCategory }) {
  return <span className="tag outline">{DATA_CATEGORIES[cat].label}</span>
}

export function Sens({ level }: { level: Sensitivity }) {
  return <span className={`sens ${level}`}><i />{level[0].toUpperCase() + level.slice(1)}</span>
}

const KIND_ICON: Record<Source['kind'], IconName> = { website: 'globe', codex: 'terminal', 'claude-code': 'terminal', browser: 'monitor' }
export function SourceBadge({ source }: { source: Source }) {
  return (
    <span className="row" style={{ gap: 8, fontSize: 13.5 }}>
      <span style={{ width: 22, height: 22, borderRadius: 6, background: source.color, display: 'grid', placeItems: 'center', color: '#fff' }}>
        <Icon name={KIND_ICON[source.kind]} size={12} stroke={2.2} />
      </span>
      <span className="trunc">{source.name}</span>
    </span>
  )
}

export const CAT_ICON: Record<AppCategoryId, IconName> = {
  travel: 'plane', streaming: 'tv', shopping: 'bag', finance: 'card', health: 'heart', productivity: 'doc', social: 'users', developer: 'code',
}

export function TrustTag({ trust }: { trust: App['trust'] }) {
  if (trust === 'verified') return <span className="tag green"><Icon name="check" size={11} stroke={2.5} />Verified</span>
  if (trust === 'community') return <span className="tag">Community</span>
  return <span className="tag red"><Icon name="alert" size={11} stroke={2.5} />Unverified</span>
}

export function Stat({ label, value, delta, tone }: { label: string; value: string | number; delta?: string; tone?: 'red' | 'green' }) {
  return (
    <div className="stat">
      <div className="label">{label}</div>
      <div className="val">{value}</div>
      {delta && <div className={`delta ${tone ?? ''}`}>{delta}</div>}
    </div>
  )
}

export function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>
}
