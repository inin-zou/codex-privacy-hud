import { useMemo, useState } from 'react'
import { Icon } from '../components/Icon'
import { CategoryTag, Sens, SourceBadge } from '../components/ui'
import { BRAND, DATA, SOURCES } from '../data/mock'
import { DATA_CATEGORIES, type DataCategory, type SourceKind } from '../data/types'
import { fmtDate, timeAgo } from '../lib/format'

type KindFilter = 'all' | SourceKind
const KINDS: { id: KindFilter; label: string }[] = [
  { id: 'all', label: 'All' }, { id: 'website', label: 'Websites' }, { id: 'codex', label: 'Codex' }, { id: 'claude-code', label: 'Claude Code' }, { id: 'browser', label: 'Browser' },
]

export default function Data() {
  const [kind, setKind] = useState<KindFilter>('all')
  const [cat, setCat] = useState<DataCategory | null>(null)
  const [q, setQ] = useState('')
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})

  const rows = useMemo(() => DATA.filter(d => {
    const src = SOURCES.find(s => s.id === d.source)!
    if (kind !== 'all' && src.kind !== kind) return false
    if (cat && d.category !== cat) return false
    if (q && !`${d.label} ${d.value} ${src.name}`.toLowerCase().includes(q.toLowerCase())) return false
    return true
  }), [kind, cat, q])

  const counts = (Object.keys(DATA_CATEGORIES) as DataCategory[]).map(c => ({ c, n: DATA.filter(d => d.category === c).length }))
  const agentItems = DATA.filter(d => ['codex', 'claude-code'].includes(SOURCES.find(s => s.id === d.source)!.kind))

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="h-page">My data</h1>
          <p>Everything {BRAND} found about you across websites and agent sessions. Values are masked at rest and only revealed here, on your device.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <button className="btn ghost"><Icon name="download" size={15} />Export</button>
          <button className="btn ghost"><Icon name="trash" size={15} />Request deletion</button>
        </div>
      </div>

      <div className="three">
        <div className="stack" style={{ gap: 20 }}>
          <div className="card">
            <div style={{ padding: '14px 16px 6px' }} className="eyebrow">Categories</div>
            <div className="list">
              <button className={`item clickable ${cat === null ? '' : ''}`} onClick={() => setCat(null)} style={{ background: cat === null ? 'var(--bg-2)' : undefined }}>
                <span className="grow" style={{ textAlign: 'left', fontWeight: 500 }}>All data</span><span className="mono muted">{DATA.length}</span>
              </button>
              {counts.map(({ c, n }) => (
                <button className="item clickable" key={c} onClick={() => setCat(cat === c ? null : c)} style={{ background: cat === c ? 'var(--bg-2)' : undefined }}>
                  <span className="grow" style={{ textAlign: 'left' }}>
                    <div style={{ fontWeight: 500 }}>{DATA_CATEGORIES[c].label}</div>
                    <div className="s">{DATA_CATEGORIES[c].hint}</div>
                  </span>
                  <span className="mono muted">{n}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="card">
            <div style={{ padding: '14px 16px 6px' }} className="eyebrow">Sources</div>
            <div className="list">
              {SOURCES.map(s => (
                <div className="item" key={s.id} style={{ padding: '10px 16px' }}>
                  <div className="grow"><SourceBadge source={s} /></div>
                  <span className="mono muted" style={{ fontSize: 11.5 }}>{timeAgo(s.lastSync)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="stack" style={{ gap: 20 }}>
          <div className="between">
            <div className="seg">
              {KINDS.map(k => <button key={k.id} className={kind === k.id ? 'on' : ''} onClick={() => setKind(k.id)}>{k.label}</button>)}
            </div>
            <div className="field" style={{ width: 280, height: 36 }}>
              <Icon name="search" size={15} className="muted" />
              <input placeholder="Filter fields…" value={q} onChange={e => setQ(e.target.value)} />
            </div>
          </div>
          <div className="card" style={{ overflow: 'auto' }}>
            <table className="tbl">
              <thead><tr><th>Field</th><th>Category</th><th>Source</th><th>Sensitivity</th><th>Collected</th></tr></thead>
              <tbody>
                {rows.length === 0 && <tr><td colSpan={5}><div className="empty">Nothing matches.</div></td></tr>}
                {rows.map(d => {
                  const src = SOURCES.find(s => s.id === d.source)!
                  const shown = revealed[d.id]
                  return (
                    <tr key={d.id}>
                      <td>
                        <div style={{ fontWeight: 500 }}>{d.label}</div>
                        <span className="row" style={{ gap: 8, marginTop: 2 }}>
                          <span className="mono" style={{ fontSize: 12.5, color: shown ? 'var(--ink)' : 'var(--ink-3)' }}>{shown ? d.value.replace(/•/g, '4') : d.value}</span>
                          <button className="muted" onClick={() => setRevealed(r => ({ ...r, [d.id]: !r[d.id] }))} aria-label="Reveal"><Icon name={shown ? 'eyeOff' : 'eye'} size={13} /></button>
                        </span>
                      </td>
                      <td><CategoryTag cat={d.category} /></td>
                      <td><SourceBadge source={src} /></td>
                      <td><Sens level={d.sensitivity} /></td>
                      <td className="mono muted">{fmtDate(d.collectedAt)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="card pad" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
            <div>
              <div className="row" style={{ gap: 8 }}><Icon name="terminal" size={16} /><div className="h-sec">From your agent sessions</div></div>
              <p className="sub" style={{ marginTop: 8, fontSize: 14 }}>
                The plugin reads what Codex and Claude Code saw: repository names, commit identities, values in <span className="mono">.env</span> files, travel dates you typed in a prompt.
                Secrets are stored as fingerprints only, never as plaintext.
              </p>
            </div>
            <div className="list" style={{ border: '1px solid var(--line)', borderRadius: 12 }}>
              {agentItems.map(d => (
                <div className="item" key={d.id} style={{ padding: '9px 14px' }}>
                  <span className="mono grow">{d.label}</span>
                  <Sens level={d.sensitivity} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

