import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Icon } from '../components/Icon'
import { BrandMark } from '../components/Shell'
import { BRAND, SLUG } from '../data/mock'

export default function Landing() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8)
    on(); window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [])

  return (
    <div>
      <header className={`mk-nav ${scrolled ? 'scrolled' : ''}`}>
        <Link to="/" className="brand"><BrandMark />{BRAND}</Link>
        <nav>
          <ScrollLink to="how">How it works</ScrollLink>
          <ScrollLink to="features">Product</ScrollLink>
          <ScrollLink to="developers">Developers</ScrollLink>
          <ScrollLink to="hackathon">Hackathon</ScrollLink>
        </nav>
        <div className="row" style={{ gap: 8 }}>
          <Link to="/app" className="btn ghost" style={{ height: 36 }}>Log in</Link>
          <Link to="/app" className="btn" style={{ height: 36 }}>Open dashboard</Link>
        </div>
      </header>

      <section className="wrap hero">
        <div className="hero-grid">
          <div>
            <div className="rise d1"><span className="tag outline" style={{ height: 28, padding: '0 12px' }}><span className="dot" style={{ background: 'var(--green)' }} />OpenAI AI Privacy Hackathon · Station F, Paris · 3 Sept 2026</span></div>
            <h1 className="rise d2" style={{ marginTop: 24 }}>The OAuth layer for your data and AI agents.</h1>
            <p className="lead rise d3">
              {BRAND} sits between your personal data and every agent or app that asks for it.
              You write the rules in plain language. Agents request consent. Every share is logged,
              explained, and stopped when it should never happen.
            </p>
            <div className="hero-cta rise d4">
              <Link to="/app" className="btn lg">Open the dashboard <Icon name="arrowRight" size={16} /></Link>
              <ScrollLink to="developers" className="btn ghost lg"><Icon name="terminal" size={16} />Install the plugin</ScrollLink>
            </div>
            <div className="rise d5 mono muted" style={{ marginTop: 40, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
              <span>26 data points found</span><span>11 apps connected</span><span>9 rules</span><span style={{ color: 'var(--red)' }}>1 leak blocked today</span>
            </div>
          </div>
          <div className="rise d3"><FlowVisual /></div>
        </div>
      </section>

      <section className="wrap section" id="how">
        <div className="eyebrow">How it works</div>
        <h2 style={{ marginTop: 14 }}>Three moves between your data and the world.</h2>
        <div className="steps">
          <div className="step">
            <div className="num">01 — See</div>
            <h3>Everything the internet and your agents know about you.</h3>
            <p>{BRAND} pulls what websites hold and what Codex or Claude Code sessions have touched: addresses, cards, repos, even the API key sitting in your env file.</p>
          </div>
          <div className="step">
            <div className="num">02 — Decide</div>
            <h3>Rules in plain language, or an agent that explains.</h3>
            <p>"Never share my location with streaming apps." Or ask the {BRAND} agent what Booking.com would receive before you connect it.</p>
          </div>
          <div className="step" style={{ background: 'var(--ink)', color: '#fff' }}>
            <div className="num" style={{ color: '#8e8ea0' }}>03 — Enforce</div>
            <h3>The plugin asks, logs, and pulls the alarm.</h3>
            <p style={{ color: '#b6b6c4' }}>Installed in Codex, Claude Code or ChatGPT agents, it intercepts every outbound share, prompts you when a rule says so, and blocks secrets before they leave your machine.</p>
          </div>
        </div>
      </section>

      <section className="wrap section" id="features" style={{ paddingTop: 0 }}>
        <div className="eyebrow">Product</div>
        <h2 style={{ marginTop: 14 }}>One dashboard. Four things you could never see before.</h2>
        <div className="feat-grid">
          <div className="feat">
            <div>
              <h3>Your data, with its provenance</h3>
              <p>Every field carries where it came from, how sensitive it is, and when it was collected. Websites and agent sessions side by side.</p>
            </div>
            <div className="preview">
              {[
                ['Home address', '12 rue Oberkampf, Paris', 'Amazon', 'high'],
                ['Upcoming trip', 'Lisbon · 12–19 Oct', 'Codex · travel-planner', 'medium'],
                ['OPENAI_API_KEY', 'sk-proj-••••••••Q4', 'Codex · travel-planner', 'critical'],
              ].map(r => (
                <div className="between" key={r[0]} style={{ padding: '8px 0', borderTop: '1px solid var(--line)', fontSize: 13 }}>
                  <div><div style={{ fontWeight: 500 }}>{r[0]}</div><div className="mono muted" style={{ fontSize: 12 }}>{r[1]}</div></div>
                  <div className="row" style={{ gap: 10 }}><span className="tag outline">{r[2]}</span><span className={`sens ${r[3]}`}><i /></span></div>
                </div>
              ))}
            </div>
          </div>
          <div className="feat">
            <div>
              <h3>Apps by category, with declared scopes</h3>
              <p>Travel, streaming, finance, developer tools. Each app declares what it needs, and {BRAND} flags anything it asks for beyond that.</p>
            </div>
            <div className="preview">
              <div className="chips" style={{ marginBottom: 12 }}>
                {['Travel · 4', 'Streaming · 3', 'Finance · 2', 'Developer · 3'].map(c => <span className="chip" key={c}>{c}</span>)}
              </div>
              <div className="between" style={{ fontSize: 13 }}>
                <div className="row"><span className="avatar sm" style={{ background: '#003580' }}>B</span><div><div style={{ fontWeight: 500 }}>Booking.com</div><div className="muted" style={{ fontSize: 12 }}>booking.com</div></div></div>
                <div className="scopes"><span className="scope allow">Identity</span><span className="scope allow">Contact</span><span className="scope ask">Financial</span></div>
              </div>
            </div>
          </div>
          <div className="feat">
            <div>
              <h3>Rules written the way you think</h3>
              <p>Type a sentence. {BRAND} turns it into a structured policy with an effect, a data scope and a target, and applies it to the next request.</p>
            </div>
            <div className="preview">
              <div style={{ fontSize: 16, letterSpacing: '-0.01em' }}>"Ask me before any Codex session shares where I am."</div>
              <div className="row" style={{ marginTop: 12, gap: 8 }}>
                <span className="effect ask">Ask</span>
                <span className="rule-sentence" style={{ fontSize: 13.5 }}>Ask before sharing <b>location</b> with <b>Codex sessions</b></span>
              </div>
            </div>
          </div>
          <div className="feat" style={{ borderColor: 'rgba(229,72,77,.35)' }}>
            <div>
              <h3>Live consent, a full log, and a loud alarm</h3>
              <p>Requests from your agents show up as consent prompts. Everything lands in the activity log. A leaked secret triggers a takeover you cannot miss.</p>
            </div>
            <div className="preview" style={{ background: '#fff' }}>
              <div className="row" style={{ gap: 10 }}>
                <span className="sev critical" style={{ width: 32, height: 32, borderRadius: 9 }}><Icon name="alert" size={16} stroke={2.2} /></span>
                <div style={{ fontSize: 13.5 }}><div style={{ fontWeight: 600 }}>Blocked: Codex tried to send OPENAI_API_KEY to paste-share.io</div><div className="muted" style={{ fontSize: 12 }}>Stopped before leaving your machine · 2 h ago</div></div>
              </div>
              <div className="divider" style={{ margin: '12px 0' }} />
              <div className="between" style={{ fontSize: 13 }}><span className="agent"><span className="ic claude">CC</span>Claude Code → GitHub</span><span className="decision allowed"><i />Allowed · r-07</span></div>
              <div className="between" style={{ fontSize: 13, marginTop: 8 }}><span className="agent"><span className="ic chatgpt">GP</span>ChatGPT → Netflix</span><span className="decision denied"><i />Denied · r-03</span></div>
            </div>
          </div>
        </div>
      </section>

      <section className="wrap" style={{ padding: '0 32px 96px' }}>
        <div className="eyebrow">Works with your agents</div>
        <div className="logos">
          <span><span className="agent"><span className="ic codex">CX</span></span>Codex</span>
          <span><span className="agent"><span className="ic claude">CC</span></span>Claude Code</span>
          <span><span className="agent"><span className="ic chatgpt">GP</span></span>ChatGPT agents</span>
          <span><span className="agent"><span className="ic cursor">CU</span></span>Cursor</span>
          <span className="muted" style={{ fontWeight: 500, fontSize: 14 }}>+ any MCP-compatible agent</span>
        </div>
      </section>

      <section className="wrap section" id="developers" style={{ paddingTop: 0 }}>
        <div className="hero-grid" style={{ alignItems: 'start' }}>
          <div>
            <div className="eyebrow">Developers</div>
            <h2 style={{ marginTop: 14 }}>One plugin. One endpoint. Consent before bytes leave.</h2>
            <p className="lead">The plugin hooks the agent's outbound tool calls. Before any payload reaches a third party it asks {BRAND} for a decision, resolved locally against your rules in under a millisecond.</p>
            <div className="row" style={{ marginTop: 28, gap: 10 }}>
              <Link to="/app/activity" className="btn ghost">See the request log <Icon name="arrowUpRight" size={15} /></Link>
            </div>
          </div>
          <pre className="code">{`$ codex plugin add @${SLUG}/consent
`}<span className="g">✓</span>{` plugin installed · policy synced (`}<span className="y">9 rules</span>{`)

`}<span className="c"># sent by the plugin before any data leaves your machine</span>{`
POST https://api.${SLUG}.dev/v1/consent
{
  "agent":   "codex",
  "session": "travel-planner",
  "app":     "booking.com",
  "fields":  ["full_name", "email", "travel_dates"]
}

`}<span className="c">← 200</span>{`
{
  "decision": `}<span className="y">"ask"</span>{`,
  "rule":     "r-09",
  "prompt":   `}<span className="p">"https://app.${SLUG}.dev/consent/7f3a"</span>{`
}`}</pre>
        </div>
      </section>

      <section className="wrap" id="hackathon" style={{ paddingBottom: 96 }}>
        <div className="card" style={{ padding: 48, borderRadius: 28, background: 'var(--bg-2)', border: 0, display: 'grid', gridTemplateColumns: '1fr auto', gap: 32, alignItems: 'center' }}>
          <div>
            <div className="eyebrow">OpenAI AI Privacy Hackathon</div>
            <h2 style={{ marginTop: 12, fontSize: 36 }}>Built in a day at Station F, so you can see the demo in two minutes.</h2>
            <p className="lead" style={{ marginTop: 12 }}>Open the dashboard, hit "Simulate agent request" and watch consent prompts, logs and a blocked leak happen live on mock data.</p>
          </div>
          <Link to="/app" className="btn lg">Try the live demo <Icon name="arrowRight" size={16} /></Link>
        </div>
      </section>

      <footer className="wrap footer">
        <span className="row"><BrandMark size={22} /> {BRAND} — the OAuth layer for your data and AI agents.</span>
        <span>Mock data · No real accounts were harmed · 2026</span>
      </footer>
    </div>
  )
}

function ScrollLink({ to, className, children }: { to: string; className?: string; children: ReactNode }) {
  return (
    <a href={`#${to}`} className={className} onClick={e => { e.preventDefault(); document.getElementById(to)?.scrollIntoView({ behavior: 'smooth' }) }}>
      {children}
    </a>
  )
}

function FlowVisual() {
  const left = [
    { y: 70, label: 'Email', src: 'google' },
    { y: 132, label: 'Home address', src: 'amazon' },
    { y: 194, label: 'Upcoming trip', src: 'codex' },
    { y: 256, label: 'OPENAI_API_KEY', src: 'codex · env', bad: true },
    { y: 318, label: 'Watch history', src: 'netflix' },
  ]
  const right = [
    { y: 100, label: 'Booking.com' },
    { y: 165, label: 'GitHub' },
    { y: 230, label: 'Netflix' },
    { y: 300, label: 'paste-share.io', bad: true },
  ]
  const GX1 = 212, GX2 = 348, GY = 210
  const inPath = (y: number) => `M156,${y} C 185,${y} 180,${GY} ${GX1},${GY}`
  const outPath = (y: number) => `M${GX2},${GY} C 378,${GY} 372,${y} 404,${y}`
  return (
    <svg className="flow" viewBox="0 0 560 420" width="100%" style={{ height: 'auto', display: 'block' }} aria-label={`Data flowing through the ${BRAND} policy gate`}>
      <defs>
        <filter id="sh" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="10" stdDeviation="12" floodColor="#0d0d0d" floodOpacity=".25" /></filter>
      </defs>
      <rect width="560" height="420" rx="28" fill="#f7f7f8" />
      <text x="16" y="36" fontFamily="var(--mono)" fontSize="11" fill="#8e8ea0">YOUR DATA</text>
      <text x="544" y="36" fontFamily="var(--mono)" fontSize="11" fill="#8e8ea0" textAnchor="end">APPS &amp; AGENTS</text>

      {left.map(n => <path key={n.y} d={inPath(n.y)} stroke="#d9d9e3" strokeWidth="1.25" fill="none" />)}
      {right.map(n => <path key={n.y} d={outPath(n.y)} stroke={n.bad ? '#f0c4c6' : '#d9d9e3'} strokeWidth="1.25" fill="none" strokeDasharray={n.bad ? '3 4' : undefined} />)}

      {left.map(n => (
        <g key={n.label}>
          <rect x="16" y={n.y - 17} width="140" height="34" rx="17" fill="#fff" stroke="#ececf1" />
          <circle cx="34" cy={n.y} r="4" fill={n.bad ? '#e5484d' : '#0d0d0d'} />
          <text x="46" y={n.y - 2} fontFamily="var(--font)" fontSize="11.5" fontWeight="600" fill="#0d0d0d">{n.label}</text>
          <text x="46" y={n.y + 10} fontFamily="var(--mono)" fontSize="9.5" fill="#8e8ea0">{n.src}</text>
        </g>
      ))}
      {right.map(n => (
        <g key={n.label}>
          <rect x="404" y={n.y - 17} width="140" height="34" rx="17" fill="#fff" stroke={n.bad ? '#f0c4c6' : '#ececf1'} />
          <text x="422" y={n.y + 4} fontFamily="var(--font)" fontSize="12" fontWeight="600" fill={n.bad ? '#b5232a' : '#0d0d0d'}>{n.label}</text>
        </g>
      ))}

      <g filter="url(#sh)">
        <rect x={GX1} y="140" width={GX2 - GX1} height="140" rx="18" fill="#0d0d0d" />
      </g>
      <g>
        <circle cx={GX1 + 22} cy="162" r="7" stroke="#fff" strokeWidth="2" fill="none" />
        <circle cx={GX1 + 22} cy="162" r="2.4" fill="#10a37f" />
        <text x={GX1 + 36} y="166" fontFamily="var(--font)" fontSize="13" fontWeight="600" fill="#fff">{BRAND} gate</text>
        <text x={GX1 + 14} y="186" fontFamily="var(--mono)" fontSize="9" fill="#a5a5b5">policy · 9 rules · 0.4ms</text>
        <rect x={GX1 + 12} y="198" width={GX2 - GX1 - 24} height="30" rx="7" fill="rgba(255,255,255,.08)" />
        <text x={GX1 + 20} y="211" fontFamily="var(--mono)" fontSize="9" fill="#3fd0a8">r-02 allow id → travel</text>
        <text x={GX1 + 20} y="222" fontFamily="var(--mono)" fontSize="9" fill="#ff8a8e">r-01 block secrets → *</text>
        <rect x={GX1 + 12} y="236" width={GX2 - GX1 - 24} height="30" rx="7" fill="rgba(255,255,255,.08)" />
        <text x={GX1 + 20} y="249" fontFamily="var(--mono)" fontSize="9" fill="#e8e8ee">3 shared · 1 asked</text>
        <text x={GX1 + 20} y="260" fontFamily="var(--mono)" fontSize="9" fill="#ff8a8e">1 blocked</text>
      </g>

      {/* packets in */}
      {left.map((n, i) => (
        <circle key={`p${n.y}`} r="4.5" fill={n.bad ? '#e5484d' : '#0d0d0d'}>
          <animateMotion dur="2.6s" begin={`${i * 0.55}s`} repeatCount="indefinite" path={inPath(n.y)} keyPoints="0;1" keyTimes="0;1" calcMode="linear" />
          <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.08;.9;1" dur="2.6s" begin={`${i * 0.55}s`} repeatCount="indefinite" />
        </circle>
      ))}
      {/* packets out */}
      {right.filter(n => !n.bad).map((n, i) => (
        <circle key={`q${n.y}`} r="4.5" fill="#10a37f">
          <animateMotion dur="2.6s" begin={`${1.3 + i * 0.7}s`} repeatCount="indefinite" path={outPath(n.y)} />
          <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.08;.9;1" dur="2.6s" begin={`${1.3 + i * 0.7}s`} repeatCount="indefinite" />
        </circle>
      ))}
      {/* blocked marker */}
      <g>
        <circle cx={GX2 + 14} cy="300" r="9" fill="#fdecec" stroke="#e5484d" strokeWidth="1.5">
          <animate attributeName="r" values="9;11;9" dur="1.6s" repeatCount="indefinite" />
        </circle>
        <path d={`M${GX2 + 10.5},296.5 l7,7 M${GX2 + 17.5},296.5 l-7,7`} stroke="#e5484d" strokeWidth="1.8" strokeLinecap="round" />
      </g>
    </svg>
  )
}
