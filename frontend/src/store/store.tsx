import { createContext, useCallback, useContext, useMemo, useReducer, type ReactNode } from 'react'
import { ALERTS, APPS, EVENTS, RULES, SCENARIOS, ago } from '../data/mock'
import type { Alert, App, DataCategory, Rule, Scenario, ShareEvent } from '../data/types'
import { evaluate, type Evaluation } from './engine'

export interface Pending { scenario: Scenario; evaluation: Evaluation; eventId: string }
export interface Toast { id: string; title: string; sub?: string; tone?: 'ok' | 'bad' | 'neutral' }

interface State {
  apps: App[]
  rules: Rule[]
  events: ShareEvent[]
  alerts: Alert[]
  pending: Pending | null
  criticalTakeover: Alert | null
  toasts: Toast[]
  drawerApp: string | null
  scenarioCursor: number
}

type Action =
  | { type: 'toggleApp'; id: string }
  | { type: 'toggleScope'; id: string; scope: DataCategory }
  | { type: 'toggleRule'; id: string }
  | { type: 'deleteRule'; id: string }
  | { type: 'addRule'; rule: Rule }
  | { type: 'simulate' }
  | { type: 'resolvePending'; decision: 'allow' | 'deny' | 'always' }
  | { type: 'resolveAlert'; id: string }
  | { type: 'dismissTakeover' }
  | { type: 'toast'; toast: Toast }
  | { type: 'untoast'; id: string }
  | { type: 'drawer'; id: string | null }

let seq = 200
const nid = (p: string) => `${p}-${seq++}`

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case 'toggleApp':
      return { ...s, apps: s.apps.map(x => x.id === a.id ? { ...x, connected: !x.connected } : x) }
    case 'toggleScope':
      return {
        ...s, apps: s.apps.map(x => x.id !== a.id ? x : {
          ...x, scopes: x.scopes.includes(a.scope) ? x.scopes.filter(sc => sc !== a.scope) : [...x.scopes, a.scope],
        }),
      }
    case 'toggleRule':
      return { ...s, rules: s.rules.map(r => r.id === a.id ? { ...r, enabled: !r.enabled } : r) }
    case 'deleteRule':
      return { ...s, rules: s.rules.filter(r => r.id !== a.id) }
    case 'addRule':
      return { ...s, rules: [a.rule, ...s.rules] }
    case 'simulate': {
      const scenario = SCENARIOS[s.scenarioCursor % SCENARIOS.length]
      const app = s.apps.find(x => x.id === scenario.app)!
      const ev = evaluate(scenario.agent, app, scenario.fields, s.rules)
      const eventId = nid('e')
      const at = new Date().toISOString()
      const primary = ev.fields.find(f => f.effect === 'block') ?? ev.fields.find(f => f.effect === 'ask') ?? ev.fields[0]
      const event: ShareEvent = {
        id: eventId, at, agent: scenario.agent, session: scenario.session, context: scenario.context,
        app: scenario.app, fields: scenario.fields,
        decision: ev.overall === 'asked' ? 'pending' : ev.overall,
        ruleId: primary?.ruleId, flagged: ev.flags.length > 0, reason: primary?.reason,
      }
      const alerts: Alert[] = ev.flags.map(f => ({ id: nid('a'), at, severity: f.severity, title: f.title, body: f.body, eventId, resolved: false }))
      const critical = alerts.find(x => x.severity === 'critical') ?? null
      const next: State = {
        ...s,
        scenarioCursor: s.scenarioCursor + 1,
        events: [event, ...s.events],
        alerts: [...alerts, ...s.alerts],
        apps: s.apps.map(x => x.id === scenario.app ? { ...x, requests: x.requests + 1, lastAccess: at } : x),
        criticalTakeover: critical,
        pending: ev.overall === 'asked' && !critical ? { scenario, evaluation: ev, eventId } : null,
      }
      if (ev.overall === 'allowed' || ev.overall === 'denied') {
        const nAllow = ev.fields.filter(f => f.effect === 'allow').length
        const nDeny = ev.fields.filter(f => f.effect === 'deny').length
        const partial = ev.overall === 'allowed' && nDeny > 0
        if (partial) event.reason = `${nDeny} field${nDeny > 1 ? 's' : ''} denied by ${ev.fields.find(f => f.effect === 'deny')?.ruleId ?? 'your rules'}`
        next.toasts = [...s.toasts, {
          id: nid('t'),
          title: partial ? `Partially shared with ${app.name}` : ev.overall === 'allowed' ? `Shared with ${app.name}` : `Denied for ${app.name}`,
          sub: partial ? `${nAllow} shared · ${nDeny} denied` : `${scenario.fields.length} field${scenario.fields.length > 1 ? 's' : ''} · rule ${primary?.ruleId ?? '—'}`,
          tone: ev.overall === 'allowed' ? 'ok' : 'bad',
        }]
      }
      return next
    }
    case 'resolvePending': {
      if (!s.pending) return s
      const { scenario, evaluation, eventId } = s.pending
      const app = s.apps.find(x => x.id === scenario.app)!
      const decision = a.decision === 'deny' ? 'denied' : 'allowed'
      let rules = s.rules
      if (a.decision === 'always') {
        const cats = [...new Set(evaluation.fields.filter(f => f.effect === 'ask').map(f => f.item.category))]
        rules = [{
          id: nid('r'), effect: 'allow', data: cats, target: { type: 'app', id: app.id }, enabled: true,
          createdBy: 'user', note: `Created from a ${scenario.agent} request on ${new Date().toLocaleDateString('en-GB')}`, createdAt: new Date().toISOString(),
        }, ...s.rules]
      }
      return {
        ...s, rules, pending: null,
        events: s.events.map(e => e.id === eventId ? { ...e, decision, reason: a.decision === 'always' ? 'You approved and created a rule' : a.decision === 'allow' ? 'You approved once' : 'You declined' } : e),
        toasts: [...s.toasts, {
          id: nid('t'),
          title: decision === 'allowed' ? `Shared with ${app.name}` : `Denied for ${app.name}`,
          sub: a.decision === 'always' ? 'New rule added' : 'Logged in activity',
          tone: decision === 'allowed' ? 'ok' : 'bad',
        }],
      }
    }
    case 'resolveAlert':
      return { ...s, alerts: s.alerts.map(x => x.id === a.id ? { ...x, resolved: true } : x) }
    case 'dismissTakeover':
      return { ...s, criticalTakeover: null }
    case 'toast':
      return { ...s, toasts: [...s.toasts, a.toast] }
    case 'untoast':
      return { ...s, toasts: s.toasts.filter(t => t.id !== a.id) }
    case 'drawer':
      return { ...s, drawerApp: a.id }
  }
}

const initial: State = {
  apps: APPS, rules: RULES, events: EVENTS, alerts: ALERTS,
  pending: null, criticalTakeover: null, toasts: [], drawerApp: null, scenarioCursor: 0,
}

interface Ctx extends State {
  dispatch: (a: Action) => void
  simulate: () => void
  addRule: (r: Omit<Rule, 'id' | 'createdAt' | 'enabled' | 'createdBy'>, by?: Rule['createdBy']) => void
  unresolved: Alert[]
}

const StoreCtx = createContext<Ctx | null>(null)

export function StoreProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial)
  const simulate = useCallback(() => dispatch({ type: 'simulate' }), [])
  const addRule = useCallback((r: Omit<Rule, 'id' | 'createdAt' | 'enabled' | 'createdBy'>, by: Rule['createdBy'] = 'user') => {
    dispatch({ type: 'addRule', rule: { ...r, id: nid('r'), enabled: true, createdBy: by, createdAt: new Date().toISOString() } })
    dispatch({ type: 'toast', toast: { id: nid('t'), title: 'Rule added', sub: 'Applies to the next request', tone: 'neutral' } })
  }, [])
  const value = useMemo<Ctx>(() => ({
    ...state, dispatch, simulate, addRule,
    unresolved: state.alerts.filter(a => !a.resolved),
  }), [state, simulate, addRule])
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>
}

export function useStore() {
  const c = useContext(StoreCtx)
  if (!c) throw new Error('useStore outside provider')
  return c
}

export { ago }
