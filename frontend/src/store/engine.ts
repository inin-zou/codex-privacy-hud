import { APPS, APP_CATEGORIES, DATA } from '../data/mock'
import { DATA_CATEGORIES } from '../data/types'
import type {
  AgentId, App, AppCategoryId, DataCategory, DataItem, Effect, Rule, RuleTarget, Severity,
} from '../data/types'

export interface FieldVerdict {
  item: DataItem
  effect: Effect | 'block'
  ruleId?: string
  reason: string
}
export interface Flag { severity: Severity; title: string; body: string }
export interface Evaluation {
  fields: FieldVerdict[]
  overall: 'allowed' | 'denied' | 'asked' | 'blocked'
  flags: Flag[]
}

const SPECIFICITY: Record<RuleTarget['type'], number> = { all: 0, category: 1, agent: 2, app: 3 }
const SEVERITY: Record<Effect, number> = { allow: 0, ask: 1, deny: 2 }

function targetMatches(t: RuleTarget, app: App, agent: AgentId) {
  switch (t.type) {
    case 'all': return true
    case 'category': return t.id === app.category
    case 'app': return t.id === app.id
    case 'agent': return t.id === agent
  }
}

/** Find the rule that governs one data category for an app + agent pair. */
export function matchRule(category: DataCategory, app: App, agent: AgentId | null, rules: Rule[]): Rule | undefined {
  const candidates = rules.filter(r =>
    r.enabled &&
    (r.data === 'all' || r.data.includes(category)) &&
    (r.target.type === 'agent' ? agent !== null && targetMatches(r.target, app, agent) : targetMatches(r.target, app, agent ?? 'codex')),
  )
  candidates.sort((a, b) =>
    SPECIFICITY[b.target.type] - SPECIFICITY[a.target.type] || SEVERITY[b.effect] - SEVERITY[a.effect])
  return candidates[0]
}

export function evaluate(agent: AgentId, app: App, fieldIds: string[], rules: Rule[]): Evaluation {
  const flags: Flag[] = []
  const items = fieldIds.map(id => DATA.find(d => d.id === id)).filter((x): x is DataItem => !!x)

  const fields: FieldVerdict[] = items.map(item => {
    if (item.category === 'secrets' || item.sensitivity === 'critical') {
      return { item, effect: 'block', ruleId: 'r-01', reason: 'Secret detected in outbound payload' }
    }
    if (app.trust === 'unknown') {
      return { item, effect: 'block', reason: `${app.name} is not a verified application` }
    }
    const rule = matchRule(item.category, app, agent, rules)
    const scopeCreep = !app.scopes.includes(item.category)
    if (!rule) {
      return { item, effect: 'ask', reason: scopeCreep ? `${app.name} never declared the ${DATA_CATEGORIES[item.category].label} scope` : 'No rule covers this data yet' }
    }
    if (scopeCreep && rule.effect === 'allow') {
      return { item, effect: 'ask', ruleId: rule.id, reason: `Allowed by ${rule.id}, but ${app.name} never declared this scope` }
    }
    return { item, effect: rule.effect, ruleId: rule.id, reason: describeRule(rule) }
  })

  const secrets = fields.filter(f => f.effect === 'block')
  if (secrets.length) {
    const names = secrets.map(f => f.item.label).join(', ')
    flags.push({
      severity: 'critical',
      title: `Blocked: ${agentLabel(agent)} tried to send ${names} to ${app.name}`,
      body: app.trust === 'unknown'
        ? `${app.domain} is not a verified application. The payload was stopped before leaving your machine.`
        : 'A live credential was found in the outbound payload. The payload was stopped before leaving your machine. Rotate the key if it was pasted anywhere else.',
    })
  }
  const creep = fields.filter(f => f.effect !== 'block' && !app.scopes.includes(f.item.category))
  if (creep.length && app.trust !== 'unknown') {
    const cats = [...new Set(creep.map(f => DATA_CATEGORIES[f.item.category].label))].join(', ')
    flags.push({
      severity: 'warning',
      title: `Scope creep: ${app.name} requested ${cats} data`,
      body: `${app.name} declared only ${app.scopes.map(s => DATA_CATEGORIES[s].label).join(', ') || 'no'} scopes, yet this request included ${cats}. ${creep.some(f => f.effect === 'deny') ? 'The field was denied by your rules and the request was flagged.' : 'Review before approving.'}`,
    })
  }

  const overall: Evaluation['overall'] =
    secrets.length ? 'blocked'
      : fields.some(f => f.effect === 'ask') ? 'asked'
        : fields.every(f => f.effect === 'deny') ? 'denied'
          : 'allowed'
  return { fields, overall, flags }
}

export function agentLabel(a: AgentId) {
  return { codex: 'Codex', 'claude-code': 'Claude Code', chatgpt: 'ChatGPT agent', cursor: 'Cursor' }[a]
}

export function targetLabel(t: RuleTarget): string {
  switch (t.type) {
    case 'all': return 'every app'
    case 'category': return `${APP_CATEGORIES.find(c => c.id === t.id)?.label ?? t.id} apps`
    case 'app': return APPS.find(a => a.id === t.id)?.name ?? t.id
    case 'agent': return `${agentLabel(t.id)} sessions`
  }
}

export function dataLabel(data: Rule['data']) {
  if (data === 'all') return 'any data'
  return data.map(c => DATA_CATEGORIES[c].label.toLowerCase()).join(' and ')
}

export function describeRule(r: Rule) {
  const verb = { allow: 'Share', ask: 'Ask before sharing', deny: 'Never share' }[r.effect]
  return `${verb} ${dataLabel(r.data)} with ${targetLabel(r.target)}`
}

/* ---------- plain-language rule parser (mock NLU) ---------- */
const CATEGORY_WORDS: Record<DataCategory, string[]> = {
  identity: ['identity', 'name', 'passport', 'birth', 'id document', 'age'],
  contact: ['contact', 'email', 'phone', 'phone number', 'mail'],
  location: ['location', 'address', 'where i', 'places', 'travel', 'trip', 'gps', 'position'],
  financial: ['financial', 'finance', 'money', 'bank', 'iban', 'card', 'payment', 'income', 'salary'],
  health: ['health', 'medical', 'allerg', 'condition', 'prescription', 'doctor'],
  preferences: ['preference', 'history', 'habits', 'taste', 'watch', 'purchase', 'search', 'device'],
  work: ['work', 'job', 'employer', 'repo', 'code', 'company', 'professional'],
  secrets: ['secret', 'api key', 'token', 'credential', 'password', 'env'],
}
const AGENT_WORDS: Record<AgentId, string[]> = {
  codex: ['codex'], 'claude-code': ['claude'], chatgpt: ['chatgpt', 'gpt'], cursor: ['cursor'],
}

export function parseRule(text: string): Omit<Rule, 'id' | 'createdAt' | 'enabled' | 'createdBy'> | null {
  const t = text.toLowerCase().trim()
  if (t.length < 6) return null
  let effect: Effect = 'allow'
  if (/\b(never|don't|do not|block|deny|refuse|no\b|forbid|hide)/.test(t)) effect = 'deny'
  else if (/\b(ask|confirm|approve|check with me|prompt|review)/.test(t)) effect = 'ask'
  else if (/\b(allow|let|can|share|ok|permit|give)/.test(t)) effect = 'allow'
  else return null

  const hasWord = (w: string) => new RegExp(`\\b${w}(s|es|ies)?\\b`).test(t)
  const data: DataCategory[] = (Object.keys(CATEGORY_WORDS) as DataCategory[])
    .filter(c => CATEGORY_WORDS[c].some(hasWord))
  const everything = /\b(anything|everything|all my data|any data|all data)\b/.test(t)

  let target: RuleTarget = { type: 'all' }
  const app = APPS.find(a => t.includes(a.name.toLowerCase()) || new RegExp(`\\b${a.id}\\b`).test(t))
  // "social apps", "travel services": the category word followed by a noun wins over a bare word,
  // so "health data with social apps" targets Social, not Health.
  const catByPhrase = APP_CATEGORIES.find(c => new RegExp(`\\b${c.label.toLowerCase()}\\s+(apps?|services?|tools?|sites?|platforms?|companies)`).test(t))
  const catByWord = APP_CATEGORIES.find(c => new RegExp(`\\b${c.label.toLowerCase()}\\b`).test(t) && !(c.id === 'health' && data.includes('health')))
  const cat = catByPhrase ?? catByWord
  const agent = (Object.keys(AGENT_WORDS) as AgentId[]).find(a => AGENT_WORDS[a].some(w => t.includes(w)))
  if (app) target = { type: 'app', id: app.id }
  else if (cat) target = { type: 'category', id: cat.id as AppCategoryId }
  else if (agent) target = { type: 'agent', id: agent }

  if (!data.length && !everything) return null
  return { effect, data: everything && !data.length ? 'all' : data, target, note: text.trim() }
}

/* ---------- agent explanation for an app ---------- */
export function explainApp(app: App, rules: Rule[]) {
  const rows = app.scopes.map(cat => {
    const rule = matchRule(cat, app, null, rules)
    const effect: Effect = cat === 'secrets' ? 'deny' : rule?.effect ?? 'ask'
    return { cat, effect, rule }
  })
  const by = (e: Effect) => rows.filter(r => r.effect === e).map(r => DATA_CATEGORIES[r.cat].label.toLowerCase())
  const allow = by('allow'), ask = by('ask'), deny = by('deny')
  const catLabel = APP_CATEGORIES.find(c => c.id === app.category)?.label.toLowerCase() ?? app.category
  const parts: string[] = []
  parts.push(`${app.name} is a ${app.trust === 'verified' ? 'verified ' : app.trust === 'unknown' ? 'n unverified ' : ' community-listed '}${catLabel} app. It declares ${app.scopes.length} scope${app.scopes.length === 1 ? '' : 's'}.`)
  if (allow.length) parts.push(`Agents can share your ${list(allow)} with it without asking you, because of your ${catLabel} rules.`)
  if (ask.length) parts.push(`For ${list(ask)}, you will get a prompt every time an agent tries.`)
  if (deny.length) parts.push(`Your ${list(deny)} will never be shared with it.`)
  const notDeclared = (Object.keys(DATA_CATEGORIES) as DataCategory[]).filter(c => !app.scopes.includes(c) && c !== 'secrets')
  if (notDeclared.length) parts.push(`Anything else (${list(notDeclared.map(c => DATA_CATEGORIES[c].label.toLowerCase()))}) is outside its declared scopes and will be flagged as scope creep if requested.`)
  parts.push('Secrets such as API keys are blocked on every local tool call, for every app.')
  return { rows, text: parts.join(' ') }
}

function list(xs: string[]) {
  if (xs.length <= 1) return xs.join('')
  return xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]
}
