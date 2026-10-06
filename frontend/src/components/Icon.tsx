const P: Record<string, string> = {
  shield: 'M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z',
  database: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  sliders: 'M4 6h10M18 6h2M4 12h2M10 12h10M4 18h12M20 18h0M14 4v4M6 10v4M16 16v4',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  bell: 'M6 16V11a6 6 0 0 1 12 0v5l2 2H4l2-2zM10 20a2 2 0 0 0 4 0',
  check: 'M5 12l5 5L20 7',
  x: 'M6 6l12 12M18 6L6 18',
  alert: 'M12 3l10 18H2L12 3zM12 10v4M12 17.5v.5',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  eyeOff: 'M3 3l18 18M10.6 10.6A3 3 0 0 0 13.4 13.4M9.9 5.2A10.5 10.5 0 0 1 12 5c6 0 10 7 10 7a17 17 0 0 1-3 3.6M6.6 6.6C3.7 8.6 2 12 2 12s4 7 10 7c1.6 0 3-.4 4.3-1',
  arrowRight: 'M5 12h14M13 6l6 6-6 6',
  arrowUpRight: 'M7 17L17 7M8 7h9v9',
  plus: 'M12 5v14M5 12h14',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  sparkle: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3zM19 16l.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7.7-2z',
  terminal: 'M4 17l6-5-6-5M12 19h8',
  lock: 'M6 11h12v9H6zM9 11V8a3 3 0 0 1 6 0v3',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  chevronDown: 'M6 9l6 6 6-6',
  chevronRight: 'M9 6l6 6-6 6',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v5M12 8v.5',
  refresh: 'M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5',
  zap: 'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
  play: 'M7 5l12 7-12 7z',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2',
  key: 'M14 4a6 6 0 0 0-5.7 7.9L3 17.2V21h4l1-1v-2h2l1-1v-2h2l.9-.9A6 6 0 1 0 14 4zM15 9h.5',
  filter: 'M4 5h16l-6 8v6l-4-2v-4L4 5z',
  code: 'M8 6l-6 6 6 6M16 6l6 6-6 6',
  logout: 'M10 4H5v16h5M14 8l5 4-5 4M19 12H9',
  download: 'M12 4v11M7 10l5 5 5-5M4 20h16',
  layers: 'M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5',
  plane: 'M10 20l1-6-7-2 16-9-5 15-3-3-2 5z',
  tv: 'M3 6h18v11H3zM8 21h8',
  bag: 'M5 8h14l-1 12H6L5 8zM9 8V6a3 3 0 0 1 6 0v2',
  card: 'M3 6h18v12H3zM3 10h18M7 15h3',
  heart: 'M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z',
  doc: 'M6 3h9l4 4v14H6zM15 3v4h4M9 12h6M9 16h6',
  users: 'M9 12a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM2 20a7 7 0 0 1 14 0M16 5a3.5 3.5 0 0 1 0 7M18 13a6 6 0 0 1 4 7',
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  cloud: 'M7 18a4 4 0 0 1-.5-8A6 6 0 0 1 18 9a4 4 0 0 1 0 9H7z',
  dot: 'M12 12h.01',
}

export type IconName = keyof typeof P

export function Icon({ name, size = 18, stroke = 1.75, className, style }: {
  name: IconName; size?: number; stroke?: number; className?: string; style?: React.CSSProperties
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke}
      strokeLinecap="round" strokeLinejoin="round" className={className} style={{ flex: 'none', ...style }} aria-hidden>
      <path d={P[name]} />
    </svg>
  )
}
