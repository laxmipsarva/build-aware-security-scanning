import fs           from 'fs'
import path         from 'path'
import { spawnSync } from 'child_process'

// ── ANSI helpers ───────────────────────────────────────────────────────────────
const ANSI = /\x1b\[[0-9;]*m/g
const strip = s => String(s).replace(ANSI, '').replace(/\r/g, '')
const esc   = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')

// ── Capture state ──────────────────────────────────────────────────────────────
let _lines = []
let _orig  = null

export function startCapture() {
  _lines = []
  _orig  = console.log
  console.log = (...args) => {
    _orig(...args)
    _lines.push(args.map(a => String(a)).join(' '))
  }
}

function stopCapture() {
  if (_orig) { console.log = _orig; _orig = null }
  const out = _lines.slice()
  _lines = []
  return out
}

// ── Line classification ────────────────────────────────────────────────────────
function classify(raw) {
  const s = strip(raw)
  if (/^ {2,6}[✓✗?–]/.test(s)) {
    if (raw.includes('\x1b[32m')) return 'pass'
    if (raw.includes('\x1b[31m')) return 'fail'
    if (raw.includes('\x1b[33m')) return 'error'
    return 'skip'
  }
  const t = s.trim()
  if (raw.includes('▸'))                                              return 'section'
  if (t.startsWith('╔') || t.startsWith('╚') || t.startsWith('║'))  return 'box'
  if (/^(Target|Date|GraphQL|Framework|Endpoints)\s*:/.test(t))      return 'meta'
  if (/^ {2}(Passed|Failed|Error|Skipped|Total)/.test(s))            return 'stat'
  return 'info'
}

// Split a result line's stripped text into {icon, label, detail}
function splitResult(raw, stripped) {
  const t      = stripped.trim()
  const icon   = t[0]                       // ✓ ✗ ? –
  const rest   = t.slice(1).trimStart()

  // DIM portion (\x1b[2m…\x1b) becomes the detail
  const dimM   = raw.match(/\x1b\[2m([^\x1b]+)\x1b/)
  const detail = dimM ? strip(dimM[1]).trim() : ''
  const label  = detail ? rest.replace(detail, '').trimEnd() : rest

  return { icon, label, detail }
}

// ── HTML builder ───────────────────────────────────────────────────────────────
function buildHtml({ title, target, stats, sections, prelude }) {
  const hasSections = sections.length > 0
  const total       = stats ? Object.values(stats).reduce((a,b) => a+b, 0) : 0
  const verdict     = stats?.failed > 0 ? 'fail' : 'pass'
  const verdictText = stats?.failed > 0 ? `⚠ ${stats.failed} Vulnerabilit${stats.failed===1?'y':'ies'} Found` : '✓ All Tests Passed'
  const dateStr     = new Date().toLocaleString()

  // ── Stats cards ──
  const statsHtml = stats ? `
  <div class="stats">
    <div class="stat-card pass"><div class="num">${stats.passed}</div><div class="lbl">Passed</div></div>
    <div class="stat-card fail"><div class="num">${stats.failed}</div><div class="lbl">Failed</div></div>
    <div class="stat-card error"><div class="num">${stats.errored}</div><div class="lbl">Errors</div></div>
    <div class="stat-card skip"><div class="num">${stats.skipped}</div><div class="lbl">Skipped</div></div>
    <div class="stat-card total"><div class="num">${total}</div><div class="lbl">Total</div></div>
  </div>` : ''

  // ── Section items ──
  function renderItem(raw, stripped) {
    const type = classify(raw)
    if (!['pass','fail','error','skip'].includes(type)) {
      const t = stripped.trim()
      if (!t) return ''
      return `<div class="item info">${esc(t)}</div>`
    }
    const { icon, label, detail } = splitResult(raw, stripped)
    return `<div class="item ${type}">` +
      `<span class="icon">${esc(icon)}</span>` +
      `<span class="label">${esc(label)}</span>` +
      (detail ? `<span class="detail">${esc(detail)}</span>` : '') +
      `</div>`
  }

  // ── Sections (runtime scanners) ──
  const sectionsHtml = hasSections ? sections.map((s, i) => {
    const fails     = s.items.filter(x => x.type === 'fail').length
    const badge     = fails > 0
      ? `<span class="badge fail">${fails} FAIL</span>`
      : `<span class="badge pass">PASS</span>`
    const openAttr  = (i < 2 || fails > 0) ? ' open' : ''
    const failClass = fails > 0 ? ' has-failures' : ''

    const bodyHtml  = s.items.map(item => renderItem(item.raw, item.stripped)).join('')

    return `<details class="section${failClass}"${openAttr}>
      <summary>${badge} ${esc(s.title)}</summary>
      <div class="section-body">${bodyHtml || '<div class="item info">No results</div>'}</div>
    </details>`
  }).join('\n') : ''

  // ── Fallback: raw prelude for bass-list (no sections) ──
  const rawLines = prelude.map(p => p.text).join('\n')
  const preludeHtml = !hasSections
    ? `<pre class="raw">${esc(rawLines)}</pre>`
    : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;
  --pass:#2ea043;--fail:#da3633;--err:#d29922;--skip:#8b949e;--blue:#58a6ff;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --mono:'SF Mono','Cascadia Code','Fira Code',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;
  line-height:1.6;padding:28px 32px;max-width:1040px;margin:0 auto}
header{border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:22px}
.title-row{display:flex;align-items:center;gap:10px;margin-bottom:6px}
h1{font-size:20px;font-weight:600}
.verdict{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:500}
.verdict.pass{background:rgba(46,160,67,.15);color:#3fb950;border:1px solid rgba(46,160,67,.4)}
.verdict.fail{background:rgba(218,54,51,.15);color:#f85149;border:1px solid rgba(218,54,51,.4)}
.meta{color:var(--dim);font-size:12px}
.meta code{font-family:var(--mono);background:rgba(255,255,255,.06);padding:1px 6px;border-radius:3px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:22px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:14px;text-align:center}
.stat-card .num{font-size:30px;font-weight:700;line-height:1.1;margin-bottom:3px}
.stat-card .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim)}
.stat-card.pass .num{color:#3fb950}.stat-card.fail .num{color:#f85149}
.stat-card.error .num{color:#d29922}.stat-card.skip .num{color:var(--dim)}
.stat-card.total .num{color:var(--text)}
details.section{background:var(--card);border:1px solid var(--border);border-radius:8px;
  margin-bottom:8px;overflow:hidden}
details.section.has-failures{border-color:rgba(218,54,51,.5)}
details.section>summary{list-style:none;padding:10px 14px;cursor:pointer;font-weight:500;
  font-size:13px;display:flex;align-items:center;gap:8px;user-select:none;color:var(--text)}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary::before{content:'▶';font-size:9px;color:var(--dim);
  transition:transform .15s;flex-shrink:0}
details.section[open]>summary::before{transform:rotate(90deg)}
.section-body{border-top:1px solid var(--border);padding:6px 0}
.item{display:flex;align-items:baseline;gap:8px;padding:3px 16px;
  font-family:var(--mono);font-size:12.5px}
.item:hover{background:rgba(255,255,255,.03)}
.item .icon{width:14px;flex-shrink:0;font-weight:700}
.item .label{flex:1;word-break:break-all}
.item .detail{color:var(--dim);font-size:11.5px;flex-shrink:0;white-space:nowrap}
.item.pass .icon{color:#3fb950}.item.fail .icon{color:#f85149}
.item.error .icon{color:#d29922}.item.skip .icon{color:var(--dim)}
.item.info{color:var(--dim);font-family:var(--font);font-size:12px;padding-left:14px}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:600;flex-shrink:0}
.badge.fail{background:rgba(218,54,51,.2);color:#f85149}
.badge.pass{background:rgba(46,160,67,.2);color:#3fb950}
pre.raw{background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:18px;font-family:var(--mono);font-size:12.5px;color:var(--dim);
  overflow-x:auto;white-space:pre-wrap;line-height:1.7}
</style>
</head>
<body>
<header>
  <div class="title-row">
    <h1>${esc(title)}</h1>
    ${stats ? `<span class="verdict ${verdict}">${verdictText}</span>` : ''}
  </div>
  <div class="meta">Target: <code>${esc(target)}</code>&nbsp;&nbsp;·&nbsp;&nbsp;${esc(dateStr)}</div>
</header>
${statsHtml}
<main>
${hasSections ? sectionsHtml : preludeHtml}
</main>
</body>
</html>`
}

// ── Public API ─────────────────────────────────────────────────────────────────
export async function writeReport({ title, target, stats }) {
  const rawLines = stopCapture()

  // Parse into sections and prelude
  const sections = []
  const prelude  = []
  let   current  = null

  for (const raw of rawLines) {
    const type    = classify(raw)
    const stripped = strip(raw)
    if (!stripped.trim()) continue

    if (type === 'section') {
      current = { title: stripped.trim().replace(/^▸\s*/, ''), items: [] }
      sections.push(current)
    } else if (current) {
      current.items.push({ type, raw, stripped })
    } else {
      prelude.push({ type, text: stripped.trim() })
    }
  }

  const html    = buildHtml({ title, target, stats, sections, prelude })
  const ts      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const slug    = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
  const outFile = path.resolve(process.cwd(), `bass-report-${slug}-${ts}.html`)

  fs.writeFileSync(outFile, html, 'utf8')
  console.log(`\nHTML report → file://${outFile}`)

  try {
    const cmd = process.platform === 'win32' ? 'start'
              : process.platform === 'darwin' ? 'open'
              : 'xdg-open'
    spawnSync(cmd, [outFile], { detached: true, stdio: 'ignore', shell: process.platform === 'win32' })
  } catch { /* best-effort */ }
}
