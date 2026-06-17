import { fileURLToPath } from 'url'
import { startCapture, writeReport } from './html-reporter.mjs'

const R = '\x1b[0m', GREEN = '\x1b[32m', RED = '\x1b[31m',
      YLW = '\x1b[33m', BOLD = '\x1b[1m', DIM = '\x1b[2m', CYAN = '\x1b[36m', MAG = '\x1b[35m'

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

// ── CSRF-specific helpers ──────────────────────────────────────────────────────

// Known CSRF token field names across frameworks
const CSRF_FIELD_NAMES = [
  '_csrf', 'csrf_token', 'csrfToken', 'CSRFToken', 'csrf',
  'csrfmiddlewaretoken', 'authenticity_token', '__RequestVerificationToken',
  '_token', 'xsrf_token', 'gorilla.csrf.Token', 'X-CSRF-Token',
]

// Known CSRF cookie names
const CSRF_COOKIE_NAMES = [
  'XSRF-TOKEN', 'csrf_token', '_csrf', 'csrftoken', 'CSRF-TOKEN',
  'xsrf-token', '__csrf', 'csrf', 'CSRF', 'laravel_session',
]

// Scrapes CSRF token from a page's HTML, meta tags, or JSON body
async function extractCsrfToken(url, cookie) {
  const r = await req(url, {
    headers: { ...(cookie ? { Cookie: cookie } : {}), Accept: 'text/html,application/json,*/*' },
  })
  if (!r.body) return null

  // <meta name="csrf-token" content="...">  (Rails, Laravel style)
  const m1 = r.body.match(/<meta\s[^>]*name=["']([^"']*(?:csrf|xsrf|token)[^"']*)["'][^>]*content=["']([^"']{8,})["']/i)
          || r.body.match(/<meta\s[^>]*content=["']([^"']{8,})["'][^>]*name=["']([^"']*(?:csrf|xsrf|token)[^"']*)["']/i)
  if (m1) {
    // normalise: group 2 is content in first pattern, group 1 in second
    const token = m1[2]?.length > 8 ? m1[2] : m1[1]
    if (token?.length > 8) return { token, fieldName: m1[1] || m1[2], source: 'meta-tag' }
  }

  // <input type="hidden" name="_csrf" value="...">
  for (const name of CSRF_FIELD_NAMES) {
    const re  = new RegExp(`<input[^>]+name=["']${name}["'][^>]+value=["']([^"']{8,})["']`, 'i')
    const re2 = new RegExp(`<input[^>]+value=["']([^"']{8,})["'][^>]+name=["']${name}["']`, 'i')
    const m = r.body.match(re) || r.body.match(re2)
    if (m) return { token: m[1], fieldName: name, source: 'hidden-input' }
  }

  // JSON response: { csrfToken: '...', csrf_token: '...', token: '...' }
  for (const key of ['csrfToken', 'csrf_token', 'token', 'csrf', 'CSRF', '_csrf']) {
    if (typeof r.json?.[key] === 'string' && r.json[key].length > 8)
      return { token: r.json[key], fieldName: key, source: 'json-body' }
  }

  // CSRF cookie set by the response itself
  const sc = r.headers?.get?.('set-cookie') || ''
  for (const name of CSRF_COOKIE_NAMES) {
    const m = sc.match(new RegExp(`(?:^|,|;|\\s)${name}=([^;,\\s]{8,})`, 'i'))
    if (m) return { token: decodeURIComponent(m[1]), fieldName: name, cookieName: name, source: 'set-cookie' }
  }

  return null
}

// Pulls a named cookie value from a Cookie: header string
function cookieValue(cookieStr, name) {
  if (!cookieStr) return null
  const m = cookieStr.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`, 'i'))
  return m ? decodeURIComponent(m[1]) : null
}

// Parses SameSite attribute of the session cookie from Set-Cookie headers
function parseSameSite(setCookieHeader) {
  if (!setCookieHeader) return null
  const m = setCookieHeader.match(/samesite\s*=\s*(strict|lax|none)/i)
  return m ? m[1].toLowerCase() : 'none-missing'
}

// Extracts eTLD+1 hostname from a URL
function hostname(url) {
  try { return new URL(url).hostname } catch { return url }
}

// Returns common state-changing endpoint candidates from known endpoints or fallback paths
function stateTargets(base, endpoints) {
  const mutations = ['POST', 'PUT', 'PATCH', 'DELETE']
  const fromList  = endpoints
    .filter(e => mutations.includes(e.method))
    .filter(e => !/login|logout|auth|register|signup/i.test(e.path))
    .map(e => ({ method: e.method, url: `${base}${e.path.replace(/:([a-zA-Z_]+)/g, '1')}`, fields: e.bodyFields || [] }))

  const fallback = [
    '/api/user/update', '/api/profile', '/api/me', '/api/account',
    '/api/settings', '/api/password/change', '/api/email/change',
    '/account/change-email', '/account/change-password',
  ].map(p => ({ method: 'POST', url: `${base}${p}`, fields: [] }))

  return [...fromList, ...fallback]
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. CSRF VULNERABILITY WITH NO DEFENSES
// Submits a state-changing POST with an authenticated session but zero CSRF
// countermeasures: no token, no Origin, no Referer. Acceptance = vulnerable.
// ══════════════════════════════════════════════════════════════════════════════
export async function testNoDefenses(base, endpoints = [], cookie, result) {
  section('1 · CSRF vulnerability with no defenses')

  if (!cookie) { result('No session cookie provided', 'skip', 'CSRF tests require an authenticated session'); return }

  const targets = stateTargets(base, endpoints)
  console.log(`\n    ${DIM}Probing ${Math.min(targets.length, 6)} state-changing endpoints...${R}`)

  let testedAny = false
  for (const { method, url, fields } of targets.slice(0, 6)) {
    const r = await req(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie,
        // Deliberately omit Origin and Referer to simulate cross-origin request
      },
      body: JSON.stringify(Object.fromEntries(fields.map(f => [f, 'test']))),
    })
    if (r.status === 0 || r.status === 404) continue
    testedAny = true

    // 4xx without explicit CSRF rejection still means server rejected — check message
    const csrfRejected = r.status === 403 &&
      /csrf|forbidden|invalid token|cross.site/i.test(r.body)
    const accepted = r.status < 400

    result(`${method} ${url.replace(base, '')} — no token, no origin/referer`,
           accepted ? 'fail' : csrfRejected ? 'pass' : 'pass',
           accepted
             ? `HTTP ${r.status} — request accepted without any CSRF controls`
             : `HTTP ${r.status}${csrfRejected ? ' — CSRF token required' : ''}`)
  }

  if (!testedAny) result('No reachable state-changing endpoints found', 'skip', 'add endpoint list or expand fallback paths')
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. CSRF TOKEN VALIDATION DEPENDS ON REQUEST METHOD
// Server validates CSRF token on POST but silently accepts GET for the same
// state-changing action. An attacker can trigger the action via a GET request
// (e.g., <img src="...">) without ever needing a CSRF token.
// ══════════════════════════════════════════════════════════════════════════════
export async function testMethodDependentToken(base, endpoints = [], cookie, result) {
  section('2 · CSRF token validation depends on request method')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const targets = stateTargets(base, endpoints)

  for (const { method, url, fields } of targets.slice(0, 5)) {
    const headers = { 'Content-Type': 'application/json', Cookie: cookie }

    // Baseline: POST with an obviously wrong token → should be 403 if CSRF is enforced
    const wrongTokenBody  = { ...Object.fromEntries(fields.map(f => [f, 'test'])), _csrf: 'invalid-token-xyz' }
    const rPostWrong = await req(url, { method: 'POST', headers, body: JSON.stringify(wrongTokenBody) })
    if (rPostWrong.status === 0 || rPostWrong.status === 404) continue

    // GET version of the same endpoint (params in query string)
    const qs      = fields.length ? '?' + fields.map(f => `${f}=test`).join('&') : ''
    const rGet    = await req(`${url}${qs}`, { method: 'GET', headers })

    // If POST with wrong token → 403, but GET → 2xx: token only enforced on POST
    const postBlocked = rPostWrong.status === 403 || rPostWrong.status === 401
    const getAccepted = rGet.ok

    if (postBlocked && getAccepted) {
      result(`GET bypasses CSRF check on ${url.replace(base, '')}`,
             'fail',
             `POST with wrong token → ${rPostWrong.status}, GET → ${rGet.status}`)
    } else if (!postBlocked) {
      result(`${url.replace(base, '')} — POST with wrong token accepted`,
             'fail',
             `HTTP ${rPostWrong.status} — CSRF token not validated at all`)
    } else {
      result(`${url.replace(base, '')}`,
             'pass',
             `POST wrong token → ${rPostWrong.status}, GET → ${rGet.status}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. CSRF TOKEN VALIDATION DEPENDS ON TOKEN BEING PRESENT
// Server validates the token when it is present in the request, but if the
// parameter is simply omitted the validation is skipped entirely.
// ══════════════════════════════════════════════════════════════════════════════
export async function testTokenPresenceDependence(base, endpoints = [], cookie, result) {
  section('3 · CSRF token validation depends on token being present')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const targets = stateTargets(base, endpoints)

  for (const { method, url, fields } of targets.slice(0, 5)) {
    const headers = { 'Content-Type': 'application/json', Cookie: cookie }
    const baseBody = Object.fromEntries(fields.map(f => [f, 'test']))

    // 1. POST with an invalid token → should be 403 if CSRF validation is active
    const rWithWrong = await req(url, {
      method, headers,
      body: JSON.stringify({ ...baseBody, _csrf: 'obviously-invalid-csrf-token' }),
    })
    if (rWithWrong.status === 0 || rWithWrong.status === 404) continue

    // 2. POST with token field completely omitted
    const rNoToken = await req(url, { method, headers, body: JSON.stringify(baseBody) })

    const wrongRejected  = rWithWrong.status === 403 || rWithWrong.status === 401
    const absentAccepted = rNoToken.ok || rNoToken.status < 400

    if (wrongRejected && absentAccepted) {
      result(`Omitting token bypasses CSRF on ${url.replace(base, '')}`,
             'fail',
             `invalid token → ${rWithWrong.status}, absent token → ${rNoToken.status}`)
    } else if (!wrongRejected) {
      result(`${url.replace(base, '')} — invalid token not rejected`,
             'err',
             `HTTP ${rWithWrong.status} — check if CSRF protection exists at all`)
    } else {
      result(`${url.replace(base, '')}`,
             'pass',
             `absent token → ${rNoToken.status} — both paths rejected`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. CSRF TOKEN NOT TIED TO USER SESSION
// The CSRF token is validated but is a global/static value not bound to the
// current session. An attacker can obtain their own valid token and reuse it
// against any victim, because server never checks token ↔ session pairing.
// ══════════════════════════════════════════════════════════════════════════════
export async function testTokenNotTiedToSession(base, endpoints = [], cookie, result) {
  section('4 · CSRF token not tied to user session')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  // Obtain a CSRF token from the app (as an "attacker" who has their own account)
  const tokenInfo = await extractCsrfToken(base, cookie)

  if (!tokenInfo) {
    result('Could not extract a CSRF token from the app', 'skip',
           'try pointing at a page that contains the CSRF token')
    return
  }

  console.log(`\n    ${DIM}Extracted token (source: ${tokenInfo.source}): ${tokenInfo.token.slice(0, 16)}...${R}`)

  const targets = stateTargets(base, endpoints)

  for (const { method, url, fields } of targets.slice(0, 4)) {
    const baseBody = Object.fromEntries(fields.map(f => [f, 'test']))
    const csrfBody = { ...baseBody, [tokenInfo.fieldName]: tokenInfo.token }

    // Send with the extracted token but with a DIFFERENT (tampered) session cookie
    // Simulates attacker's token used against a victim whose session is unknown
    const tamperedSession = cookie.replace(/=([^;]+)/, '=tampered_session_xyz_csrf_test')
    const rCrossSession = await req(url, {
      method,
      headers: { 'Content-Type': 'application/json', Cookie: tamperedSession },
      body: JSON.stringify(csrfBody),
    })
    if (rCrossSession.status === 0 || rCrossSession.status === 404) continue

    // Also send the token with NO session at all
    const rNoSession = await req(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(csrfBody),
    })

    const crossAccepted = rCrossSession.ok
    const noSessAccepted = rNoSession.ok

    if (crossAccepted) {
      result(`Token from session A works with tampered session on ${url.replace(base, '')}`,
             'fail',
             `HTTP ${rCrossSession.status} — CSRF token not bound to session`)
    } else if (noSessAccepted) {
      result(`Token works without any session cookie on ${url.replace(base, '')}`,
             'fail',
             `HTTP ${rNoSession.status} — token is session-independent`)
    } else {
      result(`${url.replace(base, '')}`,
             'pass',
             `cross-session: ${rCrossSession.status}, no-session: ${rNoSession.status}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. CSRF TOKEN TIED TO A NON-SESSION COOKIE
// The CSRF token is stored in a separate cookie (e.g. XSRF-TOKEN) rather than
// being tied to the server-side session. The server only checks that the cookie
// value matches the request body/header value — both of which an attacker can
// set by exploiting subdomain cookie injection.
// ══════════════════════════════════════════════════════════════════════════════
export async function testTokenTiedToNonSessionCookie(base, endpoints = [], cookie, result) {
  section('5 · CSRF token tied to non-session cookie')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  // Check for a dedicated CSRF cookie alongside the session cookie
  const rBase = await req(base, { headers: { Cookie: cookie } })
  const setCookieHeader = rBase.headers?.get?.('set-cookie') || ''

  let csrfCookieName = null
  let csrfCookieValue = null
  for (const name of CSRF_COOKIE_NAMES) {
    const m = setCookieHeader.match(new RegExp(`(?:^|,|\\s)${name}=([^;,\\s]{8,})`, 'i'))
    if (m) { csrfCookieName = name; csrfCookieValue = decodeURIComponent(m[1]); break }
  }

  // Also check if the existing cookie string already has a CSRF cookie
  if (!csrfCookieName) {
    for (const name of CSRF_COOKIE_NAMES) {
      const v = cookieValue(cookie, name)
      if (v && v.length >= 8) { csrfCookieName = name; csrfCookieValue = v; break }
    }
  }

  if (!csrfCookieName) {
    result('No dedicated CSRF cookie detected', 'pass',
           'CSRF token appears to be session-bound (not a separate cookie)')
    return
  }

  console.log(`\n    ${DIM}CSRF cookie detected: ${csrfCookieName}=${csrfCookieValue?.slice(0,16)}...${R}`)
  result(`Separate CSRF cookie found: ${csrfCookieName}`, 'fail',
         'token is in a cookie, not the session — attacker can inject matching cookie+body pair via subdomain')

  // Forge attack: craft an attacker-controlled CSRF value and inject it in both
  // the Cookie header and the body/header field simultaneously
  const attackerToken = 'attacker-forged-csrf-token-12345'
  const sessionOnly   = cookie.replace(new RegExp(`(?:^|;\\s*)${csrfCookieName}=[^;]*`, 'i'), '').trim().replace(/^;/, '').trim()
  const forgedCookies = `${sessionOnly}; ${csrfCookieName}=${attackerToken}`

  const targets = stateTargets(base, endpoints)
  for (const { method, url, fields } of targets.slice(0, 3)) {
    const body = {
      ...Object.fromEntries(fields.map(f => [f, 'test'])),
      [csrfCookieName.toLowerCase().replace(/-/g, '_')]: attackerToken,
      _csrf: attackerToken,
    }

    // Also try via header (Angular / Axios pattern)
    const rHeader = await req(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Cookie: forgedCookies,
        'X-XSRF-TOKEN': attackerToken,
        'X-CSRF-Token': attackerToken,
      },
      body: JSON.stringify(body),
    })
    if (rHeader.status === 0 || rHeader.status === 404) continue

    const accepted = rHeader.ok
    result(`Forged cookie+body/header CSRF on ${url.replace(base, '')}`,
           accepted ? 'fail' : 'pass',
           accepted
             ? `HTTP ${rHeader.status} — both token slots attacker-controlled`
             : `HTTP ${rHeader.status}`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. CSRF TOKEN DUPLICATED IN COOKIE (DOUBLE-SUBMIT COOKIE PATTERN)
// Server validates that the CSRF value in the request body/header matches the
// value in a CSRF cookie — but does not tie either to the server-side session.
// An attacker who can plant a cookie (e.g. via a subdomain) forges both.
// ══════════════════════════════════════════════════════════════════════════════
export async function testDuplicateCookieToken(base, endpoints = [], cookie, result) {
  section('6 · CSRF token duplicated in cookie (double-submit cookie pattern)')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  // Probe a state-changing endpoint to observe whether double-submit pattern is in use
  const targets = stateTargets(base, endpoints)
  let doubleSubmitDetected = false

  // Craft a completely attacker-controlled CSRF value
  const FORGED = 'double-submit-forged-csrf-99887766'
  const sessionCookiePart = cookie  // keep the real session, append our forged CSRF cookie

  for (const { method, url, fields } of targets.slice(0, 4)) {
    // Build body with forged token matching all known field names
    const baseBody = Object.fromEntries(fields.map(f => [f, 'test']))
    const forgedBody = {
      ...baseBody,
      ...Object.fromEntries(CSRF_FIELD_NAMES.map(n => [n, FORGED])),
    }

    // Send with session cookie + forged CSRF cookie injected
    const cookieWithForged = `${sessionCookiePart}; ${CSRF_COOKIE_NAMES[0]}=${FORGED}; _csrf=${FORGED}`

    const [rForged, rNoToken] = await Promise.all([
      req(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieWithForged,
          'X-CSRF-Token': FORGED,
          'X-XSRF-TOKEN': FORGED,
        },
        body: JSON.stringify(forgedBody),
      }),
      req(url, {
        method,
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify(baseBody),   // no CSRF token
      }),
    ])

    if (rForged.status === 0 || rForged.status === 404) continue

    const forgedAccepted = rForged.ok
    const noTokenRejected = !rNoToken.ok

    if (forgedAccepted && noTokenRejected) {
      doubleSubmitDetected = true
      result(`Double-submit forged cookie accepted on ${url.replace(base, '')}`,
             'fail',
             `forged: HTTP ${rForged.status}, no-token: HTTP ${rNoToken.status} — token not session-bound`)
    } else if (forgedAccepted) {
      result(`Forged double-submit accepted on ${url.replace(base, '')}`,
             'fail',
             `HTTP ${rForged.status} — cookie+body both attacker-controlled`)
    } else {
      result(`${url.replace(base, '')}`,
             'pass',
             `forged → ${rForged.status}, no-token → ${rNoToken.status}`)
    }
  }

  if (!doubleSubmitDetected) {
    result('Double-submit cookie pattern: no bypass detected', 'pass',
           'server either does not use this pattern or validates against session')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. SAMESITE LAX BYPASS VIA METHOD OVERRIDE
// Browsers send SameSite=Lax cookies on top-level cross-site GET requests but
// NOT on cross-site POST requests. Some frameworks honour a _method query param
// or X-HTTP-Method-Override header to change effective method server-side, so a
// POST that carries Lax cookies can masquerade as GET at the routing layer.
// ══════════════════════════════════════════════════════════════════════════════
export async function testSameSiteLaxMethodOverride(base, endpoints = [], cookie, result) {
  section('7 · SameSite Lax bypass via method override')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  // Detect the SameSite attribute in use
  const rHome = await req(base, { headers: { Cookie: cookie } })
  const setCookie = rHome.headers?.get?.('set-cookie') || ''
  const sameSite  = parseSameSite(setCookie)

  if (setCookie) {
    if (sameSite === 'strict') {
      result(`Session cookie SameSite=Strict detected`, 'pass',
             'Strict blocks all cross-site requests — method override not relevant (see test 8)')
    } else if (sameSite === 'none-missing') {
      result(`Session cookie has no SameSite attribute`, 'fail',
             'cookies sent on all cross-site requests — trivially vulnerable to CSRF (test 1)')
    } else {
      result(`Session cookie SameSite=Lax detected`, 'fail',
             'Lax only blocks cross-site POSTs — GET-equivalent overrides bypass it')
    }
  }

  // Method override techniques to convert a cross-site POST into server-side GET
  const METHOD_OVERRIDES = [
    { label: '_method=GET query param',      extra: { url: '?_method=GET' },             headers: {} },
    { label: 'X-HTTP-Method-Override: GET',  extra: {},                                   headers: { 'X-HTTP-Method-Override': 'GET' } },
    { label: 'X-Method-Override: GET',       extra: {},                                   headers: { 'X-Method-Override': 'GET' } },
    { label: 'X-HTTP-Method: GET',           extra: {},                                   headers: { 'X-HTTP-Method': 'GET' } },
    { label: '_method=GET in body',          extra: { bodyExtra: { _method: 'GET' } },    headers: {} },
  ]

  // Find POST endpoints that also respond to GET (state-changing via GET)
  const postEndpoints = (endpoints.filter(e => e.method === 'POST').slice(0, 3))
  if (!postEndpoints.length) {
    result('Method override test', 'skip', 'no POST endpoints found — provide an endpoint list')
    return
  }

  for (const ep of postEndpoints) {
    const url  = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    const body = Object.fromEntries((ep.bodyFields || []).map(f => [f, 'test']))

    // Baseline: direct GET on a POST-only endpoint should be 405
    const rGetBaseline = await req(url, { method: 'GET', headers: { Cookie: cookie } })
    const baselineStatus = rGetBaseline.status

    for (const { label, extra, headers: extraHeaders } of METHOD_OVERRIDES) {
      const targetUrl = url + (extra.url || '')
      const reqBody   = { ...body, ...(extra.bodyExtra || {}) }

      const r = await req(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie, ...extraHeaders },
        body: JSON.stringify(reqBody),
      })
      if (r.status === 0) continue

      // Vulnerable: override changed behavior vs direct GET
      const overrideAccepted = r.ok && baselineStatus >= 400
      result(`${label} on POST ${ep.path}`,
             overrideAccepted ? 'fail' : 'pass',
             overrideAccepted
               ? `HTTP ${r.status} (direct GET → ${baselineStatus}) — override accepted, Lax bypass possible`
               : `HTTP ${r.status}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. SAMESITE STRICT BYPASS VIA CLIENT-SIDE REDIRECT
// SameSite=Strict blocks cross-site requests, but a JavaScript redirect issued
// from within the same site is a same-site navigation — the browser will attach
// Strict cookies to the redirected request. An open-redirect endpoint on the
// target site lets an attacker chain: evil.com → same-site redirect → /action.
// ══════════════════════════════════════════════════════════════════════════════
export async function testSameSiteStrictRedirect(base, endpoints = [], cookie, result) {
  section('8 · SameSite Strict bypass via client-side redirect')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const rHome = await req(base, { headers: { Cookie: cookie } })
  const sameSite = parseSameSite(rHome.headers?.get?.('set-cookie') || '')
  if (sameSite === 'lax' || sameSite === 'none-missing') {
    result(`SameSite is not Strict (${sameSite})`, 'skip',
           'open-redirect bypass is most impactful against Strict; check test 7 instead')
  }

  // Common open-redirect parameter names
  const REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'returnUrl', 'returnTo',
                            'redirect_uri', 'goto', 'target', 'destination', 'to', 'location']
  // Common redirect endpoint paths
  const REDIRECT_PATHS  = [
    '/redirect', '/go', '/out', '/external', '/link', '/forward',
    '/auth/callback', '/oauth/callback', '/sso/callback',
    '/login', '/logout', '/auth/login',
  ]

  const origin      = hostname(base)
  const internalUrl = `${base}/api/user`  // benign same-site URL to test chain

  let openRedirectFound = false
  console.log(`\n    ${DIM}Probing ${REDIRECT_PATHS.length} redirect paths × ${REDIRECT_PARAMS.length} params...${R}`)

  for (const path of REDIRECT_PATHS) {
    for (const param of REDIRECT_PARAMS.slice(0, 4)) {
      const url = `${base}${path}?${param}=${encodeURIComponent(internalUrl)}`
      const r   = await req(url, { headers: { Cookie: cookie } })

      // A redirect to an internal URL we control = open redirect confirmed
      if ((r.status === 301 || r.status === 302 || r.status === 307 || r.status === 308)) {
        const loc = r.headers?.get?.('location') || ''
        if (loc.startsWith('/') || loc.includes(origin)) {
          // Redirects to same-site — not immediately exploitable but informational
          result(`Same-site redirect at ${path}?${param}=...`, 'pass',
                 `→ ${loc.slice(0, 60)} (same-site, not exploitable)`)
        } else if (loc) {
          openRedirectFound = true
          result(`Open redirect at ${path}?${param}=...`, 'fail',
                 `→ ${loc.slice(0, 80)} — cross-site redirect allows SameSite=Strict bypass chain`)
        }
      }
    }
  }

  if (!openRedirectFound) {
    result('No open-redirect endpoints found', 'pass',
           'SameSite=Strict client-side redirect bypass path not detected')
  }

  // Also probe for JavaScript-based redirects (window.location) in responses
  const jsRedirectEndpoints = endpoints.filter(e => e.method === 'GET').slice(0, 3)
  for (const ep of jsRedirectEndpoints) {
    const r = await req(`${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`, {
      headers: { Cookie: cookie, Accept: 'text/html' },
    })
    if (/window\.location\s*=\s*["']([^"']+)["']/.test(r.body)) {
      const m = r.body.match(/window\.location\s*=\s*["']([^"']+)["']/)
      result(`JS redirect in ${ep.path}: window.location = "${m?.[1]?.slice(0, 60)}"`,
             m?.[1]?.startsWith('http') ? 'fail' : 'pass',
             m?.[1]?.startsWith('http')
               ? 'external JS redirect could be exploitable as same-site hop'
               : 'relative redirect — safe')
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 9. SAMESITE STRICT BYPASS VIA SIBLING DOMAIN
// Browsers define "same-site" as eTLD+1 — all subdomains of example.com are
// same-site to each other. XSS on staging.example.com or a CORS-permissive
// subdomain allows cross-origin requests to app.example.com with Strict cookies.
// ══════════════════════════════════════════════════════════════════════════════
export async function testSameSiteSiblingDomain(base, endpoints = [], cookie, result) {
  section('9 · SameSite Strict bypass via sibling domain')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const origin = new URL(base.startsWith('http') ? base : `http://${base}`)
  const host   = origin.hostname   // e.g. app.example.com
  const parts  = host.split('.')
  // eTLD+1 for common TLDs (simplified — adequate for penetration testing)
  const etld1  = parts.length >= 2 ? parts.slice(-2).join('.') : host

  console.log(`\n    ${DIM}Target: ${host}  |  eTLD+1: ${etld1}${R}`)

  // 9a. CORS: does the server accept credentialed requests from a sibling subdomain?
  const SIBLING_SUBDOMAINS = [
    `staging.${etld1}`, `dev.${etld1}`, `test.${etld1}`,
    `uploads.${etld1}`, `static.${etld1}`, `cdn.${etld1}`,
    `assets.${etld1}`, `media.${etld1}`, `api.${etld1}`,
    `old.${etld1}`, `beta.${etld1}`, `www.${etld1}`,
  ].filter(s => s !== host)

  let siblingCorsVuln = false

  for (const sibling of SIBLING_SUBDOMAINS) {
    const r = await req(`${origin.protocol}//${host}${origin.pathname || '/'}`, {
      method: 'OPTIONS',
      headers: {
        Origin: `${origin.protocol}//${sibling}`,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
        ...(cookie ? { Cookie: cookie } : {}),
      },
    })

    const acao = r.headers?.get?.('access-control-allow-origin')  || ''
    const acac = r.headers?.get?.('access-control-allow-credentials') || ''

    if ((acao === `${origin.protocol}//${sibling}` || acao === '*') &&
        acac.toLowerCase() === 'true') {
      siblingCorsVuln = true
      result(`CORS allows credentialed requests from sibling: ${sibling}`, 'fail',
             `ACAO: ${acao}, ACAC: ${acac} — XSS on ${sibling} = full CSRF on ${host}`)
    } else if (acao && acao !== 'null' && acao !== '') {
      result(`CORS allows ${sibling} (no credentials)`, 'pass',
             `ACAO: ${acao}, ACAC: ${acac}`)
    }
  }

  if (!siblingCorsVuln) {
    result('No sibling-domain CORS misconfiguration detected', 'pass',
           `${etld1} subdomains not accepted with credentials`)
  }

  // 9b. Domain cookie attribute — does the session cookie scope to the whole eTLD+1?
  const rCheck  = await req(base, { headers: { Cookie: cookie } })
  const scHeader = rCheck.headers?.get?.('set-cookie') || ''
  const domainM  = scHeader.match(/domain\s*=\s*([^;,\s]+)/i)
  const cookieDomain = domainM?.[1]

  if (cookieDomain && (cookieDomain === `.${etld1}` || cookieDomain === etld1)) {
    result(`Session cookie Domain=.${etld1} — all subdomains receive it`, 'fail',
           'cookie scoped to eTLD+1 means sibling subdomains can make authenticated requests')
  } else if (cookieDomain) {
    result(`Session cookie Domain=${cookieDomain}`, 'pass',
           `restricted to ${cookieDomain}`)
  } else if (scHeader) {
    result('Session cookie has no Domain attribute', 'pass',
           `defaults to ${host} only — subdomains excluded`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 10. SAMESITE LAX BYPASS VIA COOKIE REFRESH
// Chrome grants a 2-minute window where a freshly-set SameSite=Lax cookie is
// treated as if it has no SameSite restriction (sent even on cross-site POSTs).
// If an attacker can trigger a cookie-refresh on the victim (e.g. by embedding
// an OAuth flow that sets a new session cookie) they have a ~120-second window.
// ══════════════════════════════════════════════════════════════════════════════
export async function testSameSiteLaxCookieRefresh(base, endpoints = [], cookie, result) {
  section('10 · SameSite Lax bypass via cookie refresh')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  // 10a. Detect cookie-refresh / session-renew endpoints
  const REFRESH_PATHS = [
    '/auth/refresh', '/api/auth/refresh', '/api/refresh', '/token/refresh',
    '/session/refresh', '/api/session', '/auth/session',
    '/oauth/authorize', '/oauth/token', '/auth/oauth',
    '/api/auth/session', '/auth/signin', '/login',
  ]

  let refreshEndpoint = null
  console.log(`\n    ${DIM}Searching for cookie-refresh endpoints...${R}`)

  for (const p of REFRESH_PATHS) {
    const r = await req(`${base}${p}`, {
      method: 'GET',
      headers: { Cookie: cookie },
    })
    if (r.status === 0 || r.status === 404) continue
    const sc = r.headers?.get?.('set-cookie') || ''
    if (sc && sc.length > 0) {
      const sameSite = parseSameSite(sc)
      if (sameSite === 'lax' || sameSite === 'none-missing') {
        refreshEndpoint = p
        result(`Cookie-refresh endpoint found: GET ${p}`, 'fail',
               `Sets new ${sameSite === 'lax' ? 'SameSite=Lax' : 'no-SameSite'} cookie — 2-min grace window exploitable`)
        break
      }
    }
  }

  if (!refreshEndpoint) {
    result('No cookie-refresh endpoint found in common paths', 'pass',
           'no refresh endpoint detected — grace-period exploit path not found')
  }

  // 10b. Check if session cookie uses SameSite=Lax (required for this attack)
  const rBase   = await req(base, { headers: { Cookie: cookie } })
  const scBase  = rBase.headers?.get?.('set-cookie') || ''
  const sameSite = parseSameSite(scBase)

  if (scBase) {
    if (sameSite === 'lax') {
      result('Session cookie is SameSite=Lax', 'fail',
             'Lax + cookie-refresh endpoint = 2-minute CSRF window; attacker triggers refresh then immediately POSTs')
    } else if (sameSite === 'strict') {
      result('Session cookie is SameSite=Strict', 'pass',
             'Strict cookies are not affected by the 2-minute Lax grace period')
    } else if (sameSite === 'none-missing') {
      result('Session cookie has no SameSite attribute', 'fail',
             'cookies sent on all cross-site requests — basic CSRF without refresh needed (see test 1)')
    }
  } else {
    result('SameSite detection', 'skip', 'no Set-Cookie header observed on base request')
  }

  // 10c. OAuth/OIDC implicit flow that sets cookies cross-site
  const oauthPaths = ['/oauth/authorize', '/auth/oauth', '/connect/authorize', '/auth/google', '/auth/github']
  for (const p of oauthPaths) {
    const r = await req(`${base}${p}`, { method: 'GET', headers: { Cookie: cookie } })
    if (r.status < 400 && (r.headers?.get?.('set-cookie') || '')) {
      result(`OAuth endpoint ${p} sets cookie`, 'fail',
             `HTTP ${r.status} — OAuth flow that sets Lax cookies enables cookie-refresh exploit`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 11. CSRF WHERE REFERER VALIDATION DEPENDS ON HEADER BEING PRESENT
// Server validates the Referer header when it is present — but if the header is
// entirely absent, the check is skipped and the request proceeds. Attackers use
// <meta name="referrer" content="no-referrer"> to suppress the header.
// ══════════════════════════════════════════════════════════════════════════════
export async function testRefererPresenceDependence(base, endpoints = [], cookie, result) {
  section('11 · CSRF Referer validation depends on header being present')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const targets = stateTargets(base, endpoints)
  const origin  = base.replace(/\/api.*$/, '')

  for (const { method, url, fields } of targets.slice(0, 5)) {
    const body    = JSON.stringify(Object.fromEntries(fields.map(f => [f, 'test'])))
    const headers = { 'Content-Type': 'application/json', Cookie: cookie }

    const [rValid, rInvalid, rAbsent] = await Promise.all([
      // Valid Referer: same origin
      req(url, { method, headers: { ...headers, Referer: `${origin}/some-page` }, body }),
      // Invalid Referer: attacker's origin
      req(url, { method, headers: { ...headers, Referer: 'https://evil-attacker.com/' }, body }),
      // Absent Referer: simulates <meta name="referrer" content="no-referrer">
      req(url, { method, headers, body }),  // no Referer key at all
    ])

    if (rValid.status === 0 || rValid.status === 404) continue

    const invalidBlocked = rInvalid.status === 403 || rInvalid.status === 401
    const absentAccepted = rAbsent.ok

    if (invalidBlocked && absentAccepted) {
      result(`Absent Referer bypasses check on ${url.replace(base, '')}`,
             'fail',
             `valid → ${rValid.status}, evil → ${rInvalid.status}, absent → ${rAbsent.status}`)
    } else if (!invalidBlocked && rValid.ok) {
      result(`${url.replace(base, '')} — no Referer validation detected`,
             'err',
             `valid: ${rValid.status}, evil: ${rInvalid.status}, absent: ${rAbsent.status}`)
    } else {
      result(`${url.replace(base, '')}`,
             'pass',
             `absent Referer → ${rAbsent.status}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 12. CSRF WITH BROKEN REFERER VALIDATION
// Server checks that the Referer header contains the expected domain, but the
// check uses a weak contains/startsWith pattern that can be bypassed by crafting
// a Referer URL where the expected domain appears as a subdomain, query param,
// or path segment of an attacker-controlled origin.
// ══════════════════════════════════════════════════════════════════════════════
export async function testBrokenRefererValidation(base, endpoints = [], cookie, result) {
  section('12 · CSRF with broken Referer validation')

  if (!cookie) { result('No session cookie provided', 'skip'); return }

  const targets = stateTargets(base, endpoints)
  const domain  = hostname(base).replace(/:\d+$/, '')  // strip port

  // Bypass payloads — each puts the legitimate domain somewhere unexpected
  const BYPASS_REFERERS = [
    { label: `Domain as subdomain of evil:  ${domain}.evil.com`,  value: `https://${domain}.evil.com/csrf` },
    { label: `Domain in query string:       evil.com?${domain}`,  value: `https://evil.com/?${domain}` },
    { label: `Domain in path:               evil.com/${domain}`,  value: `https://evil.com/${domain}/page` },
    { label: `Domain with extra prefix:     notlegit${domain}`,   value: `https://notlegit${domain}/path` },
    { label: `null Referer`,                                       value: 'null' },
    { label: `Referer only domain (no schema)`,                   value: domain },
    { label: `HTTP instead of HTTPS:        http://${domain}`,    value: `http://${domain}/page` },
  ]

  for (const { method, url, fields } of targets.slice(0, 3)) {
    const body    = JSON.stringify(Object.fromEntries(fields.map(f => [f, 'test'])))
    const headers = { 'Content-Type': 'application/json', Cookie: cookie }

    // Baseline: is Referer validation active at all?
    const rLegit  = await req(url, { method, headers: { ...headers, Referer: `${base}/page` }, body })
    const rEvil   = await req(url, { method, headers: { ...headers, Referer: 'https://evil.com/' }, body })
    if (rLegit.status === 0 || rLegit.status === 404) continue

    const validationActive = rEvil.status === 403 || rEvil.status === 401
    if (!validationActive) {
      result(`${url.replace(base, '')} — Referer validation not active`, 'skip',
             `evil Referer → ${rEvil.status}`)
      continue
    }

    // Now test each bypass
    for (const { label, value } of BYPASS_REFERERS) {
      const r = await req(url, { method, headers: { ...headers, Referer: value }, body })
      const bypassed = r.ok

      result(`${label}  [${method} ${url.replace(base, '')}]`,
             bypassed ? 'fail' : 'pass',
             bypassed
               ? `HTTP ${r.status} — weak contains() check bypassed`
               : `HTTP ${r.status}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// FULL SUITE RUNNER
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the complete CSRF security test suite.
 * @param {object}   opts
 * @param {string}   opts.base        Full API base URL
 * @param {object[]} [opts.endpoints] Endpoint list from scanProject()
 * @param {string}   [opts.cookie]    Authenticated session cookie string
 */
export async function runCsrfTests({ base, endpoints = [], cookie } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  try {
    await fetch(base, { signal: AbortSignal.timeout(4000) })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${base}${R}`)
    process.exit(1)
  }

  await testNoDefenses(base, endpoints, cookie, result)
  await testMethodDependentToken(base, endpoints, cookie, result)
  await testTokenPresenceDependence(base, endpoints, cookie, result)
  await testTokenNotTiedToSession(base, endpoints, cookie, result)
  await testTokenTiedToNonSessionCookie(base, endpoints, cookie, result)
  await testDuplicateCookieToken(base, endpoints, cookie, result)
  await testSameSiteLaxMethodOverride(base, endpoints, cookie, result)
  await testSameSiteStrictRedirect(base, endpoints, cookie, result)
  await testSameSiteSiblingDomain(base, endpoints, cookie, result)
  await testSameSiteLaxCookieRefresh(base, endpoints, cookie, result)
  await testRefererPresenceDependence(base, endpoints, cookie, result)
  await testBrokenRefererValidation(base, endpoints, cookie, result)

  return stats
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const base     = argv.find(a => a.startsWith('http')) || 'http://localhost:3000'
  const email    = process.env.TEST_EMAIL    || ''
  const password = process.env.TEST_PASSWORD || ''

  startCapture()
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  CSRF Security Test Suite                    ║`)
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
    console.log(`\n${YLW}⚠  No session cookie — most tests will be skipped.`)
    console.log(`   Set TEST_EMAIL and TEST_PASSWORD env vars to authenticate.${R}`)
  }

  const stats = await runCsrfTests({ base, endpoints, cookie })

  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  Results                                     ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`  ${GREEN}Passed  (safe)       : ${stats.passed}${R}`)
  console.log(`  ${RED}Failed  (vulnerable) : ${stats.failed}${R}`)
  console.log(`  ${YLW}Errors               : ${stats.errored}${R}`)
  console.log(`  ${DIM}Skipped              : ${stats.skipped}${R}`)
  console.log(`  Total                : ${total}`)

  await writeReport({ title: 'CSRF Security Test Suite', target: base, stats })

  if (stats.failed > 0) {
    console.log(`\n${RED}${BOLD}⚠  Vulnerabilities found — review FAIL lines above.${R}\n`)
    process.exit(1)
  } else {
    console.log(`\n${GREEN}${BOLD}✓  All executed tests passed.${R}\n`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
