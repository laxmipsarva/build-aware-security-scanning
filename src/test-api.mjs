import { fileURLToPath } from 'url'

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

// fill in a sample value for a known field name
function sampleValue(field) {
  const map = {
    email: 'test@example.com', password: 'test123', name: 'TestName',
    id: '1', pid: '1', slug: 'test', page: '1', limit: '10',
    pondName: 'TestPond', pondType: 'Freshwater', pondLength: '10',
    pondWidth: '5', pondDepth: '2', pondLocation: 'Zone A', pondStatus: 'Active',
    seeds: '100', species: 'Tilapia', price: '50', date: '2024-01-01', currency: 'INR',
    fn: 'John', ln: 'Doe', phone: '9999999999', code: '+91',
  }
  return map[field] ?? 'test'
}

// build a minimal valid body from known field names
function buildBody(fields = []) {
  return Object.fromEntries(fields.map(f => [f, sampleValue(f)]))
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. EXPLOITING API ENDPOINTS USING DOCUMENTATION
// Looks for exposed API docs (Swagger / OpenAPI / GraphQL) and checks whether
// undocumented or admin-only endpoints are accessible.
// ══════════════════════════════════════════════════════════════════════════════
export async function testDocumentationExploitation(base, endpoints = [], cookie, result) {
  section('1 · Exploiting API endpoints using documentation')

  // Strip path from base to get origin  (http://host:port)
  const origin = base.replace(/\/api.*$/, '')

  const DOC_PATHS = [
    '/swagger.json', '/swagger-ui.html', '/swagger-ui', '/swagger',
    '/openapi.json', '/openapi.yaml', '/openapi',
    '/api-docs', '/api-docs.json', '/api/swagger.json', '/api/openapi.json',
    '/docs', '/documentation', '/redoc',
    '/.well-known/openapi', '/api/schema', '/schema',
    '/graphql', '/api/graphql', '/v1/swagger.json', '/v2/swagger.json',
  ]

  let foundDocs = null

  console.log(`\n    ${DIM}Probing ${DOC_PATHS.length} common documentation paths...${R}`)

  for (const docPath of DOC_PATHS) {
    const url = `${origin}${docPath}`
    const r   = await req(url, { headers: cookie ? { Cookie: cookie } : {} })

    if (r.status === 200 && r.body) {
      const isJson  = r.body.trim().startsWith('{') || r.body.trim().startsWith('[')
      const isHtml  = /<html/i.test(r.body)
      const isSwagger = /swagger|openapi/i.test(r.body)

      if (isJson && isSwagger) {
        result(`Found API docs: ${docPath}`, 'fail', `HTTP 200 — schema exposed`)
        foundDocs = { url, body: r.body }
      } else if (isHtml && isSwagger) {
        result(`Found Swagger UI: ${docPath}`, 'fail', `HTTP 200 — UI accessible`)
      } else if (r.status === 200) {
        result(`Accessible path: ${docPath}`, 'pass', `HTTP 200 — not swagger`)
      }
    } else {
      result(`${docPath}`, 'pass', `HTTP ${r.status}`)
    }
  }

  // If we got a schema, parse it and check for undocumented endpoints
  if (foundDocs?.body) {
    console.log(`\n    ${BOLD}Checking schema for endpoints not in known list...${R}`)
    try {
      const schema = JSON.parse(foundDocs.body)
      const schemaPaths = Object.keys(schema.paths || {})
      const knownPaths  = endpoints.map(e => e.path)

      for (const sp of schemaPaths) {
        const normalised = sp.replace(/\{[^}]+\}/g, ':param')
        const inKnown    = knownPaths.some(k => k.includes(normalised.replace(':param','').replace(/\/$/,'')))
        if (!inKnown) {
          result(`Undocumented in code: ${sp}`, 'fail', 'in schema but not found by scanner')
        } else {
          result(`${sp}`, 'pass', 'matches known endpoint')
        }
      }
    } catch {
      result('Parse API schema', 'err', 'could not parse JSON schema')
    }
  }

  // Check for admin/internal paths exposed in schema
  const SENSITIVE_PATTERNS = [/admin/i, /internal/i, /debug/i, /test/i, /backup/i, /export/i, /import/i]
  for (const ep of endpoints) {
    const isSensitive = SENSITIVE_PATTERNS.some(re => re.test(ep.path))
    if (isSensitive) {
      result(`Sensitive path in codebase: ${ep.path}`, 'fail', `method: ${ep.method}, auth: ${ep.auth}`)
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. SERVER-SIDE PARAMETER POLLUTION — QUERY STRING
// Injects duplicate / encoded parameters to confuse server-side parsing.
// ══════════════════════════════════════════════════════════════════════════════
export async function testQueryParamPollution(base, endpoints = [], cookie, result) {
  section('2 · Server-side parameter pollution — query string')

  const headers = { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }

  // For each endpoint with known query params, try pollution techniques
  const targets = endpoints.filter(e => e.queryParams?.length || e.dynParams?.length)

  if (!targets.length) {
    // Fall back to probing the auth endpoint which has known body params
    targets.push({ method: 'POST', path: '/auth', bodyFields: ['email', 'password'], queryParams: [], dynParams: [] })
  }

  for (const ep of targets) {
    const params = [...(ep.queryParams || []), ...(ep.dynParams || [])]
    if (!params.length) continue

    const param = params[0]
    const url   = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`

    // 1. Duplicate param (server may use first or last — behaviour change = polluted)
    const dupUrl = `${url}?${param}=legitimate&${param}=injected`
    const [r1, r2] = await Promise.all([
      req(`${url}?${param}=legitimate`, { headers }),
      req(dupUrl, { headers }),
    ])
    const dupDiffer = r1.status !== r2.status || r1.body !== r2.body
    result(`Duplicate param ?${param}=a&${param}=b  (${ep.method} ${ep.path})`,
           dupDiffer ? 'fail' : 'pass',
           dupDiffer ? `responses differ — server uses one value` : `HTTP ${r2.status}`)

    // 2. URL-encoded ampersand: ?param=value%26extra=injected
    const encodedUrl = `${url}?${param}=value%26extra_param=injected`
    const r3 = await req(encodedUrl, { headers })
    result(`Encoded & pollution: ?${param}=value%26extra=injected`,
           r3.status === 200 && r1.status !== 200 ? 'fail' : 'pass',
           `HTTP ${r3.status}`)

    // 3. Array-style: ?param[]=a&param[]=b
    const arrayUrl = `${url}?${param}[]=value1&${param}[]=value2`
    const r4 = await req(arrayUrl, { headers })
    result(`Array notation: ?${param}[]=a&${param}[]=b`,
           r4.ok && r1.status !== r4.status ? 'fail' : 'pass',
           `HTTP ${r4.status}`)

    // 4. Null-byte truncation: ?param=value%00&param=injected
    const nullUrl = `${url}?${param}=value%00&${param}=injected`
    const r5 = await req(nullUrl, { headers })
    result(`Null-byte: ?${param}=value%00&${param}=injected`,
           r5.ok && r5.body?.includes('injected') ? 'fail' : 'pass',
           `HTTP ${r5.status}`)
  }

  // POST body pollution: JSON duplicate keys
  section('  2b · POST body parameter pollution (JSON duplicate keys)')
  const postEndpoints = endpoints.filter(e => e.method === 'POST' && e.bodyFields?.length)
  if (!postEndpoints.length) {
    result('No POST endpoints with body fields found', 'skip')
    return
  }

  for (const ep of postEndpoints) {
    const f = ep.bodyFields[0]
    // Build raw JSON with duplicate key — some parsers use first, some last
    const dupJson  = `{"${f}":"legitimate","${f}":"injected",${ep.bodyFields.slice(1).map(k=>`"${k}":"${sampleValue(k)}"`).join(',')}}`
    const r1 = await req(`${base}${ep.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: dupJson,
    })
    const r2 = await req(`${base}${ep.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: JSON.stringify(buildBody(ep.bodyFields)),
    })
    const differ = r1.status !== r2.status || r1.body !== r2.body
    result(`Duplicate JSON key "${f}" in POST ${ep.path}`,
           differ ? 'fail' : 'pass',
           differ ? `responses differ — parser uses duplicate key` : `HTTP ${r1.status}`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. FINDING AND EXPLOITING UNUSED API ENDPOINTS
// Probes for hidden, deprecated, or undiscovered endpoints via:
//   a) Common path wordlist
//   b) Unexpected HTTP methods on known endpoints
//   c) Method override headers
// ══════════════════════════════════════════════════════════════════════════════
export async function testUnusedEndpoints(base, endpoints = [], cookie, result) {
  section('3 · Finding and exploiting unused API endpoints')

  const headers = { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }

  // 3a. Common hidden paths
  const HIDDEN_PATHS = [
    '/admin', '/admin/users', '/admin/config', '/admin/debug',
    '/internal', '/internal/health', '/internal/metrics',
    '/debug', '/debug/vars', '/debug/pprof',
    '/health', '/healthz', '/readyz', '/status', '/ping',
    '/config', '/settings', '/env', '/environment',
    '/users', '/user', '/accounts', '/account',
    '/v1', '/v2', '/v3',
    '/backup', '/export', '/import', '/dump',
    '/reset', '/refresh', '/invalidate',
    '/test', '/dev', '/staging',
    '/metrics', '/stats', '/analytics',
    '/webhook', '/hooks', '/callback',
    '/private', '/secret', '/hidden',
  ]

  console.log(`\n    ${DIM}Probing ${HIDDEN_PATHS.length} common hidden paths...${R}`)
  for (const p of HIDDEN_PATHS) {
    const r = await req(`${base}${p}`, { headers })
    if (r.status !== 404 && r.status !== 0) {
      result(`${p}`, r.status < 400 ? 'fail' : 'pass',
             `HTTP ${r.status}${r.status < 400 ? ' — accessible!' : ''}`)
    }
  }

  // 3b. Unexpected HTTP methods on known endpoints
  console.log(`\n    ${DIM}Testing unexpected HTTP methods on known endpoints...${R}`)
  const HTTP_METHODS = ['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD','TRACE']

  for (const ep of endpoints.slice(0, 5)) {  // limit to first 5 to stay fast
    const url        = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    const knownMethods = ep.method.split('|')

    for (const method of HTTP_METHODS) {
      if (knownMethods.includes(method)) continue  // skip declared methods
      const r = await req(url, { method, headers })
      if (r.status < 400 && r.status !== 0) {
        result(`${method} ${ep.path} — undeclared method accepted`,
               'fail', `HTTP ${r.status}`)
      } else if (method === 'TRACE' && r.status === 200) {
        result(`TRACE ${ep.path} — TRACE enabled (reflects request headers)`,
               'fail', `HTTP ${r.status}`)
      }
    }
    result(`Unexpected methods on ${ep.path}`, 'pass', `all returned 4xx`)
  }

  // 3c. HTTP method override headers
  console.log(`\n    ${DIM}Testing method override headers...${R}`)
  const OVERRIDE_HEADERS = [
    'X-HTTP-Method-Override',
    'X-Method-Override',
    'X-HTTP-Method',
    '_method',
  ]

  for (const ep of endpoints.filter(e => e.method === 'GET').slice(0, 2)) {
    const url = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    for (const hdr of OVERRIDE_HEADERS) {
      const r = await req(url, {
        method: 'POST',
        headers: { ...headers, [hdr]: 'DELETE' },
      })
      result(`${hdr}: DELETE on GET ${ep.path}`,
             r.status < 400 ? 'fail' : 'pass',
             `HTTP ${r.status}`)
    }
  }

  // 3d. Version endpoint discovery (e.g., /v1/auth vs /v2/auth)
  console.log(`\n    ${DIM}Testing API version discovery...${R}`)
  for (const ep of endpoints.slice(0, 3)) {
    for (const version of ['/v1', '/v2', '/v3']) {
      const versionedUrl = base.replace('/api', `${version}`) + ep.path.replace(/:([a-zA-Z_]+)/g, '1')
      const r = await req(versionedUrl, { headers })
      if (r.status < 400 && r.status !== 0) {
        result(`${version}${ep.path} accessible`, 'fail', `HTTP ${r.status}`)
      }
    }
  }
  result('Version discovery scan complete', 'pass')
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. EXPLOITING MASS ASSIGNMENT VULNERABILITY
// Sends extra privileged / sensitive fields in POST/PUT bodies that should not
// be user-assignable, then checks if the server accepts / reflects them.
// ══════════════════════════════════════════════════════════════════════════════
export async function testMassAssignment(base, endpoints = [], cookie, result) {
  section('4 · Mass assignment vulnerability')

  const headers = { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }

  // Fields that should never be user-assignable
  const PRIVILEGED_FIELDS = [
    // Privilege escalation
    { key: 'isAdmin',      value: true  },
    { key: 'is_admin',     value: 1     },
    { key: 'role',         value: 'admin' },
    { key: 'roles',        value: ['admin','superuser'] },
    { key: 'permissions',  value: ['*'] },
    { key: 'admin',        value: true  },
    // Account / pricing manipulation
    { key: 'price',        value: 0     },
    { key: 'amount',       value: -1    },
    { key: 'discount',     value: 100   },
    { key: 'balance',      value: 99999 },
    { key: 'credits',      value: 9999  },
    { key: 'ponds_limit',  value: 9999  },
    // Status bypass
    { key: 'status',       value: 'active'   },
    { key: 'verified',     value: true       },
    { key: 'approved',     value: true       },
    { key: 'active',       value: true       },
    { key: 'blocked',      value: false      },
    // ID override
    { key: 'id',           value: 1          },
    { key: 'userId',       value: 1          },
    { key: 'user_id',      value: 1          },
    { key: 'customerId',   value: 1          },
    { key: 'customer_id',  value: 1          },
    { key: 'ownerId',      value: 1          },
  ]

  const postPutEndpoints = endpoints.filter(e => ['POST','PUT','PATCH'].includes(e.method))

  if (!postPutEndpoints.length) {
    result('No POST/PUT endpoints found', 'skip')
    return
  }

  for (const ep of postPutEndpoints) {
    const url      = `${base}${ep.path.replace(/:([a-zA-Z_]+)/g, '1')}`
    const baseBody = buildBody(ep.bodyFields)

    // Baseline request (no extra fields)
    const baseline = await req(url, {
      method: ep.method,
      headers,
      body: JSON.stringify(baseBody),
    })

    // Send all privileged fields in one request
    const poisonBody = { ...baseBody, ...Object.fromEntries(PRIVILEGED_FIELDS.map(f => [f.key, f.value])) }
    const poisoned   = await req(url, {
      method: ep.method,
      headers,
      body: JSON.stringify(poisonBody),
    })

    // Check 1: response body contains the injected privileged values
    const reflected = PRIVILEGED_FIELDS.some(f => {
      const v = String(f.value)
      return poisoned.body?.includes(v) && !baseline.body?.includes(v)
    })

    // Check 2: status code changed (e.g., 403 → 200 after adding isAdmin:true)
    const statusChanged = baseline.status !== poisoned.status && poisoned.ok

    if (reflected) {
      result(`${ep.method} ${ep.path} — privileged field reflected in response`,
             'fail', `Check: ${PRIVILEGED_FIELDS.filter(f => poisoned.body?.includes(String(f.value))).map(f=>f.key).join(', ')}`)
    } else if (statusChanged) {
      result(`${ep.method} ${ep.path} — status changed with extra fields`,
             'fail', `${baseline.status} → ${poisoned.status}`)
    } else {
      result(`${ep.method} ${ep.path}`, 'pass', `HTTP ${poisoned.status} — no privileged fields accepted`)
    }

    // Individual field probing for interesting results
    for (const { key, value } of PRIVILEGED_FIELDS.slice(0, 6)) {
      const singlePoison = { ...baseBody, [key]: value }
      const r = await req(url, { method: ep.method, headers, body: JSON.stringify(singlePoison) })
      const fieldReflected = r.body?.includes(String(value)) && !baseline.body?.includes(String(value))
      if (fieldReflected || (r.ok && baseline.status !== r.status)) {
        result(`  ${key}=${JSON.stringify(value)} accepted by ${ep.method} ${ep.path}`,
               'fail', `HTTP ${r.status}`)
      }
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. SERVER-SIDE PARAMETER POLLUTION — REST URL
// Injects malicious values into REST path segments to override, traverse,
// or confuse server-side routing and parameter extraction.
// ══════════════════════════════════════════════════════════════════════════════
export async function testRestUrlPollution(base, endpoints = [], cookie, result) {
  section('5 · Server-side parameter pollution — REST URL')

  const headers = { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }

  const dynamicEndpoints = endpoints.filter(e => e.dynParams?.length)
  if (!dynamicEndpoints.length) {
    result('No dynamic URL params found', 'skip', 'no :param segments')
    return
  }

  for (const ep of dynamicEndpoints) {
    const paramName  = ep.dynParams[0]
    const baseUrl    = `${base}${ep.path.replace(`:${paramName}`, '1')}`
    const baseline   = await req(baseUrl, { headers })

    const POLLUTION_PAYLOADS = [
      // Path traversal
      { label: 'Path traversal  ../admin',           value: '../admin' },
      { label: 'Path traversal  ../../etc/passwd',   value: '../../etc/passwd' },
      { label: 'Encoded traversal %2e%2e%2fadmin',   value: '%2e%2e%2fadmin' },
      // Null byte
      { label: 'Null byte  1%00',                    value: '1%00' },
      { label: 'Null byte + ext  1%00.json',          value: '1%00.json' },
      // Fragment / hash injection
      { label: 'Fragment  1%23/../admin',             value: '1%23%2f..%2fadmin' },
      // Double slash
      { label: 'Double slash  //1',                  value: '%2f1' },
      // Inject extra path param: /1/../../users
      { label: 'Extra segments  1/../../users',       value: '1/../../users' },
      // Query string inside REST param (override)
      { label: `Query override  1?${paramName}=2`,   value: `1?${paramName}=2` },
      // Array-style param
      { label: 'Array param  1,2,3',                 value: '1,2,3' },
      { label: 'Array bracket  [1]',                 value: '[1]' },
      // Unicode normalization
      { label: 'Unicode slash  1/..admin',       value: '1%c0%afadmin' },
      // Server-side template injection probe (via REST param)
      { label: 'SSTI probe  {{7*7}}',                value: encodeURIComponent('{{7*7}}') },
    ]

    for (const { label, value } of POLLUTION_PAYLOADS) {
      const pollutedUrl = `${base}${ep.path.replace(`:${paramName}`, value)}`
      const r = await req(pollutedUrl, { method: ep.method, headers })

      const traversalWorked = r.ok && r.body?.includes('root:') // /etc/passwd
      const stiWorked       = r.body?.includes('49')            // {{7*7}} = 49
      const behaviorChanged = r.ok && !baseline.ok              // was 401/403, now 200

      const vulnerable = traversalWorked || stiWorked || behaviorChanged

      result(`${label}  [${ep.method} ${ep.path}]`,
             vulnerable ? 'fail' : 'pass',
             vulnerable
               ? `HTTP ${r.status} — unexpected success`
               : `HTTP ${r.status}`)
    }

    // REST param vs query string precedence
    // If server uses req.params.pid but attacker adds ?pid=other
    const overrideUrl  = `${baseUrl}?${paramName}=999`
    const overrideRes  = await req(overrideUrl, { headers })
    const overrideWorks = overrideRes.ok && overrideRes.body !== baseline.body
    result(`Query overrides REST param: GET ${ep.path}?${paramName}=999`,
           overrideWorks ? 'fail' : 'pass',
           overrideWorks ? 'query param took precedence over path param' : `HTTP ${overrideRes.status}`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// FULL SUITE RUNNER
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the complete API security test suite.
 * @param {object}   opts
 * @param {string}   opts.base       Full API base URL
 * @param {object[]} [opts.endpoints] Endpoint list from scanProject()
 * @param {string}   [opts.cookie]   Session cookie string
 */
export async function runApiTests({ base, endpoints = [], cookie } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  // Server reachability check
  try {
    await fetch(base, { signal: AbortSignal.timeout(4000) })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${base}${R}`)
    process.exit(1)
  }

  await testDocumentationExploitation(base, endpoints, cookie, result)
  await testQueryParamPollution(base, endpoints, cookie, result)
  await testUnusedEndpoints(base, endpoints, cookie, result)
  await testMassAssignment(base, endpoints, cookie, result)
  await testRestUrlPollution(base, endpoints, cookie, result)

  return stats
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const base     = argv.find(a => a.startsWith('http')) || 'http://localhost:1010/farm-management/api'
  const email    = process.env.TEST_EMAIL    || ''
  const password = process.env.TEST_PASSWORD || ''

  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  API Security Test Suite                     ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`Target : ${base}`)
  console.log(`Date   : ${new Date().toISOString()}`)

  // Auto-discover endpoints from project path if given
  let endpoints = []
  const projectPath = argv.find(a => !a.startsWith('http') && !a.startsWith('--'))
  if (projectPath) {
    try {
      const { scanProject } = await import('./list-endpoints.mjs')
      const result = scanProject(projectPath)
      endpoints = result.endpoints
      console.log(`${GREEN}✓ Loaded ${endpoints.length} endpoints from ${projectPath}${R}`)
    } catch (e) {
      console.log(`${YLW}⚠ Could not scan project: ${e.message}${R}`)
    }
  }

  // Auth
  let cookie = null
  if (email && password) {
    process.stdout.write(`\nAuthenticating as ${email}... `)
    try {
      const res = await fetch(`${base}/auth`, {
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

  const stats = await runApiTests({ base, endpoints, cookie })

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
