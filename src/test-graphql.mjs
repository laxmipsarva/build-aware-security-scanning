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

async function gqlPost(url, query, variables = {}, extraHeaders = {}) {
  return req(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify({ query, variables }),
  })
}

// Returns true if the response looks like a GraphQL response
function looksLikeGraphQL(r) {
  if (!r.json) return false
  return 'data' in r.json || 'errors' in r.json
}

// Introspection query that retrieves schema types and fields
const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        isDeprecated
        deprecationReason
        description
        type { name kind ofType { name kind } }
        args { name type { name kind ofType { name kind } } }
      }
      inputFields { name type { name kind ofType { name kind } } }
    }
  }
}`

// Runs introspection; returns parsed __schema or null
async function fetchSchema(url, headers = {}) {
  const r = await gqlPost(url, INTROSPECTION_QUERY, {}, headers)
  if (r.json?.data?.__schema) return r.json.data.__schema
  return null
}

// Returns application types (strips built-in __ meta-types)
function userTypes(schema) {
  return (schema?.types || []).filter(t => !t.name.startsWith('__'))
}

// Returns fields for a named type
function fieldsOf(schema, typeName) {
  const t = (schema?.types || []).find(t => t.name === typeName)
  return t?.fields || []
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. FINDING A HIDDEN GRAPHQL ENDPOINT
// Probes 25+ common GraphQL paths using a lightweight typename probe to confirm
// whether a GraphQL engine is listening. Returns the first confirmed URL.
// ══════════════════════════════════════════════════════════════════════════════
export async function testHiddenEndpoints(base, cookie, result) {
  section('1 · Finding a hidden GraphQL endpoint')

  const origin = base.replace(/\/api.*$/, '').replace(/\/$/, '')
  const headers = cookie ? { Cookie: cookie } : {}

  const GQL_PATHS = [
    '/graphql',
    '/api/graphql',
    '/graphql/api',
    '/v1/graphql',
    '/v2/graphql',
    '/v3/graphql',
    '/graphql/v1',
    '/graphql/v2',
    '/api/v1/graphql',
    '/api/v2/graphql',
    '/graph',
    '/gql',
    '/query',
    '/api/query',
    '/data/graphql',
    '/app/graphql',
    '/graphiql',
    '/playground',
    '/graphql/console',
    '/graphql/explorer',
    '/altair',
    '/voyager',
    '/hasura/v1/graphql',
    '/v1alpha1/graphql',
    '/graphql/playground',
    '/api/data',
    '/subscriptions',
  ]

  // Lightweight confirmation probe — safe for any server
  const PROBE = '{ __typename }'

  console.log(`\n    ${DIM}Probing ${GQL_PATHS.length} paths with typename probe...${R}`)

  let confirmedUrl = null

  for (const p of GQL_PATHS) {
    const url = `${origin}${p}`

    // POST probe
    const rPost = await gqlPost(url, PROBE, {}, headers)

    if (looksLikeGraphQL(rPost)) {
      const isTypename = rPost.json?.data?.__typename
      result(`Found GraphQL at ${p}  (POST)`, 'fail',
             isTypename ? `__typename = ${isTypename}` : `HTTP ${rPost.status} — GraphQL error response`)
      confirmedUrl = confirmedUrl ?? url
      continue
    }

    // GET probe (some servers support GET)
    const getUrl = `${url}?query=${encodeURIComponent(PROBE)}`
    const rGet   = await req(getUrl, { headers })

    if (looksLikeGraphQL(rGet)) {
      result(`Found GraphQL at ${p}  (GET)`, 'fail',
             `HTTP ${rGet.status} — responds to GET queries`)
      confirmedUrl = confirmedUrl ?? url
      continue
    }

    // Check for GraphQL-specific error strings even on non-200
    const body = rPost.body || rGet.body
    if (/must provide query|did you mean|graphql|__typename/i.test(body) && rPost.status !== 404) {
      result(`Possible GraphQL at ${p}`, 'fail',
             `HTTP ${rPost.status} — GraphQL error string in body`)
      confirmedUrl = confirmedUrl ?? url
      continue
    }

    if (rPost.status !== 0 && rPost.status !== 404) {
      result(`${p}`, 'pass', `HTTP ${rPost.status} — not GraphQL`)
    }
  }

  // Check if GraphiQL / Playground UI is publicly accessible
  const UI_PATHS = ['/graphiql', '/playground', '/altair', '/graphql/playground', '/voyager']
  console.log(`\n    ${DIM}Checking for exposed GraphQL IDE/explorer UIs...${R}`)
  for (const p of UI_PATHS) {
    const r = await req(`${origin}${p}`, { headers })
    if (r.status === 200 && /<html/i.test(r.body) &&
        /graphql|graphiql|playground|altair|voyager/i.test(r.body)) {
      result(`GraphQL IDE exposed at ${p}`, 'fail',
             `HTTP 200 — interactive query tool accessible without auth`)
    }
  }

  if (!confirmedUrl) {
    result('No GraphQL endpoint detected', 'pass', 'all probed paths returned non-GraphQL responses')
  }

  return confirmedUrl
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. ACCIDENTAL EXPOSURE OF PRIVATE GRAPHQL FIELDS
// Runs a full introspection query and inspects the schema for sensitive field
// names, deprecated fields still in use, and revealing type names.
// ══════════════════════════════════════════════════════════════════════════════
export async function testIntrospectionExposure(gqlUrl, cookie, result) {
  section('2 · Accidental exposure of private GraphQL fields')

  const headers = cookie ? { Cookie: cookie } : {}

  // 2a. Check if introspection is enabled at all
  const schema = await fetchSchema(gqlUrl, headers)

  if (!schema) {
    // Try a simpler introspection to distinguish "disabled" from "error"
    const r = await gqlPost(gqlUrl, '{ __schema { queryType { name } } }', {}, headers)
    if (r.status === 0) {
      result('Introspection probe', 'err', `server unreachable`)
      return
    }
    const introspectionDisabled =
      r.json?.errors?.some(e => /introspection/i.test(e.message)) ||
      (!r.json?.data?.__schema && r.status < 500)
    result('Introspection enabled', introspectionDisabled ? 'pass' : 'err',
           introspectionDisabled
             ? 'disabled — good practice for production'
             : `HTTP ${r.status} — could not confirm status`)
    return
  }

  result('Introspection enabled', 'fail',
         'Full schema retrievable — disable in production (allows schema harvesting)')

  // 2b. Sensitive field names in any type
  const SENSITIVE_FIELD_PATTERNS = [
    /^password$/i, /^pass$/i, /passwd/i,
    /^secret/i, /secret$/i,
    /api[_-]?key/i, /^apikey$/i,
    /^token$/i, /access[_-]?token/i, /refresh[_-]?token/i, /auth[_-]?token/i,
    /private[_-]?key/i, /^privatekey$/i,
    /^ssn$/i, /social[_-]?security/i,
    /credit[_-]?card/i, /card[_-]?number/i, /^cvv$/i, /^cvc$/i, /^pin$/i,
    /^salt$/i, /^hash$/i, /password[_-]?hash/i,
    /^otp$/i, /one[_-]?time/i,
    /bank[_-]?account/i, /routing[_-]?number/i,
    /internal[_-]?id/i, /^internalid$/i,
    /admin[_-]?token/i,
    /^dob$/i, /date[_-]?of[_-]?birth/i,
  ]

  const SENSITIVE_TYPE_PATTERNS = [
    /admin/i, /internal/i, /private/i, /debug/i, /secret/i, /hidden/i,
    /audit/i, /credential/i, /token/i, /session/i,
  ]

  console.log(`\n    ${DIM}Scanning ${userTypes(schema).length} types for sensitive fields...${R}`)

  const sensitiveFound = []

  for (const t of userTypes(schema)) {
    // Flag sensitive type names (excluding obvious scalars/enums)
    if (t.kind === 'OBJECT' || t.kind === 'INPUT_OBJECT') {
      if (SENSITIVE_TYPE_PATTERNS.some(re => re.test(t.name))) {
        result(`Sensitive type name: ${t.name}  (kind: ${t.kind})`, 'fail',
               'type name suggests private/internal data')
      }
    }

    for (const f of (t.fields || t.inputFields || [])) {
      if (SENSITIVE_FIELD_PATTERNS.some(re => re.test(f.name))) {
        sensitiveFound.push({ type: t.name, field: f.name, deprecated: f.isDeprecated })
        result(`Sensitive field "${t.name}.${f.name}"${f.isDeprecated ? '  [deprecated]' : ''}`,
               'fail',
               `field exposes sensitive data in schema${f.isDeprecated ? ` — deprecated but still defined: ${f.deprecationReason || 'no reason given'}` : ''}`)
      }
    }
  }

  if (!sensitiveFound.length) {
    result('No sensitive field names found in schema', 'pass')
  }

  // 2c. Deprecated fields still present
  console.log(`\n    ${DIM}Checking for deprecated fields still in schema...${R}`)
  let deprecatedCount = 0
  for (const t of userTypes(schema)) {
    for (const f of (t.fields || [])) {
      if (f.isDeprecated && !SENSITIVE_FIELD_PATTERNS.some(re => re.test(f.name))) {
        deprecatedCount++
        result(`Deprecated field still exposed: ${t.name}.${f.name}`, 'fail',
               f.deprecationReason ? `reason: ${f.deprecationReason}` : 'no removal date set')
      }
    }
  }
  if (!deprecatedCount) {
    result('No deprecated fields in schema', 'pass')
  }

  // 2d. Mutations and subscriptions exposed — summarize attack surface
  const mutTypeName = schema.mutationType?.name
  const subTypeName  = schema.subscriptionType?.name
  const mutations    = mutTypeName ? fieldsOf(schema, mutTypeName) : []
  const subs         = subTypeName ? fieldsOf(schema, subTypeName) : []

  if (mutations.length) {
    result(`${mutations.length} mutation(s) exposed via introspection`, 'fail',
           `mutations: ${mutations.slice(0, 5).map(f => f.name).join(', ')}${mutations.length > 5 ? '…' : ''}`)
  }
  if (subs.length) {
    result(`${subs.length} subscription(s) exposed via introspection`, 'fail',
           `subscriptions: ${subs.slice(0, 5).map(f => f.name).join(', ')}${subs.length > 5 ? '…' : ''}`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. ACCESSING PRIVATE GRAPHQL POSTS / DATA (AUTHORIZATION BYPASS)
// Uses introspection (or common query patterns) to find object queries and then
// attempts IDOR-style access and unauthenticated field access.
// ══════════════════════════════════════════════════════════════════════════════
export async function testPrivateDataAccess(gqlUrl, cookie, result) {
  section('3 · Accessing private GraphQL posts / data (authorization)')

  const authHeaders = cookie ? { Cookie: cookie } : {}
  const noAuthHeaders = {}

  const schema = await fetchSchema(gqlUrl, authHeaders)

  // Build a list of (query field, sample query string) to probe
  const probes = []

  if (schema) {
    const queryTypeName = schema.queryType?.name || 'Query'
    const queryFields   = fieldsOf(schema, queryTypeName)

    for (const f of queryFields) {
      const idArg = f.args?.find(a => /^id$/i.test(a.name))
      if (idArg) {
        // Query field that takes an ID — prime IDOR candidate
        const scalarFields = fieldsOf(schema, f.type?.ofType?.name || f.type?.name || '')
          .filter(sf => sf.type?.kind === 'SCALAR' || sf.type?.ofType?.kind === 'SCALAR')
          .slice(0, 5)
          .map(sf => sf.name)

        const sel = scalarFields.length ? `{ ${scalarFields.join(' ')} }` : '{ id }'
        probes.push({
          name: f.name,
          query: (id) => `{ ${f.name}(id: "${id}") ${sel} }`,
        })
      }
    }
  }

  // Always include generic probes regardless of introspection
  const GENERIC_PROBES = [
    { name: 'me',     query: () => '{ me { id email name role } }' },
    { name: 'viewer', query: () => '{ viewer { id email name } }' },
    { name: 'users',  query: () => '{ users { id email name role } }' },
    { name: 'posts',  query: () => '{ posts { id title content authorId } }' },
  ]
  probes.push(...GENERIC_PROBES)

  // 3a. Unauthenticated access — can we read private data without a cookie?
  console.log(`\n    ${DIM}Testing unauthenticated access to ${probes.length} query fields...${R}`)
  for (const probe of probes.slice(0, 8)) {
    const r = await gqlPost(gqlUrl, probe.query('1'), {}, noAuthHeaders)
    const hasData   = r.json?.data && Object.values(r.json.data).some(v => v !== null)
    const hasErrors = r.json?.errors?.length > 0
    const isAuthErr = r.json?.errors?.some(e =>
      /auth|permission|forbidden|unauthori[sz]ed|not allowed/i.test(e.message))

    if (hasData) {
      result(`Unauthenticated "${probe.name}" returned data`, 'fail',
             `private data accessible without credentials`)
    } else if (hasErrors && !isAuthErr) {
      result(`"${probe.name}" errors without auth`, 'err',
             r.json.errors[0]?.message?.slice(0, 80))
    } else if (isAuthErr) {
      result(`"${probe.name}" requires authentication`, 'pass', 'auth enforced')
    } else {
      result(`"${probe.name}" — no data returned`, 'pass', `HTTP ${r.status}`)
    }
  }

  // 3b. IDOR via sequential ID enumeration on ID-based queries
  const idProbes = probes.filter(p => p.name !== 'me' && p.name !== 'viewer' &&
                                      p.name !== 'users' && p.name !== 'posts')
  if (idProbes.length) {
    console.log(`\n    ${DIM}Testing IDOR via sequential IDs (1–5) on ${idProbes.length} field(s)...${R}`)
    for (const probe of idProbes.slice(0, 3)) {
      const results = await Promise.all(
        ['1','2','3','4','5'].map(id => gqlPost(gqlUrl, probe.query(id), {}, authHeaders))
      )
      const exposed = results.filter(r =>
        r.json?.data && Object.values(r.json.data).some(v => v !== null))

      if (exposed.length > 1) {
        result(`IDOR: "${probe.name}" returns data for IDs 1–5`, 'fail',
               `${exposed.length}/5 IDs accessible — no ownership check`)
      } else if (exposed.length === 1) {
        result(`"${probe.name}" — only own record accessible`, 'pass', 'ownership filter appears enforced')
      } else {
        result(`"${probe.name}" — no records returned for IDs 1–5`, 'pass', 'or requires auth')
      }
    }
  }

  // 3c. Aliased IDOR — batch multiple IDs in one query to bypass per-query checks
  if (idProbes.length) {
    const probe = idProbes[0]
    const aliasQuery = [1,2,3,4,5]
      .map(id => `  r${id}: ${probe.query(String(id)).replace(/^{|}$/g, '').trim()}`)
      .join('\n')
    const batchQuery = `{\n${aliasQuery}\n}`

    const r = await gqlPost(gqlUrl, batchQuery, {}, authHeaders)
    const accessedIds = r.json?.data
      ? Object.entries(r.json.data).filter(([, v]) => v !== null).map(([k]) => k)
      : []

    if (accessedIds.length > 1) {
      result(`Aliased IDOR: "${probe.name}" — ${accessedIds.length} IDs in one batched query`, 'fail',
             `returned data for: ${accessedIds.join(', ')} — check field-level auth`)
    } else {
      result(`Aliased IDOR batch for "${probe.name}"`, 'pass',
             accessedIds.length === 0 ? 'no data returned' : 'only own record')
    }
  }

  // 3d. Overly permissive "users" list — full user enumeration
  const usersQ = '{ users { id email name role createdAt } }'
  const rUsers = await gqlPost(gqlUrl, usersQ, {}, noAuthHeaders)
  if (Array.isArray(rUsers.json?.data?.users) && rUsers.json.data.users.length > 0) {
    result('User list exposed without auth', 'fail',
           `${rUsers.json.data.users.length} user record(s) returned — potential PII leak`)
  } else if (Array.isArray(rUsers.json?.data?.users)) {
    result('User list query returns empty without auth', 'pass')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. PERFORMING CSRF EXPLOITS OVER GRAPHQL
// Tests whether GraphQL mutations can be triggered cross-origin via:
//   a) GET requests (query-string mutations)
//   b) form-encoded POST (no preflight in CORS)
//   c) text/plain POST (no preflight in CORS)
//   d) Permissive CORS headers + credentialed requests
//   e) Absence of CSRF token enforcement on mutations
// ══════════════════════════════════════════════════════════════════════════════
export async function testCsrfVulnerability(gqlUrl, cookie, result) {
  section('4 · CSRF exploits over GraphQL')

  const authHeaders = cookie ? { Cookie: cookie } : {}

  // Discover a mutation to use as probe (or fall back to __typename)
  let mutationQuery = 'mutation { __typename }'
  const schema = await fetchSchema(gqlUrl, authHeaders)
  if (schema) {
    const mutTypeName = schema.mutationType?.name
    const mutations   = mutTypeName ? fieldsOf(schema, mutTypeName) : []
    // Prefer low-risk mutations that don't require complex args
    const simple = mutations.find(m => !m.args?.length || m.args.length <= 2)
    if (simple) {
      const scalarReturn = fieldsOf(schema, simple.type?.ofType?.name || simple.type?.name || '')
        .filter(f => f.type?.kind === 'SCALAR' || f.type?.ofType?.kind === 'SCALAR')
        .slice(0, 2)
        .map(f => f.name)
      const sel = scalarReturn.length ? `{ ${scalarReturn.join(' ')} }` : ''
      // Build minimal argument list with dummy values
      const argStr = (simple.args || [])
        .map(a => {
          const typeName = a.type?.name || a.type?.ofType?.name || ''
          if (/int|number|float/i.test(typeName)) return `${a.name}: 0`
          if (/bool/i.test(typeName)) return `${a.name}: false`
          return `${a.name}: "test"`
        })
        .join(', ')
      mutationQuery = `mutation { ${simple.name}(${argStr}) ${sel} }`
    }
  }

  // 4a. GET-based mutation (no CORS preflight)
  const getUrl = `${gqlUrl}?query=${encodeURIComponent(mutationQuery)}`
  const rGet   = await req(getUrl, { headers: authHeaders })
  const getExecuted = looksLikeGraphQL(rGet) &&
    !rGet.json?.errors?.some(e => /GET.*mutation|mutation.*GET|only.*POST/i.test(e.message))
  result('GET request executes mutations', getExecuted ? 'fail' : 'pass',
         getExecuted
           ? `HTTP ${rGet.status} — mutation accepted via GET (CSRF vector, no preflight)`
           : `HTTP ${rGet.status} — GET mutations blocked`)

  // 4b. form-urlencoded POST (bypasses CORS preflight for simple requests)
  const rForm = await req(gqlUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...authHeaders },
    body: `query=${encodeURIComponent(mutationQuery)}`,
  })
  const formExecuted = looksLikeGraphQL(rForm) &&
    !rForm.json?.errors?.some(e => /content.type|unsupported/i.test(e.message))
  result('form-urlencoded POST executes mutations', formExecuted ? 'fail' : 'pass',
         formExecuted
           ? `HTTP ${rForm.status} — CSRF via HTML form possible (no preflight needed)`
           : `HTTP ${rForm.status} — content-type restricted`)

  // 4c. text/plain POST (bypasses CORS preflight for simple requests)
  const rText = await req(gqlUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain', ...authHeaders },
    body: JSON.stringify({ query: mutationQuery }),
  })
  const textExecuted = looksLikeGraphQL(rText) &&
    !rText.json?.errors?.some(e => /content.type|unsupported/i.test(e.message))
  result('text/plain POST executes mutations', textExecuted ? 'fail' : 'pass',
         textExecuted
           ? `HTTP ${rText.status} — CSRF via fetch(text/plain) possible`
           : `HTTP ${rText.status} — content-type restricted`)

  // 4d. CORS header inspection
  const rOptions = await req(gqlUrl, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://evil.example.com',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  })
  const acao  = rOptions.headers?.get?.('access-control-allow-origin')  || ''
  const acac  = rOptions.headers?.get?.('access-control-allow-credentials') || ''
  const acam  = rOptions.headers?.get?.('access-control-allow-methods') || ''

  if (acao === '*') {
    result('CORS: Access-Control-Allow-Origin: *', 'fail',
           'wildcard origin — any site can read unauthenticated responses')
  } else if (acao && acao !== 'null') {
    result(`CORS origin reflected/configured: ${acao}`, 'pass', `HTTP ${rOptions.status}`)
  } else {
    result('CORS: no permissive origin header', 'pass', `HTTP ${rOptions.status}`)
  }

  if (acac.toLowerCase() === 'true' && acao === '*') {
    result('CORS: credentials + wildcard origin', 'fail',
           'browsers block this but server misconfiguration could allow credentialed CSRF')
  } else if (acac.toLowerCase() === 'true') {
    result(`CORS: credentials allowed for origin "${acao}"`, 'pass',
           'review whether origin list is locked down')
  }

  // 4e. SameSite cookie attribute check
  if (cookie) {
    const rCheck = await gqlPost(gqlUrl, '{ __typename }', {}, {})
    const setCookie = rCheck.headers?.get?.('set-cookie') || ''
    if (setCookie) {
      const hasSameSite = /samesite\s*=\s*(strict|lax)/i.test(setCookie)
      result('Session cookie SameSite attribute', hasSameSite ? 'pass' : 'fail',
             hasSameSite
               ? 'SameSite=Strict/Lax prevents most CSRF'
               : 'missing SameSite attribute — cookies sent on cross-site requests')
    } else {
      result('SameSite cookie check', 'skip', 'no Set-Cookie header observed')
    }
  } else {
    result('SameSite cookie check', 'skip', 'no auth cookie provided — skipping')
  }

  // 4f. CSRF token enforcement on mutations
  const noCsrfHeaders = { ...authHeaders }
  delete noCsrfHeaders['X-CSRF-Token']
  delete noCsrfHeaders['X-Requested-With']
  const rNoCsrf = await gqlPost(gqlUrl, mutationQuery, {}, noCsrfHeaders)
  const mutationRanWithoutCsrf = looksLikeGraphQL(rNoCsrf) &&
    !rNoCsrf.json?.errors?.some(e => /csrf|forbidden|invalid token/i.test(e.message))
  result('Mutation executable without CSRF token', mutationRanWithoutCsrf ? 'fail' : 'pass',
         mutationRanWithoutCsrf
           ? `HTTP ${rNoCsrf.status} — no CSRF token required on mutations`
           : `HTTP ${rNoCsrf.status} — CSRF protection observed`)
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. BYPASSING GRAPHQL BRUTE FORCE PROTECTIONS
// Tests whether rate-limiting is applied at the HTTP request level rather than
// the per-operation level, which can be bypassed via:
//   a) JSON array batching  (multiple operations in one HTTP request)
//   b) Alias-based batching (multiple aliased calls in one query document)
//   c) Fragment amplification
//   d) Deep query nesting (complexity limit bypass)
// ══════════════════════════════════════════════════════════════════════════════
export async function testBruteForceBypass(gqlUrl, cookie, result) {
  section('5 · Bypassing GraphQL brute force protections')

  const authHeaders = cookie ? { Cookie: cookie } : {}
  const schema = await fetchSchema(gqlUrl, authHeaders)

  // Find a login-like mutation for realistic brute force simulation
  let loginMutation = null
  let loginField    = null

  if (schema) {
    const mutTypeName = schema.mutationType?.name
    const mutations   = mutTypeName ? fieldsOf(schema, mutTypeName) : []
    loginField = mutations.find(m =>
      /^(login|signin|sign_in|authenticate|createSession|getToken|createToken)$/i.test(m.name))
  }

  if (loginField) {
    const emailArg    = loginField.args?.find(a => /email|username|user/i.test(a.name))
    const passwordArg = loginField.args?.find(a => /pass|password|secret/i.test(a.name))
    const e = emailArg?.name    || 'email'
    const p = passwordArg?.name || 'password'

    const scalarReturn = fieldsOf(schema, loginField.type?.ofType?.name || loginField.type?.name || '')
      .filter(f => f.type?.kind === 'SCALAR' || f.type?.ofType?.kind === 'SCALAR')
      .slice(0, 3)
      .map(f => f.name)
    const sel = scalarReturn.length ? `{ ${scalarReturn.join(' ')} }` : ''

    loginMutation = (email, pass) =>
      `mutation { ${loginField.name}(${e}: "${email}", ${p}: "${pass}") ${sel} }`
  } else {
    // Fallback: use a harmless query for batching demonstration
    loginMutation = (email) => `{ __typename }`
  }

  // 5a. JSON array batching — send N operations in one HTTP request
  console.log(`\n    ${DIM}Testing JSON array batching (10 operations in 1 request)...${R}`)
  const BATCH_SIZE = 10
  const batchPayload = Array.from({ length: BATCH_SIZE }, (_, i) => ({
    query: loginMutation(`user${i}@example.com`, `wrongpassword${i}`),
  }))

  const rBatch = await req(gqlUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders },
    body: JSON.stringify(batchPayload),
  })

  const batchSupported = Array.isArray(rBatch.json) && rBatch.json.length === BATCH_SIZE
  const batchAccepted  = batchSupported ||
    (looksLikeGraphQL(rBatch) && !rBatch.json?.errors?.some(e =>
      /batch|array|not supported/i.test(e.message)))

  result(`JSON array batching (${BATCH_SIZE} ops in 1 request)`, batchAccepted ? 'fail' : 'pass',
         batchAccepted
           ? `HTTP ${rBatch.status} — server accepts batched array; rate limits apply per-request not per-op`
           : `HTTP ${rBatch.status} — array batching rejected or not supported`)

  // 5b. Alias-based batching — multiple aliased calls in a single query document
  console.log(`\n    ${DIM}Testing alias-based batching (10 aliases in 1 query)...${R}`)
  const ALIAS_COUNT = 10
  const aliasBody = loginField
    ? `mutation {\n${Array.from({ length: ALIAS_COUNT }, (_, i) =>
        `  a${i}: ${loginField.name}(${loginField.args?.[0]?.name || 'email'}: "u${i}@example.com", ${loginField.args?.[1]?.name || 'password'}: "pass${i}")`
      ).join('\n')}\n}`
    : `{\n${Array.from({ length: ALIAS_COUNT }, (_, i) =>
        `  a${i}: __typename`
      ).join('\n')}\n}`

  const rAlias = await gqlPost(gqlUrl, aliasBody, {}, authHeaders)
  const aliasWorked = rAlias.json?.data &&
    Object.keys(rAlias.json.data).filter(k => k.startsWith('a')).length >= ALIAS_COUNT / 2
  const aliasRateLimited = rAlias.json?.errors?.some(e =>
    /rate.limit|too many|throttl/i.test(e.message))

  result(`Alias batching (${ALIAS_COUNT} aliases in 1 query)`,
         aliasWorked && !aliasRateLimited ? 'fail' : 'pass',
         aliasWorked && !aliasRateLimited
           ? `all aliases executed — bypass per-operation rate limits`
           : aliasRateLimited
             ? `rate limited — server detects alias flooding`
             : `HTTP ${rAlias.status} — aliases not all returned`)

  // 5c. Fragment amplification — define a fragment, use it many times
  console.log(`\n    ${DIM}Testing fragment amplification (1 fragment used 10 times)...${R}`)
  const fragQuery = `
    fragment F on Query { __typename }
    {
      ${Array.from({ length: 10 }, (_, i) => `f${i}: ...F`).join('\n      ')}
    }`
  const rFrag = await gqlPost(gqlUrl, fragQuery, {}, authHeaders)
  const fragAmplified = rFrag.json?.data &&
    Object.keys(rFrag.json.data).filter(k => k.startsWith('f')).length >= 5
  result('Fragment amplification (1 fragment × 10 spreads)', fragAmplified ? 'fail' : 'pass',
         fragAmplified
           ? `server resolved all 10 spread operations from 1 definition`
           : `HTTP ${rFrag.status} — fragment amplification blocked or limited`)

  // 5d. Deep query nesting — bypass query depth/complexity limits
  console.log(`\n    ${DIM}Testing deep query nesting (depth 10)...${R}`)

  // Find a self-referencing or nested type (like User → friends → User)
  let nestedQuery = null
  if (schema) {
    for (const t of userTypes(schema)) {
      if (t.kind !== 'OBJECT') continue
      const selfRef = (t.fields || []).find(f => {
        const typeName = f.type?.name || f.type?.ofType?.name || ''
        return typeName === t.name
      })
      if (selfRef) {
        // Build depth-10 nested query
        const innermost = `{ id }`
        let nested = innermost
        for (let d = 0; d < 10; d++) nested = `{ ${selfRef.name} ${nested} }`
        const queryType = schema.queryType?.name || 'Query'
        const queryField = fieldsOf(schema, queryType).find(f => {
          const typeName = f.type?.name || f.type?.ofType?.name || ''
          return typeName === t.name
        })
        if (queryField) {
          nestedQuery = `{ ${queryField.name} ${nested} }`
        }
        break
      }
    }
  }

  if (nestedQuery) {
    const rNested = await gqlPost(gqlUrl, nestedQuery, {}, authHeaders)
    const depthBlocked = rNested.json?.errors?.some(e =>
      /depth|complex|limit|too deep/i.test(e.message))
    const depthAllowed = looksLikeGraphQL(rNested) && !depthBlocked
    result('Deep nesting (depth 10) bypasses complexity limits', depthAllowed ? 'fail' : 'pass',
           depthAllowed
             ? `HTTP ${rNested.status} — server executed deeply nested query; no depth limit`
             : depthBlocked
               ? `query depth limit enforced`
               : `HTTP ${rNested.status}`)
  } else {
    result('Deep nesting test', 'skip', 'no self-referencing type found in schema')
  }

  // 5e. Introspection-based login field enumeration (informational)
  if (loginField) {
    result(`Login mutation identified: "${loginField.name}"`, 'fail',
           `args: ${loginField.args?.map(a => a.name).join(', ')} — prime brute force target`)
  } else if (schema) {
    result('No login-like mutation found in schema', 'pass',
           'mutation names do not reveal credential endpoints')
  } else {
    result('Login mutation detection', 'skip', 'introspection unavailable')
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// FULL SUITE RUNNER
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the complete GraphQL security test suite.
 * @param {object}  opts
 * @param {string}  opts.base     Base URL (http://host:port/api or origin)
 * @param {string}  [opts.gqlUrl] Explicit GraphQL endpoint (skips discovery)
 * @param {string}  [opts.cookie] Session cookie string
 */
export async function runGraphqlTests({ base, gqlUrl, cookie } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  const origin = (base || '').replace(/\/api.*$/, '').replace(/\/$/, '')

  // Server reachability check
  try {
    await fetch(origin || base, { signal: AbortSignal.timeout(4000) })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${origin || base}${R}`)
    process.exit(1)
  }

  const discoveredUrl = gqlUrl || await testHiddenEndpoints(base, cookie, result)
  const endpoint = discoveredUrl || `${origin}/graphql`

  console.log(`\n    ${DIM}Using GraphQL endpoint: ${endpoint}${R}`)

  await testIntrospectionExposure(endpoint, cookie, result)
  await testPrivateDataAccess(endpoint, cookie, result)
  await testCsrfVulnerability(endpoint, cookie, result)
  await testBruteForceBypass(endpoint, cookie, result)

  return stats
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const base   = argv.find(a => a.startsWith('http')) || 'http://localhost:3000'
  const gqlArg = argv.find(a => a.startsWith('--graphql='))
  const gqlUrl = gqlArg ? gqlArg.replace('--graphql=', '') : undefined

  const email    = process.env.TEST_EMAIL    || ''
  const password = process.env.TEST_PASSWORD || ''

  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  GraphQL Security Test Suite                 ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`Target : ${base}`)
  if (gqlUrl) console.log(`GraphQL: ${gqlUrl}`)
  console.log(`Date   : ${new Date().toISOString()}`)

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

  const stats = await runGraphqlTests({ base, gqlUrl, cookie })

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
