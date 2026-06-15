import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  extractNextMethods,
  extractExpressRoutes,
  extractBodyFields,
  extractQueryParams,
  extractDynamicParams,
  extractModelCalls,
  detectAuth,
} from '../src/list-endpoints.mjs'

// ── extractNextMethods ─────────────────────────────────────────────────────────
describe('extractNextMethods', () => {
  test('detects async GET export', () => {
    assert.deepEqual(
      extractNextMethods('export async function GET(req) { return Response.json({}) }'),
      ['GET']
    )
  })

  test('detects non-async POST export', () => {
    assert.deepEqual(
      extractNextMethods('export function POST(req) {}'),
      ['POST']
    )
  })

  test('detects multiple method exports', () => {
    const src = `
      export async function GET(req)  { return Response.json({}) }
      export async function POST(req) { return Response.json({}) }
      export async function DELETE(req) { return Response.json({}) }
    `
    const methods = extractNextMethods(src)
    assert.ok(methods.includes('GET'),    'should include GET')
    assert.ok(methods.includes('POST'),   'should include POST')
    assert.ok(methods.includes('DELETE'), 'should include DELETE')
    assert.equal(methods.length, 3)
  })

  test('detects named re-export: export { GET, POST }', () => {
    const methods = extractNextMethods('export { GET, POST } from "./handlers"')
    assert.ok(methods.includes('GET'))
    assert.ok(methods.includes('POST'))
  })

  test('returns empty array for non-route files', () => {
    assert.deepEqual(
      extractNextMethods('const x = 1; function helper() {} export default helper'),
      []
    )
  })

  test('does not false-positive on unrelated identifiers (getUser, postData)', () => {
    // The parser uses regex, not AST — it specifically targets the `export function METHOD`
    // pattern, so camelCase names like getUser / postData are not mistaken for route exports.
    const src = `
      const getUser    = () => {}
      const postData   = 'hello'
      function deleteRecord() {}
    `
    assert.deepEqual(extractNextMethods(src), [])
  })

  test('detects PUT, PATCH, HEAD, OPTIONS', () => {
    const src = `
      export async function PUT(req) {}
      export async function PATCH(req) {}
      export async function HEAD(req) {}
      export async function OPTIONS(req) {}
    `
    const methods = extractNextMethods(src)
    ;['PUT', 'PATCH', 'HEAD', 'OPTIONS'].forEach(m =>
      assert.ok(methods.includes(m), `should include ${m}`)
    )
  })
})

// ── extractExpressRoutes ───────────────────────────────────────────────────────
describe('extractExpressRoutes', () => {
  test('detects app.get()', () => {
    const routes = extractExpressRoutes(`app.get('/users', handler)`, 'routes.js')
    assert.equal(routes.length, 1)
    assert.equal(routes[0].method, 'GET')
    assert.equal(routes[0].routePath, '/users')
  })

  test('detects router.post()', () => {
    const routes = extractExpressRoutes(`router.post('/login', handler)`, 'auth.js')
    assert.equal(routes[0].method, 'POST')
    assert.equal(routes[0].routePath, '/login')
  })

  test('detects chained .route() methods', () => {
    const src = `router.route('/profile').get(getProfile).put(updateProfile)`
    const routes = extractExpressRoutes(src, 'profile.js')
    const methods = routes.map(r => r.method)
    assert.ok(methods.includes('GET'))
    assert.ok(methods.includes('PUT'))
    routes.forEach(r => assert.equal(r.routePath, '/profile'))
  })

  test('detects multiple routes in one file', () => {
    const src = `
      router.get('/users', list)
      router.post('/users', create)
      router.delete('/users/:id', remove)
    `
    const routes = extractExpressRoutes(src, 'users.js')
    assert.equal(routes.length, 3)
  })

  test('returns empty array for non-express source', () => {
    assert.deepEqual(
      extractExpressRoutes('const x = doSomething()', 'util.js'),
      []
    )
  })
})

// ── extractBodyFields ──────────────────────────────────────────────────────────
describe('extractBodyFields', () => {
  test('picks up destructured fields from req.json()', () => {
    const fields = extractBodyFields(
      'const { email, password } = await req.json()'
    )
    assert.ok(fields.includes('email'))
    assert.ok(fields.includes('password'))
  })

  test('picks up destructured fields from body', () => {
    const fields = extractBodyFields(
      'const { name, age } = body'
    )
    assert.ok(fields.includes('name'))
    assert.ok(fields.includes('age'))
  })

  test('picks up destructured fields from req.body', () => {
    const fields = extractBodyFields(
      'const { role, active } = req.body'
    )
    assert.ok(fields.includes('role'))
    assert.ok(fields.includes('active'))
  })

  test('picks up dot-notation access on body', () => {
    const fields = extractBodyFields('const x = body.username; const y = body.token')
    assert.ok(fields.includes('username'))
    assert.ok(fields.includes('token'))
  })

  test('picks up dot-notation access on req.body', () => {
    const fields = extractBodyFields('req.body.isAdmin')
    assert.ok(fields.includes('isAdmin'))
  })

  test('picks up formData.get() field names', () => {
    const fields = extractBodyFields(`
      const file  = formData.get('file')
      const label = formData.get('label')
    `)
    assert.ok(fields.includes('file'))
    assert.ok(fields.includes('label'))
  })

  test('picks up params.get() field names', () => {
    const fields = extractBodyFields(`const v = params.get('value')`)
    assert.ok(fields.includes('value'))
  })

  test('filters out JS keyword literals', () => {
    const fields = extractBodyFields('const { undefined, null, true, false } = body')
    assert.ok(!fields.includes('undefined'))
    assert.ok(!fields.includes('null'))
    assert.ok(!fields.includes('true'))
    assert.ok(!fields.includes('false'))
  })

  test('handles aliased destructuring — keeps left-hand name', () => {
    // `const { name: firstName } = body`  → extracts 'name' (the key)
    const fields = extractBodyFields('const { name: firstName, age: years } = body')
    assert.ok(fields.includes('name'))
    assert.ok(fields.includes('age'))
  })

  test('returns empty array for source with no body access', () => {
    assert.deepEqual(extractBodyFields('const x = req.query.page'), [])
  })
})

// ── extractQueryParams ─────────────────────────────────────────────────────────
describe('extractQueryParams', () => {
  test('detects req.query.param dot access', () => {
    const params = extractQueryParams('const page = req.query.page')
    assert.ok(params.includes('page'))
  })

  test('detects multiple req.query dot accesses', () => {
    const params = extractQueryParams('req.query.sort; req.query.order; req.query.limit')
    assert.ok(params.includes('sort'))
    assert.ok(params.includes('order'))
    assert.ok(params.includes('limit'))
  })

  test('detects searchParams.get()', () => {
    const params = extractQueryParams(`
      const q     = searchParams.get('q')
      const filter = searchParams.get('filter')
    `)
    assert.ok(params.includes('q'))
    assert.ok(params.includes('filter'))
  })

  test('detects destructured req.query', () => {
    const params = extractQueryParams('const { page, limit, sort } = req.query')
    assert.ok(params.includes('page'))
    assert.ok(params.includes('limit'))
    assert.ok(params.includes('sort'))
  })

  test('returns empty array when no query access present', () => {
    assert.deepEqual(extractQueryParams('const { email } = await req.json()'), [])
  })
})

// ── extractDynamicParams ───────────────────────────────────────────────────────
describe('extractDynamicParams', () => {
  test('detects destructured await params (Next.js App Router)', () => {
    const params = extractDynamicParams('const { id } = await params')
    assert.ok(params.includes('id'))
  })

  test('detects destructured params (no await)', () => {
    const params = extractDynamicParams('const { slug, locale } = params')
    assert.ok(params.includes('slug'))
    assert.ok(params.includes('locale'))
  })

  test('detects params.property dot access', () => {
    const params = extractDynamicParams('const userId = params.userId')
    assert.ok(params.includes('userId'))
  })

  test('detects req.params.property (Express style)', () => {
    const params = extractDynamicParams('const id = req.params.id')
    assert.ok(params.includes('id'))
  })

  test('returns empty array when no param access present', () => {
    assert.deepEqual(extractDynamicParams('const x = req.query.page'), [])
  })
})

// ── extractModelCalls ──────────────────────────────────────────────────────────
describe('extractModelCalls', () => {
  test('detects import from @model path', () => {
    const calls = extractModelCalls(
      `import { UserModel, PondModel } from '@model/pond'`
    )
    assert.ok(calls.includes('UserModel'))
    assert.ok(calls.includes('PondModel'))
  })

  test('detects import from repository path', () => {
    const calls = extractModelCalls(
      `import { findUser } from '../repository/user'`
    )
    assert.ok(calls.includes('findUser'))
  })

  test('detects await calls (non-builtin)', () => {
    const calls = extractModelCalls(`
      const user = await getUser(id)
      const list = await listPonds(userId)
    `)
    assert.ok(calls.includes('getUser'))
    assert.ok(calls.includes('listPonds'))
  })

  test('does not include built-in functions', () => {
    const calls = extractModelCalls(`
      const r = await fetch(url)
      const n = await parseInt(s)
      const p = await JSON.parse(body)
    `)
    assert.ok(!calls.includes('fetch'))
    assert.ok(!calls.includes('parseInt'))
    assert.ok(!calls.includes('JSON'))
  })
})

// ── detectAuth ─────────────────────────────────────────────────────────────────
describe('detectAuth', () => {
  const cases = [
    ['cookies() call',              "const c = cookies()",                             true ],
    ['req.cookies access',          "const s = req.cookies.session",                   true ],
    ['decrypt() call',              "const payload = await decrypt(token)",             true ],
    ['verifySession call',          "await verifySession(req)",                         true ],
    ['jwt.verify call',             "jwt.verify(token, secret)",                        true ],
    ['jwtVerify call',              "await jwtVerify(token, publicKey)",                true ],
    ['Authorization header check',  "req.headers.Authorization",                        true ],
    ['bearer keyword (lowercase)',  "const scheme = 'bearer'",                          true ],
    ['req.user access',             "const user = req.user",                            true ],
    ['no auth patterns',            "const x = 1; return Response.json({ ok: true })", false],
    ['unrelated cookies string',    "const msg = 'no cookies here'",                   false],
  ]

  for (const [label, src, expected] of cases) {
    test(label, () => {
      assert.equal(detectAuth(src), expected, `detectAuth returned wrong value for: ${label}`)
    })
  }
})
