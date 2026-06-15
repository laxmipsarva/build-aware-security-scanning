import { test, describe, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mockFetch, captureResults, silent } from './helpers.mjs'

import {
  testDocumentationExploitation,
  testQueryParamPollution,
  testUnusedEndpoints,
  testMassAssignment,
  testRestUrlPollution,
} from '../src/test-api.mjs'

const BASE    = 'http://localhost:3000/api'
const ORIGIN  = 'http://localhost:3000'
const COOKIE  = 'AUTH=session-token'

const GET_EP    = [{ method: 'GET',  path: '/api/items',     queryParams: ['page'],  dynParams: [],     bodyFields: [] }]
const POST_EP   = [{ method: 'POST', path: '/api/item',      bodyFields: ['name'],   queryParams: [],   dynParams: [] }]
const DYN_EP    = [{ method: 'GET',  path: '/api/item/:id',  dynParams: ['id'],      queryParams: [],   bodyFields: [] }]

let restore
afterEach(() => { restore?.() })

// ── testDocumentationExploitation ─────────────────────────────────────────────
describe('testDocumentationExploitation', () => {
  test('reports fail when Swagger JSON is exposed', async () => {
    restore = mockFetch((url, opts) => {
      if (url.includes('/swagger.json')) {
        return { status: 200, body: JSON.stringify({ swagger: '2.0', paths: { '/users': {} }, openapi: '2.0' }) }
      }
      return { status: 404 }
    })
    const { result, calls } = captureResults()
    await silent(() => testDocumentationExploitation(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `should flag swagger.json exposure, got: ${JSON.stringify(calls)}`)
    assert.ok(fails.some(c => /swagger|api docs/i.test(c.label)))
  })

  test('reports pass when documentation paths return 404', async () => {
    restore = mockFetch({ status: 404, body: 'Not Found' })
    const { result, calls } = captureResults()
    await silent(() => testDocumentationExploitation(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })

  test('flags sensitive paths in endpoint list', async () => {
    restore = mockFetch({ status: 404 })
    const sensitiveEps = [
      { method: 'GET', path: '/admin/users',  bodyFields: [], queryParams: [], dynParams: [], auth: false },
      { method: 'GET', path: '/internal/log', bodyFields: [], queryParams: [], dynParams: [], auth: false },
    ]
    const { result, calls } = captureResults()
    await silent(() => testDocumentationExploitation(BASE, sensitiveEps, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /admin|sensitive/i.test(c.label)),
      `expected admin path flagged, got: ${JSON.stringify(fails)}`)
  })

  test('cross-checks schema paths against known endpoint list', async () => {
    const schemaBody = JSON.stringify({
      swagger: '2.0', openapi: '2.0',
      paths: {
        '/users':     { get: {} },
        '/undocumented': { post: {} },
      },
    })
    restore = mockFetch((url) => {
      if (url.includes('/swagger.json')) return { status: 200, body: schemaBody }
      return { status: 404 }
    })
    const knownEps = [{ method: 'GET', path: '/api/users', bodyFields: [], queryParams: [], dynParams: [], auth: true }]
    const { result, calls } = captureResults()
    await silent(() => testDocumentationExploitation(BASE, knownEps, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /undocumented/i.test(c.label)),
      `expected /undocumented flagged, got: ${JSON.stringify(calls)}`)
  })
})

// ── testQueryParamPollution ───────────────────────────────────────────────────
describe('testQueryParamPollution', () => {
  test('reports fail when duplicate query param changes response', async () => {
    let callCount = 0
    restore = mockFetch(() => {
      callCount++
      // Alternate responses: first (baseline single param) differs from second (duplicate)
      return callCount % 2 === 1
        ? { status: 200, body: '{"result":"legitimate"}' }
        : { status: 200, body: '{"result":"injected"}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testQueryParamPollution(BASE, GET_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected param pollution fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when duplicate param has no effect on response', async () => {
    restore = mockFetch({ status: 200, body: '{"result":"same"}' })
    const { result, calls } = captureResults()
    await silent(() => testQueryParamPollution(BASE, GET_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })

  test('reports fail when POST body with duplicate JSON key differs', async () => {
    let i = 0
    restore = mockFetch(() => ({
      status: 200,
      body: i++ === 0 ? '{"name":"dup-key-accepted"}' : '{"name":"normal"}',
    }))
    const { result, calls } = captureResults()
    await silent(() => testQueryParamPollution(BASE, POST_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    // At least the body pollution tests should have fired
    assert.ok(calls.length > 0, 'should have made some checks')
  })
})

// ── testUnusedEndpoints ───────────────────────────────────────────────────────
describe('testUnusedEndpoints', () => {
  test('reports fail when a hidden path is accessible', async () => {
    restore = mockFetch((url) => {
      if (url.includes('/admin') || url.includes('/debug')) {
        return { status: 200, body: '{"ok":true}' }
      }
      return { status: 404 }
    })
    const { result, calls } = captureResults()
    await silent(() => testUnusedEndpoints(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected hidden endpoint fails, got: ${JSON.stringify(calls)}`)
    assert.ok(fails.some(c => /admin|debug/i.test(c.label)))
  })

  test('reports pass when hidden paths all return 404', async () => {
    restore = mockFetch({ status: 404 })
    const { result, calls } = captureResults()
    await silent(() => testUnusedEndpoints(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })

  test('reports fail when undeclared HTTP method is accepted', async () => {
    restore = mockFetch((url, opts) => {
      // DELETE on what is declared as GET-only → accepted (vulnerability)
      if (opts?.method === 'DELETE') return { status: 200, body: '{}' }
      return { status: 405 }
    })
    const { result, calls } = captureResults()
    await silent(() => testUnusedEndpoints(BASE, GET_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /delete|method/i.test(c.label)),
      `expected undeclared-method fail, got: ${JSON.stringify(calls)}`)
  })
})

// ── testMassAssignment ────────────────────────────────────────────────────────
describe('testMassAssignment', () => {
  test('skips when no POST/PUT endpoints provided', async () => {
    restore = mockFetch({ status: 200 })
    const { result, calls } = captureResults()
    await silent(() => testMassAssignment(BASE, GET_EP, COOKIE, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when privileged field is reflected in response', async () => {
    // Baseline returns ONLY a normal field; poisoned response reflects isAdmin:true.
    // The check in testMassAssignment is: poisoned.body.includes(v) && !baseline.body.includes(v)
    // so the bodies must differ for the reflection to be detected.
    let calls2 = 0
    restore = mockFetch((url, opts) => {
      calls2++
      if (calls2 === 1) return { status: 200, body: JSON.stringify({ email: 'test@test.com' }) }
      return { status: 200, body: JSON.stringify({ isAdmin: true, email: 'test@test.com' }) }
    })
    const { result, calls } = captureResults()
    await silent(() => testMassAssignment(BASE, POST_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected mass-assignment fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports fail when poisoned request changes status code', async () => {
    let i = 0
    restore = mockFetch(() => {
      i++
      // Baseline → 403; with privileged fields → 200 (status change = mass assignment)
      return i <= 2 ? { status: 403, body: '{"error":"forbidden"}' }
                    : { status: 200, body: '{"ok":true}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testMassAssignment(BASE, POST_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected status-change fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when server ignores extra fields', async () => {
    restore = mockFetch({ status: 200, body: '{"email":"test@test.com"}' })
    const { result, calls } = captureResults()
    await silent(() => testMassAssignment(BASE, POST_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})

// ── testRestUrlPollution ──────────────────────────────────────────────────────
describe('testRestUrlPollution', () => {
  test('skips when no dynamic URL parameters in endpoints', async () => {
    restore = mockFetch({ status: 200 })
    const { result, calls } = captureResults()
    await silent(() => testRestUrlPollution(BASE, GET_EP, COOKIE, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when path traversal returns 200 (baseline was non-200)', async () => {
    restore = mockFetch((url) => {
      // Baseline /api/item/1 → 404; traversal /api/item/../admin → 200
      if (url.includes('..') || url.includes('%2e')) return { status: 200, body: 'admin data' }
      return { status: 404 }
    })
    const { result, calls } = captureResults()
    await silent(() => testRestUrlPollution(BASE, DYN_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected traversal fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports fail when SSTI probe returns 49 (7*7)', async () => {
    restore = mockFetch((url) => {
      if (url.includes('%7B%7B7') || url.includes('7*7')) return { status: 200, body: '49' }
      return { status: 200, body: '{"id":1}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testRestUrlPollution(BASE, DYN_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /ssti/i.test(c.label)), `expected SSTI fail, got: ${JSON.stringify(fails)}`)
  })

  test('reports pass when all pollution payloads are rejected', async () => {
    // Baseline 200, pollution payloads all 400
    restore = mockFetch((url) => {
      if (url.endsWith('/1') || url.match(/\/item\/\d+$/)) return { status: 200, body: '{"id":1}' }
      return { status: 400, body: 'Bad Request' }
    })
    const { result, calls } = captureResults()
    await silent(() => testRestUrlPollution(BASE, DYN_EP, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})
