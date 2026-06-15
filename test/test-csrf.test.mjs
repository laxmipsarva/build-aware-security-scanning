import { test, describe, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mockFetch, captureResults, silent } from './helpers.mjs'

import {
  testNoDefenses,
  testMethodDependentToken,
  testTokenPresenceDependence,
  testTokenNotTiedToSession,
  testTokenTiedToNonSessionCookie,
  testDuplicateCookieToken,
  testSameSiteLaxMethodOverride,
  testSameSiteStrictRedirect,
  testSameSiteSiblingDomain,
  testSameSiteLaxCookieRefresh,
  testRefererPresenceDependence,
  testBrokenRefererValidation,
} from '../src/test-csrf.mjs'

const BASE    = 'http://localhost:3000'
const COOKIE  = 'AUTH=test-session-token'
const ENDPOINT = [{ method: 'POST', path: '/api/profile', bodyFields: ['email'] }]

// All HTTP-touching tests need fetch mocked; suppress console noise from section()
let restore
beforeEach(() => { restore = null })
afterEach(() => { restore?.() })

// ── testNoDefenses ─────────────────────────────────────────────────────────────
describe('testNoDefenses', () => {
  test('skips when no session cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testNoDefenses(BASE, [], null, result))
    assert.equal(calls.length, 1)
    assert.equal(calls[0].status, 'skip')
  })

  test('reports fail when state-changing POST returns 200', async () => {
    // All requests return 200 — no CSRF defense
    restore = mockFetch({ status: 200, body: '{"ok":true}' })
    const { result, calls } = captureResults()
    await silent(() => testNoDefenses(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected ≥1 fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when state-changing endpoint returns 403', async () => {
    restore = mockFetch((url, opts) => {
      if (opts?.method === 'POST' || opts?.method === 'PUT') return { status: 403, body: 'Forbidden' }
      return { status: 404 }
    })
    const { result, calls } = captureResults()
    await silent(() => testNoDefenses(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, 'should have no failures when 403 returned')
  })

  test('skips endpoints returning 404', async () => {
    restore = mockFetch({ status: 404 })
    const { result, calls } = captureResults()
    await silent(() => testNoDefenses(BASE, ENDPOINT, COOKIE, result))
    // All endpoints 404 → skipped internally → only the "no endpoints" skip result
    const nonSkip = calls.filter(c => c.status !== 'skip')
    assert.equal(nonSkip.length, 0)
  })
})

// ── testMethodDependentToken ───────────────────────────────────────────────────
describe('testMethodDependentToken', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testMethodDependentToken(BASE, ENDPOINT, null, result))
    assert.ok(calls.every(c => c.status === 'skip'))
  })

  test('reports fail when POST with wrong token returns 403 but GET returns 200', async () => {
    restore = mockFetch((url, opts) => {
      if (opts?.method === 'GET') return { status: 200, body: '{"ok":true}' }
      return { status: 403, body: 'CSRF error' }
    })
    const { result, calls } = captureResults()
    await silent(() => testMethodDependentToken(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, 'GET bypass should be detected')
    assert.ok(
      fails.some(c => /get bypasses|wrong token/i.test(c.label)),
      `fail labels: ${fails.map(c => c.label).join(', ')}`
    )
  })

  test('reports pass when both POST and GET are protected', async () => {
    restore = mockFetch({ status: 403, body: 'Forbidden' })
    const { result, calls } = captureResults()
    await silent(() => testMethodDependentToken(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected failures: ${JSON.stringify(fails)}`)
  })
})

// ── testTokenPresenceDependence ────────────────────────────────────────────────
describe('testTokenPresenceDependence', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testTokenPresenceDependence(BASE, ENDPOINT, null, result))
    assert.ok(calls.every(c => c.status === 'skip'))
  })

  test('reports fail when absent token bypasses the check that rejects invalid tokens', async () => {
    let callCount = 0
    restore = mockFetch((url, opts) => {
      callCount++
      // First call: POST with invalid token → 403
      // Second call: POST without token → 200 (bypass)
      return callCount % 2 === 1 ? { status: 403 } : { status: 200, body: '{}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testTokenPresenceDependence(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, 'absent-token bypass should be flagged')
  })

  test('reports pass when absent token is also rejected', async () => {
    restore = mockFetch({ status: 403, body: 'CSRF check failed' })
    const { result, calls } = captureResults()
    await silent(() => testTokenPresenceDependence(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0)
  })
})

// ── testTokenNotTiedToSession ──────────────────────────────────────────────────
describe('testTokenNotTiedToSession', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testTokenNotTiedToSession(BASE, ENDPOINT, null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('skips when CSRF token cannot be extracted from the app', async () => {
    // App returns a page with no CSRF token
    restore = mockFetch({ status: 200, body: '<html><body>No token here</body></html>' })
    const { result, calls } = captureResults()
    await silent(() => testTokenNotTiedToSession(BASE, ENDPOINT, COOKIE, result))
    assert.ok(calls.some(c => c.status === 'skip'), `calls: ${JSON.stringify(calls)}`)
  })

  test('reports fail when token works with a tampered session', async () => {
    let i = 0
    restore = mockFetch((url, opts) => {
      i++
      // First call: GET base to extract CSRF token from HTML
      if (i === 1) return {
        status: 200,
        body: '<meta name="csrf-token" content="valid-csrf-token-abc123">',
      }
      // Subsequent calls: tampered or missing session → still 200 = token not tied to session
      return { status: 200, body: '{"ok":true}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testTokenNotTiedToSession(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `should detect session-independent token, calls: ${JSON.stringify(calls)}`)
  })
})

// ── testTokenTiedToNonSessionCookie ───────────────────────────────────────────
describe('testTokenTiedToNonSessionCookie', () => {
  test('reports pass when no dedicated CSRF cookie detected', async () => {
    restore = mockFetch({ status: 200, body: '<html>no csrf cookie</html>' })
    const { result, calls } = captureResults()
    await silent(() => testTokenTiedToNonSessionCookie(BASE, ENDPOINT, COOKIE, result))
    // If no CSRF cookie found, function returns early with a pass
    const passes = calls.filter(c => c.status === 'pass')
    assert.ok(passes.length >= 1)
  })

  test('reports fail when a separate XSRF-TOKEN cookie is present', async () => {
    restore = mockFetch((url, opts) => ({
      status: 200,
      body: '{"ok":true}',
      headers: { 'set-cookie': 'XSRF-TOKEN=attacker-value-abc; Path=/; HttpOnly' },
    }))
    const { result, calls } = captureResults()
    await silent(() => testTokenTiedToNonSessionCookie(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(
      fails.some(c => /separate csrf cookie/i.test(c.label) || /xsrf/i.test(c.label)),
      `expected CSRF cookie fail, got: ${JSON.stringify(calls)}`
    )
  })
})

// ── testDuplicateCookieToken ──────────────────────────────────────────────────
describe('testDuplicateCookieToken', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testDuplicateCookieToken(BASE, ENDPOINT, null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when forged double-submit token accepted', async () => {
    restore = mockFetch((url, opts) => {
      // Forged request (with attacker CSRF cookie + body) → 200
      // No-token request → 403 (so it looks like double-submit is enforced but broken)
      const hasCsrfBody = opts?.body?.includes('double-submit-forged')
      return hasCsrfBody ? { status: 200 } : { status: 403 }
    })
    const { result, calls } = captureResults()
    await silent(() => testDuplicateCookieToken(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected fail for forged token, calls: ${JSON.stringify(calls)}`)
  })

  test('reports pass when server rejects forged token', async () => {
    restore = mockFetch({ status: 403, body: 'CSRF validation failed' })
    const { result, calls } = captureResults()
    await silent(() => testDuplicateCookieToken(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0)
  })
})

// ── testSameSiteLaxMethodOverride ─────────────────────────────────────────────
describe('testSameSiteLaxMethodOverride', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxMethodOverride(BASE, ENDPOINT, null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports SameSite=Lax as a finding when detected in Set-Cookie', async () => {
    const postEp = [{ method: 'POST', path: '/api/profile', bodyFields: [] }]
    restore = mockFetch((url, opts) => ({
      status: opts?.method === 'GET' ? 200 : 405,
      body: '',
      headers: { 'set-cookie': 'session=abc; SameSite=Lax; Path=/' },
    }))
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxMethodOverride(BASE, postEp, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    // SameSite=Lax detection should be a fail (it's a finding)
    assert.ok(fails.some(c => /lax/i.test(c.label) || /samesite/i.test(c.label)),
      `expected Lax cookie finding, got: ${JSON.stringify(fails)}`)
  })

  test('detects method override bypass when GET accepts what POST locks', async () => {
    const postEp = [{ method: 'POST', path: '/api/update', bodyFields: ['email'] }]
    restore = mockFetch((url, opts) => {
      // Direct GET → 405; POST with _method=GET or override header → 200 (bypass!)
      if (opts?.method === 'GET' && !url.includes('_method')) return { status: 405 }
      if (opts?.method === 'POST') return { status: 200, body: '{}' }
      return { status: 405 }
    })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxMethodOverride(BASE, postEp, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(
      fails.some(c => /override|bypass|lax/i.test(c.label)),
      `expected override bypass, got: ${JSON.stringify(calls)}`
    )
  })
})

// ── testSameSiteStrictRedirect ────────────────────────────────────────────────
describe('testSameSiteStrictRedirect', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testSameSiteStrictRedirect(BASE, [], null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when an open redirect is found', async () => {
    restore = mockFetch((url, opts) => {
      if (url.includes('/redirect') || url.includes('/go')) {
        return {
          status: 302,
          headers: { location: 'https://evil.example.com/phish' },
        }
      }
      return { status: 404 }
    })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteStrictRedirect(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `should detect open redirect, calls: ${JSON.stringify(calls)}`)
    assert.ok(fails.some(c => /redirect|strict/i.test(c.label)))
  })

  test('reports pass when no open redirects found', async () => {
    restore = mockFetch({ status: 404 })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteStrictRedirect(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})

// ── testSameSiteSiblingDomain ─────────────────────────────────────────────────
describe('testSameSiteSiblingDomain', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testSameSiteSiblingDomain(BASE, [], null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when CORS allows sibling subdomain with credentials', async () => {
    restore = mockFetch((url, opts) => ({
      status: 200,
      headers: {
        'access-control-allow-origin': opts?.headers?.Origin || '',
        'access-control-allow-credentials': 'true',
      },
    }))
    const { result, calls } = captureResults()
    await silent(() => testSameSiteSiblingDomain(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /cors|sibling/i.test(c.label)),
      `expected sibling CORS fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports fail when session cookie Domain scopes to eTLD+1', async () => {
    restore = mockFetch({
      status: 200,
      headers: { 'set-cookie': 'session=abc; Domain=.localhost; Path=/' },
    })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteSiblingDomain(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /domain|etld|sib/i.test(c.label)),
      `expected domain-scoping fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when CORS does not allow siblings', async () => {
    restore = mockFetch({ status: 200, headers: {} })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteSiblingDomain(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.filter(c => /cors/i.test(c.label)).length, 0)
  })
})

// ── testSameSiteLaxCookieRefresh ──────────────────────────────────────────────
describe('testSameSiteLaxCookieRefresh', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxCookieRefresh(BASE, [], null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when a refresh endpoint sets a new Lax cookie', async () => {
    restore = mockFetch((url, opts) => {
      if (url.includes('/auth/refresh') || url.includes('/api/auth/refresh')) {
        return {
          status: 200,
          headers: { 'set-cookie': 'session=newtoken; SameSite=Lax; Path=/' },
        }
      }
      return { status: 200, headers: {} }
    })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxCookieRefresh(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.some(c => /refresh|lax|grace/i.test(c.label)),
      `expected Lax refresh fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when no Lax cookie refresh endpoint found', async () => {
    restore = mockFetch({ status: 404 })
    const { result, calls } = captureResults()
    await silent(() => testSameSiteLaxCookieRefresh(BASE, [], COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})

// ── testRefererPresenceDependence ─────────────────────────────────────────────
describe('testRefererPresenceDependence', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testRefererPresenceDependence(BASE, ENDPOINT, null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('reports fail when absent Referer bypasses validation that blocks evil Referer', async () => {
    restore = mockFetch((url, opts) => {
      const ref = opts?.headers?.Referer
      if (ref === 'https://evil-attacker.com/') return { status: 403 }
      return { status: 200, body: '{}' }  // absent or valid Referer → 200
    })
    const { result, calls } = captureResults()
    await silent(() => testRefererPresenceDependence(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1, `expected absent-Referer bypass fail, got: ${JSON.stringify(calls)}`)
  })

  test('reports pass when absent Referer is also rejected', async () => {
    restore = mockFetch({ status: 403, body: 'Referer required' })
    const { result, calls } = captureResults()
    await silent(() => testRefererPresenceDependence(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})

// ── testBrokenRefererValidation ────────────────────────────────────────────────
describe('testBrokenRefererValidation', () => {
  test('skips when no cookie provided', async () => {
    const { result, calls } = captureResults()
    await silent(() => testBrokenRefererValidation(BASE, ENDPOINT, null, result))
    assert.ok(calls.some(c => c.status === 'skip'))
  })

  test('skips per-endpoint when Referer validation is not active', async () => {
    // Both valid and evil Referer return 200 — no validation detected
    restore = mockFetch({ status: 200, body: '{}' })
    const { result, calls } = captureResults()
    await silent(() => testBrokenRefererValidation(BASE, ENDPOINT, COOKIE, result))
    const skips = calls.filter(c => c.status === 'skip')
    assert.ok(skips.length >= 1, `expected skip when validation not active, got: ${JSON.stringify(calls)}`)
  })

  test('reports fail for domain-as-subdomain bypass: target.evil.com', async () => {
    restore = mockFetch((url, opts) => {
      const ref = opts?.headers?.Referer ?? ''
      // Block only the pure evil domain
      if (ref === 'https://evil.com/') return { status: 403 }
      // Bypass payloads go through
      return { status: 200, body: '{}' }
    })
    const { result, calls } = captureResults()
    await silent(() => testBrokenRefererValidation(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.ok(fails.length >= 1,
      `expected at least one bypass to succeed, got: ${JSON.stringify(calls)}`)
    assert.ok(
      fails.some(c => /subdomain|domain as sub|evil\.com|bypass/i.test(c.label)),
      `expected subdomain-bypass fail, fails: ${JSON.stringify(fails)}`
    )
  })

  test('reports pass when all Referer bypass payloads are rejected', async () => {
    restore = mockFetch((url, opts) => {
      const ref = opts?.headers?.Referer ?? ''
      // Allow only the exact legitimate origin
      if (ref.startsWith('http://localhost:3000')) return { status: 200 }
      return { status: 403 }
    })
    const { result, calls } = captureResults()
    await silent(() => testBrokenRefererValidation(BASE, ENDPOINT, COOKIE, result))
    const fails = calls.filter(c => c.status === 'fail')
    assert.equal(fails.length, 0, `unexpected fails: ${JSON.stringify(fails)}`)
  })
})
