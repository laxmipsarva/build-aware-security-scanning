// Shared test utilities — no prod deps, uses only node:test primitives

/**
 * Replace globalThis.fetch with a controllable mock.
 *
 * handlerOrResponses can be:
 *   - A function (url, opts) => spec   — for URL/header-aware control
 *   - An array of spec objects          — consumed in order; last one repeated
 *
 * spec shape: { status?, body?, headers? }
 *   body: string (used as-is) or any value (JSON.stringified)
 *
 * Returns a restore() function — call it in afterEach / after the test.
 */
export function mockFetch(handlerOrResponses) {
  const saved = globalThis.fetch

  function buildResponse(spec = {}) {
    const status    = spec.status ?? 200
    const bodyText  = typeof spec.body === 'string'
      ? spec.body
      : JSON.stringify(spec.body ?? null)
    const hdrs = new Map(
      Object.entries(spec.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])
    )
    return {
      status,
      ok: status < 400,
      redirected: false,
      url: '',
      headers: { get: (n) => hdrs.get(n.toLowerCase()) ?? null },
      async text()  { return bodyText },
      async json()  { return JSON.parse(bodyText) },
      clone() { return this },
    }
  }

  if (typeof handlerOrResponses === 'function') {
    globalThis.fetch = async (url, opts = {}) =>
      buildResponse(handlerOrResponses(url, opts))
  } else {
    // Accept either a single spec object or an array; normalise to array
    const arr = Array.isArray(handlerOrResponses) ? handlerOrResponses : [handlerOrResponses]
    let i = 0
    globalThis.fetch = async (url, opts = {}) => {
      const spec = arr[i] ?? arr[arr.length - 1]
      i++
      return buildResponse(spec)
    }
  }

  return () => { globalThis.fetch = saved }
}

/**
 * Create a mock result() collector.
 * Returns { result, calls } where calls is an array of { label, status, detail }.
 */
export function captureResults() {
  const calls = []
  function result(label, status, detail = '') {
    calls.push({ label, status, detail })
  }
  return { result, calls }
}

/**
 * Silence console.log / console.error for the duration of fn().
 * Useful for test functions that call section() internally.
 */
export async function silent(fn) {
  const log = console.log
  const err = console.error
  const write = process.stdout.write.bind(process.stdout)
  console.log    = () => {}
  console.error  = () => {}
  // suppress process.stdout.write only for strings starting with ANSI / test module output
  process.stdout.write = (chunk, enc, cb) => {
    if (typeof chunk === 'string' && /^\s*\x1b/.test(chunk)) {
      if (typeof cb === 'function') cb()
      return true
    }
    return write(chunk, enc, cb)
  }
  try {
    return await fn()
  } finally {
    console.log   = log
    console.error = err
    process.stdout.write = write
  }
}
