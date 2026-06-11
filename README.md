# build-aware-security-scanning

A zero-dependency CLI toolkit that **discovers API endpoints** and **tests for SQL injection** across all 18 OWASP attack categories — built for Next.js (App Router & Pages Router) and Express apps.

## Install

```bash
# Global CLI
npm install -g build-aware-security-scanning

# Or as a dev dependency
npm install --save-dev build-aware-security-scanning
```

---

## CLI Commands

### `bass-list` — Endpoint Discovery

Scans your project source code and lists every API route with its HTTP methods, auth status, body fields, URL params, and DB call surface.

```bash
# Auto-detect framework in current directory
bass-list

# Point at a specific project
bass-list /path/to/project

# Also show which fields flow into database calls (SQL injection surface)
bass-list /path/to/project --sqli

# Machine-readable JSON output
bass-list /path/to/project --json
```

**Example output:**

```
╔════════════════════════════════════════════════════════════════╗
║  API Endpoint Map                                              ║
╚════════════════════════════════════════════════════════════════╝
Framework : nextjs-app
Endpoints : 9

/api/auth
  POST  ⚠ no-auth
  file: src/app/api/auth/route.js
  body fields : email, password

/api/feed/:pid
  GET   🔒 auth
  POST  🔒 auth
  url params  : pid
  body fields : seeds, species, price, date, currency
  ⚠ sqli surface: body { seeds, species, price, date } → DB
  ⚠ sqli surface: url  { pid } → DB

Summary
──────────────────────────────
  POST     4 endpoints
  GET      4 endpoints
  PUT      1 endpoint

  🔒 Auth-protected : 8
  ⚠  No auth check  : 1
```

**What it detects per route file:**

| Signal | How |
|---|---|
| HTTP methods | `export async function GET/POST/PUT/...` |
| Auth check | `cookies()`, `decrypt()`, `jwt.verify()`, `req.user` |
| Body fields | `const { x } = body`, `body.x`, `formData.get('x')` |
| URL params | `[pid]` folder + `const { pid } = params` |
| Query params | `req.query.x`, `searchParams.get('x')` |
| DB calls | Imports from model/repository layers + `await fn()` calls |

**Supported frameworks:**
- Next.js App Router (`app/api/**/route.js`)
- Next.js Pages Router (`pages/api/**/*.js`)
- Express (`app.get()`, `router.post()`, `.route('/x').get().post()`)

---

### `bass-sqli` — SQL Injection Test Suite

Fires 18 SQL injection attack categories at your running API and reports pass/fail per payload.

```bash
# Test localhost:1010/farm-management/api (default)
bass-sqli

# Custom base URL
bass-sqli http://localhost:3000/api

# With credentials (enables authenticated endpoint tests)
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-sqli

# With OOB server for categories 16 & 17 (out-of-band)
OOB_HOST=xyz.oast.fun bass-sqli
```

**Example output:**

```
╔══════════════════════════════════════════════╗
║  SQL Injection Test Suite                    ║
╚══════════════════════════════════════════════╝

▸ 2 · Login bypass
    ✓ email: admin'--
    ✓ email: ' OR 1=1--
    ✓ email: ' OR '1'='1'--

▸ 13 · Visible error-based SQLi
    ✓ '
    ✓ ' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--

▸ 14 · Blind — time delays  (threshold: 3000ms)
    ✓ '; SELECT SLEEP(4)--   142ms HTTP 401
    ✓ '; WAITFOR DELAY '0:0:4'--   98ms HTTP 401

╔══════════════════════════════════════════════╗
║  Results                                     ║
╚══════════════════════════════════════════════╝
  Passed  (safe)       : 87
  Failed  (vulnerable) : 0
  Errors               : 0
  Skipped              : 4
  Total                : 91

✓  All executed tests passed.
```

---

## Attack Categories Covered

| # | Category | Detection method |
|---|---|---|
| 1 | WHERE clause — hidden data retrieval | Row count vs baseline |
| 2 | Login bypass | `200 + isAuth:true` on bad credentials |
| 3 | DB version fingerprint — Oracle | Oracle banner / ORA- errors in response |
| 4 | DB version fingerprint — MySQL / MSSQL | Version string regex in response |
| 5 | Schema enumeration — `information_schema` | Table/column names leaked |
| 6 | Schema enumeration — Oracle `all_tables` | ORA- errors |
| 7 | UNION — column count detection | `ORDER BY N` + `UNION SELECT NULL,...` |
| 8 | UNION — finding a text column | Canary string reflected in response |
| 9 | UNION — data retrieval from other tables | Email pattern in response |
| 10 | UNION — multiple values in one column | `CONCAT` / `GROUP_CONCAT` output |
| 11 | Blind — conditional responses | TRUE vs FALSE condition body diff |
| 12 | Blind — conditional errors | TRUE→200, FALSE→DB error (1/0) |
| 13 | Visible error-based | `EXTRACTVALUE`, `UPDATEXML`, unmatched quotes |
| 14 | Blind — time delays | Response time ≥ threshold |
| 15 | Blind — time delays + data retrieval | `IF(condition, SLEEP(4), 0)` |
| 16 | Blind — out-of-band interaction | Requires `OOB_HOST` env var |
| 17 | Blind — out-of-band data exfiltration | Requires `OOB_HOST` env var |
| 18 | Filter bypass via XML / encoding | Entities, double-encode, comment breaks, case mix |

---

## Programmatic API

Both tools are fully importable for use inside your own test suites.

```js
import { scanProject, printEndpoints } from 'build-aware-security-scanning'

// Scan a project and get structured data
const result = scanProject('/path/to/project')
console.log(result.endpoints)
// [{ method: 'POST', path: '/api/auth', auth: false, bodyFields: ['email','password'], ... }]

// Print the formatted table
printEndpoints(result, { showSqli: true })
```

```js
import { runAll, testLoginBypass, testTimeDelay } from 'build-aware-security-scanning'

const BASE = 'http://localhost:3000/api'

// Run the full suite
const stats = await runAll({
  base:     BASE,
  email:    'admin@example.com',
  password: 'secret',
  oobHost:  'xyz.oast.fun',      // optional
})
// { passed: 87, failed: 0, errored: 0, skipped: 4 }

// Or run individual categories
import { makeResult, makeStats } from 'build-aware-security-scanning'
const stats  = { passed: 0, failed: 0, errored: 0, skipped: 0 }
const result = (label, status, detail) => { stats[{ pass:'passed', fail:'failed', err:'errored', skip:'skipped' }[status]]++; }

await testLoginBypass(BASE, result)
await testTimeDelay(BASE, result)
```

### `scanProject(projectDir)` → `{ framework, basePath, endpoints[] }`

Each endpoint object:

```ts
{
  method:      string          // 'GET' | 'POST' | 'PUT' | ...
  path:        string          // '/api/feed/:pid'
  auth:        boolean         // true if session/cookie check detected
  bodyFields:  string[]        // ['seeds', 'species', 'price']
  queryParams: string[]        // ['page', 'limit']
  dynParams:   string[]        // ['pid']
  modelCalls:  string[]        // ['addPondFeed', 'getFarm']
  file:        string          // 'src/app/api/feed/[pid]/route.js'
}
```

### `runAll(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | Full API base URL |
| `email` | `string` | Credentials for authenticated tests |
| `password` | `string` | |
| `oobHost` | `string` | OOB callback hostname for categories 16–17 |

---

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `TEST_EMAIL` | `bass-sqli` | Login email for authenticated tests |
| `TEST_PASSWORD` | `bass-sqli` | Login password |
| `OOB_HOST` | `bass-sqli` | OOB server hostname (e.g. `xyz.oast.fun`) |

---

## Requirements

- Node.js ≥ 18
- No runtime dependencies — uses only Node.js built-ins and the native `fetch` API

---

## License

MIT
