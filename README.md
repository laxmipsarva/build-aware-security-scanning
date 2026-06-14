# build-aware-security-scanning

A zero-dependency CLI toolkit that **discovers API endpoints**, **tests for SQL injection** across all 18 OWASP attack categories, **tests for API-level vulnerabilities** including mass assignment and parameter pollution, **tests GraphQL endpoints** for introspection, IDOR, and brute-force bypasses, **tests for CSRF vulnerabilities** across 12 attack patterns, and **tests for XSS & CSP misconfigurations** across all 28 PortSwigger XSS categories — built for Next.js (App Router & Pages Router) and Express apps.

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

**Attack categories:**

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

### `bass-api` — API Security Test Suite

Tests the **running API** for 5 categories of API-level vulnerabilities, optionally using the endpoint list produced by `bass-list`.

```bash
# Test default URL (localhost:1010)
bass-api

# Custom base URL
bass-api http://localhost:3000/api

# Pass project path → auto-discovers endpoints and uses them as test targets
bass-api http://localhost:1010/farm-management/api /path/to/project

# With credentials (enables authenticated tests)
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-api http://... /path/to/project
```

**Attack categories:**

| # | Category | What is tested |
|---|---|---|
| 1 | **API documentation exploitation** | Probes 20+ common doc paths (`/swagger.json`, `/openapi.json`, `/api-docs`, `/redoc`, …). Parses any found schema and flags endpoints missing from source code. Alerts on admin/internal paths. |
| 2 | **Server-side parameter pollution — query string** | Duplicate params (`?id=1&id=2`), encoded `&` (`%26`), array notation (`id[]=1`), null-byte truncation (`id=val%00`), duplicate JSON keys in POST bodies. |
| 3 | **Finding and exploiting unused endpoints** | Wordlist of 30+ hidden paths (`/admin`, `/debug`, `/health`, `/export`, …), unexpected HTTP methods on known routes, method-override headers (`X-HTTP-Method-Override`), API version discovery (`/v1`, `/v2`, `/v3`). |
| 4 | **Mass assignment vulnerability** | Injects 20 privileged fields (`isAdmin`, `role`, `price`, `balance`, `verified`, `userId`, …) into every POST/PUT body. Flags if the response reflects any injected value or if the HTTP status changes. |
| 5 | **Server-side parameter pollution — REST URL** | Path traversal (`../admin`, `%2e%2e%2f`), null-byte (`1%00.json`), fragment injection, double slash, array params (`1,2,3`), SSTI probe (`{{7*7}}`), query-string override of REST param. |

---

### `bass-graphql` — GraphQL Security Test Suite

Tests a **running GraphQL endpoint** for 5 categories of GraphQL-specific vulnerabilities. Automatically discovers the GraphQL endpoint if not specified.

```bash
# Test default URL (localhost:3000)
bass-graphql

# Custom base URL (endpoint auto-discovered)
bass-graphql http://localhost:3000/api

# Explicit GraphQL endpoint (skips discovery)
bass-graphql http://localhost:3000/api --graphql=http://localhost:3000/graphql

# With credentials (enables authenticated tests)
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-graphql http://localhost:3000/api
```

**Attack categories:**

| # | Category | What is tested |
|---|---|---|
| 1 | **Finding a hidden GraphQL endpoint** | Probes 27 common GraphQL paths (`/graphql`, `/api/graphql`, `/gql`, `/query`, …) via POST and GET typename probes. Also checks for exposed GraphQL IDE/explorer UIs (GraphiQL, Playground, Altair, Voyager). |
| 2 | **Accidental exposure of private GraphQL fields** | Runs full introspection; scans all types for sensitive field names (password, token, secret, SSN, CVV, …) and sensitive type names (Admin, Internal, Credential, …). Also flags deprecated fields still in the schema and exposed mutations/subscriptions. |
| 3 | **Accessing private GraphQL data (authorization bypass)** | Tests unauthenticated access to schema-derived and common query fields (`me`, `viewer`, `users`, `posts`). Probes IDOR via sequential ID enumeration and aliased batch queries. Checks for unrestricted user-list exposure. |
| 4 | **CSRF exploits over GraphQL** | Checks whether mutations are executable via GET requests, `application/x-www-form-urlencoded`, and `text/plain` POST bodies (all bypass CORS preflight). Inspects CORS headers for wildcard origins and credentialed access. Verifies SameSite cookie attributes and CSRF token enforcement on mutations. |
| 5 | **Bypassing GraphQL brute force protections** | Tests JSON array batching (10 operations in one HTTP request), alias-based batching (10 aliased calls in one query), fragment amplification, and deep query nesting (depth 10). Also identifies login mutations by name for targeted brute-force enumeration. |

---

### `bass-csrf` — CSRF Security Test Suite

Tests the **running app** for 12 categories of CSRF vulnerabilities covering token weaknesses, SameSite bypasses, and Referer validation flaws. Requires an authenticated session to run most tests.

```bash
# Test default URL (localhost:3000) — most tests skipped without credentials
bass-csrf

# Custom base URL with credentials
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-csrf http://localhost:3000

# Pass project path to use discovered endpoints as test targets
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-csrf http://localhost:3000 /path/to/project
```

**Attack categories:**

| # | Category | What is tested |
|---|---|---|
| 1 | **No defenses** | Submits state-changing POST with authenticated session but no CSRF token, no Origin, and no Referer. Acceptance = vulnerable. |
| 2 | **Token validation depends on request method** | Sends POST with wrong token (expects 403), then sends GET for the same action. If GET is accepted, CSRF token is only enforced on POST. |
| 3 | **Token validation depends on token being present** | Sends POST with an invalid token (expects 403), then re-sends with the token field entirely omitted. If omission is accepted, validation is skipped when the field is absent. |
| 4 | **CSRF token not tied to user session** | Extracts a valid CSRF token from the app, then submits it with a tampered or missing session cookie. If accepted, the token is not session-bound and can be reused across victims. |
| 5 | **CSRF token tied to non-session cookie** | Detects a dedicated CSRF cookie (e.g. `XSRF-TOKEN`). Then forges both the cookie and the matching body/header field with attacker-controlled values to demonstrate subdomain injection risk. |
| 6 | **Double-submit cookie pattern** | Crafts an attacker-controlled CSRF value, injects it in both the session cookie and all known CSRF field names, and sends a forged request. If accepted, the double-submit pattern is bypassable. |
| 7 | **SameSite Lax bypass via method override** | Detects the SameSite attribute in use, then tests `_method=GET` query param, `X-HTTP-Method-Override`, `X-Method-Override`, and `X-HTTP-Method` headers on POST endpoints to convert a cross-site POST into a server-side GET. |
| 8 | **SameSite Strict bypass via client-side redirect** | Probes 12 common redirect paths × 4 redirect parameters for open redirects. An open redirect on the same site allows an attacker to chain: evil.com → same-site redirect → sensitive action with Strict cookies attached. Also checks for external `window.location` JS redirects. |
| 9 | **SameSite Strict bypass via sibling domain** | Checks CORS preflight responses for all common subdomains (staging, dev, test, uploads, static, cdn, …). If a sibling subdomain is accepted with `Access-Control-Allow-Credentials: true`, XSS there enables full CSRF on the main domain. Also checks if the session cookie Domain attribute scopes to the whole eTLD+1. |
| 10 | **SameSite Lax bypass via cookie refresh** | Searches for cookie-refresh endpoints (`/auth/refresh`, `/oauth/authorize`, `/auth/session`, …) that set new Lax or no-SameSite cookies. Chrome's 2-minute Lax grace window allows cross-site POSTs immediately after a cookie refresh. |
| 11 | **Referer validation depends on header being present** | Sends three parallel requests: valid same-origin Referer, attacker Referer, and no Referer. If the attacker Referer is blocked but the absent Referer is accepted, the check is bypassable via `<meta name="referrer" content="no-referrer">`. |
| 12 | **Broken Referer validation** | Confirms Referer validation is active, then tests 7 bypass payloads: domain as subdomain of evil host, domain in query string, domain in URL path, prefix bypass, `null` Referer, schema-less Referer, and HTTP instead of HTTPS. |

---

### `bass-xss` — XSS & CSP Security Test Suite

Tests the **running app** for all 28 XSS attack categories from the PortSwigger Web Security Academy, plus full CSP header analysis. Combines static DOM analysis (examining page source for dangerous source→sink chains) with active reflection probing (sending payloads and checking responses).

```bash
# Test default URL (localhost:3000)
bass-xss

# Custom base URL
bass-xss http://localhost:3000

# Pass project path to use discovered endpoints as test targets
bass-xss http://localhost:3000 /path/to/project

# With credentials (enables stored XSS tests)
TEST_EMAIL=admin@example.com TEST_PASSWORD=secret bass-xss http://localhost:3000 /path/to/project
```

**Attack categories:**

| # | Category | What is tested |
|---|---|---|
| 1 | **Reflected XSS — HTML context, nothing encoded** | Sends `<script>`, `<img onerror>`, `<svg onload>`, `<body onload>` payloads via query params and checks if they appear unencoded in the HTML response. |
| 2 | **Stored XSS — HTML context, nothing encoded** | Submits XSS payload to POST/PUT endpoints, then checks GET responses for unencoded reflection. |
| 3 | **DOM XSS — document.write(location.search)** | Statically analyzes all inline `<script>` blocks for `document.write()` / `document.writeln()` calls that co-occur with `location.search` or `location.hash` sources. |
| 4 | **DOM XSS — innerHTML(location.search)** | Scans script blocks for `.innerHTML`, `.outerHTML`, and `.insertAdjacentHTML()` sinks that co-occur with user-controlled sources. |
| 5 | **DOM XSS — jQuery .attr("href") sink** | Detects jQuery `.attr("href", ...)` calls driven by `location.search` or other sources — attacker can inject `javascript:` URI. |
| 6 | **DOM XSS — jQuery selector + hashchange** | Looks for `$(location.hash)` patterns inside `hashchange` event handlers — hash value used directly as jQuery selector, executing HTML. |
| 7 | **Reflected XSS into attribute — angle brackets encoded** | Probes whether `"` (double-quote) is left unencoded inside attribute values even when `<>` are HTML-encoded, allowing attribute breakout with `" onmouseover=...`. |
| 8 | **Stored XSS into anchor href — double quotes encoded** | Submits `javascript:` URIs to fields that accept URLs; checks if `javascript:` scheme is stored and reflected in `href` / `src` attributes. |
| 9 | **Reflected XSS in JS string — angle brackets encoded** | Tests whether `'` (single quote) passes through unencoded inside a JavaScript string variable, allowing `'; alert(1)//` string termination. |
| 10 | **DOM XSS — document.write inside `<select>`** | Detects `document.write(location.search)` patterns inside pages containing `<select>` elements — attacker injects `</select><img onerror=...>` to escape the element. |
| 11 | **DOM XSS — AngularJS `{{expression}}`** | Detects AngularJS (v1.x) usage via `ng-app`, `ng-controller`, and `angular.js` references. Probes `?param={{7*7}}` — if response contains `49` (not the literal `{{7*7}}`), AngularJS evaluated the expression. |
| 12 | **Reflected DOM XSS** | Checks whether server-reflected values land inside `<script>` blocks (rather than raw HTML), signalling that the value may flow into a client-side DOM sink. |
| 13 | **Stored DOM XSS** | Submits payloads via POST, then checks if they appear inside `<script>` blocks in subsequent GET responses. |
| 14 | **Reflected XSS — most tags & attributes blocked** | Tests `<body onresize>`, `<body onpageshow>`, `<input autofocus onfocus>`, and `<details ontoggle>` — less-common HTML5 event handlers that may bypass tag/attribute blocklists. |
| 15 | **Reflected XSS — all tags blocked except custom ones** | Tests `<xss onmouseover>` and `<xss onfocus tabindex=1>` — custom HTML elements are not in standard blocklists and still support event handlers. |
| 16 | **Reflected XSS — some SVG markup allowed** | Tests `<svg onload>`, `<svg><animatetransform onbegin>`, and `<svg><animate onbegin>` — SVG elements support event handlers even when HTML elements are blocked. |
| 17 | **Reflected XSS in canonical link tag** | Probes `<link rel=canonical href=... accesskey=x onclick=...>` — a canonical link with `accesskey` can trigger `onclick` via keyboard shortcut, bypassing interactive-event restrictions. |
| 18 | **Reflected XSS in JS string — `'` and `\` escaped** | Tests `\\'-payload` — if the server escapes `'` with `\` but does not double-escape `\`, the attacker sends `\'` and the `\` is consumed, leaving `'` to close the string. |
| 19 | **Reflected XSS in JS string — `<>`, `"` encoded, `'` escaped** | Tests `</script><script>payload</script>` — parser-level script block termination bypasses JS-string escaping entirely, since the HTML parser closes the script block before the JS parser reaches the escape. |
| 20 | **Stored XSS into onclick event — HTML entities bypass** | Submits `&apos;`, `&#x27;` in POST body fields; checks if the browser decodes the HTML entity back to `'` inside an `onclick` attribute value, breaking out of the JS string. |
| 21 | **Reflected XSS into template literal — all chars escaped** | Tests `${payload}` — if all quote variants, `<>`, and `\` are encoded but the value is placed inside a `` ` `` template literal, `${expression}` still executes. |
| 22 | **Exploiting XSS to steal cookies** | Checks session cookie `HttpOnly` flag (missing = `document.cookie` readable by XSS), `Secure` flag, and `SameSite` attribute. |
| 23 | **Exploiting XSS to capture passwords** | Checks whether password `<input>` fields on the page have `autocomplete=off` or `autocomplete=new-password`. Missing protection means XSS can inject a fake login field and capture password-manager auto-fill. |
| 24 | **Exploiting XSS to bypass CSRF defenses** | Checks whether CSRF tokens are present in `<meta>` tags, hidden `<input>` fields, or inline `<script>` blocks — all of which are readable by any same-origin XSS, allowing the token to be stolen and replayed. |
| 25 | **Reflected XSS — event handlers and href blocked** | Tests `<object data="javascript:...">` and `<math><mtext><option>` constructs that reach execution without standard event handlers or `href`. |
| 26 | **Reflected XSS in JavaScript URL — some chars blocked** | Tests HTML-entity-encoded `javascript:`, `javascript:throw/...`, and `javascript:onerror=...,throw 1` — alternate javascript: URI forms that bypass simple string-matching filters. |
| 27 | **Reflected XSS protected by strict CSP — dangling markup** | When `script-src` is strict but `img-src` allows external hosts, tests whether an injected `<img src='//evil.com/?` causes page content after the injection point (CSRF token, email, nonce) to leak as a URL query parameter. Also checks `connect-src` permissiveness. |
| 28 | **Reflected XSS protected by CSP — CSP bypass** | Full CSP header analysis: `'unsafe-inline'` without nonce/hash, `'unsafe-eval'`, wildcard `*` in `script-src`, `data:` URIs, known JSONP/CDN bypass hosts (googleapis, cdnjs, jsdelivr), missing `base-uri` (base-tag injection), missing `form-action` (form hijacking), static/reused nonces, and missing `report-uri`. |

---

## OWASP Coverage

Each tool maps directly to specific entries in the **[OWASP Top 10 (2021)](https://owasp.org/Top10/)** for web applications and the **[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)** for APIs.

### `bass-sqli` — OWASP Top 10 (2021)

| OWASP | Category | What the suite covers |
|---|---|---|
| **A03:2021** | **Injection** | All 18 SQLi attack classes: error-based, blind boolean, blind time-delay (MySQL/MSSQL/Oracle), UNION-based data retrieval, login bypass, out-of-band interaction and exfiltration, schema enumeration via `information_schema` and `all_tables`, and encoding/filter bypass (XML entities, double-encode, comment breaks, case mixing). Every discovered endpoint is tested. |

### `bass-api` — OWASP API Security Top 10 (2023)

| OWASP API | Category | What the suite covers |
|---|---|---|
| **API3:2023** | **Broken Object Property Level Authorization** | Mass assignment: injects 20 privileged fields (`isAdmin`, `role`, `price`, `balance`, `verified`, `userId`, …) into every POST/PUT body and flags any that are reflected in the response or change the HTTP status. |
| **API8:2023** | **Security Misconfiguration** | Query-string parameter pollution (duplicate params, encoded `&`, array notation, null-byte truncation, duplicate JSON keys) and REST URL pollution (path traversal, null-byte, fragment injection, double slash, SSTI probe `{{7*7}}`, query-string REST param override). |
| **API9:2023** | **Improper Inventory Management** | Documentation exploitation probes 20+ doc endpoints (`/swagger.json`, `/openapi.json`, `/api-docs`, `/redoc`, …) and parses any found schema to surface undocumented or admin paths. Hidden endpoint discovery probes 30+ unlisted paths (`/admin`, `/debug`, `/health`, `/export`, …), unexpected HTTP methods, method-override headers, and API version paths (`/v1`, `/v2`, `/v3`). |

### `bass-graphql` — OWASP API Security Top 10 (2023)

| OWASP API | Category | What the suite covers |
|---|---|---|
| **API1:2023** | **Broken Object Level Authorization** | Tests unauthenticated access to schema-derived and common query fields (`me`, `viewer`, `users`, `posts`). Probes IDOR via sequential ID enumeration (IDs 1–5) and aliased batch queries. Checks for unrestricted user-list exposure returning PII without credentials. |
| **API4:2023** | **Unrestricted Resource Consumption** | Brute-force bypass: sends JSON array batches (10 operations in one HTTP request), alias floods (10 aliased calls in one query document), fragment amplification (one fragment spread 10 times), and deep query nesting (depth 10) to verify that rate limiting applies per-operation rather than per-request. |
| **API8:2023** | **Security Misconfiguration** | Full introspection scan for sensitive field names (password, token, secret, SSN, CVV, …) and sensitive type names (Admin, Internal, Credential, Session, …). Flags deprecated fields still present in schema. CORS header inspection detects wildcard `Access-Control-Allow-Origin` and credentialed cross-origin access. Checks `Content-Type` restrictions and SameSite cookie attributes on mutations. |
| **API9:2023** | **Improper Inventory Management** | Hidden endpoint discovery probes 27 common GraphQL paths via POST and GET typename probes. Separately checks for publicly exposed GraphQL IDE/explorer UIs (GraphiQL, Playground, Altair, Voyager) that allow unauthenticated schema browsing and query execution. |

### `bass-xss` — OWASP Top 10 (2021)

| OWASP | Category | What the suite covers |
|---|---|---|
| **A03:2021** | **Injection** (includes XSS) | All 28 XSS attack patterns: reflected (HTML context, attribute, JS string, template literal), stored (HTML, href, event handler), DOM-based (document.write, innerHTML, jQuery, AngularJS), and all filter bypass techniques (blocked tags, SVG, custom elements, canonical link, JS URL variants). |
| **A01:2021** | **Broken Access Control** | Cookie theft via XSS (HttpOnly missing), password capture via auto-fill (autocomplete missing), and CSRF-bypass via XSS (CSRF token readable from DOM). |
| **A05:2021** | **Security Misconfiguration** | Full CSP header analysis: missing header, report-only mode, `'unsafe-inline'`/`'unsafe-eval'`, wildcard `*`, `data:` URIs, known CDN/JSONP bypass hosts, missing `base-uri`, missing `form-action`, static nonces, dangling markup exfiltration via permissive `img-src`, and missing violation reporting. |

### `bass-csrf` — OWASP Top 10 (2021)

| OWASP | Category | What the suite covers |
|---|---|---|
| **A01:2021** | **Broken Access Control** | All 12 CSRF test categories verify that state-changing endpoints correctly reject cross-origin requests: missing defenses (no token, no Origin, no Referer); token bypass via method dependency (GET skips token check), token presence dependency (omitted field skips check), cross-session token reuse (token not bound to session), and forged double-submit cookies; SameSite bypasses via method-override headers (`X-HTTP-Method-Override`, `_method=GET`), open-redirect chains (Strict bypass), sibling-domain CORS misconfiguration, and the 2-minute Lax cookie-refresh grace window; Referer validation bypass via absent header (no-referrer meta tag) and weak contains-check payloads (domain as subdomain, in query string, in path, with prefix). |

---

## Programmatic API

All tools are fully importable for use inside your own test suites.

### Endpoint discovery

```js
import { scanProject, printEndpoints } from 'build-aware-security-scanning'

const result = scanProject('/path/to/project')
console.log(result.endpoints)
// [{ method: 'POST', path: '/api/auth', auth: false, bodyFields: ['email','password'], ... }]

printEndpoints(result, { showSqli: true })
```

### SQL injection

```js
import { runAll, testLoginBypass, testTimeDelay } from 'build-aware-security-scanning'

const stats = await runAll({
  base:     'http://localhost:3000/api',
  email:    'admin@example.com',
  password: 'secret',
  oobHost:  'xyz.oast.fun',   // optional
})
// { passed: 87, failed: 0, errored: 0, skipped: 4 }

// Or run individual categories
const stats2 = { passed: 0, failed: 0, errored: 0, skipped: 0 }
const result = (label, status) => { stats2[{pass:'passed',fail:'failed',err:'errored',skip:'skipped'}[status]]++ }
await testLoginBypass('http://localhost:3000/api', result)
await testTimeDelay('http://localhost:3000/api', result)
```

### API security

```js
import { runApiTests, testMassAssignment, testRestUrlPollution } from 'build-aware-security-scanning'
import { scanProject } from 'build-aware-security-scanning'

const { endpoints } = scanProject('/path/to/project')

const stats = await runApiTests({
  base:      'http://localhost:3000/api',
  endpoints,
  cookie:    'AUTH=<session_token>',
})
// { passed: 42, failed: 0, errored: 0, skipped: 3 }

// Run a single category
const stats2 = { passed:0, failed:0, errored:0, skipped:0 }
const result = (label, status) => { stats2[{pass:'passed',fail:'failed',err:'errored',skip:'skipped'}[status]]++ }
await testMassAssignment('http://localhost:3000/api', endpoints, 'AUTH=token', result)
```

### GraphQL security

```js
import {
  runGraphqlTests,
  testHiddenEndpoints,
  testIntrospectionExposure,
  testPrivateDataAccess,
  testCsrfVulnerability,
  testBruteForceBypass,
} from 'build-aware-security-scanning'

// Run the full suite (auto-discovers GraphQL endpoint)
const stats = await runGraphqlTests({
  base:   'http://localhost:3000/api',
  cookie: 'AUTH=<session_token>',  // optional
})
// { passed: 18, failed: 2, errored: 0, skipped: 1 }

// Provide an explicit GraphQL URL to skip discovery
const stats2 = await runGraphqlTests({
  base:   'http://localhost:3000',
  gqlUrl: 'http://localhost:3000/graphql',
  cookie: 'AUTH=<session_token>',
})

// Run individual categories
const stats3 = { passed:0, failed:0, errored:0, skipped:0 }
const result = (label, status) => { stats3[{pass:'passed',fail:'failed',err:'errored',skip:'skipped'}[status]]++ }
const gqlUrl = 'http://localhost:3000/graphql'
await testIntrospectionExposure(gqlUrl, 'AUTH=token', result)
await testBruteForceBypass(gqlUrl, 'AUTH=token', result)
```

### XSS & CSP security

```js
import {
  runXssTests,
  testReflectedXssHtml,
  testDomXssDocumentWrite,
  testDomXssInnerHtml,
  testDomXssJquery,
  testXssInAttributes,
  testXssInJsStrings,
  testAngularJsXss,
  testXssFilterBypass,
  testStoredXssEventHandler,
  testXssExploitability,
  testCspSecurity,
} from 'build-aware-security-scanning'
import { scanProject } from 'build-aware-security-scanning'

const { endpoints } = scanProject('/path/to/project')

// Run the full suite
const stats = await runXssTests({
  base:      'http://localhost:3000',
  endpoints,
  cookie:    'AUTH=<session_token>',  // optional — enables stored XSS tests
})
// { passed: 14, failed: 3, errored: 1, skipped: 2 }

// Run individual categories
const stats2 = { passed:0, failed:0, errored:0, skipped:0 }
const result = (label, status) => { stats2[{pass:'passed',fail:'failed',err:'errored',skip:'skipped'}[status]]++ }
await testCspSecurity('http://localhost:3000', endpoints, null, result)
await testDomXssInnerHtml('http://localhost:3000', endpoints, null, result)
```

### CSRF security

```js
import {
  runCsrfTests,
  testNoDefenses,
  testTokenNotTiedToSession,
  testSameSiteLaxMethodOverride,
  testBrokenRefererValidation,
} from 'build-aware-security-scanning'
import { scanProject } from 'build-aware-security-scanning'

const { endpoints } = scanProject('/path/to/project')

// Run the full suite
const stats = await runCsrfTests({
  base:      'http://localhost:3000',
  endpoints,
  cookie:    'AUTH=<session_token>',
})
// { passed: 24, failed: 1, errored: 0, skipped: 6 }

// Run individual categories
const stats2 = { passed:0, failed:0, errored:0, skipped:0 }
const result = (label, status) => { stats2[{pass:'passed',fail:'failed',err:'errored',skip:'skipped'}[status]]++ }
await testNoDefenses('http://localhost:3000', endpoints, 'AUTH=token', result)
await testBrokenRefererValidation('http://localhost:3000', endpoints, 'AUTH=token', result)
```

---

## API Reference

### `scanProject(projectDir)` → `{ framework, basePath, endpoints[] }`

Each endpoint object:

```ts
{
  method:      string    // 'GET' | 'POST' | 'PUT' | ...
  path:        string    // '/api/feed/:pid'
  auth:        boolean   // true if session/cookie check detected
  bodyFields:  string[]  // ['seeds', 'species', 'price']
  queryParams: string[]  // ['page', 'limit']
  dynParams:   string[]  // ['pid']
  modelCalls:  string[]  // ['addPondFeed', 'getFarm']
  file:        string    // 'src/app/api/feed/[pid]/route.js'
}
```

### `runAll(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | Full API base URL |
| `email` | `string` | Credentials for authenticated tests |
| `password` | `string` | |
| `oobHost` | `string` | OOB callback hostname for categories 16–17 |

### `runApiTests(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | Full API base URL |
| `endpoints` | `object[]` | Endpoint list from `scanProject()` |
| `cookie` | `string` | Authenticated session cookie string |

### `runGraphqlTests(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | Base URL used for endpoint discovery and auth |
| `gqlUrl` | `string` | Explicit GraphQL URL — skips the discovery phase |
| `cookie` | `string` | Authenticated session cookie string |

### `runXssTests(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | App origin URL (e.g. `http://localhost:3000`) |
| `endpoints` | `object[]` | Endpoint list from `scanProject()` — used to target reflection and stored XSS probes |
| `cookie` | `string` | Authenticated session cookie — required for stored XSS tests (cats 2, 13, 20) |

### `runCsrfTests(opts)` → `Promise<{ passed, failed, errored, skipped }>`

| Option | Type | Description |
|---|---|---|
| `base` | `string` | Full app base URL |
| `endpoints` | `object[]` | Endpoint list from `scanProject()` — used to find state-changing targets |
| `cookie` | `string` | Authenticated session cookie string — required for most tests |

---

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `TEST_EMAIL` | all CLIs | Login email for authenticated tests |
| `TEST_PASSWORD` | all CLIs | Login password |
| `OOB_HOST` | `bass-sqli` | OOB server hostname (e.g. `xyz.oast.fun`) for out-of-band SQLi categories 16–17 |

---

## Requirements

- Node.js ≥ 18
- No runtime dependencies — uses only Node.js built-ins and the native `fetch` API

---

## License

MIT
