import fs   from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

// ── ANSI ───────────────────────────────────────────────────────────────────────
const R    = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM  = '\x1b[2m'
const RED  = '\x1b[31m'
const GRN  = '\x1b[32m'
const YLW  = '\x1b[33m'
const CYN  = '\x1b[36m'
const MAG  = '\x1b[35m'

const HTTP_METHODS  = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']
const METHOD_COLOR  = { GET: GRN, POST: YLW, PUT: CYN, PATCH: MAG, DELETE: RED, HEAD: DIM, OPTIONS: DIM }

// ══════════════════════════════════════════════════════════════════════════════
// FRAMEWORK DETECTION
// ══════════════════════════════════════════════════════════════════════════════
export function detectFramework(dir) {
  const pkg  = readJson(path.join(dir, 'package.json'))
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies }

  const appApi   = [path.join(dir,'src','app','api'),   path.join(dir,'app','api')  ].find(fs.existsSync)
  const pagesApi = [path.join(dir,'src','pages','api'), path.join(dir,'pages','api')].find(fs.existsSync)
  const nextConf = ['next.config.js','next.config.mjs','next.config.ts']
                     .map(f => path.join(dir,f)).find(fs.existsSync)

  let basePath = ''
  if (nextConf) {
    const conf = readFile(nextConf)
    const m = conf?.match(/basePath\s*:\s*['"`]([^'"`]+)['"`]/)
    if (m) basePath = m[1]
  }

  if ('next' in deps || nextConf) {
    if (appApi)   return { type: 'nextjs-app',   apiRoot: appApi,   basePath }
    if (pagesApi) return { type: 'nextjs-pages', apiRoot: pagesApi, basePath }
  }
  if ('express' in deps) return { type: 'express', basePath }
  if (appApi)             return { type: 'nextjs-app',   apiRoot: appApi,   basePath }
  if (pagesApi)           return { type: 'nextjs-pages', apiRoot: pagesApi, basePath }
  return { type: 'unknown', basePath }
}

// ══════════════════════════════════════════════════════════════════════════════
// FILE WALKER
// ══════════════════════════════════════════════════════════════════════════════
export function walkDir(dir, exts = ['.js','.ts','.mjs','.cjs']) {
  const out = []
  if (!fs.existsSync(dir)) return out
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.') || e.name === 'node_modules') continue
    const full = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walkDir(full, exts))
    else if (exts.some(x => e.name.endsWith(x))) out.push(full)
  }
  return out
}

// ══════════════════════════════════════════════════════════════════════════════
// PARSERS
// ══════════════════════════════════════════════════════════════════════════════
export function extractNextMethods(src) {
  return HTTP_METHODS.filter(m =>
    new RegExp(`export\\s+(async\\s+)?function\\s+${m}\\b`).test(src) ||
    new RegExp(`export\\s+\\{[^}]*\\b${m}\\b[^}]*\\}`).test(src)
  )
}

export function extractExpressRoutes(src, filePath) {
  const routes = []
  const re = /(?:app|router)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"`](\/[^'"`]*)['"`]/gi
  let m
  while ((m = re.exec(src)) !== null)
    routes.push({ method: m[1].toUpperCase(), routePath: m[2] })

  const routeRe = /\.route\s*\(\s*['"`](\/[^'"`]*)['"`]\s*\)((?:\s*\.\s*(?:get|post|put|patch|delete)\s*\([^)]*\))+)/gi
  while ((m = routeRe.exec(src)) !== null) {
    const rp = m[1], chain = m[2], mRe = /\.\s*(get|post|put|patch|delete)\s*\(/gi
    let n
    while ((n = mRe.exec(chain)) !== null)
      routes.push({ method: n[1].toUpperCase(), routePath: rp })
  }
  return routes
}

export function detectAuth(src) {
  return /cookies\s*\(/.test(src) || /req\.cookies/.test(src) ||
         /decrypt\s*\(/.test(src)  || /verifySession/.test(src) ||
         /jwt\.verify/.test(src)   || /jwtVerify/.test(src)    ||
         /authorization/i.test(src)|| /bearer/i.test(src)      ||
         /req\.user\b/.test(src)
}

export function extractBodyFields(src) {
  const fields = new Set()
  let m
  const destructure = /const\s*\{([^}]+)\}\s*=\s*(?:await\s+)?(?:req\.json\s*\(\s*\)|body|req\.body)/g
  while ((m = destructure.exec(src)) !== null)
    m[1].split(',').map(f => f.trim().split(':')[0].trim()).filter(Boolean).forEach(f => fields.add(f))
  const dot = /(?:body|req\.body)\.([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = dot.exec(src)) !== null) fields.add(m[1])
  const fget = /(?:formData|params)\.get\s*\(\s*['"`]([^'"`]+)['"`]/g
  while ((m = fget.exec(src)) !== null) fields.add(m[1])
  return [...fields].filter(f => !['undefined','null','true','false'].includes(f))
}

export function extractQueryParams(src) {
  const params = new Set()
  let m
  const qDot = /req\.query\.([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = qDot.exec(src)) !== null) params.add(m[1])
  const qGet = /searchParams\.get\s*\(\s*['"`]([^'"`]+)['"`]/g
  while ((m = qGet.exec(src)) !== null) params.add(m[1])
  const qDes = /const\s*\{([^}]+)\}\s*=\s*req\.query/g
  while ((m = qDes.exec(src)) !== null)
    m[1].split(',').map(f => f.trim().split(':')[0].trim()).filter(Boolean).forEach(f => params.add(f))
  return [...params]
}

export function extractDynamicParams(src) {
  const params = new Set()
  let m
  const des = /const\s*\{([^}]+)\}\s*=\s*(?:await\s+)?params/g
  while ((m = des.exec(src)) !== null)
    m[1].split(',').map(f => f.trim().split(':')[0].trim()).filter(Boolean).forEach(f => params.add(f))
  const dot = /params\.([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = dot.exec(src)) !== null) params.add(m[1])
  const req = /req\.params\.([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = req.exec(src)) !== null) params.add(m[1])
  return [...params]
}

export function extractModelCalls(src) {
  const calls = new Set()
  let m
  const imp = /import\s*\{([^}]+)\}\s*from\s*['"`][^'"`]*(?:@model|_model|model|repository|repo|db)[^'"`]*['"`]/g
  while ((m = imp.exec(src)) !== null)
    m[1].split(',').map(f => f.trim().split(' as ')[0].trim()).filter(Boolean).forEach(f => calls.add(f))
  const callRe = /await\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g
  const skip = new Set(['fetch','require','import','JSON','Object','Array','Promise','console','Math','Date','parseInt','parseFloat','isNaN','Boolean','String','Number'])
  while ((m = callRe.exec(src)) !== null)
    if (!skip.has(m[1])) calls.add(m[1])
  return [...calls]
}

// ══════════════════════════════════════════════════════════════════════════════
// SCANNERS
// ══════════════════════════════════════════════════════════════════════════════
function filePathToRoute(filePath, apiRoot, basePath) {
  let rel = path.relative(apiRoot, path.dirname(filePath)).replace(/\\/g, '/')
  if (rel === '.') rel = ''
  rel = rel.replace(/\[\.\.\.([^\]]+)\]/g, ':$1*').replace(/\[([^\]]+)\]/g, ':$1')
  return `${basePath}/api${rel ? '/' + rel : ''}`
}

export function scanNextjsApp(apiRoot, basePath, projectDir) {
  const endpoints = []
  for (const file of walkDir(apiRoot).filter(f => /route\.(js|ts|mjs)$/.test(f))) {
    const src = readFile(file)
    if (!src) continue
    const methods = extractNextMethods(src)
    if (!methods.length) continue
    const shared = {
      path:        filePathToRoute(file, apiRoot, basePath),
      auth:        detectAuth(src),
      bodyFields:  extractBodyFields(src),
      queryParams: extractQueryParams(src),
      dynParams:   extractDynamicParams(src),
      modelCalls:  extractModelCalls(src),
      file:        path.relative(projectDir, file),
    }
    for (const method of methods) endpoints.push({ method, ...shared })
  }
  return endpoints
}

export function scanNextjsPages(apiRoot, basePath, projectDir) {
  const endpoints = []
  for (const file of walkDir(apiRoot).filter(f => /\.(js|ts|mjs)$/.test(f))) {
    const src = readFile(file)
    if (!src) continue
    const named   = HTTP_METHODS.filter(m => new RegExp(`export\\s+(async\\s+)?function\\s+${m}\\b`).test(src))
    const hasDef  = /export\s+default\s+(async\s+)?function/.test(src)
    const methods = named.length ? named : hasDef ? ['GET','POST','PUT','PATCH','DELETE'] : []
    if (!methods.length) continue
    let rel = path.relative(apiRoot, file).replace(/\\/g,'/').replace(/\.(js|ts|mjs)$/,'')
    if (rel === 'index') rel = ''
    rel = rel.replace(/\[\.\.\.([^\]]+)\]/g,':$1*').replace(/\[([^\]]+)\]/g,':$1')
    endpoints.push({
      method:      methods.join('|'),
      path:        `${basePath}/api${rel ? '/' + rel : ''}`,
      auth:        detectAuth(src),
      bodyFields:  extractBodyFields(src),
      queryParams: extractQueryParams(src),
      dynParams:   extractDynamicParams(src),
      modelCalls:  extractModelCalls(src),
      file:        path.relative(projectDir, file),
    })
  }
  return endpoints
}

export function scanExpress(dir, basePath, projectDir) {
  const endpoints = []
  for (const file of walkDir(dir).filter(f => /\.(js|ts|mjs|cjs)$/.test(f))) {
    const src = readFile(file)
    if (!src) continue
    const routes = extractExpressRoutes(src, file)
    if (!routes.length) continue
    const shared = {
      auth:        detectAuth(src),
      bodyFields:  extractBodyFields(src),
      queryParams: extractQueryParams(src),
      dynParams:   extractDynamicParams(src),
      modelCalls:  extractModelCalls(src),
      file:        path.relative(projectDir, file),
    }
    for (const { method, routePath } of routes)
      endpoints.push({ method, path: `${basePath}${routePath}`, ...shared })
  }
  return endpoints
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN EXPORT — programmatic API
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Scan a project directory and return all API endpoints.
 * @param {string} projectDir  Absolute path to the project root
 * @returns {{ type: string, endpoints: object[] }}
 */
export function scanProject(projectDir) {
  const fw = detectFramework(projectDir)
  let endpoints = []

  if (fw.type === 'nextjs-app')
    endpoints = scanNextjsApp(fw.apiRoot, fw.basePath, projectDir)
  else if (fw.type === 'nextjs-pages')
    endpoints = scanNextjsPages(fw.apiRoot, fw.basePath, projectDir)
  else if (fw.type === 'express')
    endpoints = scanExpress(projectDir, fw.basePath, projectDir)
  else {
    const appApi = [path.join(projectDir,'src','app','api'), path.join(projectDir,'app','api')].find(fs.existsSync)
    if (appApi) { endpoints = scanNextjsApp(appApi, fw.basePath, projectDir); fw.type = 'nextjs-app' }
    else        { endpoints = scanExpress(projectDir, fw.basePath, projectDir); fw.type = 'express' }
  }

  return { framework: fw.type, basePath: fw.basePath, endpoints }
}

// ══════════════════════════════════════════════════════════════════════════════
// OUTPUT
// ══════════════════════════════════════════════════════════════════════════════
export function printEndpoints(result, { showSqli = false } = {}) {
  const { framework, endpoints } = result

  console.log(`\n${BOLD}╔════════════════════════════════════════════════════════════════╗`)
  console.log(`║  API Endpoint Map                                              ║`)
  console.log(`╚════════════════════════════════════════════════════════════════╝${R}`)
  console.log(`${DIM}Framework : ${framework}\nEndpoints : ${endpoints.length}${R}\n`)

  const byPath = {}
  for (const ep of endpoints) (byPath[ep.path] ||= []).push(ep)

  for (const [routePath, eps] of Object.entries(byPath)) {
    console.log(`${BOLD}${CYN}${routePath}${R}`)
    for (const ep of eps) {
      const auth = ep.auth ? `${GRN}🔒 auth${R}` : `${YLW}⚠ no-auth${R}`
      const meth = ep.method.split('|').map(m => `${METHOD_COLOR[m]||R}${BOLD}${m}${R}`).join(' ')
      console.log(`  ${meth}  ${auth}`)
      console.log(`  ${DIM}file: ${ep.file}${R}`)
      if (ep.dynParams.length)   console.log(`  ${MAG}url params  :${R} ${ep.dynParams.join(', ')}`)
      if (ep.queryParams.length) console.log(`  ${CYN}query params:${R} ${ep.queryParams.join(', ')}`)
      if (ep.bodyFields.length)  console.log(`  ${YLW}body fields :${R} ${ep.bodyFields.join(', ')}`)
      if (showSqli && ep.modelCalls.length) {
        console.log(`  ${RED}db calls    :${R} ${ep.modelCalls.join(', ')}`)
        if (ep.bodyFields.length)  console.log(`  ${RED}⚠ sqli surface: body { ${ep.bodyFields.join(', ')} } → DB${R}`)
        if (ep.dynParams.length)   console.log(`  ${RED}⚠ sqli surface: url  { ${ep.dynParams.join(', ')} } → DB${R}`)
      }
      console.log()
    }
  }

  const byMethod = {}
  for (const ep of endpoints)
    for (const m of ep.method.split('|')) byMethod[m] = (byMethod[m] || 0) + 1

  console.log(`${BOLD}Summary${R}\n${'─'.repeat(30)}`)
  for (const [m, c] of Object.entries(byMethod))
    console.log(`  ${METHOD_COLOR[m]||R}${BOLD}${m.padEnd(8)}${R} ${c} endpoint${c > 1 ? 's' : ''}`)

  const authCount   = endpoints.filter(e => e.auth).length
  const noAuthCount = endpoints.length - authCount
  console.log(`\n  ${GRN}🔒 Auth-protected : ${authCount}${R}`)
  console.log(`  ${YLW}⚠  No auth check  : ${noAuthCount}${R}`)
  if (noAuthCount > 0 && !showSqli)
    console.log(`\n${DIM}Tip: run with --sqli to see SQL injection surface per endpoint${R}`)
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI entry — only runs when executed directly
// ══════════════════════════════════════════════════════════════════════════════
export async function main(argv = process.argv.slice(2)) {
  const showJson   = argv.includes('--json')
  const showSqli   = argv.includes('--sqli')
  const projectDir = path.resolve(argv.find(a => !a.startsWith('--')) || process.cwd())

  const result = scanProject(projectDir)

  if (showJson) console.log(JSON.stringify(result, null, 2))
  else          printEndpoints(result, { showSqli })
}

// helpers
function readFile(p) { try { return fs.readFileSync(p, 'utf8') } catch { return null } }
function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch { return null } }

// run if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) main()
