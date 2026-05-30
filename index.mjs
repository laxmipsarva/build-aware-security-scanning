// Programmatic API — import what you need
export {
  // Endpoint scanner
  scanProject,
  printEndpoints,
  detectFramework,
  walkDir,
  // individual parsers
  extractNextMethods,
  extractBodyFields,
  extractQueryParams,
  extractDynamicParams,
  extractModelCalls,
  detectAuth,
} from './src/list-endpoints.mjs'

export {
  // Full suite runner
  runAll,
  getSessionCookie,
  // Individual attack categories
  testLoginBypass,
  testWhereClause,
  testOracleVersion,
  testMySQLVersion,
  testInfoSchema,
  testOracleSchema,
  testUnionColumnCount,
  testUnionFindTextCol,
  testUnionDataRetrieval,
  testUnionMultiValue,
  testBlindConditional,
  testBlindConditionalErrors,
  testVisibleErrors,
  testTimeDelay,
  testTimeDelayDataRetrieval,
  testOutOfBand,
  testFilterBypass,
} from './src/test-sqli.mjs'
