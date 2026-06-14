// Programmatic API — import what you need

export {
  // Endpoint scanner
  scanProject,
  printEndpoints,
  detectFramework,
  walkDir,
  // Individual parsers
  extractNextMethods,
  extractBodyFields,
  extractQueryParams,
  extractDynamicParams,
  extractModelCalls,
  detectAuth,
} from './src/list-endpoints.mjs'

export {
  // Full SQLi suite runner
  runAll,
  getSessionCookie,
  // Individual SQLi attack categories
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

export {
  // Full API security suite runner
  runApiTests,
  // Individual API attack categories
  testDocumentationExploitation,
  testQueryParamPollution,
  testUnusedEndpoints,
  testMassAssignment,
  testRestUrlPollution,
} from './src/test-api.mjs'

export {
  // Full GraphQL security suite runner
  runGraphqlTests,
  // Individual GraphQL attack categories
  testHiddenEndpoints,
  testIntrospectionExposure,
  testPrivateDataAccess,
  testCsrfVulnerability,
  testBruteForceBypass,
} from './src/test-graphql.mjs'

export {
  // Full CSRF security suite runner
  runCsrfTests,
  // Individual CSRF attack categories
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
} from './src/test-csrf.mjs'

export {
  // Full XSS & CSP security suite runner
  runXssTests,
  // Individual XSS / CSP attack categories
  testReflectedXssHtml,
  testStoredXssHtml,
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
} from './src/test-xss.mjs'
