#!/usr/bin/env bash
# TestGap — Test Coverage Gap Pattern Definitions
# Each pattern: REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical — Security/payment/auth code with zero tests
#   high     — Core source file or function with no coverage
#   medium   — Test quality issue or organization problem
#   low      — Improvement opportunity or minor gap
#
# IMPORTANT: All regexes must use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alpha:]] instead of \w
# - Avoid Perl-only features (\d, \w, etc.)
#
# Pattern categories:
#   MT — Missing Tests
#   TQ — Test Quality
#   CG — Critical Gaps
#   TO — Test Organization
#   CI — Coverage Indicators

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# 1. MISSING TESTS (MT) — Source code without corresponding tests
# ═══════════════════════════════════════════════════════════════════════════

declare -a TESTGAP_MT_PATTERNS=()

TESTGAP_MT_PATTERNS+=(
  # Source files with no corresponding test file (file-level checks in analyzer)
  'PLACEHOLDER_NO_TEST_FILE|high|MT-001|Source file has no corresponding test file|Create a test file matching the source file naming convention'

  # Exported functions with no test (JS/TS)
  'export[[:space:]]+(async[[:space:]]+)?function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*|high|MT-002|Exported function may lack test coverage|Add a test case for this exported function in the corresponding test file'
  'export[[:space:]]+const[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*(async[[:space:]]*)?\(|high|MT-003|Exported arrow function may lack test coverage|Add a test case for this exported const function'
  'export[[:space:]]+default[[:space:]]+(function|class)[[:space:]]+[a-zA-Z_]|high|MT-004|Default export may lack test coverage|Add a test case for the default export'
  'export[[:space:]]+class[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*|high|MT-005|Exported class may lack test coverage|Add a test class or describe block for this exported class'
  'module\.exports[[:space:]]*=[[:space:]]*\{|high|MT-006|CommonJS module exports may lack test coverage|Add tests for each exported member of module.exports'
  'module\.exports\.[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=|high|MT-007|CommonJS named export may lack test coverage|Add a test case for this named export'

  # Python public functions/classes
  'def[[:space:]]+[a-z_][a-z0-9_]*[[:space:]]*\(|high|MT-008|Python function may lack test coverage|Add a test_* function for this function in the test file'
  'class[[:space:]]+[A-Z][a-zA-Z0-9_]*[[:space:]]*[\(:]|high|MT-009|Python class may lack test coverage|Add a TestClassName class with test methods'

  # Go exported functions
  'func[[:space:]]+[A-Z][a-zA-Z0-9_]*[[:space:]]*\(|high|MT-010|Go exported function may lack test coverage|Add a Test function in the _test.go file'
  'func[[:space:]]+\([a-zA-Z_][a-zA-Z0-9_]*[[:space:]]+\*?[a-zA-Z_][a-zA-Z0-9_]*\)[[:space:]]+[A-Z][a-zA-Z0-9_]*|high|MT-011|Go exported method may lack test coverage|Add a Test function for this method'

  # Java public methods
  'public[[:space:]]+(static[[:space:]]+)?[a-zA-Z<>[\]]+[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(|high|MT-012|Java public method may lack test coverage|Add a @Test method in the corresponding Test class'

  # Ruby public methods
  'def[[:space:]]+[a-z_][a-z0-9_]*|high|MT-013|Ruby method may lack test coverage|Add an it block or test method for this method'

  # API endpoint handlers (JS/TS)
  '\.(get|post|put|patch|delete)\([[:space:]]*["\x27/]|critical|MT-014|API route handler may lack integration test|Add an integration test that exercises this HTTP endpoint'
  'router\.(get|post|put|patch|delete)\(|critical|MT-015|Express router endpoint may lack test|Add a supertest or equivalent integration test for this route'
  'app\.(get|post|put|patch|delete)\([[:space:]]*["\x27/]|critical|MT-016|Express app endpoint may lack test|Add an integration test for this endpoint'

  # API handlers (Python)
  '@app\.(route|get|post|put|patch|delete)\(|critical|MT-017|Flask/FastAPI route may lack test|Add a test using the test client for this endpoint'

  # Middleware (JS/TS)
  'app\.use\([[:space:]]*(async[[:space:]]*)?\(req|high|MT-018|Express middleware may lack test coverage|Add tests for middleware behavior including error cases'

  # Error handlers
  'app\.use\([[:space:]]*(async[[:space:]]*)?\(err|high|MT-019|Error handler middleware may lack test|Add tests that trigger error conditions and verify handler response'

  # Database models/migrations (JS/TS)
  'PLACEHOLDER_NO_MODEL_TESTS|high|MT-020|Database model file may lack test coverage|Add tests for model validation, relationships, and query methods'

  # Utility/helper files
  'PLACEHOLDER_NO_UTIL_TESTS|high|MT-021|Utility/helper file may lack test coverage|Add unit tests for each utility function'

  # Config validators
  'PLACEHOLDER_NO_VALIDATOR_TESTS|high|MT-022|Config validation code may lack test coverage|Add tests for valid and invalid configuration inputs'
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. TEST QUALITY (TQ) — Tests that exist but have quality issues
# ═══════════════════════════════════════════════════════════════════════════

declare -a TESTGAP_TQ_PATTERNS=()

TESTGAP_TQ_PATTERNS+=(
  # Test files with no assertions (JS/TS)
  'PLACEHOLDER_NO_ASSERTIONS|high|TQ-001|Test file contains no assertions — tests exist but verify nothing|Add expect(), assert(), or should assertions to each test case'

  # Tests with only console.log (JS/TS)
  'console\.log\(|medium|TQ-002|Test uses console.log — possible print debugging instead of assertions|Replace console.log with proper assertions: expect(value).toBe(expected)'

  # Empty test bodies (JS/TS) — it/test with empty callback
  'it\([[:space:]]*["\x27][^"]*["\x27][[:space:]]*,[[:space:]]*(async[[:space:]]*)?\(\)[[:space:]]*=>[[:space:]]*\{[[:space:]]*\}|high|TQ-003|Empty test body — test block with no code|Add test implementation with assertions inside the test block'
  'test\([[:space:]]*["\x27][^"]*["\x27][[:space:]]*,[[:space:]]*(async[[:space:]]*)?\(\)[[:space:]]*=>[[:space:]]*\{[[:space:]]*\}|high|TQ-004|Empty test body — test block with no code|Add test implementation with assertions inside the test block'

  # Tests that never import the module under test (file-level check)
  'PLACEHOLDER_NO_IMPORT|medium|TQ-005|Test file does not import the module under test|Import the module being tested: import { fn } from "../module"'

  # Skipped tests (JS/TS)
  '\.skip\(|medium|TQ-006|Skipped test (.skip) — test is never executed|Fix the test and remove .skip, or delete the test entirely'
  'xit\(|medium|TQ-007|Skipped test (xit) — test is never executed|Fix the test and change xit back to it'
  'xdescribe\(|medium|TQ-008|Skipped describe block (xdescribe) — entire suite is skipped|Fix the suite and change xdescribe back to describe'
  'test\.skip\(|medium|TQ-009|Skipped test (test.skip) — test is never executed|Fix the test and remove .skip'

  # Skipped tests (Python)
  '@pytest\.mark\.skip|medium|TQ-010|Skipped test (@pytest.mark.skip) — test is never executed|Fix the test and remove the skip marker'
  '@unittest\.skip|medium|TQ-011|Skipped test (@unittest.skip) — test is never executed|Fix the test and remove the skip decorator'
  'pytest\.skip\(|medium|TQ-012|Skipped test (pytest.skip()) — test skipped at runtime|Fix the condition or remove the skip call'

  # Skipped tests (Go)
  't\.Skip\(|medium|TQ-013|Skipped test (t.Skip) — test is not executed|Fix the test and remove t.Skip()'

  # Skipped tests (Ruby)
  'pending[[:space:]]+["\x27]|medium|TQ-014|Pending test (pending) — test is not verified|Implement the test and remove the pending marker'

  # Tests with hardcoded sleep/delay (JS/TS)
  'setTimeout\([^,]+,[[:space:]]*[0-9]|medium|TQ-015|Test uses setTimeout — possible flaky timing dependency|Use async/await with proper mocking instead of setTimeout'
  'sleep\([[:space:]]*[0-9]|medium|TQ-016|Test uses sleep/delay — flaky timing dependency|Use mocked timers or event-driven assertions instead of sleep'
  'time\.Sleep\(|medium|TQ-017|Go test uses time.Sleep — flaky timing dependency|Use channels, sync.WaitGroup, or test timeouts instead of time.Sleep'
  'Thread\.sleep\(|medium|TQ-018|Java test uses Thread.sleep — flaky timing dependency|Use Awaitility or CountDownLatch instead of Thread.sleep'

  # Tests that mock everything (file-level check)
  'PLACEHOLDER_OVER_MOCKING|medium|TQ-019|Test file has excessive mocking — may be testing mocks, not real code|Reduce mocking; test real behavior with integration tests'

  # Duplicate test names (file-level check)
  'PLACEHOLDER_DUPLICATE_TEST_NAMES|low|TQ-020|Duplicate test names detected — potential copy-paste error|Give each test a unique, descriptive name'

  # Tests without cleanup/teardown
  'PLACEHOLDER_NO_CLEANUP|low|TQ-021|Tests create resources but have no cleanup/teardown|Add afterEach/tearDown to clean up test resources'

  # Assertion-free catch blocks in tests
  'catch[[:space:]]*\([a-zA-Z_]*\)[[:space:]]*\{[[:space:]]*\}|medium|TQ-022|Empty catch block in test — errors silently swallowed|Add assertions in catch block or use expect().toThrow() pattern'
  'except[[:space:]]*.*:[[:space:]]*$|medium|TQ-023|Empty except block in test — errors silently swallowed|Add assertions in except block or use pytest.raises() pattern'
  'except:[[:space:]]*pass|medium|TQ-024|Except: pass in test — errors silently swallowed|Use pytest.raises() to verify expected exceptions'

  # Tests with only TODO comments
  '#[[:space:]]*TODO.*test|low|TQ-025|TODO comment about test — test not yet implemented|Write the test or remove the TODO'
  '//[[:space:]]*TODO.*test|low|TQ-026|TODO comment about test — test not yet implemented|Write the test or remove the TODO'

  # Jest test.todo (placeholder test)
  'test\.todo\(|low|TQ-027|test.todo() — placeholder test not yet implemented|Write the test implementation or remove the todo'
  'it\.todo\(|low|TQ-028|it.todo() — placeholder test not yet implemented|Write the test implementation or remove the todo'
)

# ═══════════════════════════════════════════════════════════════════════════
# 3. CRITICAL GAPS (CG) — Security-critical code without tests
# ═══════════════════════════════════════════════════════════════════════════

declare -a TESTGAP_CG_PATTERNS=()

TESTGAP_CG_PATTERNS+=(
  # Authentication code
  'function[[:space:]]+(authenticate|login|signIn|verifyToken|validateToken|checkAuth)|critical|CG-001|Authentication function may lack test coverage|Add tests for valid credentials, invalid credentials, token expiry, and edge cases'
  'def[[:space:]]+(authenticate|login|sign_in|verify_token|validate_token|check_auth)|critical|CG-002|Authentication function may lack test coverage|Add tests for valid/invalid credentials and token scenarios'
  'passport\.(use|authenticate)\(|critical|CG-003|Passport.js auth strategy may lack test coverage|Add integration tests for each authentication strategy'
  'jwt\.(sign|verify|decode)\(|critical|CG-004|JWT token operation may lack test coverage|Add tests for signing, verification, expiry, and invalid tokens'

  # Authorization code
  'function[[:space:]]+(authorize|checkPermission|hasRole|isAdmin|canAccess)|critical|CG-005|Authorization function may lack test coverage|Add tests for allowed access, denied access, and role hierarchy'
  'def[[:space:]]+(authorize|check_permission|has_role|is_admin|can_access)|critical|CG-006|Authorization function may lack test coverage|Add tests for permission checks with various roles'
  '@(login_required|permission_required|requires_auth|admin_required)|critical|CG-007|Auth decorator may lack test coverage|Add tests for authenticated and unauthenticated request scenarios'

  # Payment processing
  'function[[:space:]]+(processPayment|charge|createPayment|handlePayment|refund)|critical|CG-008|Payment function may lack test coverage|Add tests for successful payment, declined card, error handling, and refunds'
  'def[[:space:]]+(process_payment|charge|create_payment|handle_payment|refund)|critical|CG-009|Payment function may lack test coverage|Add tests for payment success, failure, and edge cases'
  'stripe\.(charges|paymentIntents|subscriptions)\.|critical|CG-010|Stripe API call may lack test coverage|Add tests with mocked Stripe API responses for success and error cases'

  # Data validation
  'function[[:space:]]+(validate|sanitize|parseInput|checkInput)|high|CG-011|Validation function may lack test coverage|Add tests for valid input, invalid input, edge cases, and XSS/injection attempts'
  'def[[:space:]]+(validate|sanitize|parse_input|check_input)|high|CG-012|Validation function may lack test coverage|Add tests for boundary values, malformed input, and injection attempts'
  '\.(validate|isValid|matches)\([[:space:]]*["\x27/]|high|CG-013|Validation call may lack test coverage|Add tests that exercise validation with valid and invalid inputs'

  # Security-critical functions
  'function[[:space:]]+(encrypt|decrypt|hashPassword|verifyPassword|generateToken)|critical|CG-014|Security-critical function may lack test coverage|Add tests for encryption/decryption roundtrip, hash verification, and key rotation'
  'def[[:space:]]+(encrypt|decrypt|hash_password|verify_password|generate_token)|critical|CG-015|Security-critical function may lack test coverage|Add tests for crypto operations with known test vectors'
  'bcrypt\.(hash|compare|genSalt)\(|critical|CG-016|bcrypt operation may lack test coverage|Add tests for password hashing and comparison'
  'crypto\.(createHash|createCipher|randomBytes)\(|high|CG-017|Crypto operation may lack test coverage|Add tests for crypto operations with known inputs/outputs'

  # Error boundary/fallback code
  'function[[:space:]]+(handleError|errorHandler|onError|fallback|recover)|high|CG-018|Error handler may lack test coverage|Add tests that trigger errors and verify handler behavior'
  'class[[:space:]]+[A-Za-z]*ErrorBoundary|high|CG-019|React Error Boundary may lack test coverage|Add tests that trigger rendering errors and verify fallback UI'

  # Database transaction code
  'function[[:space:]]+(beginTransaction|commitTransaction|rollbackTransaction|withTransaction)|high|CG-020|Database transaction code may lack test coverage|Add tests for commit success, rollback on error, and concurrent transactions'
  '\.transaction\([[:space:]]*(async|function)|high|CG-021|Database transaction may lack test coverage|Add tests for successful transactions and rollback scenarios'

  # File I/O operations
  'function[[:space:]]+(readFile|writeFile|deleteFile|uploadFile|downloadFile)|high|CG-022|File I/O function may lack test coverage|Add tests for read/write success, file not found, permission errors'
  'def[[:space:]]+(read_file|write_file|delete_file|upload_file|download_file)|high|CG-023|File I/O function may lack test coverage|Add tests with temp files for I/O operations'

  # Rate limiting
  'function[[:space:]]+(rateLimit|throttle|checkRateLimit)|high|CG-024|Rate limiter may lack test coverage|Add tests for under-limit, at-limit, and over-limit scenarios'
  'rateLimit\(|high|CG-025|Rate limiting middleware may lack test coverage|Add integration tests verifying rate limit headers and blocking'
)

# ═══════════════════════════════════════════════════════════════════════════
# 4. TEST ORGANIZATION (TO) — Test infrastructure issues
# ═══════════════════════════════════════════════════════════════════════════

declare -a TESTGAP_TO_PATTERNS=()

TESTGAP_TO_PATTERNS+=(
  # No test config file detected (file-level checks in analyzer)
  'PLACEHOLDER_NO_TEST_CONFIG|medium|TO-001|No test configuration file detected (jest.config, pytest.ini, etc.)|Create a test configuration file for your test runner'

  # No test runner in package.json (file-level check)
  'PLACEHOLDER_NO_TEST_SCRIPT|medium|TO-002|No test script configured in package.json/setup.py/go.mod|Add a test script to your project configuration'

  # Test files in wrong directory (file-level check)
  'PLACEHOLDER_WRONG_TEST_DIR|low|TO-003|Test file found in unexpected directory structure|Move test files to standard test directory (tests/, __tests__/, spec/)'

  # Mixed unit and integration tests (file-level check)
  'PLACEHOLDER_MIXED_TEST_TYPES|low|TO-004|Unit and integration tests mixed in same directory|Separate unit tests and integration tests into distinct directories'

  # Stale snapshot files (JS/TS)
  'PLACEHOLDER_STALE_SNAPSHOTS|low|TO-005|Snapshot files found that may be outdated|Run jest --updateSnapshot to refresh or review stale snapshot files'

  # Test fixtures scattered
  'PLACEHOLDER_SCATTERED_FIXTURES|low|TO-006|Test fixtures scattered across multiple directories|Consolidate fixtures into a shared fixtures/ or __fixtures__/ directory'

  # Missing test helper/setup
  'PLACEHOLDER_NO_TEST_SETUP|low|TO-007|No test setup/helper file found|Create a test setup file for shared configuration and utilities'

  # Large test file
  'PLACEHOLDER_LARGE_TEST_FILE|low|TO-008|Test file exceeds 500 lines — may be hard to maintain|Split large test files into focused, smaller test modules'

  # No describe/context grouping (JS/TS)
  'PLACEHOLDER_NO_DESCRIBE_GROUPING|low|TO-009|Test file has no describe() grouping — flat test structure|Group related tests with describe() blocks for better organization'

  # Test file naming inconsistency (file-level check)
  'PLACEHOLDER_INCONSISTENT_NAMING|low|TO-010|Test file naming is inconsistent across project|Standardize on one test naming convention: *.test.ts or *.spec.ts'
)

# ═══════════════════════════════════════════════════════════════════════════
# 5. COVERAGE INDICATORS (CI) — Complexity-based gap indicators
# ═══════════════════════════════════════════════════════════════════════════

declare -a TESTGAP_CI_PATTERNS=()

TESTGAP_CI_PATTERNS+=(
  # High complexity functions (many branches) — detected by nested if/else
  'if[[:space:]]*\(.*\)[[:space:]]*\{[[:space:]]*$|high|CI-001|Conditional branch may lack test coverage for all paths|Add tests for both true and false branches of each conditional'

  # Functions with many parameters (likely complex)
  'function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([^)]*,[^)]*,[^)]*,[^)]*,|high|CI-002|Function with 5+ parameters — likely complex, needs thorough tests|Add tests covering parameter combinations and edge cases'
  'def[[:space:]]+[a-z_][a-z0-9_]*[[:space:]]*\([^)]*,[^)]*,[^)]*,[^)]*,|high|CI-003|Function with 5+ parameters — likely complex, needs thorough tests|Add tests for parameter combinations and default value handling'

  # Files with high line count (>200 lines) — file-level check
  'PLACEHOLDER_LARGE_SOURCE_FILE|medium|CI-004|Source file exceeds 200 lines without test coverage|Prioritize testing for large, complex source files'

  # Nested conditionals (3+ levels)
  'if[[:space:]]*\(.*if[[:space:]]*\(.*if[[:space:]]*\(|high|CI-005|Deeply nested conditionals (3+ levels) — high complexity|Add tests for each nesting path; consider refactoring to reduce complexity'

  # Try/catch blocks (JS/TS)
  'try[[:space:]]*\{|medium|CI-006|Try/catch block — error path may lack test coverage|Add tests that trigger the error path in addition to the happy path'

  # Try/except blocks (Python)
  'try:|medium|CI-007|Try/except block — error path may lack test coverage|Add tests using pytest.raises() for the error path'

  # Switch/case statements (JS/TS)
  'switch[[:space:]]*\(|medium|CI-008|Switch statement — each case may need test coverage|Add a test for each case branch including the default case'

  # Multiple return statements (complex flow)
  'return[[:space:]]+[^;]*;|medium|CI-009|Multiple return paths — each path may need test coverage|Add tests that exercise each return path'

  # Ternary in function body (compact but often untested)
  '[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*[^=].*\?[^:]*:[[:space:]]|low|CI-010|Ternary expression — both branches may need test coverage|Add tests for both truthy and falsy conditions of the ternary'

  # Callback hell / deeply nested callbacks
  'function[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*$|medium|CI-011|Nested callback — may indicate complex async logic lacking tests|Add tests for callback success, failure, and timeout scenarios'

  # Promise chains
  '\.then\([[:space:]]*(async[[:space:]]*)?\(|medium|CI-012|Promise chain — each .then() step may need test coverage|Add tests for each step in the promise chain including rejection'

  # Regex patterns in source (often tricky to test)
  'new[[:space:]]+RegExp\(|low|CI-013|Dynamic regex construction — edge cases may lack tests|Add tests with various input strings including edge cases and empty strings'
  '/[^/]+/[gimsuvy]*[[:space:]]*(;|\)|\.|,)|low|CI-014|Regex literal — pattern matching may lack test coverage|Add tests for matching and non-matching inputs'
)

# ═══════════════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════════════

# Get total pattern count across all categories
testgap_pattern_count() {
  local count=0
  count=$((count + ${#TESTGAP_MT_PATTERNS[@]}))
  count=$((count + ${#TESTGAP_TQ_PATTERNS[@]}))
  count=$((count + ${#TESTGAP_CG_PATTERNS[@]}))
  count=$((count + ${#TESTGAP_TO_PATTERNS[@]}))
  count=$((count + ${#TESTGAP_CI_PATTERNS[@]}))
  echo "$count"
}

# List patterns by category
testgap_list_patterns() {
  local filter_cat="${1:-all}"
  local -n _patterns_ref

  case "$filter_cat" in
    MT) _patterns_ref=TESTGAP_MT_PATTERNS ;;
    TQ) _patterns_ref=TESTGAP_TQ_PATTERNS ;;
    CG) _patterns_ref=TESTGAP_CG_PATTERNS ;;
    TO) _patterns_ref=TESTGAP_TO_PATTERNS ;;
    CI) _patterns_ref=TESTGAP_CI_PATTERNS ;;
    all)
      testgap_list_patterns "MT"
      testgap_list_patterns "TQ"
      testgap_list_patterns "CG"
      testgap_list_patterns "TO"
      testgap_list_patterns "CI"
      return
      ;;
    *)
      echo "Unknown category: $filter_cat"
      return 1
      ;;
  esac

  for entry in "${_patterns_ref[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    # Skip placeholder patterns
    [[ "$regex" == PLACEHOLDER_* ]] && continue
    printf "%-8s %-8s %s\n" "$check_id" "$severity" "$description"
  done
}

# Get patterns array name for a category
get_patterns_for_category() {
  local category="$1"
  case "$category" in
    mt|MT) echo "TESTGAP_MT_PATTERNS" ;;
    tq|TQ) echo "TESTGAP_TQ_PATTERNS" ;;
    cg|CG) echo "TESTGAP_CG_PATTERNS" ;;
    to|TO) echo "TESTGAP_TO_PATTERNS" ;;
    ci|CI) echo "TESTGAP_CI_PATTERNS" ;;
    *)     echo "" ;;
  esac
}

# Severity to numeric points for scoring
severity_to_points() {
  case "$1" in
    critical) echo 25 ;;
    high)     echo 15 ;;
    medium)   echo 8 ;;
    low)      echo 3 ;;
    *)        echo 0 ;;
  esac
}

# Get all non-placeholder patterns from a category as a flat list
get_active_patterns() {
  local category="$1"
  local patterns_name
  patterns_name=$(get_patterns_for_category "$category")
  [[ -z "$patterns_name" ]] && return

  local -n _ref="$patterns_name"
  for entry in "${_ref[@]}"; do
    IFS='|' read -r regex _sev _id _desc _rec <<< "$entry"
    [[ "$regex" == PLACEHOLDER_* ]] && continue
    echo "$entry"
  done
}
