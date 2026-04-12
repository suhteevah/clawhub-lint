#!/usr/bin/env bash
# RetryLint -- Retry & Resilience Pattern Definitions
# 90 patterns across 6 categories, 15 patterns each.
#
# Format per line:
#   REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical -- Immediate reliability risk (infinite loops, no timeout, thundering herd)
#   high     -- Significant resilience problem requiring prompt attention
#   medium   -- Moderate concern that should be addressed in current sprint
#   low      -- Best practice suggestion or informational finding
#
# IMPORTANT: All regexes use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alnum:]] instead of \w
# - NEVER use pipe (|) for alternation inside regex -- it conflicts with
#   the field delimiter. Use separate patterns or character classes instead.
# - Use \b-free alternatives where boundary assertions are unavailable
#
# Categories:
#   RL (Retry Logic)          -- 15 patterns (RL-001 to RL-015)
#   BO (Backoff Strategy)     -- 15 patterns (BO-001 to BO-015)
#   CB (Circuit Breaker)      -- 15 patterns (CB-001 to CB-015)
#   TO (Timeout Configuration)-- 15 patterns (TO-001 to TO-015)
#   TH (Thundering Herd)      -- 15 patterns (TH-001 to TH-015)
#   FT (Fault Tolerance)      -- 15 patterns (FT-001 to FT-015)

set -euo pipefail

# ============================================================================
# 1. RETRY LOGIC (RL-001 through RL-015)
#    Detects missing retry logic, infinite retry loops, missing max retry
#    count, retry without delay, retry on non-idempotent operations.
# ============================================================================

declare -a RETRYLINT_RL_PATTERNS=()

RETRYLINT_RL_PATTERNS+=(
  # RL-001: Infinite retry loop with while(true) and retry
  'while[[:space:]]*\(true\).*retry|critical|RL-001|Infinite retry loop detected (while true with retry)|Add maximum retry count to prevent infinite loops'

  # RL-002: Retry count set to -1 (unlimited retries)
  'retry.*=[[:space:]]*-1|critical|RL-002|Retry count set to -1 (unlimited retries)|Set a reasonable max retry count (3-5 for most operations)'

  # RL-003: Catch-all retry without error type filtering
  'catch.*retry\(\)|high|RL-003|Catch-all retry without error type filtering|Only retry transient errors (network, 5xx); fail fast on 4xx and logic errors'

  # RL-004: While loop with retry and no break/max condition
  'while[[:space:]]*\(true\)[[:space:]]*\{[[:space:]]*try|critical|RL-004|Unbounded while(true) retry loop without exit condition|Add max retry count and break condition to prevent infinite loops'

  # RL-005: Retry count set to very high number (over 99)
  'retries[[:space:]]*[:=][[:space:]]*[0-9]{3,}|high|RL-005|Retry count set excessively high (100+ retries)|Reduce max retries to 3-5; use exponential backoff instead of many retries'

  # RL-006: Recursive retry without depth tracking
  'function.*retry.*retry\(|high|RL-006|Recursive retry function without depth tracking|Add depth parameter or use iterative approach with max retry count'

  # RL-007: Fetch/HTTP call without retry wrapper
  'fetch\([[:space:]]*["\x27]http[^)]*\)[[:space:]]*\.|medium|RL-007|HTTP fetch call without retry wrapper|Wrap HTTP calls in retry logic for transient failure handling'

  # RL-008: Axios call without retry interceptor
  'axios\.[a-z]+\([[:space:]]*["\x27]http[^)]*\)[[:space:]]*\.|medium|RL-008|Axios HTTP call without retry configuration|Add axios-retry or custom retry interceptor for transient failures'

  # RL-009: Python requests without retry adapter
  'requests\.[a-z]+\([[:space:]]*["\x27]http|medium|RL-009|Python requests call without retry adapter|Use urllib3.util.retry.Retry with requests.Session for automatic retries'

  # RL-010: Database connection without retry logic
  'createConnection\([^)]*\)[[:space:]]*;|medium|RL-010|Database connection created without retry logic|Add retry logic for database connections with exponential backoff'

  # RL-011: Retry on POST/PUT/DELETE (non-idempotent)
  'retry.*POST[[:space:]]|high|RL-011|Retry configured for non-idempotent POST operation|Only retry idempotent operations; use idempotency keys for non-idempotent retries'

  # RL-012: maxRetries set to 0 (retries disabled)
  'maxRetries[[:space:]]*[:=][[:space:]]*0|low|RL-012|Max retries explicitly set to 0 (retries disabled)|Consider enabling retries (1-3) for transient failure resilience'

  # RL-013: Retry with no error logging
  'catch[[:space:]]*\{[[:space:]]*retry|medium|RL-013|Retry in catch block without error logging|Log retry attempts with error details and attempt number before retrying'

  # RL-014: Infinite for loop used for retry
  'for[[:space:]]*\(;;\)[[:space:]]*\{.*retry|critical|RL-014|Infinite for(;;) loop used for retry logic|Replace with bounded for loop: for(let i=0; i<maxRetries; i++)'

  # RL-015: gRPC call without retry policy
  'grpc\.[A-Za-z]*Client\([^)]*\)[[:space:]]*;|medium|RL-015|gRPC client created without retry policy configuration|Configure gRPC retry policy with maxAttempts, backoff, and retryableStatusCodes'
)

# ============================================================================
# 2. BACKOFF STRATEGY (BO-001 through BO-015)
#    Detects fixed delay retry, missing exponential backoff, missing jitter,
#    too-short retry delays, backoff without cap.
# ============================================================================

declare -a RETRYLINT_BO_PATTERNS=()

RETRYLINT_BO_PATTERNS+=(
  # BO-001: Fixed 1-second delay in retry loop (no exponential backoff)
  'sleep\([[:space:]]*1[[:space:]]*\).*retry|high|BO-001|Fixed 1-second delay in retry loop (no exponential backoff)|Use exponential backoff: delay = baseDelay * 2^attempt + random jitter'

  # BO-002: Very short retry delay under 100ms (Java Thread.sleep)
  'Thread\.sleep\([[:space:]]*[0-9]{1,2}\)|medium|BO-002|Very short retry delay (under 100ms) may overwhelm target|Use exponential backoff starting at 1000ms minimum'

  # BO-003: Sub-second retry delay in JavaScript setTimeout
  'setTimeout.*retry.*,[[:space:]]*[0-9]{1,3}\)|high|BO-003|Sub-second retry delay in setTimeout|Use exponential backoff: Math.min(baseDelay * 2**attempt, maxDelay)'

  # BO-004: Fixed sleep in Python retry loop
  'time\.sleep\([[:space:]]*[0-9]+\).*retry|medium|BO-004|Fixed delay in Python retry loop (no exponential backoff)|Use tenacity library or manual exponential backoff with jitter'

  # BO-005: Retry delay without jitter component
  'delay[[:space:]]*=[[:space:]]*baseDelay[[:space:]]*\*[[:space:]]*2|medium|BO-005|Exponential backoff without jitter (correlated retries)|Add jitter: delay = baseDelay * 2^attempt + random(0, baseDelay)'

  # BO-006: Constant retry interval assignment
  'retryInterval[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*;|medium|BO-006|Constant retry interval (no backoff progression)|Use exponential backoff: retryInterval = Math.min(base * 2^attempt, maxDelay)'

  # BO-007: Backoff multiplied but no maximum cap
  'backoff[[:space:]]*\*=[[:space:]]*2|medium|BO-007|Backoff doubles without maximum cap (can grow unbounded)|Add cap: backoff = Math.min(backoff * 2, MAX_BACKOFF)'

  # BO-008: Go time.Sleep with fixed duration in retry
  'time\.Sleep\([0-9]+[[:space:]]*\*[[:space:]]*time\.|medium|BO-008|Fixed duration in Go retry loop (no exponential backoff)|Use exponential backoff with jitter; consider cenkalti/backoff library'

  # BO-009: Ruby sleep with constant in retry
  'sleep[[:space:]]+[0-9]+[[:space:]]*$|low|BO-009|Fixed sleep duration (potential retry without backoff)|If inside retry loop, use exponential backoff with jitter'

  # BO-010: Java retry with Thread.sleep and constant
  'Thread\.sleep\([[:space:]]*[A-Z_]*DELAY|medium|BO-010|Thread.sleep with constant delay in retry context|Replace constant delay with exponential backoff strategy'

  # BO-011: Retry delay under 50ms (aggressive)
  'delay[[:space:]]*[:=][[:space:]]*[1-4][0-9][[:space:]]*[;,]|high|BO-011|Retry delay under 50ms (extremely aggressive)|Minimum retry delay should be 100-1000ms to avoid overwhelming services'

  # BO-012: Backoff without randomization (C# Task.Delay)
  'Task\.Delay\([[:space:]]*[0-9]+[[:space:]]*\*|medium|BO-012|C# Task.Delay with deterministic backoff (no jitter)|Add random jitter: await Task.Delay(delay + random.Next(0, jitter))'

  # BO-013: waitForTimeout/waitFor with fixed ms in retry
  'waitFor\([[:space:]]*[0-9]+\)|low|BO-013|Fixed wait duration in retry context|Use progressive backoff if this is retry-related waiting'

  # BO-014: Immediate retry (delay of 0)
  'delay[[:space:]]*[:=][[:space:]]*0[[:space:]]*[;,}]|high|BO-014|Retry delay set to 0 (immediate retry with no backoff)|Add minimum delay of 100ms with exponential backoff for subsequent retries'

  # BO-015: Linear backoff increment instead of exponential
  'delay[[:space:]]*\+=[[:space:]]*[0-9]+|low|BO-015|Linear backoff increment instead of exponential|Use exponential backoff (delay *= 2) instead of linear (delay += N) for better load distribution'
)

# ============================================================================
# 3. CIRCUIT BREAKER (CB-001 through CB-015)
#    Detects missing circuit breaker on external calls, improper circuit
#    breaker configuration, missing half-open state, no failure threshold.
# ============================================================================

declare -a RETRYLINT_CB_PATTERNS=()

RETRYLINT_CB_PATTERNS+=(
  # CB-001: HTTP fetch without circuit breaker
  'fetch\([[:space:]]*["\x27]http|medium|CB-001|HTTP fetch call without circuit breaker pattern|Wrap external HTTP calls in a circuit breaker (opossum, cockatiel, resilience4j)'

  # CB-002: Axios HTTP call without circuit breaker
  'axios\.[a-z]+\([[:space:]]*["\x27]http|medium|CB-002|Axios HTTP call without circuit breaker|Use a circuit breaker library for external service calls'

  # CB-003: Python requests without circuit breaker
  'requests\.[a-z]+\([[:space:]]*["\x27]http|medium|CB-003|Python requests call without circuit breaker|Use pybreaker or tenacity with circuit breaker for external calls'

  # CB-004: Circuit breaker threshold set to 1 (too sensitive)
  'threshold[[:space:]]*[:=][[:space:]]*1[[:space:]]*[;,}]|medium|CB-004|Circuit breaker failure threshold set to 1 (trips on first failure)|Set threshold to 3-5 failures to avoid false circuit opens'

  # CB-005: Circuit breaker with no reset timeout
  'CircuitBreaker\([^)]*\)[[:space:]]*;|low|CB-005|Circuit breaker instantiated without visible reset timeout|Configure resetTimeout to allow periodic health probes (e.g., 30-60 seconds)'

  # CB-006: External API call in loop without circuit breaker
  'for.*\{.*fetch\([[:space:]]*["\x27]http|high|CB-006|External API calls in loop without circuit breaker protection|Add circuit breaker to prevent cascade failures during API outages'

  # CB-007: HttpClient without circuit breaker (C#)
  'HttpClient\(\)[[:space:]]*;|medium|CB-007|HttpClient created without circuit breaker (C#)|Use Polly circuit breaker policy with HttpClientFactory'

  # CB-008: WebClient without circuit breaker (Java Spring)
  'WebClient\.create\(|medium|CB-008|Spring WebClient created without circuit breaker|Add Resilience4j CircuitBreaker to WebClient filter chain'

  # CB-009: Circuit breaker open state without fallback
  'circuitBreaker\.open|medium|CB-009|Circuit breaker opens but no fallback handler configured|Add fallback response when circuit is open (cached data, default, or error message)'

  # CB-010: Manual boolean circuit breaker (no half-open)
  'isCircuitOpen[[:space:]]*=[[:space:]]*true|high|CB-010|Manual boolean circuit breaker (missing half-open state)|Use a proper circuit breaker library with open/half-open/closed states'

  # CB-011: RestTemplate without circuit breaker (Java)
  'RestTemplate\(\)[[:space:]]*;|medium|CB-011|Spring RestTemplate without circuit breaker protection|Wrap RestTemplate calls with Resilience4j or Spring Cloud CircuitBreaker'

  # CB-012: gRPC client without circuit breaker
  'grpc\.[A-Za-z]*Client\(|medium|CB-012|gRPC client without circuit breaker pattern|Add circuit breaker middleware for gRPC calls to external services'

  # CB-013: Database query in retry without circuit breaker
  'retry.*query\(|medium|CB-013|Database query retried without circuit breaker|Add circuit breaker for database calls to prevent connection pool exhaustion'

  # CB-014: Circuit breaker timeout set too high (over 5 minutes)
  'resetTimeout[[:space:]]*[:=][[:space:]]*[0-9]{6,}|medium|CB-014|Circuit breaker reset timeout over 5 minutes (too slow recovery)|Set resetTimeout to 30-60 seconds for faster recovery probing'

  # CB-015: Microservice call without circuit breaker
  'serviceName.*fetch\([[:space:]]*["\x27]http|medium|CB-015|Microservice call without circuit breaker protection|Wrap inter-service calls in circuit breakers to prevent cascade failures'
)

# ============================================================================
# 4. TIMEOUT CONFIGURATION (TO-001 through TO-015)
#    Detects missing timeouts, timeout set to 0, excessively long timeouts,
#    missing connection vs read timeout separation.
# ============================================================================

declare -a RETRYLINT_TO_PATTERNS=()

RETRYLINT_TO_PATTERNS+=(
  # TO-001: fetch() without timeout/AbortController
  'fetch\([^)]*\)[[:space:]]*$|medium|TO-001|fetch() call without timeout configuration|Add AbortController with timeout: const controller = new AbortController(); setTimeout(() => controller.abort(), 5000)'

  # TO-002: Timeout explicitly set to 0 (infinite wait)
  'timeout[[:space:]]*:[[:space:]]*0[[:space:]]*[,}]|critical|TO-002|Timeout explicitly set to 0 (infinite wait)|Set a reasonable timeout (5-30 seconds depending on operation)'

  # TO-003: Timeout exceeds 100 seconds
  'timeout[[:space:]]*:[[:space:]]*[0-9]{6,}|high|TO-003|Timeout exceeds 100 seconds (likely misconfigured)|Set timeout under 60s; use async processing for long operations'

  # TO-004: Axios request without timeout option
  'axios\.[a-z]+\([[:space:]]*["\x27]http[^)]*\)[[:space:]]*;|medium|TO-004|Axios request without explicit timeout configuration|Set timeout in axios config: axios.get(url, { timeout: 5000 })'

  # TO-005: Python requests without timeout parameter
  'requests\.[a-z]+\([^)]*\)[[:space:]]*$|medium|TO-005|Python requests call without timeout parameter|Always pass timeout: requests.get(url, timeout=5)'

  # TO-006: Socket created without timeout
  'new[[:space:]]Socket\(\)|medium|TO-006|Socket created without timeout configuration|Set socket timeout: socket.setTimeout(5000) or configure in constructor'

  # TO-007: Database query without timeout/statement timeout
  'query\([[:space:]]*["\x27][^)]*\)[[:space:]]*;|low|TO-007|Database query without visible timeout configuration|Set statement_timeout or query timeout to prevent long-running queries'

  # TO-008: HTTP connection pool without timeout
  'connectionPool[[:space:]]*[:=].*\{|low|TO-008|HTTP connection pool without explicit timeout settings|Configure connectTimeout, readTimeout, and idleTimeout on connection pools'

  # TO-009: gRPC call without deadline
  'grpc\.[A-Za-z]*\([^)]*\)[[:space:]]*;|medium|TO-009|gRPC call without deadline configuration|Always set gRPC deadlines: client.method(request, {deadline: Date.now() + 5000})'

  # TO-010: WebSocket without connection timeout
  'new[[:space:]]WebSocket\([^)]*\)[[:space:]]*;|medium|TO-010|WebSocket created without connection timeout|Configure connection timeout and ping/pong keepalive intervals'

  # TO-011: C# HttpClient without Timeout property
  'new[[:space:]]HttpClient\(\)[[:space:]]*;|medium|TO-011|C# HttpClient without Timeout property set|Set HttpClient.Timeout = TimeSpan.FromSeconds(30) before making requests'

  # TO-012: Java OkHttpClient without timeout
  'OkHttpClient\(\)|medium|TO-012|OkHttpClient created without timeout configuration|Configure connectTimeout, readTimeout, writeTimeout on OkHttpClient.Builder'

  # TO-013: Redis client without command timeout
  'createClient\([^)]*\)[[:space:]]*;.*redis|low|TO-013|Redis client without visible command timeout|Set commandTimeout on Redis client to prevent blocking on slow commands'

  # TO-014: Promise.all without timeout wrapper
  'Promise\.all\([[:space:]]*\[|medium|TO-014|Promise.all without timeout wrapper (waits for slowest)|Add Promise.race with timeout: Promise.race([Promise.all(...), timeoutPromise])'

  # TO-015: Kafka consumer without session timeout
  'consumer\.[a-z]*\([[:space:]]*\{|low|TO-015|Kafka consumer without visible session timeout configuration|Set session.timeout.ms and heartbeat.interval.ms for consumer group stability'
)

# ============================================================================
# 5. THUNDERING HERD (TH-001 through TH-015)
#    Detects retry on 429 without Retry-After, missing request coalescing,
#    cache stampede, reconnect storms, simultaneous retry without jitter.
# ============================================================================

declare -a RETRYLINT_TH_PATTERNS=()

RETRYLINT_TH_PATTERNS+=(
  # TH-001: Retrying on 429 without Retry-After check
  '429.*retry|high|TH-001|Retrying on 429 (Too Many Requests) without Retry-After check|Read and respect Retry-After header before retrying 429 responses'

  # TH-002: Fixed delay reconnection (thundering herd risk)
  'reconnect.*setTimeout\([^,]*,[[:space:]]*[0-9]+\)|medium|TH-002|Fixed delay reconnection (thundering herd risk)|Add jitter to reconnection delay: baseDelay + Math.random() * jitterRange'

  # TH-003: Cache miss triggers direct backend fetch
  'cache\.get.*null.*fetch\(|high|TH-003|Cache miss triggers immediate backend fetch (stampede risk)|Use cache stampede protection: lock-based fetch or probabilistic early expiry'

  # TH-004: Multiple subscribers reconnect simultaneously
  'subscribers.*reconnect\(\)|medium|TH-004|Multiple subscribers reconnect simultaneously (thundering herd)|Add random jitter to each subscriber reconnection delay'

  # TH-005: setInterval for retry polling (no jitter)
  'setInterval\([^,]*retry[^,]*,[[:space:]]*[0-9]+\)|high|TH-005|setInterval used for retry polling without jitter|Use setTimeout with jittered exponential backoff instead of fixed intervals'

  # TH-006: All workers retry at same time
  'workers.*forEach.*retry|medium|TH-006|All workers retry simultaneously (thundering herd pattern)|Stagger worker retries with random jitter per worker'

  # TH-007: Cron-based retry at fixed schedule
  'cron.*retry|low|TH-007|Cron-scheduled retry at fixed time (burst risk)|Add random offset to cron-based retries to distribute load'

  # TH-008: Client-side retry without server load awareness
  'retry.*[0-9]+[[:space:]]*times|low|TH-008|Fixed retry count without server load awareness|Implement adaptive retry that respects server capacity signals (429, 503)'

  # TH-009: Reconnect-all on connection loss
  'reconnectAll\(\)|high|TH-009|reconnectAll triggers simultaneous reconnections|Implement staggered reconnection with per-connection jittered backoff'

  # TH-010: Cache invalidation triggers parallel rebuilds
  'invalidateCache.*rebuild|medium|TH-010|Cache invalidation triggers immediate parallel rebuilds (stampede)|Use single-flight or lock-based cache rebuild to prevent stampede'

  # TH-011: Health check retry for all instances simultaneously
  'healthCheck.*retry.*all|medium|TH-011|Health check retries all instances simultaneously|Stagger health check retries with per-instance jitter'

  # TH-012: Event handler retries without deduplication
  'on\([[:space:]]*["\x27]error["\x27].*retry|medium|TH-012|Error event handler retries without deduplication|Add request deduplication to prevent duplicate retry storms'

  # TH-013: Parallel Promise retry without coordination
  'Promise\.all.*retry|medium|TH-013|Parallel promises retry without coordination|Use p-limit or semaphore to limit concurrent retries'

  # TH-014: Rate limit with retry loop (no backpressure)
  'rateLimi.*retry|medium|TH-014|Rate limited response retried without backpressure|Implement token bucket or leaky bucket with proper rate limit handling'

  # TH-015: Connection pool exhaustion retry pattern
  'pool.*exhausted.*retry|high|TH-015|Connection pool exhaustion triggers retry (amplifies problem)|Add backoff and circuit breaker for pool exhaustion instead of immediate retry'
)

# ============================================================================
# 6. FAULT TOLERANCE (FT-001 through FT-015)
#    Detects missing fallback, no graceful degradation, missing bulkhead,
#    missing idempotency keys, no dead letter queue.
# ============================================================================

declare -a RETRYLINT_FT_PATTERNS=()

RETRYLINT_FT_PATTERNS+=(
  # FT-001: Exception re-thrown without fallback
  'catch.*throw[[:space:]]|low|FT-001|Exception re-thrown without fallback or degraded response|Consider providing a fallback value or degraded response instead of re-throwing'

  # FT-002: Empty catch block swallows errors
  'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*\}|high|FT-002|Empty catch block swallows errors without fallback or logging|Add error handling: log the error and provide fallback behavior'

  # FT-003: Single point of failure on external dependency
  'await[[:space:]]fetch\([^)]*\)[[:space:]]*;[[:space:]]*$|low|FT-003|External call without fallback on failure|Add try/catch with fallback: cached data, default value, or graceful degradation'

  # FT-004: Message consumer without dead letter queue
  'consumer\.[a-z]*\([^)]*\)[[:space:]]*;[[:space:]]*$|low|FT-004|Message consumer without visible dead letter queue handling|Configure dead letter queue for failed message processing'

  # FT-005: Missing idempotency key on retry
  'retry.*POST.*\{|medium|FT-005|POST request retried without idempotency key|Add Idempotency-Key header for safe retries of non-idempotent operations'

  # FT-006: Catch block only logs without recovery
  'catch.*console\.log\([^)]*\)[[:space:]]*;[[:space:]]*\}|medium|FT-006|Catch block only logs error without recovery strategy|Add fallback logic: return cached data, default response, or trigger circuit breaker'

  # FT-007: Process.exit on transient error
  'process\.exit\([[:space:]]*1[[:space:]]*\)|high|FT-007|process.exit(1) called on error (no graceful degradation)|Handle errors gracefully instead of terminating; use circuit breakers for persistent failures'

  # FT-008: Sys.exit on error without cleanup
  'sys\.exit\([[:space:]]*1[[:space:]]*\)|high|FT-008|sys.exit(1) on error without graceful shutdown|Implement graceful degradation and cleanup before exit; avoid exit on transient errors'

  # FT-009: Hard crash on unhandled promise rejection
  'unhandledRejection.*process\.exit|high|FT-009|Process exits on unhandled promise rejection|Add global error handler with graceful degradation instead of hard crash'

  # FT-010: Single database without read replica fallback
  'getConnection\(\).*throw|low|FT-010|Database connection failure throws without fallback|Add read replica or cache fallback for database connection failures'

  # FT-011: API call without response validation
  'await.*fetch.*\.json\(\)|low|FT-011|API response consumed without status validation or fallback|Check response.ok and provide fallback for non-200 responses'

  # FT-012: Bulk operation without partial failure handling
  'Promise\.all\([[:space:]]*\[.*\][[:space:]]*\)|low|FT-012|Promise.all fails on first rejection (no partial success handling)|Use Promise.allSettled for bulk operations to handle partial failures'

  # FT-013: Delete operation without soft-delete pattern
  'DELETE.*permanent|low|FT-013|Permanent deletion without soft-delete or undo capability|Implement soft-delete pattern for recoverability and audit compliance'

  # FT-014: Missing health check endpoint
  'createServer\([^)]*\)[[:space:]]*;|low|FT-014|Server created without visible health check endpoint|Add /health and /ready endpoints for load balancer and orchestrator probes'

  # FT-015: No graceful shutdown handler
  'listen\([[:space:]]*[0-9]+|low|FT-015|Server listening without graceful shutdown handler|Add SIGTERM/SIGINT handlers for graceful shutdown with connection draining'
)

# ============================================================================
# Utility Functions
# ============================================================================

# Get total pattern count across all categories
retrylint_pattern_count() {
  local count=0
  count=$((count + ${#RETRYLINT_RL_PATTERNS[@]}))
  count=$((count + ${#RETRYLINT_BO_PATTERNS[@]}))
  count=$((count + ${#RETRYLINT_CB_PATTERNS[@]}))
  count=$((count + ${#RETRYLINT_TO_PATTERNS[@]}))
  count=$((count + ${#RETRYLINT_TH_PATTERNS[@]}))
  count=$((count + ${#RETRYLINT_FT_PATTERNS[@]}))
  echo "$count"
}

# Get pattern count for a specific category
retrylint_category_count() {
  local category="$1"
  local patterns_name
  patterns_name=$(get_retrylint_patterns_for_category "$category")
  if [[ -z "$patterns_name" ]]; then
    echo 0
    return
  fi
  local -n _ref="$patterns_name"
  echo "${#_ref[@]}"
}

# Get patterns array name for a category
get_retrylint_patterns_for_category() {
  local category="$1"
  case "$category" in
    RL|rl) echo "RETRYLINT_RL_PATTERNS" ;;
    BO|bo) echo "RETRYLINT_BO_PATTERNS" ;;
    CB|cb) echo "RETRYLINT_CB_PATTERNS" ;;
    TO|to) echo "RETRYLINT_TO_PATTERNS" ;;
    TH|th) echo "RETRYLINT_TH_PATTERNS" ;;
    FT|ft) echo "RETRYLINT_FT_PATTERNS" ;;
    *)     echo "" ;;
  esac
}

# Get the human-readable label for a category
get_retrylint_category_label() {
  local category="$1"
  case "$category" in
    RL|rl) echo "Retry Logic" ;;
    BO|bo) echo "Backoff Strategy" ;;
    CB|cb) echo "Circuit Breaker" ;;
    TO|to) echo "Timeout Configuration" ;;
    TH|th) echo "Thundering Herd" ;;
    FT|ft) echo "Fault Tolerance" ;;
    *)     echo "$category" ;;
  esac
}

# All category codes for iteration
get_all_retrylint_categories() {
  echo "RL BO CB TO TH FT"
}

# Get categories available for a given tier level
# free=0 -> RL, BO (30 patterns)
# pro=1  -> RL, BO, CB, TO (60 patterns)
# team=2 -> all 6 (90 patterns)
# enterprise=3 -> all 6 (90 patterns)
get_retrylint_categories_for_tier() {
  local tier_level="${1:-0}"
  if [[ "$tier_level" -ge 2 ]]; then
    echo "RL BO CB TO TH FT"
  elif [[ "$tier_level" -ge 1 ]]; then
    echo "RL BO CB TO"
  else
    echo "RL BO"
  fi
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

# List patterns by category
retrylint_list_patterns() {
  local filter_category="${1:-all}"

  if [[ "$filter_category" == "all" ]]; then
    for cat in RL BO CB TO TH FT; do
      retrylint_list_patterns "$cat"
    done
    return
  fi

  local patterns_name
  patterns_name=$(get_retrylint_patterns_for_category "$filter_category")
  if [[ -z "$patterns_name" ]]; then
    echo "Unknown category: $filter_category"
    return 1
  fi

  local -n _patterns_ref="$patterns_name"
  local label
  label=$(get_retrylint_category_label "$filter_category")

  echo "  ${label} (${filter_category}):"
  for entry in "${_patterns_ref[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    printf "    %-8s %-10s %s\n" "$check_id" "$severity" "$description"
  done
  echo ""
}

# Validate that a category code is valid
is_valid_retrylint_category() {
  local category="$1"
  case "$category" in
    RL|rl|BO|bo|CB|cb|TO|to|TH|th|FT|ft) return 0 ;;
    *) return 1 ;;
  esac
}
