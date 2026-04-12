#!/usr/bin/env bash
# SQLGuard — SQL Vulnerability Pattern Definitions
# Each pattern: REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical — Immediate SQL injection risk, directly exploitable
#   high     — Significant vulnerability or unsafe pattern
#   medium   — Best practice violation, potential risk
#   low      — Informational, improvement opportunity
#
# IMPORTANT: All regexes must use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alnum:]] instead of \w
# - Avoid Perl-only features (\d, \w, etc.)

set -euo pipefail

# ── Pattern registries by vulnerability category ─────────────────────────
#
# Format: "regex|severity|check_id|description|recommendation"
# Patterns use POSIX extended grep regex (ERE) syntax.

# ═══════════════════════════════════════════════════════════════════════════
# 1. SQL INJECTION RISK PATTERNS (20 patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_INJECTION_PATTERNS=()

SQLGUARD_INJECTION_PATTERNS+=(
  # String concatenation in SQL queries — JS/TS
  'query\([[:space:]]*["\x27`]SELECT[[:space:]].*\+[[:space:]]*[a-zA-Z]|critical|SI-001|String concatenation in SQL query (JS/TS)|Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])'

  # String concatenation in SQL — Python
  'execute\([[:space:]]*["\x27]SELECT[[:space:]].*\+[[:space:]]*[a-zA-Z]|critical|SI-002|String concatenation in cursor.execute() (Python)|Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (id,))'

  # f-string in SQL — Python
  'execute\([[:space:]]*f["\x27]|critical|SI-003|f-string used in SQL execute() — direct injection risk|Use parameterized queries with %s placeholders instead of f-strings'

  # .format() in SQL — Python
  'execute\(.*\.format\(|critical|SI-004|.format() used to build SQL query — injection risk|Use parameterized queries with %s placeholders instead of .format()'

  # % operator in SQL — Python
  'execute\([[:space:]]*["\x27].*%[sd].*%[[:space:]]*\(|critical|SI-005|% string formatting in SQL execute() — injection risk|Use parameterized queries: cursor.execute("...WHERE id = %s", (id,))'

  # Template literals in SQL — JS/TS
  'query\([[:space:]]*`[^`]*\$\{|critical|SI-006|Template literal with interpolation in SQL query|Use parameterized queries with ? or $1 placeholders'

  # fmt.Sprintf in SQL — Go
  'fmt\.Sprintf\([[:space:]]*["\x27`].*SELECT|critical|SI-007|fmt.Sprintf used to build SQL query (Go)|Use parameterized queries: db.Query("SELECT ... WHERE id = $1", id)'
  'fmt\.Sprintf\([[:space:]]*["\x27`].*INSERT|critical|SI-008|fmt.Sprintf used to build SQL INSERT (Go)|Use parameterized queries with $1 placeholders'
  'fmt\.Sprintf\([[:space:]]*["\x27`].*UPDATE|critical|SI-009|fmt.Sprintf used to build SQL UPDATE (Go)|Use parameterized queries with $1 placeholders'
  'fmt\.Sprintf\([[:space:]]*["\x27`].*DELETE|critical|SI-010|fmt.Sprintf used to build SQL DELETE (Go)|Use parameterized queries with $1 placeholders'

  # Dynamic table/column names from user input
  'FROM[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|critical|SI-011|Dynamic table name from variable — SQL injection risk|Whitelist allowed table names; never use user input directly in FROM clause'
  'ORDER[[:space:]]+BY[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|high|SI-012|Dynamic ORDER BY from variable — injection risk|Whitelist allowed column names for ORDER BY'

  # LIKE clause with unescaped wildcards
  'LIKE[[:space:]]+["\x27`]?%[[:space:]]*\+[[:space:]]*[a-zA-Z]|high|SI-013|LIKE clause with unescaped user input — wildcard injection|Escape % and _ characters in user input before use in LIKE clauses'

  # LIMIT/OFFSET from unsanitized input
  'LIMIT[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|high|SI-014|Dynamic LIMIT from user input|Validate LIMIT as a positive integer before use in query'
  'OFFSET[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|high|SI-015|Dynamic OFFSET from user input|Validate OFFSET as a non-negative integer before use in query'

  # exec/eval with SQL
  'exec\([[:space:]]*["\x27`].*SELECT|critical|SI-016|exec() with SQL query — code injection risk|Never use exec() for SQL; use parameterized queries through database driver'
  'eval\([[:space:]]*["\x27`].*SELECT|critical|SI-017|eval() with SQL query — code injection risk|Never use eval() for SQL; use parameterized queries through database driver'

  # PHP variable interpolation in SQL
  '\$_[A-Z]+\[.*\].*SELECT|critical|SI-018|PHP superglobal directly in SQL query — injection risk|Use prepared statements: $stmt = $pdo->prepare("SELECT ... WHERE id = ?"); $stmt->execute([$id])'
  '\$_[A-Z]+\[.*\].*INSERT|critical|SI-019|PHP superglobal directly in SQL INSERT — injection risk|Use prepared statements with PDO or mysqli'

  # Ruby string interpolation in SQL
  '(execute|query)\([[:space:]]*".*#\{|critical|SI-020|Ruby string interpolation in SQL query — injection risk|Use parameterized queries: connection.exec_params("SELECT ... WHERE id = $1", [id])'
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. MISSING PARAMETERIZATION PATTERNS (18 patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_PARAMETERIZATION_PATTERNS=()

SQLGUARD_PARAMETERIZATION_PATTERNS+=(
  # JS/TS — db.query with concatenation
  'db\.query\([[:space:]]*["\x27].*WHERE.*=[[:space:]]*["\x27][[:space:]]*\+|critical|MP-001|db.query() with string concatenation in WHERE clause|Use parameterized queries: db.query("...WHERE id = ?", [id])'

  # JS/TS — connection.query with concatenation
  'connection\.query\([[:space:]]*["\x27].*\+|high|MP-002|connection.query() with string concatenation|Use parameterized queries with ? placeholders'

  # Python — cursor.execute with concatenation
  'cursor\.execute\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|critical|MP-003|cursor.execute() with string concatenation|Use parameterized queries: cursor.execute("...WHERE id = %s", (id,))'

  # Python — string concat in execute
  '\.execute\([[:space:]]*["\x27].*%[[:space:]]*[a-zA-Z]|critical|MP-004|String interpolation with % in execute()|Use parameterized queries with %s and tuple of values'

  # Go — db.Query with string concat
  'db\.Query\([[:space:]]*["\x27`].*\+[[:space:]]*[a-zA-Z]|critical|MP-005|db.Query() with string concatenation (Go)|Use parameterized queries: db.Query("...WHERE id = $1", id)'

  # Go — db.Exec with string concat
  'db\.Exec\([[:space:]]*["\x27`].*\+[[:space:]]*[a-zA-Z]|critical|MP-006|db.Exec() with string concatenation (Go)|Use parameterized queries: db.Exec("...SET name = $1 WHERE id = $2", name, id)'

  # Java — Statement with concatenation
  'createStatement\(\).*execute.*\+[[:space:]]*[a-zA-Z]|critical|MP-007|Statement.execute() with string concatenation (Java)|Use PreparedStatement with ? parameter placeholders'
  'Statement.*execute\([[:space:]]*["\x27].*\+|critical|MP-008|Statement.execute() with concatenation (Java)|Use PreparedStatement: pstmt = conn.prepareStatement("SELECT ... WHERE id = ?")'

  # Java — PreparedStatement with concat
  'prepareStatement\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|critical|MP-009|PreparedStatement built with string concatenation (Java)|Build SQL string without user input, then use setString/setInt for parameters'

  # PHP — direct query with variable
  'mysql_query\([[:space:]]*["\x27].*\$|critical|MP-010|mysql_query() with variable interpolation (PHP)|Use PDO prepared statements: $stmt = $pdo->prepare("...WHERE id = ?"); $stmt->execute([$id])'
  'mysqli_query\(.*["\x27].*\$|high|MP-011|mysqli_query() with variable interpolation (PHP)|Use mysqli prepared statements: $stmt = $mysqli->prepare("...WHERE id = ?")'

  # Dynamic IN() list built with string join
  'IN[[:space:]]*\([[:space:]]*["\x27`]?[[:space:]]*\+|high|MP-012|Dynamic IN() list built with string concatenation|Build IN() with parameterized placeholders: IN (?, ?, ?) with parameter array'
  '\.join\([[:space:]]*["\x27`],["\x27`]\).*IN|high|MP-013|Array.join() used to build IN() clause|Use parameterized IN() with placeholder generation: IN (${ids.map(() => "?").join(",")})'

  # Concatenated WHERE clauses
  'WHERE.*\+=[[:space:]]*["\x27`].*AND|high|MP-014|WHERE clause built with += string concatenation|Use a query builder or parameterized query construction'
  'WHERE.*\+=[[:space:]]*["\x27`].*OR|high|MP-015|WHERE clause built with += string concatenation|Use a query builder or parameterized query construction'

  # Raw SQL in ORM bypass
  '\.raw\([[:space:]]*["\x27`].*\+[[:space:]]*[a-zA-Z]|critical|MP-016|ORM .raw() with string concatenation — bypasses ORM protections|Use ORM parameterization: Model.raw("...WHERE id = ?", [id])'

  # PHP PDO query without prepare
  '\$pdo->query\([[:space:]]*["\x27].*\$|high|MP-017|PDO::query() with variable interpolation — not parameterized|Use $pdo->prepare() with execute() for parameterized queries'

  # Ruby string concat in execute
  '\.execute\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|high|MP-018|execute() with string concatenation in query|Use parameterized queries with placeholder syntax'
)

# ═══════════════════════════════════════════════════════════════════════════
# 3. DANGEROUS QUERY PATTERNS (20 patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_DANGEROUS_PATTERNS=()

SQLGUARD_DANGEROUS_PATTERNS+=(
  # SELECT * usage
  'SELECT[[:space:]]+\*[[:space:]]+FROM|medium|DQ-001|SELECT * used — fetches all columns unnecessarily|Specify only required columns: SELECT id, name, email FROM ...'

  # DROP TABLE
  'DROP[[:space:]]+TABLE|critical|DQ-002|DROP TABLE in application code — data loss risk|Remove DDL from application code; use managed migrations only'
  'DROP[[:space:]]+DATABASE|critical|DQ-003|DROP DATABASE in application code — catastrophic data loss|Remove DDL from application code; database management should be administrative only'

  # TRUNCATE TABLE
  'TRUNCATE[[:space:]]+TABLE|critical|DQ-004|TRUNCATE TABLE in application code — irrecoverable data deletion|Use soft deletes or managed administrative operations instead'

  # DELETE without WHERE
  'DELETE[[:space:]]+FROM[[:space:]]+[a-zA-Z_]+[[:space:]]*;|critical|DQ-005|DELETE without WHERE clause — deletes all rows|Always include a WHERE clause with DELETE statements'
  'DELETE[[:space:]]+FROM[[:space:]]+[a-zA-Z_]+[[:space:]]*$|high|DQ-006|DELETE without WHERE clause — may delete all rows|Always include a WHERE clause with DELETE statements'

  # UPDATE without WHERE
  'UPDATE[[:space:]]+[a-zA-Z_]+[[:space:]]+SET[[:space:]].*[^W][^H][^E][^R][^E];|high|DQ-007|UPDATE without WHERE clause — updates all rows|Always include a WHERE clause with UPDATE statements'

  # GRANT ALL
  'GRANT[[:space:]]+ALL|critical|DQ-008|GRANT ALL in application code — overly permissive|Grant only required permissions; follow principle of least privilege'
  'GRANT[[:space:]].*TO[[:space:]]+["\x27]?[a-zA-Z]|high|DQ-009|GRANT statement in application code|Manage permissions through administrative scripts, not application code'

  # ALTER TABLE in application code
  'ALTER[[:space:]]+TABLE|medium|DQ-010|ALTER TABLE in application code|DDL operations should be in migration files, not application code'

  # CREATE USER in application code
  'CREATE[[:space:]]+USER|high|DQ-011|CREATE USER in application code|User management should be administrative; remove from application code'

  # Raw DDL operations
  'CREATE[[:space:]]+TABLE|medium|DQ-012|CREATE TABLE in application code|Use managed migrations (e.g., Flyway, Alembic, Knex) for schema changes'
  'CREATE[[:space:]]+INDEX|low|DQ-013|CREATE INDEX in application code|Index management should be in migration files'

  # Stored procedures with dynamic names
  'EXEC[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|critical|DQ-014|Dynamic stored procedure name — injection risk|Whitelist allowed procedure names; never use user input for procedure names'
  'CALL[[:space:]]+["\x27`]?[[:space:]]*\+[[:space:]]*[a-zA-Z]|critical|DQ-015|Dynamic CALL with variable — procedure injection risk|Whitelist allowed procedure names'

  # UNION-based patterns without sanitization
  'UNION[[:space:]]+SELECT.*\+[[:space:]]*[a-zA-Z]|critical|DQ-016|UNION SELECT with string concatenation — UNION injection risk|Use parameterized queries; validate and whitelist UNION subquery components'
  'UNION[[:space:]]+ALL[[:space:]]+SELECT.*\+|critical|DQ-017|UNION ALL SELECT with concatenation — injection risk|Use parameterized queries for all parts of UNION queries'

  # INTO OUTFILE / DUMPFILE
  'INTO[[:space:]]+OUTFILE|critical|DQ-018|INTO OUTFILE — writes server files, potential data exfiltration|Remove file output from queries; use application-level export instead'
  'INTO[[:space:]]+DUMPFILE|critical|DQ-019|INTO DUMPFILE — writes binary data to server|Remove DUMPFILE; use application-level file handling'

  # LOAD_FILE
  'LOAD_FILE[[:space:]]*\(|critical|DQ-020|LOAD_FILE() — reads arbitrary server files|Remove LOAD_FILE(); read files through application code with proper authorization'
)

# ═══════════════════════════════════════════════════════════════════════════
# 4. ORM MISUSE & BYPASS PATTERNS (18 patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_ORM_PATTERNS=()

SQLGUARD_ORM_PATTERNS+=(
  # Django .raw() with interpolation
  '\.raw\([[:space:]]*["\x27].*%[sd]|high|OM-001|Django .raw() with string formatting — bypasses ORM protections|Use .raw() with params: Model.objects.raw("SELECT ... WHERE id = %s", [id])'
  '\.raw\([[:space:]]*f["\x27]|critical|OM-002|Django .raw() with f-string — SQL injection via ORM bypass|Use .raw() with params list instead of f-string interpolation'

  # Django .extra()
  '\.extra\([[:space:]]*where[[:space:]]*=|high|OM-003|Django .extra(where=...) — deprecated and unsafe|Replace .extra() with .annotate() and F/Q expressions'
  '\.extra\([[:space:]]*select[[:space:]]*=|high|OM-004|Django .extra(select=...) — deprecated and unsafe|Replace .extra() with .annotate() and database functions'

  # Sequelize.literal() with user input
  'Sequelize\.literal\([[:space:]]*["\x27`].*\+|critical|OM-005|Sequelize.literal() with string concatenation — injection via ORM|Use Sequelize.literal() only with constant strings; pass variables as bind parameters'
  'sequelize\.literal\([[:space:]]*`[^`]*\$\{|critical|OM-006|Sequelize.literal() with template literal interpolation|Use bind parameters instead of interpolating into Sequelize.literal()'

  # knex.raw() with variables
  'knex\.raw\([[:space:]]*["\x27`].*\+[[:space:]]*[a-zA-Z]|critical|OM-007|knex.raw() with string concatenation — SQL injection risk|Use knex.raw("... WHERE id = ?", [id]) with bindings'
  'knex\.raw\([[:space:]]*`[^`]*\$\{|critical|OM-008|knex.raw() with template literal interpolation|Use knex.raw() with binding array parameter'

  # ActiveRecord find_by_sql with interpolation
  'find_by_sql\([[:space:]]*["\x27].*#\{|critical|OM-009|ActiveRecord find_by_sql with string interpolation — injection risk|Use find_by_sql with bind parameters: find_by_sql(["SELECT ... WHERE id = ?", id])'

  # ActiveRecord .where with string concatenation
  '\.where\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|high|OM-010|ActiveRecord .where() with string concatenation|Use hash conditions: .where(id: id) or .where("id = ?", id)'
  '\.where\([[:space:]]*["\x27].*#\{|high|OM-011|ActiveRecord .where() with string interpolation|Use placeholder syntax: .where("name = ?", name)'

  # TypeORM raw queries
  '\.createQueryBuilder\(.*\.where\([[:space:]]*["\x27`].*\+|high|OM-012|TypeORM QueryBuilder .where() with concatenation|Use .where("user.id = :id", { id: userId }) with parameter binding'
  'getRepository\(.*\.query\([[:space:]]*["\x27`].*\+|high|OM-013|TypeORM .query() with string concatenation|Use QueryBuilder with parameter binding instead of raw queries'

  # Prisma raw queries
  '\$queryRaw\([[:space:]]*`[^`]*\$\{|critical|OM-014|Prisma $queryRaw with template literal — injection risk|Use Prisma.sql tagged template: prisma.$queryRaw(Prisma.sql`SELECT ... WHERE id = ${id}`)'
  '\$executeRaw\([[:space:]]*`[^`]*\$\{|critical|OM-015|Prisma $executeRaw with template literal — injection risk|Use Prisma.sql tagged template for safe parameterization'

  # SQLAlchemy text() with concatenation
  'text\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|high|OM-016|SQLAlchemy text() with string concatenation|Use text() with bindparams: text("SELECT ... WHERE id = :id").bindparams(id=user_id)'
  'text\([[:space:]]*f["\x27]|critical|OM-017|SQLAlchemy text() with f-string — injection risk|Use text() with named bind parameters instead of f-string interpolation'

  # Hibernate raw SQL
  'createNativeQuery\([[:space:]]*["\x27].*\+[[:space:]]*[a-zA-Z]|critical|OM-018|Hibernate createNativeQuery() with string concatenation|Use named parameters: createNativeQuery("SELECT ... WHERE id = :id").setParameter("id", id)'
)

# ═══════════════════════════════════════════════════════════════════════════
# 5. N+1 & PERFORMANCE ANTI-PATTERNS (10 patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_PERFORMANCE_PATTERNS=()

SQLGUARD_PERFORMANCE_PATTERNS+=(
  # Queries inside loops — JS/TS
  'for[[:space:]]*\(.*\)[[:space:]]*\{[[:space:]]*.*\.query\(|medium|NP-001|SQL query inside for loop — potential N+1 query pattern|Use batch queries, JOINs, or eager loading instead of per-item queries'
  'forEach\(.*\.query\(|medium|NP-002|SQL query inside forEach — potential N+1 pattern|Batch queries outside the loop or use IN() with collected IDs'

  # Queries inside loops — Python
  'for[[:space:]]+[a-zA-Z_]+[[:space:]]+in[[:space:]].*:.*execute\(|medium|NP-003|SQL execute() inside Python for loop — N+1 pattern|Use executemany() or batch the query with IN() clause'
  'for[[:space:]]+[a-zA-Z_]+[[:space:]]+in[[:space:]].*:.*\.get\(|medium|NP-004|ORM .get() inside Python for loop — N+1 query pattern|Use select_related(), prefetch_related(), or bulk queries'

  # Queries inside loops — Go
  'for[[:space:]].*;.*;.*\{.*db\.Query|medium|NP-005|db.Query inside Go for loop — N+1 pattern|Batch queries using IN() clause or prepare statements outside the loop'

  # Queries inside loops — Ruby
  '\.each[[:space:]]+do.*\.find\(|medium|NP-006|ActiveRecord .find() inside .each loop — N+1 pattern|Use .includes() or .preload() for eager loading'
  '\.each[[:space:]]+do.*\.where\(|medium|NP-007|ActiveRecord .where() inside .each loop — N+1 pattern|Use .includes(), .preload(), or batch the query'

  # Missing eager loading hints
  'PLACEHOLDER_MISSING_EAGER_LOAD|medium|NP-008|Related model queries without eager loading|Use includes(), prefetch_related(), or JOINs to batch related queries'

  # Unbounded SELECT without LIMIT
  'SELECT[[:space:]].*FROM[[:space:]]+[a-zA-Z_]+[[:space:]]*;[[:space:]]*$|low|NP-009|SELECT without LIMIT — may return excessive rows|Add LIMIT clause to prevent unbounded result sets in application queries'

  # Cursor iteration without batching
  'cursor\.[[:space:]]*fetchall\(\)|low|NP-010|cursor.fetchall() loads entire result into memory|Use cursor.fetchmany(size) or iterate cursor for large result sets'
)

# ═══════════════════════════════════════════════════════════════════════════
# 6. AUTHENTICATION & ACCESS CONTROL PATTERNS (9+ patterns)
# ═══════════════════════════════════════════════════════════════════════════

declare -a SQLGUARD_ACCESS_PATTERNS=()

SQLGUARD_ACCESS_PATTERNS+=(
  # Hardcoded SQL credentials
  'password[[:space:]]*[:=][[:space:]]*["\x27][a-zA-Z0-9!@#$%^&*]{4,}["\x27]|critical|AC-001|Hardcoded database password in source code|Use environment variables or a secrets manager for database credentials'
  '(db_pass|DB_PASS|dbPassword|db_password)[[:space:]]*[:=][[:space:]]*["\x27][^"\x27$]{4,}|critical|AC-002|Hardcoded database password variable|Use environment variables: process.env.DB_PASSWORD or os.environ["DB_PASSWORD"]'

  # Connection strings with plaintext passwords
  '(mysql|postgres|postgresql|mongodb|mssql)://[a-zA-Z0-9_]+:[^@$\{]+@|critical|AC-003|Database connection string with plaintext password|Use environment variables for connection strings: process.env.DATABASE_URL'
  'Data[[:space:]]+Source=.*Password[[:space:]]*=[[:space:]]*[a-zA-Z0-9]|critical|AC-004|ADO.NET connection string with plaintext password|Use integrated security or environment variables for credentials'

  # Disabled SSL for database connections
  'sslmode[[:space:]]*=[[:space:]]*disable|high|AC-005|SSL disabled for database connection|Enable SSL: sslmode=require or sslmode=verify-full for production'
  'ssl[[:space:]]*[:=][[:space:]]*false|high|AC-006|SSL disabled for database connection|Enable SSL for database connections in production environments'

  # Wildcard GRANT
  'GRANT[[:space:]]+ALL[[:space:]]+PRIVILEGES[[:space:]]+ON[[:space:]]+\*\.\*|critical|AC-007|GRANT ALL PRIVILEGES ON *.* — superuser-level access|Grant only required permissions on specific databases and tables'

  # Comment-based auth bypass patterns
  '--[[:space:]]*$|low|AC-008|SQL comment at end of line — potential auth bypass indicator|Review query construction; comments should not appear in dynamic queries'
  '#[[:space:]]*$|low|AC-009|MySQL comment at end of line — potential auth bypass indicator|Review query construction for comment injection risks'

  # Time-based blind injection indicators
  'SLEEP\([[:space:]]*[0-9]|high|AC-010|SLEEP() function in query — time-based blind injection indicator|Remove SLEEP() from application queries; this is a common injection payload'
  'BENCHMARK\([[:space:]]*[0-9]|high|AC-011|BENCHMARK() function — time-based blind injection indicator|Remove BENCHMARK() from application queries'
  'WAITFOR[[:space:]]+DELAY|high|AC-012|WAITFOR DELAY — MSSQL time-based blind injection indicator|Remove WAITFOR DELAY from application queries'
)

# ═══════════════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════════════

# Get total pattern count across all categories
sqlguard_pattern_count() {
  local count=0
  count=$((count + ${#SQLGUARD_INJECTION_PATTERNS[@]}))
  count=$((count + ${#SQLGUARD_PARAMETERIZATION_PATTERNS[@]}))
  count=$((count + ${#SQLGUARD_DANGEROUS_PATTERNS[@]}))
  count=$((count + ${#SQLGUARD_ORM_PATTERNS[@]}))
  count=$((count + ${#SQLGUARD_PERFORMANCE_PATTERNS[@]}))
  count=$((count + ${#SQLGUARD_ACCESS_PATTERNS[@]}))
  echo "$count"
}

# List patterns by category
sqlguard_list_patterns() {
  local filter_type="${1:-all}"
  local -n _patterns_ref

  case "$filter_type" in
    INJECTION)         _patterns_ref=SQLGUARD_INJECTION_PATTERNS ;;
    PARAMETERIZATION)  _patterns_ref=SQLGUARD_PARAMETERIZATION_PATTERNS ;;
    DANGEROUS)         _patterns_ref=SQLGUARD_DANGEROUS_PATTERNS ;;
    ORM)               _patterns_ref=SQLGUARD_ORM_PATTERNS ;;
    PERFORMANCE)       _patterns_ref=SQLGUARD_PERFORMANCE_PATTERNS ;;
    ACCESS)            _patterns_ref=SQLGUARD_ACCESS_PATTERNS ;;
    all)
      sqlguard_list_patterns "INJECTION"
      sqlguard_list_patterns "PARAMETERIZATION"
      sqlguard_list_patterns "DANGEROUS"
      sqlguard_list_patterns "ORM"
      sqlguard_list_patterns "PERFORMANCE"
      sqlguard_list_patterns "ACCESS"
      return
      ;;
    *)
      echo "Unknown category: $filter_type"
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

# Get patterns array name for a vulnerability category
get_patterns_for_category() {
  local category="$1"
  case "$category" in
    injection)         echo "SQLGUARD_INJECTION_PATTERNS" ;;
    parameterization)  echo "SQLGUARD_PARAMETERIZATION_PATTERNS" ;;
    dangerous)         echo "SQLGUARD_DANGEROUS_PATTERNS" ;;
    orm)               echo "SQLGUARD_ORM_PATTERNS" ;;
    performance)       echo "SQLGUARD_PERFORMANCE_PATTERNS" ;;
    access)            echo "SQLGUARD_ACCESS_PATTERNS" ;;
    *)                 echo "" ;;
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

# OWASP Top 10 mapping
get_owasp_reference() {
  local check_id="$1"
  local prefix="${check_id%%-*}"
  case "$prefix" in
    SI) echo "OWASP A03:2021 Injection — SQL Injection via unsafe input handling" ;;
    MP) echo "OWASP A03:2021 Injection — Missing parameterized queries" ;;
    DQ) echo "OWASP A03:2021 Injection — Dangerous SQL constructs" ;;
    OM) echo "OWASP A03:2021 Injection — ORM misuse bypassing protections" ;;
    NP) echo "OWASP A04:2021 Insecure Design — Performance anti-patterns" ;;
    AC) echo "OWASP A07:2021 Identification and Authentication Failures" ;;
    *)  echo "" ;;
  esac
}

# CWE mapping
get_cwe_reference() {
  local check_id="$1"
  local prefix="${check_id%%-*}"
  case "$prefix" in
    SI) echo "CWE-89: SQL Injection" ;;
    MP) echo "CWE-89: SQL Injection (Improper Neutralization of Special Elements)" ;;
    DQ) echo "CWE-20: Improper Input Validation" ;;
    OM) echo "CWE-89: SQL Injection via ORM Bypass" ;;
    NP) echo "CWE-400: Uncontrolled Resource Consumption" ;;
    AC) echo "CWE-798: Use of Hard-coded Credentials" ;;
    *)  echo "" ;;
  esac
}
