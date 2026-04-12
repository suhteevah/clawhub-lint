#!/usr/bin/env bash
# SchemaLint -- Database Schema & Query Anti-Pattern Definitions
# 90 patterns across 6 categories, 15 patterns each.
#
# Format per line:
#   REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical -- Data loss, corruption, or severe performance degradation
#   high     -- Significant schema or query bug that will cause real problems
#   medium   -- Moderate concern that should be addressed
#   low      -- Best practice suggestion
#
# IMPORTANT: All regexes use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alnum:]] instead of \w
# - NEVER use pipe (|) for alternation inside regex -- it conflicts with
#   the field delimiter. Use separate patterns or character classes instead.

set -euo pipefail

# ===========================================================================
# IX -- Indexing Issues (15 patterns: IX-001 to IX-015)
# Free tier
# ===========================================================================

declare -a SCHEMALINT_IX_PATTERNS=(
  'REFERENCES[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*\)[[:space:]]*$|high|IX-001|Foreign key column without explicit index -- full table scans on JOINs|Add CREATE INDEX on every foreign key column for JOIN performance'
  'CREATE[[:space:]]+TABLE[[:space:]]+[[:alnum:]_]+[[:space:]]*\([^)]*_id[[:space:]]+INT|medium|IX-002|Column ending in _id likely a foreign key -- verify an index exists|Add an index on all _id columns used as foreign keys'
  'CREATE[[:space:]]+INDEX[[:space:]]+[[:alnum:]_]+[[:space:]]+ON[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+|medium|IX-003|Composite index with 4+ columns -- diminishing returns and write overhead|Limit composite indexes to 3 columns max; review query patterns'
  'WHERE[[:space:]]+[[:alnum:]_]+[[:space:]]*LIKE[[:space:]]+["\x27]%|high|IX-004|Leading wildcard LIKE query cannot use indexes -- full table scan|Use full-text search or reverse index instead of leading wildcard LIKE'
  'SELECT[[:space:]].*FROM[[:space:]]+[[:alnum:]_]+[[:space:]]*;|medium|IX-005|Query without WHERE clause reads entire table|Add WHERE clause or LIMIT to avoid full table scans'
  'INDEX[[:space:]]+[[:alnum:]_]+[[:space:]]+ON[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+\([[:space:]]*[0-9]+\)|low|IX-006|Prefix index on column -- may reduce selectivity|Verify prefix length provides adequate selectivity for your data'
  'WHERE[[:space:]]+[[:alnum:]_]+[[:space:]]*![[:space:]]*=|medium|IX-007|Not-equal condition usually cannot use index effectively|Restructure query to use positive equality or range conditions'
  'WHERE[[:space:]].*LOWER\([[:space:]]*[[:alnum:]_]+|high|IX-008|LOWER() on column in WHERE prevents index usage|Create a case-insensitive index or use CITEXT type instead'
  'WHERE[[:space:]].*UPPER\([[:space:]]*[[:alnum:]_]+|high|IX-009|UPPER() on column in WHERE prevents index usage|Create a case-insensitive index or use CITEXT type instead'
  'WHERE[[:space:]].*YEAR\([[:space:]]*[[:alnum:]_]+|medium|IX-010|YEAR() function on date column prevents index usage|Use range condition: date_col >= X AND date_col < Y'
  'WHERE[[:space:]].*CAST\([[:space:]]*[[:alnum:]_]+|medium|IX-011|CAST on column in WHERE clause prevents index usage|Store data in the correct type or create a computed column with index'
  'WHERE[[:space:]].*COALESCE\([[:space:]]*[[:alnum:]_]+|medium|IX-012|COALESCE on column in WHERE prevents index usage|Use IS NULL / IS NOT NULL with UNION or separate conditions'
  'ORDER[[:space:]]+BY[[:space:]]+[[:alnum:]_]+[[:space:]]+DESC[[:space:]]*,[[:space:]]*[[:alnum:]_]+[[:space:]]+ASC|low|IX-013|Mixed ASC/DESC ordering requires matching index direction|Create index with matching sort directions for this query pattern'
  'FORCE[[:space:]]+INDEX|low|IX-014|FORCE INDEX overrides optimizer -- may degrade with data changes|Remove FORCE INDEX and let optimizer choose; investigate root cause'
  'IGNORE[[:space:]]+INDEX|low|IX-015|IGNORE INDEX overrides optimizer -- may cause unexpected plan changes|Remove IGNORE INDEX and let optimizer choose; investigate root cause'
)

# ===========================================================================
# TY -- Type Safety (15 patterns: TY-001 to TY-015)
# Free tier
# ===========================================================================

declare -a SCHEMALINT_TY_PATTERNS=(
  'VARCHAR\([[:space:]]*255[[:space:]]*\)|medium|TY-001|Default VARCHAR(255) suggests no thought given to actual max length|Set VARCHAR length to actual maximum expected value for the field'
  'TEXT[[:space:]]+.*[Nn]ame|medium|TY-002|TEXT type for a name field -- likely too large and not indexable efficiently|Use VARCHAR with appropriate length for name fields'
  'TEXT[[:space:]]+.*[Ee]mail|medium|TY-003|TEXT type for email field -- emails have a known max length of 254|Use VARCHAR(254) for email fields per RFC 5321'
  'TEXT[[:space:]]+.*[Pp]hone|medium|TY-004|TEXT type for phone number field -- use VARCHAR(20) or dedicated type|Use VARCHAR(20) for phone fields; consider E.164 format validation'
  'INT[[:space:]]+.*[Ii]s_[[:alnum:]]|high|TY-005|INT for boolean flag (is_*) wastes space and reduces clarity|Use BOOLEAN or TINYINT(1) for boolean flag columns'
  'INT[[:space:]]+.*[Hh]as_[[:alnum:]]|high|TY-006|INT for boolean flag (has_*) wastes space and reduces clarity|Use BOOLEAN or TINYINT(1) for boolean flag columns'
  'VARCHAR.*[Jj][Ss][Oo][Nn]|high|TY-007|Storing JSON in VARCHAR column -- use native JSON type for validation|Use JSON or JSONB column type for structured JSON data'
  'TEXT[[:space:]]+.*[Jj][Ss][Oo][Nn]|high|TY-008|Storing JSON in TEXT column -- no validation or query operators|Use JSON or JSONB column type for structured JSON data'
  'FLOAT[[:space:]]+.*[Pp]rice|critical|TY-009|FLOAT for monetary values causes rounding errors|Use DECIMAL or NUMERIC with fixed precision for monetary values'
  'FLOAT[[:space:]]+.*[Aa]mount|critical|TY-010|FLOAT for monetary amounts causes rounding errors|Use DECIMAL or NUMERIC with fixed precision for monetary values'
  'DOUBLE[[:space:]]+.*[Cc]urrency|critical|TY-011|DOUBLE for currency values causes rounding errors|Use DECIMAL or NUMERIC with fixed precision for currency'
  'FLOAT[[:space:]]+.*[Bb]alance|critical|TY-012|FLOAT for balance values causes rounding errors|Use DECIMAL or NUMERIC with fixed precision for balance fields'
  'VARCHAR[[:space:]]*\([[:space:]]*[0-9]+[[:space:]]*\)[[:space:]]+.*[Uu][Uu][Ii][Dd]|medium|TY-013|Storing UUID as VARCHAR wastes space vs native UUID type|Use native UUID type or BINARY(16) for compact UUID storage'
  'CHAR\([[:space:]]*1[[:space:]]*\)[[:space:]]+.*[Ss]tatus|medium|TY-014|Single-char status codes are cryptic and error-prone|Use ENUM or a status lookup table for readable status values'
  'VARCHAR[[:space:]]*\([[:space:]]*[0-9]+[[:space:]]*\)[[:space:]]+.*[Ii][Pp]|low|TY-015|Storing IP addresses as VARCHAR -- consider native INET type|Use INET type (PostgreSQL) or BINARY for compact IP storage'
)

# ===========================================================================
# NM -- Naming Conventions (15 patterns: NM-001 to NM-015)
# Pro tier
# ===========================================================================

declare -a SCHEMALINT_NM_PATTERNS=(
  'CREATE[[:space:]]+TABLE[[:space:]]+["\x60]?[Uu]ser["\x60]?[[:space:]]*\(|high|NM-001|Table named user is a reserved word in most SQL databases|Rename to users, accounts, or another non-reserved name'
  'CREATE[[:space:]]+TABLE[[:space:]]+["\x60]?[Oo]rder["\x60]?[[:space:]]*\(|high|NM-002|Table named order is a reserved word in SQL|Rename to orders, purchase_orders, or another non-reserved name'
  'CREATE[[:space:]]+TABLE[[:space:]]+["\x60]?[Gg]roup["\x60]?[[:space:]]*\(|high|NM-003|Table named group is a reserved word in SQL|Rename to groups, user_groups, or another non-reserved name'
  'CREATE[[:space:]]+TABLE[[:space:]]+["\x60]?[Tt]able["\x60]?[[:space:]]*\(|high|NM-004|Table named table is a reserved word in SQL|Choose a descriptive non-reserved name for the table'
  '[[:space:]]["\x60]?data["\x60]?[[:space:]]+VARCHAR|medium|NM-005|Column named data is ambiguous -- provides no semantic meaning|Use a descriptive column name indicating what data is stored'
  '[[:space:]]["\x60]?value["\x60]?[[:space:]]+VARCHAR|medium|NM-006|Column named value is ambiguous -- provides no semantic meaning|Use a descriptive column name indicating what value is stored'
  '[[:space:]]["\x60]?type["\x60]?[[:space:]]+VARCHAR|low|NM-007|Column named type is a reserved word in some databases|Rename to category, kind, or a domain-specific type name'
  '[[:space:]]["\x60]?status["\x60]?[[:space:]]+INT|low|NM-008|Numeric status column with no documentation of valid values|Use ENUM or add a CHECK constraint with documented status values'
  '[[:space:]]["\x60]?flag["\x60]?[[:space:]]+|low|NM-009|Column named flag is generic and unclear|Name boolean columns with is_ or has_ prefix for clarity'
  'CREATE[[:space:]]+TABLE[[:space:]]+[[:alnum:]]*[A-Z][[:alnum:]]*[A-Z]|medium|NM-010|CamelCase table name -- SQL convention uses snake_case|Use snake_case for table names (e.g., user_accounts not UserAccounts)'
  '[[:space:]][[:alnum:]]*[A-Z][[:alnum:]]*[A-Z][[:alnum:]]*[[:space:]]+INT|low|NM-011|CamelCase column name -- SQL convention uses snake_case|Use snake_case for column names (e.g., first_name not firstName)'
  'CREATE[[:space:]]+TABLE[[:space:]]+[[:alnum:]_]+s[[:space:]]*\(.*[[:space:]]id[[:space:]]+|low|NM-012|Plural table name with id column -- verify naming consistency|Use consistent convention: plural tables (users) with singular FK (user_id)'
  '[[:space:]]["\x60]?temp["\x60]?[[:space:]]+|low|NM-013|Column named temp -- temporary columns often become permanent|Give the column a proper descriptive name before deploying'
  '[[:space:]]["\x60]?misc["\x60]?[[:space:]]+|low|NM-014|Column named misc -- suggests poor data modeling|Break into specific named columns or use a typed JSON field'
  'CREATE[[:space:]]+TABLE[[:space:]]+["\x60]?[[:alnum:]_]*[0-9]+["\x60]?[[:space:]]*\(|medium|NM-015|Table name contains numbers -- may indicate poor normalization|Review if numbered tables should be a single table with a type column'
)

# ===========================================================================
# RL -- Relationships & Constraints (15 patterns: RL-001 to RL-015)
# Pro tier
# ===========================================================================

declare -a SCHEMALINT_RL_PATTERNS=(
  'REFERENCES[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*\)[[:space:]]*$|high|RL-001|Foreign key without ON DELETE clause -- orphan rows on parent deletion|Add ON DELETE CASCADE, SET NULL, or RESTRICT based on business rules'
  'REFERENCES[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*\)[[:space:]]*[^O]*$|high|RL-002|Foreign key missing ON UPDATE clause for cascading updates|Add ON UPDATE CASCADE or RESTRICT to handle parent key changes'
  '[[:space:]][[:alnum:]_]+[[:space:]]+INT[[:space:]]*$|medium|RL-003|INT column without NOT NULL or DEFAULT -- allows unexpected NULLs|Add NOT NULL constraint with appropriate DEFAULT value'
  '[[:space:]][[:alnum:]_]+[[:space:]]+VARCHAR[[:space:]]*\([[:space:]]*[0-9]+[[:space:]]*\)[[:space:]]*$|medium|RL-004|VARCHAR column without NOT NULL -- empty string vs NULL ambiguity|Add NOT NULL DEFAULT empty string or document NULL semantics'
  '_id[[:space:]]+INT[[:space:]]+NOT[[:space:]]+NULL[[:space:]]*$|medium|RL-005|Foreign key column (_id) without REFERENCES constraint|Add explicit FOREIGN KEY REFERENCES to enforce referential integrity'
  'CREATE[[:space:]]+TABLE[[:space:]]+[[:alnum:]_]+[[:space:]]*\([^)]*[[:space:]]id[[:space:]]+INT[[:space:]]+NOT[[:space:]]+NULL[[:space:]]*$|medium|RL-006|Primary key column without AUTO_INCREMENT or SERIAL|Use AUTO_INCREMENT (MySQL), SERIAL (PostgreSQL), or IDENTITY for PKs'
  'REFERENCES[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*id[[:space:]]*\)[[:space:]]+ON[[:space:]]+DELETE[[:space:]]+CASCADE|low|RL-007|CASCADE delete may cause unintended mass deletion|Verify CASCADE is appropriate; consider SET NULL or RESTRICT for safety'
  'ON[[:space:]]+DELETE[[:space:]]+SET[[:space:]]+NULL|low|RL-008|SET NULL on delete -- verify column is nullable and NULL is handled|Ensure application code handles NULL foreign key values gracefully'
  'FOREIGN[[:space:]]+KEY[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*\)[[:space:]]+REFERENCES[[:space:]]+[[:alnum:]_]+[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*\).*FOREIGN[[:space:]]+KEY|medium|RL-009|Table with multiple foreign keys -- verify no circular reference chain|Map relationship graph to confirm no circular dependency cycles'
  'self_join|low|RL-010|Self-referencing relationship pattern detected|Add max depth constraint or use a closure table for hierarchical data'
  'parent_id[[:space:]]+INT|low|RL-011|Adjacency list pattern (parent_id) -- limits query depth in SQL|Consider closure table or materialized path for deep hierarchies'
  'CHECK[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*>[[:space:]]*0|low|RL-012|CHECK constraint for positive values -- good practice|Verify all numeric business rules have appropriate CHECK constraints'
  'UNIQUE[[:space:]]*\([[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+[[:space:]]*,[[:space:]]*[[:alnum:]_]+|low|RL-013|Composite UNIQUE constraint on 4+ columns -- may indicate denormalization|Review if the table should be normalized into separate entities'
  'NOT[[:space:]]+NULL[[:space:]]+DEFAULT[[:space:]]+NULL|critical|RL-014|Contradictory NOT NULL DEFAULT NULL -- will error on insert without value|Remove DEFAULT NULL or remove NOT NULL constraint'
  'WITHOUT[[:space:]]+ROWID|low|RL-015|WITHOUT ROWID table (SQLite) -- verify performance benefit for your access pattern|Benchmark WITH vs WITHOUT ROWID for your specific workload'
)

# ===========================================================================
# QP -- Query Patterns (15 patterns: QP-001 to QP-015)
# Team tier
# ===========================================================================

declare -a SCHEMALINT_QP_PATTERNS=(
  'SELECT[[:space:]]+\*[[:space:]]+FROM|high|QP-001|SELECT * returns all columns -- wastes bandwidth and breaks on schema changes|List specific columns needed instead of using SELECT *'
  'SELECT[[:space:]].*FROM[[:space:]]+[[:alnum:]_]+[[:space:]]*;[[:space:]]*$|medium|QP-002|Query without WHERE or LIMIT may return unbounded results|Add WHERE clause or LIMIT to prevent returning entire table'
  'SELECT[[:space:]].*FROM.*WHERE.*["\x27][[:space:]]*\+[[:space:]]*[[:alnum:]]|critical|QP-003|String concatenation in SQL query -- SQL injection vulnerability|Use parameterized queries or prepared statements instead'
  'query\([[:space:]]*["\x27].*\+[[:space:]]*[[:alnum:]]|critical|QP-004|String concatenation in query() call -- SQL injection risk|Use parameterized queries: query(sql, [params])'
  'execute\([[:space:]]*["\x27].*\+[[:space:]]*[[:alnum:]]|critical|QP-005|String concatenation in execute() -- SQL injection risk|Use parameterized queries: execute(sql, params)'
  'f["\x27]SELECT[[:space:]]|critical|QP-006|f-string SQL query -- SQL injection vulnerability|Use parameterized queries with %s or ? placeholders'
  'WHERE[[:space:]]+1[[:space:]]*=[[:space:]]*1|medium|QP-007|WHERE 1=1 tautology -- often a sign of dynamic query building|Use a proper query builder instead of string-based dynamic SQL'
  'SELECT[[:space:]].*FROM[[:space:]]+[[:alnum:]_]+[[:space:]]+WHERE[[:space:]]+[[:alnum:]_]+[[:space:]]+IN[[:space:]]*\([[:space:]]*SELECT|medium|QP-008|Subquery in IN clause may be slow for large datasets|Rewrite as JOIN or use EXISTS for better query plan'
  'SELECT[[:space:]].*DISTINCT[[:space:]]+\*|high|QP-009|DISTINCT * is expensive and usually indicates a JOIN problem|Fix the JOIN to avoid duplicates instead of using DISTINCT *'
  'ORDER[[:space:]]+BY[[:space:]]+RAND\(\)|high|QP-010|ORDER BY RAND() scans entire table -- extremely slow on large tables|Use application-side random selection or a random row technique'
  'ORDER[[:space:]]+BY[[:space:]]+[0-9]+|low|QP-011|ORDER BY column number is fragile -- breaks if SELECT changes|Use explicit column names in ORDER BY clause'
  'SELECT[[:space:]].*COUNT\(\*\)[[:space:]]+FROM[[:space:]]+[[:alnum:]_]+[[:space:]]*;|low|QP-012|COUNT(*) on full table can be slow without index|Add WHERE clause or use approximate count for large tables'
  'LIKE[[:space:]]+["\x27]%.*%["\x27]|medium|QP-013|Double-sided wildcard LIKE cannot use indexes at all|Use full-text search (FTS) for substring matching patterns'
  'NOT[[:space:]]+IN[[:space:]]*\([[:space:]]*SELECT|medium|QP-014|NOT IN with subquery fails silently if subquery returns NULL|Use NOT EXISTS or LEFT JOIN ... IS NULL instead of NOT IN subquery'
  '\.findAll\(\)[[:space:]]*$|medium|QP-015|ORM findAll() without filters returns entire table|Add where conditions, limit, and pagination to findAll() calls'
)

# ===========================================================================
# MG -- Migration Safety (15 patterns: MG-001 to MG-015)
# Team tier
# ===========================================================================

declare -a SCHEMALINT_MG_PATTERNS=(
  'DROP[[:space:]]+COLUMN|critical|MG-001|DROP COLUMN is destructive and irreversible -- data loss risk|Create backup, add new column, migrate data, then deprecate old column'
  'DROP[[:space:]]+TABLE|critical|MG-002|DROP TABLE is irreversible -- permanent data loss|Create backup before dropping; use IF EXISTS to prevent errors'
  'RENAME[[:space:]]+TABLE|high|MG-003|RENAME TABLE breaks all references -- queries, views, stored procs|Use alias or new table with data copy instead of direct rename'
  'RENAME[[:space:]]+COLUMN|high|MG-004|RENAME COLUMN breaks application code referencing old name|Add new column, migrate data, update code, then drop old column'
  'ALTER[[:space:]]+TABLE.*ADD[[:space:]]+.*NOT[[:space:]]+NULL[[:space:]]*$|critical|MG-005|Adding NOT NULL column without DEFAULT fails on existing rows|Add DEFAULT value with NOT NULL or make nullable first then backfill'
  'ALTER[[:space:]]+TABLE.*MODIFY.*VARCHAR[[:space:]]*\([[:space:]]*[0-9]+[[:space:]]*\)|medium|MG-006|Shrinking VARCHAR length can truncate existing data|Verify no existing data exceeds the new length before modifying'
  'ALTER[[:space:]]+TABLE.*DROP[[:space:]]+PRIMARY|critical|MG-007|Dropping primary key removes uniqueness guarantee|Ensure new PK or unique constraint is added in same migration'
  'ALTER[[:space:]]+TABLE.*DROP[[:space:]]+INDEX|medium|MG-008|Dropping index may degrade query performance significantly|Verify the index is truly unused before dropping; check slow query log'
  'ALTER[[:space:]]+TABLE.*CHANGE[[:space:]]+.*INT.*BIGINT|low|MG-009|Changing INT to BIGINT on large table causes long lock|Use online DDL or pt-online-schema-change for zero-downtime migration'
  'TRUNCATE[[:space:]]+TABLE|critical|MG-010|TRUNCATE TABLE deletes all data without logging individual rows|Use DELETE with WHERE for selective removal; backup before truncate'
  'ALTER[[:space:]]+TABLE.*DROP[[:space:]]+FOREIGN|medium|MG-011|Dropping foreign key removes referential integrity protection|Ensure application-level validation exists before dropping FK constraint'
  'ALTER[[:space:]]+TABLE.*ENGINE[[:space:]]*=|medium|MG-012|Changing storage engine requires full table rebuild and lock|Schedule engine change during maintenance window with backup'
  'ALTER[[:space:]]+TABLE.*ADD.*AFTER[[:space:]]+[[:alnum:]_]+|low|MG-013|Column ordering with AFTER is cosmetic and causes full table rewrite|Add column at end; column order rarely matters for functionality'
  'UPDATE[[:space:]]+[[:alnum:]_]+[[:space:]]+SET[[:space:]]+.*WHERE[[:space:]]+1[[:space:]]*=[[:space:]]*1|high|MG-014|UPDATE with always-true WHERE clause modifies all rows|Add specific WHERE condition or confirm mass update is intentional'
  'DELETE[[:space:]]+FROM[[:space:]]+[[:alnum:]_]+[[:space:]]*;|critical|MG-015|DELETE without WHERE clause removes all rows from table|Add WHERE clause to target specific rows; use TRUNCATE for full wipe'
)

# ===========================================================================
# Utility Functions
# ===========================================================================

# Count total patterns
schemalint_pattern_count() {
  local count=0
  count=$((count + ${#SCHEMALINT_IX_PATTERNS[@]}))
  count=$((count + ${#SCHEMALINT_TY_PATTERNS[@]}))
  count=$((count + ${#SCHEMALINT_NM_PATTERNS[@]}))
  count=$((count + ${#SCHEMALINT_RL_PATTERNS[@]}))
  count=$((count + ${#SCHEMALINT_QP_PATTERNS[@]}))
  count=$((count + ${#SCHEMALINT_MG_PATTERNS[@]}))
  echo "$count"
}

# Count patterns in a specific category
schemalint_category_count() {
  local cat="$1"
  case "$cat" in
    IX) echo "${#SCHEMALINT_IX_PATTERNS[@]}" ;;
    TY) echo "${#SCHEMALINT_TY_PATTERNS[@]}" ;;
    NM) echo "${#SCHEMALINT_NM_PATTERNS[@]}" ;;
    RL) echo "${#SCHEMALINT_RL_PATTERNS[@]}" ;;
    QP) echo "${#SCHEMALINT_QP_PATTERNS[@]}" ;;
    MG) echo "${#SCHEMALINT_MG_PATTERNS[@]}" ;;
    *)  echo "0" ;;
  esac
}

# Get the bash array name for a category code
get_schemalint_patterns_for_category() {
  local cat="$1"
  case "$cat" in
    IX) echo "SCHEMALINT_IX_PATTERNS" ;;
    TY) echo "SCHEMALINT_TY_PATTERNS" ;;
    NM) echo "SCHEMALINT_NM_PATTERNS" ;;
    RL) echo "SCHEMALINT_RL_PATTERNS" ;;
    QP) echo "SCHEMALINT_QP_PATTERNS" ;;
    MG) echo "SCHEMALINT_MG_PATTERNS" ;;
    *)  echo "" ;;
  esac
}

# Get human-readable label for a category code
get_schemalint_category_label() {
  local cat="$1"
  case "$cat" in
    IX) echo "Indexing Issues" ;;
    TY) echo "Type Safety" ;;
    NM) echo "Naming Conventions" ;;
    RL) echo "Relationships & Constraints" ;;
    QP) echo "Query Patterns" ;;
    MG) echo "Migration Safety" ;;
    *)  echo "Unknown" ;;
  esac
}

# Get space-separated list of category codes available at a given tier level.
# Tier levels: 0=free (IX, TY), 1=pro (IX, TY, NM, RL), 2/3=team/enterprise (all)
get_schemalint_categories_for_tier() {
  local tier_level="$1"
  case "$tier_level" in
    0) echo "IX TY" ;;
    1) echo "IX TY NM RL" ;;
    2|3) echo "IX TY NM RL QP MG" ;;
    *) echo "IX TY" ;;
  esac
}

# Severity to point deduction mapping
severity_to_points() {
  local severity="$1"
  case "$severity" in
    critical) echo 25 ;;
    high)     echo 15 ;;
    medium)   echo  8 ;;
    low)      echo  3 ;;
    *)        echo  0 ;;
  esac
}

# Validate that a string is a known category code
is_valid_schemalint_category() {
  local cat="$1"
  case "$cat" in
    IX|TY|NM|RL|QP|MG) return 0 ;;
    *) return 1 ;;
  esac
}

# List patterns in a given category or "all"
schemalint_list_patterns() {
  local filter="${1:-all}"

  local categories="IX TY NM RL QP MG"
  if [[ "$filter" != "all" ]]; then
    filter=$(echo "$filter" | tr '[:lower:]' '[:upper:]')
    categories="$filter"
  fi

  for cat in $categories; do
    local label
    label=$(get_schemalint_category_label "$cat")
    echo -e "${BOLD:-}--- ${cat}: ${label} ---${NC:-}"

    local arr_name
    arr_name=$(get_schemalint_patterns_for_category "$cat")
    [[ -z "$arr_name" ]] && continue

    local -n _arr="$arr_name"
    for entry in "${_arr[@]}"; do
      IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
      local sev_upper
      sev_upper=$(echo "$severity" | tr '[:lower:]' '[:upper:]')
      echo "  [$sev_upper] $check_id: $description"
    done
    echo ""
  done
}
