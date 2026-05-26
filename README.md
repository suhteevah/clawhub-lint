# clawhub-lint

**3,348 patterns. 39 analyzers. Zero dependencies. One command.**

A unified static analysis suite that scans codebases for anti-patterns, security issues, and code quality problems across 39 categories. Pure Bash, POSIX grep-based, runs anywhere.

## Quick Start

```bash
# Scan everything
./clawhub-lint.sh scan /path/to/project

# Scan with specific tools
./clawhub-lint.sh scan . --tools sqlguard,secretscan,authaudit

# Only high/critical findings
./clawhub-lint.sh scan . --severity high

# List available analyzers
./clawhub-lint.sh list

# Count total patterns
./clawhub-lint.sh count
```

## What It Catches

| Analyzer | Patterns | What it finds |
|---|---|---|
| accesslint | 97 | Accessibility anti-patterns |
| apishield | 75 | API security & design issues |
| asyncguard | 90 | Async/await anti-patterns, unhandled promises |
| authaudit | 90 | Authentication & authorization flaws |
| bundlephobia | 90 | Bundle size & dependency bloat |
| cachelint | 90 | Caching anti-patterns, stampede risks |
| cloudguard | 90 | Cloud infrastructure & IaC security |
| concurrencyguard | 90 | Race conditions, concurrency bugs |
| configsafe | 131 | Configuration & environment issues |
| containerlint | 90 | Docker/container anti-patterns |
| cronlint | 90 | Cron job & scheduled task issues |
| cryptolint | 90 | Cryptography misuse, weak algorithms |
| dateguard | 90 | Date/time bugs, timezone issues |
| deadcode | 98 | Dead code, unused exports |
| doccoverage | 86 | Documentation gaps |
| envguard | 76 | Environment variable security |
| errorlens | 90 | Error handling anti-patterns |
| eventlint | 90 | Event queue & messaging issues |
| featurelint | 90 | Feature flag hygiene |
| gqllint | 90 | GraphQL security & design |
| httplint | 90 | HTTP client/server misconfig |
| i18ncheck | 90 | Internationalization readiness |
| inputshield | 90 | Input validation & sanitization |
| licenseguard | 90 | License compliance |
| logsentry | 90 | Logging quality & observability |
| memguard | 90 | Memory leaks & resource management |
| migratesafe | 90 | Database migration safety |
| perfguard | 90 | Performance anti-patterns |
| pipelinelint | 90 | CI/CD pipeline issues |
| ratelint | 90 | Rate limiting anti-patterns |
| regexguard | 90 | Regex safety, ReDoS risks |
| retrylint | 90 | Retry & resilience patterns |
| schemalint | 90 | Schema validation issues |
| secretscan | 90 | Hardcoded secrets, API keys |
| serdelint | 90 | Serialization anti-patterns |
| sqlguard | 90 | SQL injection & query safety |
| styleguard | 90 | Code style & naming conventions |
| testgap | 98 | Test coverage gaps |
| typedrift | 90 | Type safety & drift issues |

## Scoring

Every scan produces a 100-point score:
- **Critical** finding: -25 points
- **High**: -15 points
- **Medium**: -8 points  
- **Low**: -3 points

Grades: A (90+), B (80-89), C (70-79), D (60-69), F (<60)

## How It Works

Each analyzer defines patterns in `REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION` format using POSIX ERE regex (grep -E compatible). The unified CLI loads all requested pattern sets and runs them against discovered source files, skipping binaries, vendored code, and build artifacts.

## Origin

These 39 analyzers were originally shipped as individual repos (4+ per day) by Matt Gates / Ridge Cell Repair LLC using Claude. This consolidated version combines them into a single installable tool.

## License

MIT

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

## Support This Project

If you find this project useful, consider buying me a coffee! Your support helps me keep building and sharing open-source tools.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.me/baal_hosting)

**PayPal:** [baal_hosting@live.com](https://paypal.me/baal_hosting)

Every donation, no matter how small, is greatly appreciated and motivates continued development. Thank you!
