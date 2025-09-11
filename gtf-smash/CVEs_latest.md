# Vulnerability Report for getwilds/gtf-smash:latest

Report generated on 2025-09-10 16:31:15 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 5 |
| 🟡 Medium | 11 |
| 🟢 Low | 14 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 11 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/gtf-smash:latest  │    1C     5H    11M    14L     1?   
    digest             │  f6dda10ea564                       │                                     
  Base image           │  python:3.12-slim                   │    0C     5H    11M    14L     1?   
  Refreshed base image │  python:3.12-slim                   │    0C     0H     1M    20L          
                       │                                     │           -5    -10     +6     -1   
  Updated base image   │  python:3.13-slim                   │    0C     0H     1M    20L          
                       │                                     │           -5    -10     +6     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/gtf-smash:latest
    View base image update recommendations → docker scout recommendations getwilds/gtf-smash:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gtf-smash:latest --org <organization>
```
</details>
