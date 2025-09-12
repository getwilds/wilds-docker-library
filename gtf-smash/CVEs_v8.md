# Vulnerability Report for getwilds/gtf-smash:v8

Report generated on 2025-09-10 16:30:51 PST

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
Target               │  getwilds/gtf-smash:v8  │    1C     5H    11M    14L     1?   
    digest             │  1db4c2fb4093                   │                                     
  Base image           │  python:3.12-slim               │    0C     5H    11M    14L     1?   
  Refreshed base image │  python:3.12-slim               │    0C     0H     1M    20L          
                       │                                 │           -5    -10     +6     -1   
  Updated base image   │  python:3.13-slim               │    0C     0H     1M    20L          
                       │                                 │           -5    -10     +6     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/gtf-smash:v8
    View base image update recommendations → docker scout recommendations getwilds/gtf-smash:v8
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gtf-smash:v8 --org <organization>
```
</details>
