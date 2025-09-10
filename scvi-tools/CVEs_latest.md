# Vulnerability Report for getwilds/scvi-tools:latest

Report generated on 2025-09-10 17:57:57 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 7 |
| 🟡 Medium | 21 |
| 🟢 Low | 15 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 5 |
| 🟡 Medium | 15 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/scvi-tools:latest  │    5C     7H    21M    15L     1?   
    digest             │  bfa946ff3165                        │                                     
  Base image           │  python:3.12-slim                    │    1C     5H    15M    13L     1?   
  Refreshed base image │  python:3.12-slim                    │    0C     0H     1M    20L          
                       │                                      │    -1     -5    -14     +7     -1   
  Updated base image   │  python:3.13-slim                    │    0C     0H     1M    20L          
                       │                                      │    -1     -5    -14     +7     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/scvi-tools:latest
    View base image update recommendations → docker scout recommendations getwilds/scvi-tools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scvi-tools:latest --org <organization>
```
</details>
