# Vulnerability Report for getwilds/scanpy:latest

Report generated on 2025-09-10 17:17:00 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
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
Target               │  getwilds/scanpy:latest  │    0C     5H    11M    14L     1?   
    digest             │  a74e1137ef5f                    │                                     
  Base image           │  python:3.12-slim                │    0C     5H    11M    14L     1?   
  Refreshed base image │  python:3.12-slim                │    0C     0H     1M    20L          
                       │                                  │           -5    -10     +6     -1   
  Updated base image   │  python:3.13-slim                │    0C     0H     1M    20L          
                       │                                  │           -5    -10     +6     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/scanpy:latest
    View base image update recommendations → docker scout recommendations getwilds/scanpy:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scanpy:latest --org <organization>
```
</details>
