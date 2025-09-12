# Vulnerability Report for getwilds/scanpy:1.10.2

Report generated on 2025-09-10 17:16:23 PST

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
Target               │  getwilds/scanpy:1.10.2  │    0C     5H    11M    14L     1?   
    digest             │  533ab8e4b699                    │                                     
  Base image           │  python:3.12-slim                │    0C     5H    11M    14L     1?   
  Refreshed base image │  python:3.12-slim                │    0C     0H     1M    20L          
                       │                                  │           -5    -10     +6     -1   
  Updated base image   │  python:3.13-slim                │    0C     0H     1M    20L          
                       │                                  │           -5    -10     +6     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/scanpy:1.10.2
    View base image update recommendations → docker scout recommendations getwilds/scanpy:1.10.2
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scanpy:1.10.2 --org <organization>
```
</details>
