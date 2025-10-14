# Vulnerability Report for getwilds/combine-counts:0.1.0

Report generated on 2025-09-10 17:06:53 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 11 |
| 🟢 Low | 12 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 11 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/combine-counts:0.1.0  │    0C     4H    11M    12L     1?   
    digest             │  c3e071a4da5b                           │                                     
  Base image           │  python:3.12-slim                       │    0C     4H    11M    12L     1?   
  Refreshed base image │  python:3.12-slim                       │    0C     0H     1M    20L          
                       │                                         │           -4    -10     +8     -1   
  Updated base image   │  python:3.13-slim                       │    0C     0H     1M    20L          
                       │                                         │           -4    -10     +8     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/combine-counts:0.1.0
    View base image update recommendations → docker scout recommendations getwilds/combine-counts:0.1.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/combine-counts:0.1.0 --org <organization>
```
</details>
