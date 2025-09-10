# Vulnerability Report for getwilds/scvi-tools:1.1.6

Report generated on 2025-09-10 17:53:00 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 21 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🟢 Low | 20 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/scvi-tools:1.1.6  │    2C     0H     2M    21L   
    digest           │  687022a89202                       │                              
  Base image         │  python:3.12-slim                   │    0C     0H     1M    20L   
  Updated base image │  python:3.13-slim                   │    0C     0H     1M    20L   
                     │                                     │                              

What's next:
    View vulnerabilities → docker scout cves getwilds/scvi-tools:1.1.6
    View base image update recommendations → docker scout recommendations getwilds/scvi-tools:1.1.6
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scvi-tools:1.1.6 --org <organization>
```
</details>
