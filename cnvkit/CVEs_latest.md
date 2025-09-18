# Vulnerability Report for getwilds/cnvkit:latest

Report generated on 2025-09-18 05:57:35 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 2 |
| 🟢 Low | 78 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.10-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 2 |
| 🟢 Low | 20 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/cnvkit:latest  │    0C     3H     2M    78L   
    digest           │  237a8b43bb6e                    │                              
  Base image         │  python:3.10-slim                │    0C     2H     2M    20L   
  Updated base image │  python:3.13-slim                │    0C     0H     1M    20L   
                     │                                  │           -2     -1          

What's next:
    View vulnerabilities → docker scout cves getwilds/cnvkit:latest
    View base image update recommendations → docker scout recommendations getwilds/cnvkit:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cnvkit:latest --org <organization>
```
</details>
