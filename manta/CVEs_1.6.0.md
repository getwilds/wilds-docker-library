# Vulnerability Report for getwilds/manta:1.6.0

Report generated on 2025-09-10 16:28:06 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1 |
| 🟢 Low | 4 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:2-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `python:3.9-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/manta:1.6.0  │    0C     5H     1M     4L   
    digest           │  84f3fe0d9b56                  │                              
  Base image         │  python:2-slim                 │    0C     5H     1M     0L   
  Updated base image │  python:3.9-slim               │    0C     3H     2M    20L   
                     │                                │           -2     +1    +20   

What's next:
    View vulnerabilities → docker scout cves getwilds/manta:1.6.0
    View base image update recommendations → docker scout recommendations getwilds/manta:1.6.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/manta:1.6.0 --org <organization>
```
</details>
