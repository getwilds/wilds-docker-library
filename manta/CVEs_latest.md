# Vulnerability Report for getwilds/manta:latest

Report generated on 2025-09-10 16:28:34 PST

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
Target             │  getwilds/manta:latest  │    0C     5H     1M     4L   
    digest           │  6d64e8b839b9                   │                              
  Base image         │  python:2-slim                  │    0C     5H     1M     0L   
  Updated base image │  python:3.9-slim                │    0C     3H     2M    20L   
                     │                                 │           -2     +1    +20   

What's next:
    View vulnerabilities → docker scout cves getwilds/manta:latest
    View base image update recommendations → docker scout recommendations getwilds/manta:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/manta:latest --org <organization>
```
</details>
