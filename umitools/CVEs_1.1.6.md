# Vulnerability Report for getwilds/umitools:1.1.6

Report generated on 2025-09-10 17:58:49 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 23 |
| 🟡 Medium | 32 |
| 🟢 Low | 118 |
| ⚪ Unknown | 5 |

## 🐳 Base Image

**Image:** `python:3.12`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 21 |
| 🟡 Medium | 32 |
| 🟢 Low | 117 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12`

**Updated base image:** `python:3.12-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/umitools:1.1.6  │    3C    23H    32M   118L     5?   
    digest             │  ca0a3fc5f476                     │                                     
  Base image           │  python:3.12                      │    3C    21H    32M   117L     5?   
  Refreshed base image │  python:3.12                      │    0C     4H     3M   141L     2?   
                       │                                   │    -3    -17    -29    +24     -3   
  Updated base image   │  python:3.12-slim                 │    0C     0H     1M    20L          
                       │                                   │    -3    -21    -31    -97     -5   

What's next:
    View vulnerabilities → docker scout cves getwilds/umitools:1.1.6
    View base image update recommendations → docker scout recommendations getwilds/umitools:1.1.6
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/umitools:1.1.6 --org <organization>
```
</details>
