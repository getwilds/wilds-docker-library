# Vulnerability Report for getwilds/annotsv:3.4.4

Report generated on 2025-09-10 16:38:07 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 22 |
| 🟠 High | 102 |
| 🟡 Medium | 76 |
| 🟢 Low | 30 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 10 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/annotsv:3.4.4  │   22C   102H    76M    30L   
    digest             │  4e0e8b17d00b                    │                              
  Base image           │  ubuntu:22.04                    │    0C     0H    10M    13L   
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     3M    12L   
                       │                                  │                  -7     -1   
  Updated base image   │  ubuntu:24.04                    │    0C     0H     4M     5L   
                       │                                  │                  -6     -8   

What's next:
    View vulnerabilities → docker scout cves getwilds/annotsv:3.4.4
    View base image update recommendations → docker scout recommendations getwilds/annotsv:3.4.4
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/annotsv:3.4.4 --org <organization>
```
</details>
