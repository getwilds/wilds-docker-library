# Vulnerability Report for getwilds/delly:1.2.9

Report generated on 2025-09-10 17:01:56 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 15 |
| 🟢 Low | 16 |
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
Target               │  getwilds/delly:1.2.9  │    0C     0H    15M    16L   
    digest             │  818d5ade2efd                  │                              
  Base image           │  ubuntu:22.04                  │    0C     0H    10M    13L   
  Refreshed base image │  ubuntu:22.04                  │    0C     0H     3M    12L   
                       │                                │                  -7     -1   
  Updated base image   │  ubuntu:24.04                  │    0C     0H     4M     5L   
                       │                                │                  -6     -8   

What's next:
    View vulnerabilities → docker scout cves getwilds/delly:1.2.9
    View base image update recommendations → docker scout recommendations getwilds/delly:1.2.9
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/delly:1.2.9 --org <organization>
```
</details>
