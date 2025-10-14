# Vulnerability Report for getwilds/shapemapper:2.3

Report generated on 2025-09-10 17:12:22 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 17 |
| 🟡 Medium | 46 |
| 🟢 Low | 20 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 20 |
| 🟢 Low | 17 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/shapemapper:2.3  │    1C    17H    46M    20L     2?   
    digest             │  d79b96365a32                      │                                     
  Base image           │  ubuntu:22.04                      │    0C     0H    20M    17L          
  Refreshed base image │  ubuntu:22.04                      │    0C     0H     3M    12L          
                       │                                    │                 -17     -5          
  Updated base image   │  ubuntu:24.04                      │    0C     0H     4M     5L          
                       │                                    │                 -16    -12          

What's next:
    View vulnerabilities → docker scout cves getwilds/shapemapper:2.3
    View base image update recommendations → docker scout recommendations getwilds/shapemapper:2.3
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/shapemapper:2.3 --org <organization>
```
</details>
