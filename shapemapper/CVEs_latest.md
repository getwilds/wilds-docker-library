# Vulnerability Report for getwilds/shapemapper:latest

Report generated on 2025-09-10 17:14:00 PST

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
Target               │  getwilds/shapemapper:latest  │    1C    17H    46M    20L     2?   
    digest             │  f0c93f75561d                         │                                     
  Base image           │  ubuntu:22.04                         │    0C     0H    20M    17L          
  Refreshed base image │  ubuntu:22.04                         │    0C     0H     3M    12L          
                       │                                       │                 -17     -5          
  Updated base image   │  ubuntu:24.04                         │    0C     0H     4M     5L          
                       │                                       │                 -16    -12          

What's next:
    View vulnerabilities → docker scout cves getwilds/shapemapper:latest
    View base image update recommendations → docker scout recommendations getwilds/shapemapper:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/shapemapper:latest --org <organization>
```
</details>
