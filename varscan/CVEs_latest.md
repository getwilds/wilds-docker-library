# Vulnerability Report for getwilds/varscan:latest

Report generated on 2025-09-10 16:26:48 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1398 |
| 🟢 Low | 79 |
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
Target               │  getwilds/varscan:latest  │    0C     2H   1398M    79L   
    digest             │  d81e80829d15                     │                               
  Base image           │  ubuntu:22.04                     │    0C     0H    10M    13L    
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     3M    12L    
                       │                                   │                  -7     -1    
  Updated base image   │  ubuntu:24.04                     │    0C     0H     4M     5L    
                       │                                   │                  -6     -8    

What's next:
    View vulnerabilities → docker scout cves getwilds/varscan:latest
    View base image update recommendations → docker scout recommendations getwilds/varscan:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/varscan:latest --org <organization>
```
</details>
