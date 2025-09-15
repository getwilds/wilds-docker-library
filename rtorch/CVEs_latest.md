# Vulnerability Report for getwilds/rtorch:latest

Report generated on 2025-09-15 18:11:45 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 74 |
| 🟡 Medium | 3177 |
| 🟢 Low | 160 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 43 |
| 🟢 Low | 33 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/rtorch:latest  │    0C    74H   3177M   160L   
    digest             │  757f5fe60194                    │                               
  Base image           │  ubuntu:22.04                    │    0C     0H    43M    33L    
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     4M    12L    
                       │                                  │                 -39    -21    
  Updated base image   │  ubuntu:24.04                    │    0C     0H     5M     5L    
                       │                                  │                 -38    -28    

What's next:
    View vulnerabilities → docker scout cves getwilds/rtorch:latest
    View base image update recommendations → docker scout recommendations getwilds/rtorch:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rtorch:latest --org <organization>
```
</details>
