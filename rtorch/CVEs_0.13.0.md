# Vulnerability Report for getwilds/rtorch:0.13.0

Report generated on 2025-09-10 17:27:50 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 72 |
| 🟡 Medium | 3189 |
| 🟢 Low | 164 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 42 |
| 🟢 Low | 33 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/rtorch:0.13.0  │    0C    72H   3189M   164L   
    digest             │  f8084300c74e                    │                               
  Base image           │  ubuntu:22.04                    │    0C     0H    42M    33L    
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     3M    12L    
                       │                                  │                 -39    -21    
  Updated base image   │  ubuntu:24.04                    │    0C     0H     4M     5L    
                       │                                  │                 -38    -28    

What's next:
    View vulnerabilities → docker scout cves getwilds/rtorch:0.13.0
    View base image update recommendations → docker scout recommendations getwilds/rtorch:0.13.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rtorch:0.13.0 --org <organization>
```
</details>
