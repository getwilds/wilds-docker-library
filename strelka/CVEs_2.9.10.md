# Vulnerability Report for getwilds/strelka:2.9.10

Report generated on 2025-09-10 16:13:55 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1142 |
| 🟢 Low | 65 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/strelka:2.9.10  │    0C     0H   1142M    65L   
    digest             │  0a8251054025                     │                               
  Base image           │  ubuntu:22.04                     │    0C     0H     3M    13L    
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     3M    12L    
                       │                                   │                         -1    
  Updated base image   │  ubuntu:25.10                     │    0C     0H     0M     0L    
                       │                                   │                  -3    -13    

What's next:
    View vulnerabilities → docker scout cves getwilds/strelka:2.9.10
    View base image update recommendations → docker scout recommendations getwilds/strelka:2.9.10
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/strelka:2.9.10 --org <organization>
```
</details>
