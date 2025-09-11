# Vulnerability Report for getwilds/gatk:4.3.0.0

Report generated on 2025-09-10 17:03:23 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 61 |
| 🟡 Medium | 1131 |
| 🟢 Low | 57 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/gatk:4.3.0.0  │   16C    61H   1131M    57L   
    digest             │  72b9b124d12f                   │                               
  Base image           │  ubuntu:24.04                   │    0C     0H     5M     5L    
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     4M     5L    
                       │                                 │                  -1           
  Updated base image   │  ubuntu:25.04                   │    0C     0H     5M     4L    
                       │                                 │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/gatk:4.3.0.0
    View base image update recommendations → docker scout recommendations getwilds/gatk:4.3.0.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gatk:4.3.0.0 --org <organization>
```
</details>
