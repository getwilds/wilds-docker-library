# Vulnerability Report for getwilds/bcftools:latest

Report generated on 2025-09-10 17:36:29 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1074 |
| 🟢 Low | 36 |
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
Target               │  getwilds/bcftools:latest  │    0C     2H   1074M    36L   
    digest             │  ec8b131c6873                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H     5M     5L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     4M     5L    
                       │                                    │                  -1           
  Updated base image   │  ubuntu:25.04                      │    0C     0H     5M     4L    
                       │                                    │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/bcftools:latest
    View base image update recommendations → docker scout recommendations getwilds/bcftools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bcftools:latest --org <organization>
```
</details>
