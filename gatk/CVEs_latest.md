# Vulnerability Report for getwilds/gatk:latest

Report generated on 2025-09-10 17:04:40 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 16 |
| 🟡 Medium | 1108 |
| 🟢 Low | 53 |
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
Target               │  getwilds/gatk:latest  │    1C    16H   1108M    53L   
    digest             │  074caf850874                  │                               
  Base image           │  ubuntu:24.04                  │    0C     0H     5M     5L    
  Refreshed base image │  ubuntu:24.04                  │    0C     0H     4M     5L    
                       │                                │                  -1           
  Updated base image   │  ubuntu:25.04                  │    0C     0H     5M     4L    
                       │                                │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/gatk:latest
    View base image update recommendations → docker scout recommendations getwilds/gatk:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gatk:latest --org <organization>
```
</details>
