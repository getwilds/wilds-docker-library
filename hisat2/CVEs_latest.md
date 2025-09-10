# Vulnerability Report for getwilds/hisat2:latest

Report generated on 2025-09-10 16:30:27 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1390 |
| 🟢 Low | 39 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/hisat2:latest  │    0C     5H   1390M    39L   
    digest             │  65b2320dbd31                    │                               
  Base image           │  ubuntu:24.04                    │    0C     0H    13M     5L    
  Refreshed base image │  ubuntu:24.04                    │    0C     0H     4M     5L    
                       │                                  │                  -9           
  Updated base image   │  ubuntu:25.04                    │    0C     0H     5M     4L    
                       │                                  │                  -8     -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/hisat2:latest
    View base image update recommendations → docker scout recommendations getwilds/hisat2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/hisat2:latest --org <organization>
```
</details>
