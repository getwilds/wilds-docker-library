# Vulnerability Report for getwilds/bedtools:latest

Report generated on 2025-09-10 17:41:21 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1242 |
| 🟢 Low | 37 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 12 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/bedtools:latest  │    0C     3H   1242M    37L   
    digest             │  24516c43b5f8                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H    12M     5L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     4M     5L    
                       │                                    │                  -8           
  Updated base image   │  ubuntu:25.04                      │    0C     0H     5M     4L    
                       │                                    │                  -7     -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/bedtools:latest
    View base image update recommendations → docker scout recommendations getwilds/bedtools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedtools:latest --org <organization>
```
</details>
