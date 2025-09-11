# Vulnerability Report for getwilds/samtools:latest

Report generated on 2025-09-10 16:25:24 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1001 |
| 🟢 Low | 35 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/samtools:latest  │    0C     2H   1001M    35L   
    digest             │  24aedc580d6b                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H     4M     5L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     4M     5L    
                       │                                    │                               
  Updated base image   │  ubuntu:25.10                      │    0C     0H     0M     0L    
                       │                                    │                  -4     -5    

What's next:
    View vulnerabilities → docker scout cves getwilds/samtools:latest
    View base image update recommendations → docker scout recommendations getwilds/samtools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/samtools:latest --org <organization>
```
</details>
