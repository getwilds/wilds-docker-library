# Vulnerability Report for getwilds/annovar:hg19

Report generated on 2025-09-10 16:41:44 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 22 |
| 🟡 Medium | 1924 |
| 🟢 Low | 51 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 19 |
| 🟢 Low | 7 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/annovar:hg19  │    0C    22H   1924M    51L   
    digest             │  3e7d6cdb81e6                   │                               
  Base image           │  ubuntu:24.04                   │    0C     0H    19M     7L    
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     4M     5L    
                       │                                 │                 -15     -2    
  Updated base image   │  ubuntu:25.04                   │    0C     0H     5M     4L    
                       │                                 │                 -14     -3    

What's next:
    View vulnerabilities → docker scout cves getwilds/annovar:hg19
    View base image update recommendations → docker scout recommendations getwilds/annovar:hg19
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/annovar:hg19 --org <organization>
```
</details>
