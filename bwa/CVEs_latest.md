# Vulnerability Report for getwilds/bwa:latest

Report generated on 2025-09-10 17:10:43 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1374 |
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
Target               │  getwilds/bwa:latest  │    0C     3H   1374M    39L   
    digest             │  c0e6812079e0                 │                               
  Base image           │  ubuntu:24.04                 │    0C     0H    13M     5L    
  Refreshed base image │  ubuntu:24.04                 │    0C     0H     4M     5L    
                       │                               │                  -9           
  Updated base image   │  ubuntu:25.04                 │    0C     0H     5M     4L    
                       │                               │                  -8     -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/bwa:latest
    View base image update recommendations → docker scout recommendations getwilds/bwa:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bwa:latest --org <organization>
```
</details>
