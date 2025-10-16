# Vulnerability Report for getwilds/cellranger:latest

Report generated on 2025-09-10 17:20:37 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 8 |
| 🟠 High | 71 |
| 🟡 Medium | 3382 |
| 🟢 Low | 80 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 33 |
| 🟢 Low | 16 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/cellranger:latest  │    8C    71H   3382M    80L     2?   
    digest             │  886b9b9a85f0                        │                                      
  Base image           │  ubuntu:24.04                        │    0C     0H    33M    16L           
  Refreshed base image │  ubuntu:24.04                        │    0C     0H     4M     5L           
                       │                                      │                 -29    -11           
  Updated base image   │  ubuntu:25.10                        │    0C     0H     0M     0L           
                       │                                      │                 -33    -16           

What's next:
    View vulnerabilities → docker scout cves getwilds/cellranger:latest
    View base image update recommendations → docker scout recommendations getwilds/cellranger:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cellranger:latest --org <organization>
```
</details>
