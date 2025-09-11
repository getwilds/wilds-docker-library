# Vulnerability Report for getwilds/picard:latest

Report generated on 2025-09-10 17:09:44 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 49 |
| 🟢 Low | 20 |
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
Target               │  getwilds/picard:latest  │    0C     2H    49M    20L   
    digest             │  65839270a2e5                    │                              
  Base image           │  ubuntu:24.04                    │    0C     0H    13M     5L   
  Refreshed base image │  ubuntu:24.04                    │    0C     0H     4M     5L   
                       │                                  │                  -9          
  Updated base image   │  ubuntu:25.04                    │    0C     0H     5M     4L   
                       │                                  │                  -8     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/picard:latest
    View base image update recommendations → docker scout recommendations getwilds/picard:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/picard:latest --org <organization>
```
</details>
