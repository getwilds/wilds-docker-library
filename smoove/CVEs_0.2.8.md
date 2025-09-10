# Vulnerability Report for getwilds/smoove:0.2.8

Report generated on 2025-09-10 17:14:51 PST

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 52 |
| 🟡 Medium | 1420 |
| 🟢 Low | 67 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 10 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/smoove:0.2.8  │    5C    52H   1420M    67L   
    digest             │  9fa669bb0fdf                   │                               
  Base image           │  ubuntu:22.04                   │    0C     0H    10M    13L    
  Refreshed base image │  ubuntu:22.04                   │    0C     0H     3M    12L    
                       │                                 │                  -7     -1    
  Updated base image   │  ubuntu:24.04                   │    0C     0H     4M     5L    
                       │                                 │                  -6     -8    

What's next:
    View vulnerabilities → docker scout cves getwilds/smoove:0.2.8
    View base image update recommendations → docker scout recommendations getwilds/smoove:0.2.8
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/smoove:0.2.8 --org <organization>
```
</details>
