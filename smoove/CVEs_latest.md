# Vulnerability Report for getwilds/smoove:latest

Report generated on 2025-10-01 09:51:03 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 54 |
| 🟡 Medium | 1736 |
| 🟢 Low | 69 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/smoove:latest  │    5C    54H   1736M    69L   
    digest             │  0e11696c630c                    │                               
  Base image           │  ubuntu:22.04                    │    0C     0H    11M    14L    
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     4M    13L    
                       │                                  │                  -7     -1    
  Updated base image   │  ubuntu:24.04                    │    0C     0H     5M     6L    
                       │                                  │                  -6     -8    

What's next:
    View vulnerabilities → docker scout cves getwilds/smoove:latest
    View base image update recommendations → docker scout recommendations getwilds/smoove:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/smoove:latest --org <organization>
```
</details>
