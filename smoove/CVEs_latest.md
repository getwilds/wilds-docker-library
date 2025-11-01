# Vulnerability Report for getwilds/smoove:latest

Report generated on 2025-11-01 09:56:42 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 54 |
| 🟡 Medium | 1271 |
| 🟢 Low | 68 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/smoove:latest  │    5C    54H   1271M    68L   
    digest           │  484aa3af4be2                    │                               
  Base image         │  ubuntu:22.04                    │    0C     0H     2M    12L    
  Updated base image │  ubuntu:24.04                    │    0C     0H     2M     5L    
                     │                                  │                         -7    

What's next:
    View vulnerabilities → docker scout cves getwilds/smoove:latest
    View base image update recommendations → docker scout recommendations getwilds/smoove:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/smoove:latest --org <organization>
```
</details>
