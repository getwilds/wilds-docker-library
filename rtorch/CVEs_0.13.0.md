# Vulnerability Report for getwilds/rtorch:0.13.0

Report generated on 2025-10-01 09:15:09 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 77 |
| 🟡 Medium | 3581 |
| 🟢 Low | 171 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 43 |
| 🟢 Low | 34 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/rtorch:0.13.0  │    0C    77H   3581M   171L   
    digest             │  ced4966e6273                    │                               
  Base image           │  ubuntu:22.04                    │    0C     0H    43M    34L    
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     4M    13L    
                       │                                  │                 -39    -21    
  Updated base image   │  ubuntu:24.04                    │    0C     0H     5M     6L    
                       │                                  │                 -38    -28    

What's next:
    View vulnerabilities → docker scout cves getwilds/rtorch:0.13.0
    View base image update recommendations → docker scout recommendations getwilds/rtorch:0.13.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rtorch:0.13.0 --org <organization>
```
</details>
