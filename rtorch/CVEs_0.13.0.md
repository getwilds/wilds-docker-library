# Vulnerability Report for getwilds/rtorch:0.13.0

Report generated on 2025-11-01 09:18:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 90 |
| 🟡 Medium | 3569 |
| 🟢 Low | 177 |
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
Target               │  getwilds/rtorch:0.13.0  │    0C    90H   3569M   177L   
    digest             │  ced4966e6273                    │                               
  Base image           │  ubuntu:22.04                    │    0C     0H    43M    34L    
  Refreshed base image │  ubuntu:22.04                    │    0C     0H     2M    12L    
                       │                                  │                 -41    -22    
  Updated base image   │  ubuntu:24.04                    │    0C     0H     2M     5L    
                       │                                  │                 -41    -29    

What's next:
    View vulnerabilities → docker scout cves getwilds/rtorch:0.13.0
    View base image update recommendations → docker scout recommendations getwilds/rtorch:0.13.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rtorch:0.13.0 --org <organization>
```
</details>
