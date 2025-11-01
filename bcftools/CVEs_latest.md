# Vulnerability Report for getwilds/bcftools:latest

Report generated on 2025-11-01 08:14:07 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1105 |
| 🟢 Low | 36 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bcftools:latest  │    0C     3H   1105M    36L   
    digest           │  07ff1327a25b                      │                               
  Base image         │  ubuntu:24.04                      │    0C     0H     2M     5L    
  Updated base image │  ubuntu:25.04                      │    0C     0H     2M     4L    
                     │                                    │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/bcftools:latest
    View base image update recommendations → docker scout recommendations getwilds/bcftools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bcftools:latest --org <organization>
```
</details>
