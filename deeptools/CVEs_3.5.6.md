# Vulnerability Report for getwilds/deeptools:3.5.6

Report generated on 2026-03-20 16:34:48 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 8 |
| 🟡 Medium | 18 |
| 🟢 Low | 6 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:20.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/deeptools:3.5.6-amd64  │    0C     8H    18M     6L  
   digest           │  91d47f2ca15f                            │                             
 Base image         │  ubuntu:20.04                            │    0C     0H     5M     0L  
 Updated base image │  ubuntu:25.10                            │    0C     0H     0M     0L  
                    │                                          │                  -5         

What's next:
    View vulnerabilities → docker scout cves getwilds/deeptools:3.5.6-amd64
    View base image update recommendations → docker scout recommendations getwilds/deeptools:3.5.6-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deeptools:3.5.6-amd64 --org <organization>
```
</details>
