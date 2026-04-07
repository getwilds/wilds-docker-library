# Vulnerability Report for getwilds/viennarna:latest

Report generated on 2026-04-07 17:22:17 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 7 |
| 🟡 Medium | 19 |
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
Target             │  getwilds/viennarna:latest-amd64  │    0C     7H    19M     6L  
   digest           │  dd96cfa771f3                             │                             
 Base image         │  ubuntu:20.04                             │    0C     0H     5M     0L  
 Updated base image │  ubuntu:25.10                             │    0C     0H     0M     0L  
                    │                                           │                  -5         

What's next:
    View vulnerabilities → docker scout cves getwilds/viennarna:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/viennarna:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/viennarna:latest-amd64 --org <organization>
```
</details>
