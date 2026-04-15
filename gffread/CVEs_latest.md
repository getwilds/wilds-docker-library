# Vulnerability Report for getwilds/gffread:latest

Report generated on 2026-04-14 18:42:58 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 7 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 7 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/gffread:latest-amd64  │    0C     0H     2M     7L  
   digest           │  52adf6046d81                           │                             
 Base image         │  ubuntu:24.04                           │    0C     0H     2M     7L  
 Updated base image │  ubuntu:25.10                           │    0C     0H     0M     0L  
                    │                                         │                  -2     -7  

What's next:
    View vulnerabilities → docker scout cves getwilds/gffread:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/gffread:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gffread:latest-amd64 --org <organization>
```
</details>
