# Vulnerability Report for getwilds/rmats-turbo:4.3.0

Report generated on 2026-01-29 08:18:55 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| 🟢 Low | 115 |
| ⚪ Unknown | 4 |

## 🐳 Base Image

**Image:** `debian:11`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| 🟢 Low | 15 |

## 🔄 Recommendations

**Updated base image:** `debian:stable-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/rmats-turbo:4.3.0  │    0C     2H     0M   115L     4?  
   digest           │  6780b86a569b                        │                                    
 Base image         │  debian:11                           │    0C     2H     0M    15L     1?  
 Updated base image │  debian:stable-slim                  │    0C     1H     2M    25L     5?  
                    │                                      │           -1     +2    +10     +4  

What's next:
    View vulnerabilities → docker scout cves getwilds/rmats-turbo:4.3.0
    View base image update recommendations → docker scout recommendations getwilds/rmats-turbo:4.3.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rmats-turbo:4.3.0 --org <organization>
```
</details>
