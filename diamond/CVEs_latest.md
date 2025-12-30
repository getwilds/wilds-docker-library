# Vulnerability Report for getwilds/diamond:latest

Report generated on 2025-12-30 19:12:56 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 7 |
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

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/diamond:latest  │    0C     0H    13M     7L  
   digest           │  60f2ca44a32b                     │                             
 Base image         │  ubuntu:24.04                     │    0C     0H     2M     5L  
 Updated base image │  ubuntu:26.04                     │    0C     0H     0M     0L  
                    │                                   │                  -2     -5  

What's next:
    View vulnerabilities → docker scout cves getwilds/diamond:latest
    View base image update recommendations → docker scout recommendations getwilds/diamond:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/diamond:latest --org <organization>
```
</details>
