# Vulnerability Report for getwilds/multiqc:latest

Report generated on 2026-03-27 23:15:20 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 24 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.13-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 23 |

## 🔄 Recommendations

**Updated base image:** `python:3.14-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/multiqc:latest-amd64  │    0C     0H     2M    24L  
   digest           │  ea91772e0c77                           │                             
 Base image         │  python:3.13-slim                       │    0C     0H     2M    23L  
 Updated base image │  python:3.14-slim                       │    0C     0H     2M    23L  
                    │                                         │                             

What's next:
    View vulnerabilities → docker scout cves getwilds/multiqc:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/multiqc:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/multiqc:latest-amd64 --org <organization>
```
</details>
