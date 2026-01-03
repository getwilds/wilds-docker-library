# Vulnerability Report for getwilds/megahit:latest

Report generated on 2026-01-03 00:00:43 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 12 |
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
Target             │  getwilds/megahit:latest  │    0C     0H     3M    12L  
   digest           │  9819eb33b14c                     │                             
 Base image         │  ubuntu:22.04                     │    0C     0H     2M    12L  
 Updated base image │  ubuntu:24.04                     │    0C     0H     2M     5L  
                    │                                   │                         -7  

What's next:
    View vulnerabilities → docker scout cves getwilds/megahit:latest
    View base image update recommendations → docker scout recommendations getwilds/megahit:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/megahit:latest --org <organization>
```
</details>
