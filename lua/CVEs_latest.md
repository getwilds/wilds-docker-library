# Vulnerability Report for getwilds/lua:latest

Report generated on 2026-05-05 17:21:00 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 748 |
| 🟢 Low | 26 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 9 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/lua:latest-amd64  │    0C     1H   748M    26L  
   digest           │  5fecc344beb4                       │                             
 Base image         │  ubuntu:24.04                       │    0C     0H     9M     2L  
 Updated base image │  ubuntu:25.10                       │    0C     0H     0M     0L  
                    │                                     │                  -9     -2  

What's next:
    View vulnerabilities → docker scout cves getwilds/lua:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/lua:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/lua:latest-amd64 --org <organization>
```
</details>
