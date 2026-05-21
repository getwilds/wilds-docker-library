# Vulnerability Report for getwilds/mosdepth:latest

Report generated on 2026-05-21 22:59:49 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 23 |
| 🟢 Low | 2 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 22 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/mosdepth:latest  │    0C     0H    23M     2L  
   digest           │  cdc5331c5d96                      │                             
 Base image         │  ubuntu:24.04                      │    0C     0H    22M     2L  
 Updated base image │  ubuntu:25.10                      │    0C     0H     0M     0L  
                    │                                    │                 -22     -2  

What's next:
    View vulnerabilities → docker scout cves getwilds/mosdepth:latest
    View base image update recommendations → docker scout recommendations getwilds/mosdepth:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/mosdepth:latest --org <organization>
```
</details>
