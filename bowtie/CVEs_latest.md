# Vulnerability Report for getwilds/bowtie:latest

Report generated on 2026-03-27 05:39:16 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 670 |
| 🟢 Low | 32 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 4 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bowtie:latest-amd64  │    1C     2H   670M    32L  
   digest           │  8099168ba6d5                          │                             
 Base image         │  ubuntu:24.04                          │    0C     0H     4M     4L  
 Updated base image │  ubuntu:25.10                          │    0C     0H     0M     0L  
                    │                                        │                  -4     -4  

What's next:
    View vulnerabilities → docker scout cves getwilds/bowtie:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/bowtie:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bowtie:latest-amd64 --org <organization>
```
</details>
