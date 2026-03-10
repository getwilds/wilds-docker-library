# Vulnerability Report for getwilds/bowtie2:2.5.4

Report generated on 2026-03-10 06:41:26 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 552 |
| 🟢 Low | 33 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bowtie2:2.5.4-amd64  │    0C     0H   552M    33L  
   digest           │  49e22a70699a                          │                             
 Base image         │  ubuntu:24.04                          │    0C     0H     4M     5L  
 Updated base image │  ubuntu:26.04                          │    0C     0H     0M     0L  
                    │                                        │                  -4     -5  

What's next:
    View vulnerabilities → docker scout cves getwilds/bowtie2:2.5.4-amd64
    View base image update recommendations → docker scout recommendations getwilds/bowtie2:2.5.4-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bowtie2:2.5.4-amd64 --org <organization>
```
</details>
