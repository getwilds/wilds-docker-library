# Vulnerability Report for getwilds/ollama:0.5.4

Report generated on 2026-04-20 18:26:18 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 21 |
| 🟡 Medium | 1657 |
| 🟢 Low | 84 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 28 |
| 🟢 Low | 29 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/ollama:0.5.4-amd64  │    3C    21H   1657M    84L  
   digest             │  f40b3cce4428                         │                              
 Base image           │  ubuntu:22.04                         │    0C     1H    28M    29L   
 Refreshed base image │  ubuntu:22.04                         │    0C     0H     1M     9L   
                      │                                       │           -1    -27    -20   
 Updated base image   │  ubuntu:24.04                         │    0C     0H     1M     2L   
                      │                                       │           -1    -27    -27   

What's next:
    View vulnerabilities → docker scout cves getwilds/ollama:0.5.4-amd64
    View base image update recommendations → docker scout recommendations getwilds/ollama:0.5.4-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/ollama:0.5.4-amd64 --org <organization>
```
</details>
