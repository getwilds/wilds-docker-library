# Vulnerability Report for getwilds/ena-tools:latest

Report generated on 2026-03-27 21:15:44 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 6 |
| 🟠 High | 43 |
| 🟡 Medium | 58 |
| 🟢 Low | 22 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `eclipse-temurin:21-jre-jammy`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 6 |
| 🟢 Low | 11 |

## 🔄 Recommendations

**Updated base image:** `eclipse-temurin:25-jre-jammy`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/ena-tools:latest-amd64  │    6C    43H    58M    22L     2?  
   digest           │  9a3c564a4921                             │                                    
 Base image         │  eclipse-temurin:21-jre-jammy             │    0C     0H     6M    11L         
 Updated base image │  eclipse-temurin:25-jre-jammy             │    0C     0H     5M    11L         
                    │                                           │                  -1                

What's next:
    View vulnerabilities → docker scout cves getwilds/ena-tools:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/ena-tools:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/ena-tools:latest-amd64 --org <organization>
```
</details>
