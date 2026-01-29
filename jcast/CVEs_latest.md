# Vulnerability Report for getwilds/jcast:latest

Report generated on 2026-01-29 08:14:02 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 4 |
| 🟢 Low | 25 |
| ⚪ Unknown | 5 |

## 🐳 Base Image

**Image:** `python:3.11-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 3 |
| 🟢 Low | 25 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/jcast:latest-amd64  │    0C     2H     4M    25L     5?  
   digest           │  bbec2ace8e08                         │                                    
 Base image         │  python:3.11-slim                     │    0C     2H     3M    25L     5?  
 Updated base image │  python:3.13-slim                     │    0C     1H     2M    25L     5?  
                    │                                       │           -1     -1                

What's next:
    View vulnerabilities → docker scout cves getwilds/jcast:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/jcast:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/jcast:latest-amd64 --org <organization>
```
</details>
