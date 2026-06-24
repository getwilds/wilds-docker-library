# Vulnerability Report for getwilds/cellbender:latest

Report generated on 2026-06-24 22:16:13 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 15 |
| 🟡 Medium | 23 |
| 🟢 Low | 147 |
| ⚪ Unknown | 12 |

## 🐳 Base Image

**Image:** `python:3.11-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 7 |
| 🟢 Low | 26 |

## 🔄 Recommendations

**Updated base image:** `python:3.14-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/cellbender:latest-amd64  │    3C    15H    23M   147L    12?  
   digest           │  7affced19e2e                              │                                    
 Base image         │  python:3.11-slim                          │    1C     3H     7M    26L     2?  
 Updated base image │  python:3.14-slim                          │    1C     2H     3M    25L     2?  
                    │                                            │           -1     -4     -1         

What's next:
    View vulnerabilities → docker scout cves getwilds/cellbender:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/cellbender:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cellbender:latest-amd64 --org <organization>
```
</details>
