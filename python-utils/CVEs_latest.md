# Vulnerability Report for getwilds/python-utils:latest

Report generated on 2026-05-08 23:18:00 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 7 |
| 🟢 Low | 40 |
| ⚪ Unknown | 7 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 23 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/python-utils:latest-amd64  │    0C     5H     7M    40L     7?  
   digest           │  1e2f0291d76c                                │                                    
 Base image         │  python:3.12-slim                            │    0C     0H     4M    23L         
 Updated base image │  python:3.13-slim                            │    0C     0H     3M    22L         
                    │                                              │                  -1     -1         

What's next:
    View vulnerabilities → docker scout cves getwilds/python-utils:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/python-utils:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/python-utils:latest-amd64 --org <organization>
```
</details>
