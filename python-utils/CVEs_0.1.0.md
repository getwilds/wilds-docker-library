# Vulnerability Report for getwilds/python-utils:0.1.0

Report generated on 2026-04-24 20:55:11 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 3 |
| 🟢 Low | 39 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 23 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/python-utils:0.1.0-amd64  │    0C     1H     3M    39L  
   digest           │  670dfd1cd24b                               │                             
 Base image         │  python:3.12-slim                           │    0C     0H     3M    23L  
 Updated base image │  python:3.13-slim                           │    0C     0H     2M    22L  
                    │                                             │                  -1     -1  

What's next:
    View vulnerabilities → docker scout cves getwilds/python-utils:0.1.0-amd64
    View base image update recommendations → docker scout recommendations getwilds/python-utils:0.1.0-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/python-utils:0.1.0-amd64 --org <organization>
```
</details>
