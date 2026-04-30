# Vulnerability Report for getwilds/umitools:1.1.6

Report generated on 2026-04-30 00:47:53 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 15 |
| 🟡 Medium | 21 |
| 🟢 Low | 205 |
| ⚪ Unknown | 4 |

## 🐳 Base Image

**Image:** `python:3.11-bookworm`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 15 |
| 🟡 Medium | 21 |
| 🟢 Low | 205 |

## 🔄 Recommendations

**Updated base image:** `python:3.14-bookworm`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/umitools:1.1.6-amd64  │    0C    15H    21M   205L     4?  
   digest           │  7afb15261238                           │                                    
 Base image         │  python:3.11-bookworm                   │    0C    15H    21M   205L     4?  
 Updated base image │  python:3.14-bookworm                   │    0C    14H    20M   204L     4?  
                    │                                         │           -1     -1     -1         

What's next:
    View vulnerabilities → docker scout cves getwilds/umitools:1.1.6-amd64
    View base image update recommendations → docker scout recommendations getwilds/umitools:1.1.6-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/umitools:1.1.6-amd64 --org <organization>
```
</details>
