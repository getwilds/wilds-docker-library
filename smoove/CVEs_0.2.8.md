# Vulnerability Report for getwilds/smoove:0.2.8

Report generated on 2025-10-15 16:21:02 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 52 |
| 🟡 Medium | 1236 |
| 🟢 Low | 62 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/smoove:0.2.8  │    5C    52H   1236M    62L   
    digest           │  88765edee54d                   │                               
  Base image         │  ubuntu:22.04                   │    0C     0H     2M    12L    
  Updated base image │  ubuntu:24.04                   │    0C     0H     2M     5L    
                     │                                 │                         -7    

What's next:
    View vulnerabilities → docker scout cves getwilds/smoove:0.2.8
    View base image update recommendations → docker scout recommendations getwilds/smoove:0.2.8
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/smoove:0.2.8 --org <organization>
```
</details>
