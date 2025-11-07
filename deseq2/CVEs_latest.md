# Vulnerability Report for getwilds/deseq2:latest

Report generated on 2025-11-07 23:48:19 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 139 |
| 🟡 Medium | 4056 |
| 🟢 Low | 276 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.17`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 133 |
| 🟡 Medium | 4027 |
| 🟢 Low | 239 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/deseq2:latest         │    4C   139H   4056M   276L   
    digest   │  17aaa6dcba33                           │                               
  Base image │  bioconductor/bioconductor_docker:3.17  │    4C   133H   4027M   239L   

What's next:
    View vulnerabilities → docker scout cves getwilds/deseq2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deseq2:latest --org <organization>
```
</details>
