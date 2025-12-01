# Vulnerability Report for getwilds/deseq2:latest

Report generated on 2025-12-01 09:38:33 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 142 |
| 🟡 Medium | 4119 |
| 🟢 Low | 279 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.17`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 136 |
| 🟡 Medium | 4090 |
| 🟢 Low | 242 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/deseq2:latest         │    4C   142H   4119M   279L   
    digest   │  9dd763af740c                           │                               
  Base image │  bioconductor/bioconductor_docker:3.17  │    4C   136H   4090M   242L   

What's next:
    View vulnerabilities → docker scout cves getwilds/deseq2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deseq2:latest --org <organization>
```
</details>
