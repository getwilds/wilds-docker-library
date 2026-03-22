# Vulnerability Report for getwilds/ena-tools:2.1.1

Report generated on 2026-03-22 05:09:55 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 7 |
| 🟠 High | 45 |
| 🟡 Medium | 58 |
| 🟢 Low | 14 |
| ⚪ Unknown | 3 |

## 🐳 Base Image

**Image:** `oisupport/staging-amd64:21-jre-alpine`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 1 |
| 🟡 Medium | 7 |
| 🟢 Low | 3 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/ena-tools:2.1.1-amd64  │    7C    45H    58M    14L     3?  
   digest   │  da310235869c                            │                                    
 Base image │  oisupport/staging-amd64:21-jre-alpine   │    1C     1H     7M     3L     1?  

What's next:
    View vulnerabilities → docker scout cves getwilds/ena-tools:2.1.1-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/ena-tools:2.1.1-amd64 --org <organization>
```
</details>
