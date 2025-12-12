# Vulnerability Report for getwilds/ena-tools:2.1.1

Report generated on 2025-12-12 18:37:44 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 6 |
| 🟠 High | 40 |
| 🟡 Medium | 53 |
| 🟢 Low | 11 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `eclipse-temurin:21-jre-alpine`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 4 |
| 🟢 Low | 3 |

## 🔄 Recommendations

**Updated base image:** `eclipse-temurin:25-jre-alpine`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/ena-tools:2.1.1-amd64  │    6C    40H    53M    11L   
    digest           │  eb58f4318db6                            │                              
  Base image         │  eclipse-temurin:21-jre-alpine           │    0C     3H     4M     3L   
  Updated base image │  eclipse-temurin:25-jre-alpine           │    0C     3H     3M     2L   
                     │                                          │                  -1     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/ena-tools:2.1.1-amd64
    View base image update recommendations → docker scout recommendations getwilds/ena-tools:2.1.1-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/ena-tools:2.1.1-amd64 --org <organization>
```
</details>
