# Vulnerability Report for getwilds/mosdepth:0.3.14

Report generated on 2026-06-10 17:32:07 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 25 |
| 🟢 Low | 3 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 26 |
| 🟢 Low | 11 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/mosdepth:0.3.14  │    0C     0H    25M     3L  
   digest           │  0d7cc84b71cd                      │                             
 Base image         │  ubuntu:24.04                      │    0C     1H    26M    11L  
 Updated base image │  ubuntu:25.10                      │    0C     0H     0M     0L  
                    │                                    │           -1    -26    -11  

What's next:
    View vulnerabilities → docker scout cves getwilds/mosdepth:0.3.14
    View base image update recommendations → docker scout recommendations getwilds/mosdepth:0.3.14
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/mosdepth:0.3.14 --org <organization>
```
</details>
