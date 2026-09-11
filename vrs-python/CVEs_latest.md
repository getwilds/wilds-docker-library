# Vulnerability Report for getwilds/vrs-python:latest

Report generated on 2026-09-11 18:58:10 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 20 |
| 🟡 Medium | 17 |
| 🟢 Low | 101 |
| ⚪ Unknown | 27 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 7 |
| 🟢 Low | 25 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/vrs-python:latest-amd64  │    5C    20H    17M   101L    27?  
   digest   │  fb5e90fbf4f3                              │                                    
 Base image │  python:3.12-slim                          │    0C     1H     7M    25L         

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    601 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/vrs-python:latest-amd64
    View vulnerabilities → docker scout cves getwilds/vrs-python:latest-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/vrs-python:latest-amd64
```
</details>
