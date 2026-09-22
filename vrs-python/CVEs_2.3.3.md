# Vulnerability Report for getwilds/vrs-python:2.3.3

Report generated on 2026-09-17 05:00:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 30 |
| 🟡 Medium | 26 |
| 🟢 Low | 118 |
| ⚪ Unknown | 30 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 10 |
| 🟡 Medium | 11 |
| 🟢 Low | 29 |

## 🔄 Recommendations

**Updated base image:** `python:alpine`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/vrs-python:2.3.3  │   10C    30H    26M   118L    30?  
   digest           │  092c8c358551                       │                                    
 Base image         │  python:3.12-slim                   │    5C    10H    11M    29L     3?  
 Updated base image │  python:alpine                      │    0C     7H     1M     0L         
                    │                                     │    -5     -3    -10    -29     -3  

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    601 packages             
 !      │ Fixable critical or high vulnerabilities found │    4C     8H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/vrs-python:2.3.3
    View vulnerabilities → docker scout cves getwilds/vrs-python:2.3.3
    View base image update recommendations → docker scout recommendations getwilds/vrs-python:2.3.3
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/vrs-python:2.3.3
```
</details>
