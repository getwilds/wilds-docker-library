# Vulnerability Report for getwilds/varscan:2.4.6

Report generated on 2026-10-23 16:09:01 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 24 |
| 🟢 Low | 10 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 19 |
| 🟢 Low | 7 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/varscan:2.4.6-amd64  │    0C     0H    24M    10L  
   digest           │  e1c20dedf9cc                          │                             
 Base image         │  ubuntu:22.04                          │    0C     0H    19M     7L  
 Updated base image │  ubuntu:24.04                          │    0C     0H    21M     2L  
                    │                                        │                  +2     -5  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    315 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/varscan:2.4.6-amd64
    View vulnerabilities → docker scout cves getwilds/varscan:2.4.6-amd64
    View base image update recommendations → docker scout recommendations getwilds/varscan:2.4.6-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/varscan:2.4.6-amd64
```
</details>
