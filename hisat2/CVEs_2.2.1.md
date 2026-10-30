# Vulnerability Report for getwilds/hisat2:2.2.1

Report generated on 2026-10-29 16:51:18 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 21 |
| 🟢 Low | 2 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 20 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/hisat2:2.2.1  │    0C     0H    21M     2L  
   digest           │  d51d00e9f3c0                   │                             
 Base image         │  ubuntu:24.04                   │    0C     0H    20M     2L  
 Updated base image │  ubuntu:26.10                   │    0C     0H     0M     0L  
                    │                                 │                 -20     -2  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    399 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/hisat2:2.2.1
    View vulnerabilities → docker scout cves getwilds/hisat2:2.2.1
    View base image update recommendations → docker scout recommendations getwilds/hisat2:2.2.1
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/hisat2:2.2.1
```
</details>
