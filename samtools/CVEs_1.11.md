# Vulnerability Report for getwilds/samtools:1.11

Report generated on 2026-10-20 04:06:17 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 22 |
| 🟢 Low | 11 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 20 |
| 🟢 Low | 2 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/samtools:1.11-amd64  │    0C     0H    22M    11L  
   digest   │  fbe885ee80ab                          │                             
 Base image │  ubuntu:24.04                          │    0C     0H    20M     2L  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    415 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/samtools:1.11-amd64
    View vulnerabilities → docker scout cves getwilds/samtools:1.11-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/samtools:1.11-amd64
```
</details>
