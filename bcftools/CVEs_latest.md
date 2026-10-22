# Vulnerability Report for getwilds/bcftools:latest

Report generated on 2026-10-22 16:24:59 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 22 |
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

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/bcftools:latest-amd64  │    0C     0H    22M     2L  
   digest   │  7e9b3c48373a                            │                             
 Base image │  ubuntu:24.04                            │    0C     0H    20M     2L  

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
    View policy violations → docker scout policy getwilds/bcftools:latest-amd64
    View vulnerabilities → docker scout cves getwilds/bcftools:latest-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/bcftools:latest-amd64
```
</details>
