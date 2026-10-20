# Vulnerability Report for getwilds/gatk:4.3.0.0

Report generated on 2026-10-20 16:35:11 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 70 |
| 🟡 Medium | 94 |
| 🟢 Low | 30 |
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
Target     │  getwilds/gatk:4.3.0.0  │   16C    70H    94M    30L  
   digest   │  765ec7167335                   │                             
 Base image │  ubuntu:24.04                   │    0C     0H    20M     2L  

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    688 packages             
 !      │ Fixable critical or high vulnerabilities found │   11C    64H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/gatk:4.3.0.0
    View vulnerabilities → docker scout cves getwilds/gatk:4.3.0.0
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/gatk:4.3.0.0
```
</details>
