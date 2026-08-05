# Vulnerability Report for getwilds/edger:latest

Report generated on 2026-08-05 05:06:35 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 214 |
| 🟡 Medium | 2140 |
| 🟢 Low | 310 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor:3.23`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 214 |
| 🟡 Medium | 2140 |
| 🟢 Low | 308 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/edger:latest   │   16C   214H   2140M   310L     2?  
   digest   │  c69c851f797c                    │                                     
 Base image │  bioconductor/bioconductor:3.23  │   16C   214H   2140M   308L     2?  

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    3075 packages            
 !      │ Fixable critical or high vulnerabilities found │   16C   174H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/edger:latest
    View vulnerabilities → docker scout cves getwilds/edger:latest
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/edger:latest
```
</details>
