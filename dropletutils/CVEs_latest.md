# Vulnerability Report for getwilds/dropletutils:latest

Report generated on 2026-08-19 19:18:25 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 201 |
| 🟡 Medium | 2821 |
| 🟢 Low | 263 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.23`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 201 |
| 🟡 Medium | 2821 |
| 🟢 Low | 261 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/dropletutils:latest   │   10C   201H   2821M   263L     2?  
   digest   │  a85be25e725a                           │                                     
 Base image │  bioconductor/bioconductor_docker:3.23  │   10C   201H   2821M   261L     2?  

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    3043 packages            
 !      │ Fixable critical or high vulnerabilities found │    7C   153H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/dropletutils:latest
    View vulnerabilities → docker scout cves getwilds/dropletutils:latest
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/dropletutils:latest
```
</details>
