# Vulnerability Report for getwilds/scran:1.40.0

Report generated on 2026-08-06 22:27:59 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 214 |
| 🟡 Medium | 2160 |
| 🟢 Low | 310 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor:3.23`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 214 |
| 🟡 Medium | 2160 |
| 🟢 Low | 308 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/scran:1.40.0   │   16C   214H   2160M   310L     2?  
   digest   │  1eae6236dc56                    │                                     
 Base image │  bioconductor/bioconductor:3.23  │   16C   214H   2160M   308L     2?  

Policy status  FAILED  (2/7 policies met, 3 missing data)
Health score  E  (28%)

 Status │                   Policy                   │     Results     
────────┼────────────────────────────────────────────┼─────────────────
 !      │ Image runs as the root user                │                 
 ?      │ No data                                    │    No data      
 ?      │ No data                                    │    No data      
 ?      │ No data                                    │    No data      
 ✓      │ No outdated base images                    │                 
 ✓      │ No unapproved base images                  │    0 deviations 
 !      │ Required supply chain attestations missing │    2 deviations 

What's next:
    View policy violations → docker scout policy getwilds/scran:1.40.0
    View vulnerabilities → docker scout cves getwilds/scran:1.40.0
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/scran:1.40.0
```
</details>
