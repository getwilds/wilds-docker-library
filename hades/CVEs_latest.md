# Vulnerability Report for getwilds/hades:latest

Report generated on 2026-09-17 02:25:41 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 136 |
| 🟡 Medium | 2213 |
| 🟢 Low | 170 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/hades:latest  │    5C   136H   2213M   170L  
   digest             │  e687738a1ff3                   │                              
 Base image           │  ubuntu:24.04                   │    0C     0H    13M     2L   
 Refreshed base image │  ubuntu:24.04                   │    0C     0H     7M     2L   
                      │                                 │                  -6          
 Updated base image   │  ubuntu:26.04                   │    0C     0H     0M     0L   
                      │                                 │                 -13     -2   

Policy status  FAILED  (2/7 policies met)
Health score  E  (28%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    1091 packages            
 !      │ Fixable critical or high vulnerabilities found │    0C     9H     0M     0L  
 !      │ High-profile vulnerabilities found             │    0C     1H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/hades:latest
    View vulnerabilities → docker scout cves getwilds/hades:latest
    View base image update recommendations → docker scout recommendations getwilds/hades:latest
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/hades:latest
```
</details>
