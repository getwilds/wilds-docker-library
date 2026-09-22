# Vulnerability Report for getwilds/vrs-python:2.3.3dbx

Report generated on 2026-09-17 05:07:27 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 251 |
| 🟡 Medium | 2296 |
| 🟢 Low | 186 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 34 |
| 🟢 Low | 11 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/vrs-python:2.3.3dbx  │   10C   251H   2296M   186L     2?  
   digest             │  01926550d4ff                          │                                     
 Base image           │  ubuntu:24.04                          │    0C     0H    34M    11L          
 Refreshed base image │  ubuntu:24.04                          │    0C     0H     7M     2L          
                      │                                        │                 -27     -9          
 Updated base image   │  ubuntu:26.04                          │    0C     0H     0M     0L          
                      │                                        │                 -34    -11          

Policy status  FAILED  (2/7 policies met)
Health score  E  (28%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    1091 packages            
 !      │ Fixable critical or high vulnerabilities found │    5C   122H     0M     0L  
 !      │ High-profile vulnerabilities found             │    0C     1H     1M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/vrs-python:2.3.3dbx
    View vulnerabilities → docker scout cves getwilds/vrs-python:2.3.3dbx
    View base image update recommendations → docker scout recommendations getwilds/vrs-python:2.3.3dbx
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/vrs-python:2.3.3dbx
```
</details>
