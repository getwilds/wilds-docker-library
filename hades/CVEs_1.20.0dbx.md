# Vulnerability Report for getwilds/hades:1.20.0dbx

Report generated on 2026-09-17 01:07:35 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 146 |
| 🟡 Medium | 2255 |
| 🟢 Low | 184 |
| ⚪ Unknown | 0 |

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
Target               │  getwilds/hades:1.20.0dbx  │    5C   146H   2255M   184L  
   digest             │  d2a5505e2bcc                      │                              
 Base image           │  ubuntu:24.04                      │    0C     0H    34M    11L   
 Refreshed base image │  ubuntu:24.04                      │    0C     0H     7M     2L   
                      │                                    │                 -27     -9   
 Updated base image   │  ubuntu:26.04                      │    0C     0H     0M     0L   
                      │                                    │                 -34    -11   

Policy status  FAILED  (2/7 policies met)
Health score  E  (28%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    1649 packages            
 !      │ Fixable critical or high vulnerabilities found │    0C    18H     0M     0L  
 !      │ High-profile vulnerabilities found             │    0C     1H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/hades:1.20.0dbx
    View vulnerabilities → docker scout cves getwilds/hades:1.20.0dbx
    View base image update recommendations → docker scout recommendations getwilds/hades:1.20.0dbx
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/hades:1.20.0dbx
```
</details>
