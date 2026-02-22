# Phase 8: Threat Modeling & Synthesis

## LineageOS Institutional Security Assessment — Insider Threat Analysis

**Date:** 2026-02-22
**Classification:** Security Research
**Methodology:** Primary-source analysis of governance documents, source code, infrastructure configurations, and build scripts across 13 repositories + web sources.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Model 8.1: Malicious Infrastructure Manager](#2-threat-model-81-malicious-infrastructure-manager)
3. [Threat Model 8.2: Malicious Head Developer](#3-threat-model-82-malicious-head-developer)
4. [Threat Model 8.3: Compromised Build Server](#4-threat-model-83-compromised-build-server)
5. [Threat Model 8.4: Compromised Vendor Blob Source](#5-threat-model-84-compromised-vendor-blob-source)
6. [Comparative Analysis (8.5)](#6-comparative-analysis-85)
7. [Trust Boundary Map](#7-trust-boundary-map)
8. [Single Points of Failure Ranking](#8-single-points-of-failure-ranking)
9. [Risk Matrix](#9-risk-matrix)
10. [Recommendations](#10-recommendations)

---

## 1. Executive Summary

This assessment evaluates LineageOS's resilience against insider threats — specifically the scenario where head developers, key holders, or infrastructure managers act maliciously. The analysis is grounded entirely in primary sources: actual code, configuration files, governance documents, and infrastructure repos.

### Bottom Line

**LineageOS has a critical concentration-of-trust problem centered on a single individual and an opaque signing pipeline.** While the project has commendable governance documentation and open-source transparency for its codebase, the infrastructure layer where code becomes signed builds delivered to users is characterized by:

1. **One person (Tom Powell / zifnab06) simultaneously holds**: LLC ownership with legal veto power, sole Tailscale admin, Infrastructure Manager with signing key access, Director, Developer Relations Manager, and Public Relations member. No documented mechanism exists to override or remove this individual.

2. **The signing pipeline is completely opaque**: No public source code documents the process between unsigned build upload and signed OTA distribution. The signing keys are stored as unencrypted files with no HSM, no multi-party control, and no rotation in 9+ years.

3. **Code review is optional at every level**: All ~250 maintainers and 9 directors can bypass Gerrit review via direct push. The `c3po` service account has unrestricted force-push with `skip-validation` across all repositories. No automated guardrails enforce review.

4. **The build environment is compromised-by-default**: An EOL Docker base image, unpinned binary downloads, SSH keys exposed to all build code, and an unversioned `/lineage/setup.sh` that executes in every build.

5. **Vendor blobs are an unguarded attack surface**: 501+ repos of binary blobs with no signature verification, no provenance attestation, non-fatal hash mismatches, and SHA1-only pinning.

### Key Statistic

An insider with Tom Powell's access could theoretically compromise every LineageOS device in the world with a single malicious signed OTA update, using only documented, legitimate access mechanisms, with no automated detection or prevention system in place.

---

## 2. Threat Model 8.1: Malicious Infrastructure Manager

**Scenario:** One of the 2 Infrastructure Managers acts maliciously or is compromised.

### Attacker Profile

| Attribute | Tom Powell (zifnab06) | Chirayu Desai (chirayudesai) |
|---|---|---|
| Tailscale Group | group:admin + group:infra | group:infra only |
| Can tag/untag hosts | Yes (sole) | No |
| SSH root to all infra | Yes | Yes |
| Signing key access | Yes (inferred) | Yes (inferred) |
| LLC owner veto | Yes | No |
| Can revoke other's access | Yes (via Tailscale admin) | No |
| Director vote | Yes (1/9) | Yes (1/9) |

### Attack Tree: Malicious Tom Powell (zifnab06)

```
ROOT: Distribute malicious signed OTA to all LineageOS users
│
├── PATH A: Direct signing key abuse (Fastest, ~1 hour)
│   ├── 1. SSH to signing server as root (Tailscale group:infra)
│   ├── 2. Access unencrypted .pk8 files in vendor/lineage-priv/keys/
│   ├── 3. Sign a pre-prepared malicious target-files package
│   ├── 4. Place signed OTA on download.lineageos.org
│   └── 5. Users auto-download via Updater app
│       Mitigation: NONE (no multi-party control, no audit trail)
│       Detection: NONE (opaque signing process)
│
├── PATH B: Build pipeline injection (Stealthier, ~24 hours)
│   ├── 1. SSH to build host, modify /lineage/setup.sh
│   ├── 2. setup.sh injects backdoor during next nightly build
│   ├── 3. Backdoored build uploaded to blob.lineageos.org
│   ├── 4. Signing process signs the backdoored build normally
│   └── 5. Distributed via OTA
│       Mitigation: NONE (setup.sh is unversioned, unaudited)
│       Detection: VERY LOW (would require comparing source to build output)
│
├── PATH C: Persistent supply chain compromise (Most stealthy)
│   ├── 1. Push malicious commit to build-config/main
│   ├── 2. mirror-branches.yml force-pushes to all version branches
│   ├── 3. Every future build for all versions includes the backdoor
│   └── 4. Signed normally
│       Mitigation: Commit is visible in git history
│       Detection: LOW (legitimate build-config changes are routine)
│
├── PATH D: Lock out other Infrastructure Manager
│   ├── 1. Remove chirayudesai from group:infra in tailscale-config
│   ├── 2. Push to main (auto-deployed via GitHub Actions)
│   ├── 3. Chirayu loses all infrastructure SSH access immediately
│   └── 4. Use LLC veto to block governance response
│       Mitigation: NONE (no override mechanism documented)
│       Detection: Change visible in tailscale-config git history
│
└── PATH E: Exfiltrate signing keys for persistent access
    ├── 1. SSH to signing infrastructure
    ├── 2. Copy unencrypted .pk8 files (no password protection)
    ├── 3. Retain ability to sign builds indefinitely
    └── 4. Use off-infrastructure to create targeted malicious updates
        Mitigation: NONE (no key access logging, no HSM binding)
        Detection: NEAR ZERO (no usage monitoring)
```

### Attack Tree: Malicious Chirayu Desai (chirayudesai)

```
ROOT: Distribute malicious signed OTA
│
├── PATH A: Direct signing key abuse
│   ├── 1. SSH to signing server (group:infra)
│   ├── 2. Access signing keys
│   ├── 3. Sign malicious build
│   └── Same as Powell Path A
│       Note: Cannot lock out Powell
│
├── PATH B: Build pipeline injection
│   └── Same as Powell Path B
│
└── LIMITATION: Cannot revoke Powell's access
    └── Powell can detect and revoke Desai's access first
```

### Mitigations Present vs Absent

| Control | Status |
|---|---|
| Multi-party signing | **ABSENT** |
| HSM-bound keys | **ABSENT** |
| Signing audit log | **ABSENT** |
| Symmetric access revocation | **ABSENT** (asymmetric: Powell > Desai) |
| Build reproducibility | **ABSENT** |
| Independent build verification | **ABSENT** |
| Key rotation | **ABSENT** (9+ years, no rotation) |
| Governance override for rogue LLC owner | **ABSENT** |

---

## 3. Threat Model 8.2: Malicious Head Developer

**Scenario:** One of the 9 Directors (Head Developers) acts maliciously.

### Capabilities

Every Head Developer has:
- Global +2 Code-Review and Submit on ALL repositories
- Direct push (bypass Gerrit review) on ALL repositories
- `forgeAuthor`, `forgeCommitter`, `forgeServerAsCommitter` permissions
- Vote on governance decisions (1/9)
- Access to private directorial communication channels

### Attack Tree: Malicious Head Developer (Non-Infrastructure)

```
ROOT: Inject backdoor into LineageOS builds
│
├── PATH A: Direct push to security-critical repo (Fastest)
│   ├── 1. git push lineage HEAD:refs/heads/lineage-23.2
│   │   Target repos: android_frameworks_base, android_system_core,
│   │                 android_system_security, android_build
│   ├── 2. Change is immediately replicated to GitHub mirror
│   ├── 3. Next build incorporates the malicious code
│   └── 4. Signed normally (developer doesn't need signing access)
│       Mitigation: Change visible in Gerrit/git history
│       Detection: LOW-MEDIUM (direct pushes are routine for merges)
│
├── PATH B: Forge commit authorship (Stealthier)
│   ├── 1. Use forgeCommitter permission to attribute commit to another dev
│   ├── 2. Direct push to target repo
│   └── 3. Forensic trail points to wrong person
│       Mitigation: No commit signing requirement
│       Detection: VERY LOW (forged authorship looks legitimate)
│
├── PATH C: Modify build manifest (Maximum impact)
│   ├── 1. Direct push to LineageOS/android (repo manifest)
│   │   (Head-Developers group has exclusive access)
│   ├── 2. Add or swap a repository to a malicious fork
│   ├── 3. All builds pull the malicious repo
│   └── 4. Revert after one build cycle
│       Mitigation: Manifest changes are highly visible
│       Detection: MEDIUM (but easy to disguise as "AOSP merge")
│
├── PATH D: Slow board capture
│   ├── 1. Recruit 4 allies (need 5/9 for simple majority)
│   ├── 2. As directors depart, appoint allied replacements
│   │   (Directors choose their own replacements, no external oversight)
│   ├── 3. With 5/9 majority, control all governance decisions
│   ├── 4. Modify charter (only 3 director approvals needed)
│   └── 5. Grant allies infrastructure access
│       Mitigation: Public charter changes visible in git
│       Detection: VERY LOW (gradual, appears legitimate)
│
└── PATH E: Approve malicious contribution from external attacker
    ├── 1. External attacker submits plausible-looking Gerrit change
    ├── 2. Malicious director gives +2 and submits
    └── 3. No second reviewer required
        Mitigation: Change visible in Gerrit
        Detection: LOW (routine code review)
```

### Key Vulnerability: No Mandatory Second Reviewer

The single most impactful missing control is mandatory peer review. A Head Developer can:
1. Write code
2. Self-review (+2)
3. Self-submit
4. All in one action, via direct push

No Gerrit hook, no submit requirement, no automated check prevents this.

---

## 4. Threat Model 8.3: Compromised Build Server

**Scenario:** An attacker gains access to a Buildkite build agent or the `c3po` service account.

### Attack Surface

| Entry Point | Access Gained |
|---|---|
| Buildkite org admin | Pipeline config, environment vars, build triggers |
| c3po SSH key | Force push to ANY Gerrit repo, skip all validation |
| Docker container escape | Host access, persistent volume access |
| Malicious code in any of ~600 repos | SSH agent access during build |
| /buildkite-secrets/ volume | SSH keys for blob.lineageos.org and Gerrit |
| /lineage/setup.sh on persistent volume | Arbitrary code execution in every build |

### Attack Tree: Compromised Build Agent

```
ROOT: Inject malicious code into official LineageOS builds
│
├── PATH A: Exploit SSH keys loaded in build container
│   ├── 1. Merge code into ANY of ~600 LineageOS repos
│   │   (device tree, kernel, framework — many repos have
│   │    multiple maintainers with direct push)
│   ├── 2. Code executes during build (envsetup.sh, Makefile, etc.)
│   ├── 3. Code accesses SSH agent (loaded by hooks/environment)
│   ├── 4a. SCP malicious files to blob.lineageos.org
│   │   OR
│   ├── 4b. Force push to Gerrit as c3po with skip-validation
│   └── 5. Persistent compromise of build pipeline
│       Mitigation: Build logs may capture anomalous SSH usage
│       Detection: LOW (build output is voluminous)
│
├── PATH B: Modify /lineage/setup.sh
│   ├── 1. Access build host (via SSH key or container escape)
│   ├── 2. Modify /lineage/setup.sh on persistent Docker volume
│   ├── 3. Every subsequent build sources this file
│   └── 4. Arbitrary code runs with full build privileges
│       Mitigation: NONE (file is unversioned, no integrity check)
│       Detection: NEAR ZERO
│
├── PATH C: Replace unsigned artifacts on blob.lineageos.org
│   ├── 1. Use jenkins@blob SSH key (from /buildkite-secrets/)
│   ├── 2. Replace target-files.zip in /home/jenkins/incoming/
│   ├── 3. Signing process signs the replacement
│   └── 4. Distributed as legitimate build
│       Mitigation: BUILD_UUID provides path unpredictability
│       Detection: LOW (no integrity verification of uploads)
│
└── PATH D: Supply chain via Docker image
    ├── 1. Compromise Docker Hub ubuntu:16.04 tag (or CDN)
    ├── 2. Or: Compromise Buildkite agent download (unpinned "latest")
    ├── 3. Modified binary executes in every build container
    └── 4. Persistent across all builds until image is rebuilt
        Mitigation: NONE (no digest pinning, no hash verification)
        Detection: VERY LOW
```

---

## 5. Threat Model 8.4: Compromised Vendor Blob Source

**Scenario:** Malicious binary injection via TheMuppets or OEM dumps.

### Attack Tree: Malicious Blob Injection

```
ROOT: Inject malicious binary blob into LineageOS builds
│
├── PATH A: Direct push to TheMuppets repo
│   ├── 1. Obtain push access to proprietary_vendor_<device> repo
│   │   (TheMuppets membership is opaque; governance undocumented)
│   ├── 2. Replace a HAL library or system daemon blob
│   ├── 3. Update proprietary-files.txt hash to match
│   │   (if pinned; most blobs are unpinned)
│   ├── 4. Shallow clone depth of 1 hides history
│   └── 5. Next LineageOS build incorporates malicious blob
│       Mitigation: NONE (binary content, no code review)
│       Detection: NEAR ZERO (blobs are opaque binaries)
│
├── PATH B: Malicious fixup function
│   ├── 1. Device maintainer adds fixup to extract-files.py
│   │   e.g., binary_regex_replace that injects shellcode
│   ├── 2. Fixup runs post-extraction, modifies blob
│   ├── 3. Dual-hash system records post-fixup hash as legitimate
│   └── 4. Fixup code in Python, reviewed on Gerrit
│       Mitigation: Fixup code is reviewable (if someone reads it)
│       Detection: LOW (binary regex replacements are hard to assess)
│
├── PATH C: Modified source firmware image
│   ├── 1. Provide modified OEM firmware for extraction
│   ├── 2. --download-sha256 is optional, hash self-attested
│   ├── 3. All extracted blobs are silently modified
│   └── 4. No verification against original OEM image
│       Mitigation: NONE (source provenance not verified)
│       Detection: NEAR ZERO
│
└── PATH D: SHA1 collision (theoretical)
    ├── 1. Craft malicious blob with same SHA1 as legitimate
    ├── 2. Pinned hash in proprietary-files.txt matches
    └── 3. Malicious blob accepted
        Mitigation: SHA1 collision is expensive (but feasible)
        Detection: ZERO (hash matches)
```

---

## 6. Comparative Analysis (8.5)

### LineageOS vs Reference Projects

| Security Practice | LineageOS | GrapheneOS | CalyxOS | F-Droid |
|---|---|---|---|---|
| **Reproducible builds** | No | Partial (working toward) | No | Yes (for apps) |
| **HSM for signing keys** | No evidence | Yes (documented) | Unknown | Yes (documented) |
| **Multi-party signing** | No | Unknown (small team) | Unknown | Yes (multiple key holders) |
| **Key rotation** | Never (9+ years) | Has rotated | Unknown | Has rotated |
| **Certificate pinning in updater** | No | Yes (TLS pinning) | Unknown | Yes (repo signing) |
| **Mandatory code review** | No (direct push allowed) | Yes (mandatory) | Unknown | Yes |
| **Signed API responses** | No | Unknown | Unknown | Yes (repo index is signed) |
| **Build environment pinning** | No (EOL Ubuntu, unpinned deps) | Yes (reproducible env) | Unknown | Yes (for apps) |
| **Locked bootloader support** | No (unlocked required) | Yes (relocking supported) | No | N/A |
| **Vendor blob verification** | SHA1 only, non-fatal | Minimal blobs (Pixel only) | Unknown | N/A |
| **Post-incident transparency** | Poor (promised post-mortem never published) | Good | Unknown | Good |
| **Independent security audit** | Never | Yes (multiple) | Unknown | Partial |
| **Governance transparency** | Good (charter public) | Limited (small team) | Moderate | Good |
| **CVE tracking transparency** | Reduced (tracker taken offline) | Good | Unknown | N/A |

### Key Gaps Relative to Best Practice

1. **No HSM usage**: GrapheneOS and F-Droid use hardware-bound signing keys. LineageOS stores keys as unencrypted files.

2. **No reproducible builds**: F-Droid achieves app-level reproducibility. GrapheneOS is working toward full system reproducibility. LineageOS has no reproducibility mechanism.

3. **No mandatory code review**: GrapheneOS requires review for all changes. LineageOS allows any of ~250 people to bypass review.

4. **No independent audit**: GrapheneOS has undergone multiple security audits. LineageOS has never published one.

5. **No locked bootloader support**: GrapheneOS supports relocking the bootloader, providing a hardware-backed chain of trust. LineageOS requires an unlocked bootloader, breaking the AVB trust chain.

---

## 7. Trust Boundary Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL WORLD                                   │
│  Users (~millions), OEM firmware images, upstream AOSP, mirror operators│
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────────────────┐
         │           TRUST BOUNDARY 1: Code Contribution               │
         │                                                             │
         │  Gerrit Review (review.lineageos.org)                       │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ ~250 maintainers can BYPASS review (direct push)    │    │
         │  │ 9 directors can push to ANY repo                    │    │
         │  │ c3po service account: unrestricted + skip-validation│    │
         │  │ No mandatory peer review                            │    │
         │  │ forgeCommitter allows identity spoofing             │    │
         │  │ No commit signing enforcement                       │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                           │                                 │
         │  GitHub Mirror ◄──────────┤ (auto-replicated from Gerrit)   │
         │  Build system pulls from GitHub (not Gerrit!)               │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │           TRUST BOUNDARY 2: Build Pipeline                  │
         │                                                             │
         │  Buildkite CI + Docker containers                           │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ 15 identified injection points                      │    │
         │  │ EOL Docker base image (ubuntu:16.04)                │    │
         │  │ SSH keys exposed to all build code                  │    │
         │  │ /lineage/setup.sh: unversioned arbitrary execution  │    │
         │  │ Unpinned source sync (branch heads, not commits)    │    │
         │  │ No build attestation or manifest recording          │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                           │                                 │
         │  Vendor blobs (TheMuppets, 501 repos)                       │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ Binary content, no code review possible             │    │
         │  │ SHA1 pinning is non-fatal                           │    │
         │  │ No provenance verification                          │    │
         │  │ Opaque governance and membership                    │    │
         │  └─────────────────────────────────────────────────────┘    │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │     TRUST BOUNDARY 3: Signing (MOST CRITICAL)               │
         │                                                             │
         │  ████████████████████████████████████████████████████████   │
         │  █             COMPLETELY OPAQUE                        █   │
         │  █                                                      █   │
         │  █  blob.lineageos.org receives unsigned artifacts      █   │
         │  █  Signing happens somewhere (no public source code)   █   │
         │  █  Keys: unencrypted RSA-2048/SHA-1, no HSM           █   │
         │  █  No multi-party control                              █   │
         │  █  No audit trail                                      █   │
         │  █  No key rotation (since Jan 7, 2017)                 █   │
         │  █  2 people have access (1 is sole admin)              █   │
         │  █                                                      █   │
         │  ████████████████████████████████████████████████████████   │
         └────────────────────────────┬────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────────┐
         │     TRUST BOUNDARY 4: Distribution                          │
         │                                                             │
         │  OTA API (Flask on Fly.io, auto-deployed from GitHub)       │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ No response signing (API JSON is unsigned)          │    │
         │  │ Upstream data trusted without verification          │    │
         │  │ Auto-deploy on push to main                         │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                                                             │
         │  Mirror network (Mirrorbits + rsync mirrors)                │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ No content signing at mirror level                  │    │
         │  │ rsync sync every 15 min, no integrity verification  │    │
         │  │ Mirror operators can serve selectively              │    │
         │  └─────────────────────────────────────────────────────┘    │
         │                                                             │
         │  Updater App (on device)                                    │
         │  ┌─────────────────────────────────────────────────────┐    │
         │  │ No certificate pinning                              │    │
         │  │ No hash verification of downloads                   │    │
         │  │ RecoverySystem.verifyPackage() is SOLE gate         │    │
         │  │ = Everything reduces to the signing key             │    │
         │  └─────────────────────────────────────────────────────┘    │
         └─────────────────────────────────────────────────────────────┘
```

---

## 8. Single Points of Failure Ranking

### Tier 1: CRITICAL (System-wide compromise)

| # | SPOF | Impact | Who/What | Mitigations |
|---|------|--------|----------|-------------|
| 1 | **OTA Signing Key** | All devices can receive malicious updates | Unencrypted .pk8 file, RSA-2048/SHA-1, on infrastructure accessible to 2 people | None. No HSM, no threshold, no rotation, no audit. |
| 2 | **Tom Powell (zifnab06)** | LLC veto + sole admin + infra access + signing access + director vote | Single individual | None. No mechanism to override LLC owner. |
| 3 | **Opaque signing pipeline** | Unsigned-to-signed transformation is invisible | Process running on infrastructure with no public source | None. No transparency, no reproducibility. |

### Tier 2: HIGH (Multi-device or infrastructure-wide)

| # | SPOF | Impact | Who/What | Mitigations |
|---|------|--------|----------|-------------|
| 4 | **c3po service account** | Unrestricted Gerrit access, skip-validation, force push | SSH key in /buildkite-secrets/ | Gerrit logs force pushes, but c3po usage is routine |
| 5 | **build-config main branch** | Single commit affects all LineageOS version builds | Force-mirror workflow propagates to all branches | Commit is visible in git history |
| 6 | **/lineage/setup.sh** | Arbitrary code execution in every build | Unversioned file on persistent Docker volume | None |
| 7 | **GitHub org admin** | Can push to all repos (build pulls from GitHub, not Gerrit) | Unknown number of org admins | GitHub audit log |

### Tier 3: MEDIUM (Per-device or partial)

| # | SPOF | Impact | Who/What | Mitigations |
|---|------|--------|----------|-------------|
| 8 | **TheMuppets repos** | Binary blob injection per device | Push access holders (unknown number) | None for binary content |
| 9 | **OTA API server** | Manipulate update metadata for all users | GitHub repo or FLY_API_TOKEN | OTA signature prevents false packages (but allows downgrade) |
| 10 | **Individual device maintainer** | Compromise repos for their device(s) | ~240 maintainers with direct push | Commit visible in history |

---

## 9. Risk Matrix

| Risk | Likelihood | Impact | Detectability | Overall Risk | Current Mitigations |
|------|-----------|--------|--------------|-------------|-------------------|
| Signing key exfiltration by insider | Medium | Critical | Near-zero | **CRITICAL** | None |
| Malicious build injection via setup.sh | Low-Medium | Critical | Near-zero | **CRITICAL** | None |
| Single-person governance capture (LLC owner) | Low | Critical | Very Low | **HIGH** | Charter (ineffective against LLC owner) |
| Malicious direct push by Head Developer | Low | High | Low | **HIGH** | Git history |
| Build pipeline supply chain (Docker, deps) | Low | Critical | Very Low | **HIGH** | None |
| Malicious blob via TheMuppets | Low-Medium | High | Near-zero | **HIGH** | None |
| c3po credential compromise | Low | High | Low | **HIGH** | Gerrit logs |
| OTA API manipulation (metadata) | Low | Medium | Low | **MEDIUM** | OTA signature (partial) |
| Mirror-level attack | Low | Low-Medium | Low | **MEDIUM** | OTA signature |
| Retired director abuse | Very Low | Medium | Low | **LOW-MEDIUM** | Git history |

---

## 10. Recommendations

### Immediate Priority (Addresses Critical Risk)

**R1: Implement multi-party signing**
- Require 2-of-3 key holders to sign each build
- Use threshold cryptography or multi-signature scheme
- Each key holder uses an independent HSM
- No single individual can produce a signed build

**R2: Move signing keys to HSM**
- Migrate from unencrypted filesystem to Hardware Security Modules
- Bind keys to hardware — prevent exfiltration
- Implement key access logging

**R3: Document and publish the signing pipeline**
- Make the signing process source-available
- Publish signing logs (what was signed, when, by whom)
- Consider a transparency log (like Certificate Transparency)

**R4: Resolve the Tom Powell concentration-of-power**
- Add at least one more person to Tailscale group:admin
- Document LLC membership publicly
- Create a documented "break glass" procedure for infrastructure lockout
- Establish symmetric access revocation capability

### High Priority (Addresses High Risk)

**R5: Enforce mandatory code review for security-critical repos**
- Deploy a Gerrit `submit` requirement mandating +2 from a reviewer who is NOT the author
- At minimum, protect: android_frameworks_base, android_system_core, android_build, android_vendor_lineage, android manifest, hudson, scripts, build-config

**R6: Scope build container access**
- Don't load all SSH keys into every build container
- Separate the jenkins@blob SCP key from the c3po@gerrit key
- Consider ephemeral credentials per build

**R7: Pin and verify Docker build environment**
- Pin base images by digest hash
- Verify all downloaded binaries (tini, buildkite-agent, repo) by SHA-256
- Upgrade from EOL ubuntu:16.04

**R8: Version-control /lineage/setup.sh**
- Move setup.sh content into the build-config repo
- Or: remove the sourcing mechanism entirely
- Or: at minimum, log its contents at build start

**R9: Implement build attestation**
- Save `repo manifest -r` output alongside each build
- Publish build inputs for third-party verification
- Consider SLSA framework compliance

### Medium Priority (Defense in Depth)

**R10: Rotate signing keys**
- Establish a key rotation policy (e.g., annually)
- Use Android's key rotation mechanism (APK Signature Scheme v3)
- Rotate immediately as a precautionary measure given 9+ years without rotation

**R11: Upgrade cryptographic algorithms**
- Migrate platform keys from RSA-2048/SHA-1 to RSA-4096/SHA-256 or Ed25519
- Disable SHA-1 for new signatures

**R12: Strengthen vendor blob security**
- Migrate from SHA1 to SHA256 in proprietary-files.txt
- Make hash mismatches fatal by default
- Implement provenance metadata for blob sourcing
- Audit and document TheMuppets governance and access controls

**R13: Add certificate pinning to Updater app**
- Pin the TLS certificate or public key for download.lineageos.org
- Verify SHA-256 hash of downloaded files against API response
- Sign API responses

**R14: Publish post-incident reports and conduct independent audit**
- Publish the long-overdue 2020 SaltStack post-mortem
- Commission an independent security audit of signing infrastructure
- Establish a vulnerability disclosure and incident response policy

**R15: Require commit signing**
- Enforce GPG or SSH commit signing for at least Head Developers and Infrastructure commits
- Remove forgeServerAsCommitter permission (or restrict to service accounts)

---

## Methodology

This assessment was conducted by analyzing primary sources only:

**Repositories analyzed (13):**
- LineageOS/charter (governance)
- lineageos-infra/gerrit-config (code review permissions)
- lineageos-infra/gerrit-hooks (automated guardrails)
- lineageos-infra/build-config (build pipeline)
- lineageos-infra/docker-android (build environment)
- lineageos-infra/tailscale-config (network access)
- lineageos-infra/auth (org membership)
- lineageos-infra/updater (OTA API)
- LineageOS/android_packages_apps_Updater (updater app)
- LineageOS/android_vendor_lineage (vendor config, signing)
- LineageOS/scripts (key generation, migration)
- LineageOS/update_verifier (verification tool)
- LineageOS/android_tools_extract-utils (blob extraction)

**Web sources:**
- wiki.lineageos.org (contributors, signing, bypassing gerrit, verifying builds)
- lineageos.org (blog posts, mirroring docs, engineering posts)
- buildkite.com/lineageos (pipeline visibility)
- GitHub organizations (LineageOS, lineageos-infra, TheMuppets)
- Trademark registration (justia.com)
- Incident reports (security news, GitHub issues, status pages)

**All findings are grounded in actual code, configuration, and documentation — no speculation without evidence.**

---

## Phase Reports Index

| Phase | Focus | Output File |
|---|---|---|
| 1 | Governance & Legal Structure | `phase1-governance/governance-analysis.md` |
| 2 | Code Review & Commit Access | `phase2-code-review/code-review-analysis.md` |
| 3 | Build Pipeline Security | `phase3-build-pipeline/build-pipeline-analysis.md` |
| 4 | Signing Infrastructure | `phase4-signing/signing-analysis.md` |
| 5 | OTA Update & Distribution | `phase5-ota-update/ota-update-analysis.md` |
| 6 | Vendor Blob Supply Chain | `phase6-vendor-blobs/vendor-blob-analysis.md` |
| 7 | Historical Incidents | `phase7-incidents/incident-analysis.md` |
| 8 | Threat Modeling & Synthesis | `phase8-synthesis/threat-models.md` (this document) |
