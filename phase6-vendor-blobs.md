# Phase 6: Vendor Blob Supply Chain Analysis

## Executive Summary

LineageOS's vendor blob supply chain represents one of the most critical attack surfaces for insider threats. The extraction tooling (`android_tools_extract-utils`) provides **SHA1 hash-based pinning** for blob integrity, but this mechanism functions primarily as a **preservation control rather than a security control**. The TheMuppets organization, which hosts the pre-extracted vendor blobs for hundreds of devices, operates under an opaque trust model with minimal public accountability. The charter's device-support-requirements impose textual policy constraints on blob sourcing, but enforcement is entirely procedural -- no automated mechanism exists to prevent or detect policy violations at build time.

---

## 6.1 Blob Extraction Tooling Integrity Verification Audit

### Architecture Overview

The extraction tooling lives in `android_tools_extract-utils/extract_utils/` and consists of a modular Python framework. The critical files for integrity analysis are:

- **`file.py`** -- Parses `proprietary-files.txt` entries including the `|hash` syntax
- **`module.py`** -- Contains the core extraction processing logic including hash verification
- **`utils.py`** -- Provides `file_path_sha1()` and `file_path_sha256()` hash functions
- **`source.py`** -- Manages extraction from ADB, disk dumps, URLs, and archives
- **`fixups_blob.py`** -- Post-extraction binary patching (patchelf, regex replace, apktool)

### Hash Algorithm: SHA1 (Not SHA256)

The blob integrity system uses **SHA1** exclusively for file-level hash verification:

```python
# utils.py, lines 73-74
def file_path_sha1(file_path: str):
    return file_path_hash(file_path, hashlib.sha1())
```

SHA256 exists in the codebase (`file_path_sha256` at line 77) but is used **only** for download verification of source archives (`--download-sha256` argument, checked in `urlretrieve_resume`), never for blob-level integrity verification.

### The Three Processing Modes

The `module.py` file (`ExtractUtilsModule` class) implements three distinct processing paths, each with different integrity guarantees:

#### 1. Simple File Processing (No Hash, No Kang)
**File:** `module.py`, lines 836-858 (`process_simple_file`)

When a blob has **no hash** in `proprietary-files.txt`, it is copied from the source with no integrity verification whatsoever. Fixups are applied if configured, and a warning is printed if the fixup was a no-op:

```python
def process_simple_file(self, file: File, file_path: str):
    should_fixup = self.should_fixup_file(file)
    if not should_fixup:
        return  # <-- NO verification at all
    pre_fixup_hash = file_path_sha1(file_path)
    self.fixup_module_file(file, file_path)
    post_fixup_hash = file_path_sha1(file_path)
    # Only warns if fixup was no-op, does NOT verify content
```

**Security finding:** The majority of blobs in a typical `proprietary-files.txt` have no hash. These files are extracted from the source and placed into the vendor tree with **zero cryptographic verification** of their content. An attacker who controls the source image or dump directory can substitute arbitrary binaries.

#### 2. Kanged File Processing (Hash Generation Mode)
**File:** `module.py`, lines 860-893 (`process_kanged_file`)

The `--kang` flag is used when "borrowing" blobs from a different device or firmware version. In this mode, hashes are **computed and written** to `proprietary-files.txt`, not verified:

```python
def process_kanged_file(self, file: File, file_path: str):
    pre_fixup_hash = file_path_sha1(file_path)
    # ... fixups ...
    file.set_hash(pre_fixup_hash)
    file.set_fixup_hash(post_fixup_hash)
```

**Security finding:** Kang mode inherently trusts whatever source provides the blobs. The generated hashes record what was extracted, not what should have been extracted.

#### 3. Pinned File Processing (Hash Verification Mode)
**File:** `module.py`, lines 895-1000 (`process_pinned_file`)

This is the **only mode that performs actual integrity verification**. When a blob has a hash in `proprietary-files.txt`, the system:

1. First attempts to restore from a backup of the existing vendor tree
2. Compares the SHA1 of the restored/extracted file against the pinned hash
3. If there is a fixup hash, verifies both pre-fixup and post-fixup hashes

The verification logic has four possible outcomes (`PinnedFileProcessResult`):
- `MATCH` -- Hash matches, file is accepted
- `MISMATCH` -- Hash does not match; **file is still accepted** (prints yellow warning)
- `BAD_FIXUP` -- Fixup hash mismatch; file is rejected (returns `False`)

**Critical security finding:** A hash mismatch does NOT cause extraction to fail. From `process_file` (line 1086-1101):

```python
elif file.hash is not None:
    self.process_pinned_file(file, file_path, False)
    # Return value from process_pinned_file is IGNORED here
```

When a file is extracted from source (not backup), the return value of `process_pinned_file` is **silently discarded**. The file proceeds to the vendor tree regardless of whether the hash matched. Only the `BAD_FIXUP` case during backup restoration causes a hard failure. This means **hash pinning is purely informational for source-extracted files** -- the mismatch is logged as a yellow warning, but extraction continues.

### Source Provenance: No Verification

The `source.py` file reveals that blobs can be sourced from:
- A connected ADB device (`AdbSource`)
- A local directory (`DiskSource`)
- A downloaded archive (`create_downloadable_source`)
- A local archive file (`create_extractable_source`)

None of these source types verify the provenance of the blobs. There is no:
- Signature verification on source images
- Certificate pinning for download URLs
- Manifest of expected files beyond `proprietary-files.txt`
- Verification that the source image is an unmodified OEM release

The only download integrity check is an optional `--download-sha256` for the archive itself (line 319-324 in `source.py`), but this SHA256 is passed as a command-line argument, not embedded in any signed manifest.

### Fixup System: Post-Extraction Binary Modification

The `fixups_blob.py` file implements a powerful binary patching system that runs **after** extraction. Available fixup operations include:

- `replace_needed` / `add_needed` / `remove_needed` -- ELF shared library dependency patching via `patchelf`
- `binary_regex_replace` -- Arbitrary byte-level regex replacement in binaries
- `sig_replace` -- Binary signature/pattern replacement
- `regex_replace` -- Text-level regex replacement
- `patch_file` / `patch_dir` -- Apply git-format patches to extracted binaries
- `apktool_patch` -- Decompile, patch, and recompile APKs
- `strip_debug_sections` -- Remove debug info via `llvm-strip`

**Security finding:** The fixup system is extremely powerful and can modify any binary in arbitrary ways. Fixup functions are defined in device-specific `extract-files.py` scripts, which are maintained by individual device maintainers. A malicious maintainer could define a fixup that injects code into a blob, and the dual-hash system (`hash|fixup_hash`) would record this as legitimate.

### External Tool Dependencies

The extraction pipeline depends on prebuilt binaries in `prebuilts/extract-tools/linux-x86/bin/`:
- `ota_extractor` -- OTA payload extraction
- `patchelf` (4 versions: 0.8, 0.9, 0.17.2, 0.18)
- `stripzip`
- `apktool.jar`
- `brotli`
- `llvm-strip`

These prebuilts are consumed from the Android source tree without independent verification.

---

## 6.2 TheMuppets Organization Trust Model Analysis

### Organization Structure

TheMuppets is a GitHub organization hosting **501+ repositories** of pre-extracted proprietary vendor blobs. It also mirrors on GitLab at `the-muppets`. The organization's manifest repository (`TheMuppets/manifests`) contains a `muppets.xml` file with approximately 400+ project entries, covering vendors including Google, Samsung, Motorola, OnePlus, Sony, Xiaomi, and many others.

### Visible Membership

The organization has **extremely limited public membership visibility**. Only one member is publicly visible: `kardebayan` (Debayan Kar). The `manifests` repository shows **87+ contributors** over 338 commits since January 2017, but the organization membership list itself is opaque.

### Trust Model Assessment

The TheMuppets trust model has several concerning properties from an insider threat perspective:

1. **Centralized binary distribution:** TheMuppets serves as a single point of distribution for hundreds of proprietary binary blobs. All repositories use `clone-depth="1"` (shallow clones), which means consumers cannot easily audit the history of blob changes.

2. **No public governance:** Unlike the main LineageOS organization which has a charter, directors, and documented decision-making processes, TheMuppets has no visible governance structure, membership criteria, or access control documentation.

3. **Relationship to LineageOS is implicit:** The `lineage.dependencies` file in device trees can pull from TheMuppets via the manifest, but TheMuppets is a separate GitHub organization from `LineageOS`. The charter states: "This file MUST NOT include any dependencies outside of the 'LineageOS' organization." However, TheMuppets repos are typically pulled via a local manifest or the roomservice mechanism, not directly via `lineage.dependencies`.

4. **Push access scope unclear:** It is unknown how many individuals have push access to the 501+ repositories. Given the volume of devices covered, it is likely that many device maintainers have write access to their respective `proprietary_vendor_*` repositories. A single compromised or malicious account with push access could inject modified blobs that would be consumed by every LineageOS build for that device.

5. **No commit signing requirement:** There is no evidence of mandatory GPG-signed commits for TheMuppets repositories. Blob commits are typically automated extractions from OEM images.

6. **No reproducibility mechanism:** There is no documented process for independently reproducing or verifying the blobs in TheMuppets against the original OEM firmware images. Users and the build system must trust that the blobs were extracted faithfully.

### Supply Chain Risk

TheMuppets represents a **high-value target** for supply chain attacks. A compromised TheMuppets repository would inject malicious blobs into every downstream build. The combination of:
- Binary-only content (not reviewable in code review)
- Shallow cloning (limits audit capability)
- Opaque membership (unclear trust boundary)
- No signature verification in the extraction tooling

...creates a scenario where a single insider with push access could compromise the entire device ecosystem.

---

## 6.3 SHA1 Pinning Assessment: Security or Preservation?

### The Pinning Mechanism

The `proprietary-files.txt` format supports hash pinning via the `|` separator:

```
vendor/lib/libexample.so|a1b2c3d4e5f6...
vendor/lib/libfixed.so|pre_fixup_hash|post_fixup_hash
```

The `File` class in `file.py` (lines 133-173) parses these hashes:

```python
def __parse_extras(self, line: str):
    # ...
    hashes_len = len(hashes)
    if hashes_len >= 1:
        file_hash = hashes[0]       # Pre-fixup SHA1
    if hashes_len == 2:
        file_fixup_hash = hashes[1]  # Post-fixup SHA1
```

### Designed Purpose: Preservation, Not Security

Based on the official LineageOS wiki documentation and the code analysis, SHA1 pinning was designed for **blob preservation during re-extraction**, not as a security mechanism:

> "If the copy of that blob in the existing vendor tree does not match the sha1sum then it is ignored and extraction proceeds normally. If it does match then it will be kept regardless of the contents of the device/dump."

The stated use case is protecting "kanged" blobs (blobs borrowed from different devices) from being overwritten when the maintainer re-runs extraction against updated firmware. This is a **configuration management** function, not a security function.

### Why It Fails as a Security Control

1. **SHA1 is cryptographically broken:** SHA1 has been vulnerable to collision attacks since 2017 (SHAttered). While a pre-image attack is harder, using SHA1 for security purposes in 2026 is well below industry standards.

2. **Hash mismatches are non-fatal:** As documented in section 6.1, when extracting from source, a hash mismatch generates a **warning** but does not stop extraction. The file is accepted regardless.

3. **Hashes are self-attested:** The hashes in `proprietary-files.txt` are maintained by device maintainers themselves. A malicious maintainer would simply update the hash to match their modified blob.

4. **No trusted root of verification:** There is no PKI, no signature over the hash list, and no independent party that attests to the correctness of the hashes. The hash is stored in the same repository controlled by the same maintainers who control the blobs.

5. **`--kang` mode overwrites hashes:** Running extraction with `--kang` automatically recomputes and saves new hashes, making it trivial to "legitimately" update a hash to match modified content.

6. **Backup-first verification is local:** The pinned file system first tries to restore from a local backup of the vendor directory. This backup is created from the existing vendor tree content, which is itself derived from TheMuppets or a previous extraction. The trust chain is circular.

### The Dual-Hash System

The dual-hash system (`hash|fixup_hash`) exists to handle the case where fixups modify a blob post-extraction. This is strictly a reproducibility mechanism:
- `hash` = SHA1 of the blob as extracted from the OEM image
- `fixup_hash` = SHA1 of the blob after fixup functions are applied

If the existing vendor tree copy matches `fixup_hash`, the file is considered already fixed up and is kept. If it matches `hash`, fixups are re-applied. This prevents unnecessary re-fixup operations but does not provide any security guarantee.

### Assessment Verdict

**SHA1 pinning in proprietary-files.txt is a preservation/reproducibility control, not a security control.** It protects customized blobs from accidental overwriting during re-extraction. It does not protect against intentional substitution by insiders, supply chain compromise, or any adversary who can modify both the blob and its hash.

---

## 6.4 Charter Blob Restrictions: Enforcement Mechanism Analysis

### Charter Requirements (device-support-requirements.md)

The charter's "Proprietary files extraction" section (lines 281-289) establishes these requirements:

| Requirement | Strength | Enforcement |
|---|---|---|
| Working extraction script MUST exist | MUST | Manual review during device promotion |
| SHOULD use global extraction script | SHOULD | Peer pressure only |
| Custom scripts MUST have wiki docs | MUST | Manual review |
| Blobs MUST come from publicly-released images or transferable sources | MUST | **None automated** |
| Un-pinned blobs MUST have source comment | MUST | **None automated** |
| Non-default blobs MUST be pinned with source comment | MUST | **None automated** |
| MUST NOT include Megvii/SenseTime blobs | MUST NOT | **None automated** |

### Enforcement Gaps

#### 1. No Build-Time Enforcement

There is no build system check that validates:
- Whether blobs were extracted from an approved source
- Whether the comments in `proprietary-files.txt` accurately reflect the actual blob source
- Whether pinned hashes correspond to legitimate OEM firmware

The extraction tooling processes `proprietary-files.txt` mechanically -- it reads paths and optional hashes but does not parse or validate comments.

#### 2. The Megvii/SenseTime Restriction Has No Technical Enforcement

The charter states: "Devices MUST NOT include blobs belonging to Megvii Technology Ltd. or SenseTime Group Ltd."

This is a **policy-only** restriction. The extraction tooling has no blocklist, no string matching for Megvii/SenseTime identifiers, and no mechanism to detect or reject blobs from these vendors. Compliance depends entirely on maintainer diligence and reviewer knowledge.

#### 3. Source Documentation is Self-Attested

The requirement for source comments in `proprietary-files.txt` is a documentation standard:

```
# Extracted from device-vendor-image-v1.0.zip
vendor/lib/libfoo.so

# Kanged from device-other-v2.0
vendor/lib/libbar.so|abc123def456
```

These comments are human-readable text with no structured format. There is no:
- Verification that the stated source URL is valid
- Check that the claimed firmware version exists
- Cryptographic link between the comment and the actual blob content
- Automated enforcement that every un-pinned file has a comment

#### 4. "Publicly-Released Image" Requirement is Unverifiable

The charter requires blobs from "publicly-released images" or sources with "appropriately transferrable use/release/dissemination rights." This is fundamentally a legal/policy requirement that cannot be technically enforced. The extraction tooling accepts any source -- a local directory, an ADB-connected device, or a URL -- without verifying its origin.

#### 5. Enforcement is Procedural, Not Technical

Based on the charter's structure, enforcement of blob restrictions occurs through:

1. **Device promotion process:** When a device is submitted for official LineageOS support, directors review the device tree and may check blob sourcing. This is a one-time gate, not continuous monitoring.

2. **Gerrit code review:** Changes to device trees and `proprietary-files.txt` go through Gerrit review. However, binary blobs in TheMuppets are committed separately and are not subject to the same review process.

3. **Exception process:** The charter requires 3 Project Directors to approve deviations. This suggests a manual, committee-based enforcement model.

4. **Post-hoc compliance:** The charter states exceptions "SHOULD be made via change request to this repository" and "MUST be documented on the Wiki." This is retrospective documentation, not preventive enforcement.

---

## Key Vulnerabilities from Insider Threat Perspective

### Critical Risk: Malicious Blob Injection via TheMuppets

**Attack path:** An insider with push access to a TheMuppets `proprietary_vendor_*` repository modifies a vendor blob (e.g., a HAL library, a system daemon) to include a backdoor. The modified blob is committed with an updated extraction comment. The LineageOS build infrastructure pulls the blob during the next build cycle. No automated check detects the modification.

**Impact:** Code execution at the hardware abstraction layer or system daemon level, affecting all users of that device.

**Why it succeeds:**
- Binary blobs are not subject to code review
- No signature verification on TheMuppets content
- SHA1 hashes in `proprietary-files.txt` would be updated to match
- No reproducibility verification against original OEM firmware

### High Risk: Malicious Fixup Function

**Attack path:** A device maintainer introduces a fixup in `extract-files.py` that applies a `binary_regex_replace` or `sig_replace` to inject malicious code into a blob during the extraction process. The dual-hash system records the post-fixup hash, making the modification appear intentional and legitimate.

**Why it succeeds:**
- Fixups are expected to modify binaries
- The dual-hash system normalizes this behavior
- Fixup code is Python that runs with full access to the file
- Reviewers may not scrutinize the semantic effect of binary regex replacements

### Medium Risk: Source Image Substitution

**Attack path:** An insider provides a URL or local path to a modified firmware image for extraction. The extraction tooling faithfully extracts all blobs from the compromised source. If `--download-sha256` is not used (it is optional), no integrity check occurs on the source archive.

**Why it succeeds:**
- Source provenance is not verified
- `--download-sha256` is optional and the hash is provided by the same person providing the URL
- The extracted blobs are binary content with no embedded signatures (in most cases)

### Low-Medium Risk: SHA1 Collision-Based Hash Bypass

**Attack path:** An attacker crafts a malicious blob that has the same SHA1 hash as the legitimate blob (collision attack). The pinned hash in `proprietary-files.txt` would match, and the malicious blob would be accepted.

**Why this is lower risk:** SHA1 collision attacks require crafting both files simultaneously (chosen-prefix collision), which is not trivial for arbitrary binary formats like ELF shared libraries. However, this risk will increase over time as SHA1 attacks improve.

---

## Recommendations

1. **Migrate from SHA1 to SHA256** for blob pinning in `proprietary-files.txt` and throughout the extraction tooling.

2. **Make hash mismatches fatal by default.** Currently, mismatches for source-extracted files are silently accepted. Add a `--strict` mode that fails extraction on any hash mismatch.

3. **Implement reproducible extraction verification.** Publish the exact OEM firmware image SHA256 alongside `proprietary-files.txt` so that any party can independently verify the extraction.

4. **Add blob provenance metadata.** Extend the file format to include structured source information (firmware URL, version, SHA256) rather than free-form comments.

5. **Implement a Megvii/SenseTime blocklist.** Scan extracted blobs for known identifiers (strings, package names, certificate subjects) to technically enforce the charter restriction.

6. **Audit TheMuppets access controls.** Establish minimum governance requirements: mandatory 2FA, commit signing, access logs, and periodic access review for TheMuppets push access.

7. **Consider signing TheMuppets commits.** Implement automated GPG signing or Sigstore-based signing for blob commits, with public verification in the build system.

8. **Add binary diffing for blob updates.** When blobs change between extractions, automatically generate and log binary diffs to enable review of what changed.

---

## Source Files Analyzed

### Extract-Utils Python Source
- `sources/android_tools_extract-utils/extract_utils/extract.py` -- Image extraction pipeline
- `sources/android_tools_extract-utils/extract_utils/file.py` -- `proprietary-files.txt` parser, hash parsing (lines 133-173)
- `sources/android_tools_extract-utils/extract_utils/module.py` -- Core processing logic, hash verification (lines 836-1000, 1026-1103)
- `sources/android_tools_extract-utils/extract_utils/source.py` -- Source abstraction (ADB, disk, URL)
- `sources/android_tools_extract-utils/extract_utils/postprocess.py` -- Post-processing (carrier settings only)
- `sources/android_tools_extract-utils/extract_utils/utils.py` -- SHA1/SHA256 hash functions (lines 62-78)
- `sources/android_tools_extract-utils/extract_utils/fixups_blob.py` -- Binary fixup operations (patchelf, regex, apktool)
- `sources/android_tools_extract-utils/extract_utils/fixups.py` -- Fixup registry flatten logic
- `sources/android_tools_extract-utils/extract_utils/fixups_lib.py` -- Library name fixups
- `sources/android_tools_extract-utils/extract_utils/args.py` -- CLI argument parsing (--kang, --download-sha256)
- `sources/android_tools_extract-utils/extract_utils/tools.py` -- External tool paths (patchelf, apktool, etc.)
- `sources/android_tools_extract-utils/extract_utils/makefiles.py` -- Build system makefile generation
- `sources/android_tools_extract-utils/extract_utils/elf.py` -- ELF binary analysis
- `sources/android_tools_extract-utils/extract.py` -- Top-level extraction entry point

### Charter
- `sources/charter/device-support-requirements.md` -- Device support requirements (blob restrictions at lines 281-289)

### Web Sources
- https://github.com/TheMuppets -- Organization overview (501 repos, 1 visible member)
- https://github.com/TheMuppets/manifests -- Manifest repository (87+ contributors, 400+ device entries)
- https://wiki.lineageos.org/proprietary_blobs -- Official documentation on blob format and SHA1 pinning semantics
