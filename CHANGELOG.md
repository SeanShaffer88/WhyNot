# Changelog

## 1.1 — 2026-10-22

Hardening pass over the original draft. No checks were removed; several were
fixed so they cannot crash the diagnosis itself, and four missing causes were
added. Full audit trail: `docs/REVIEW.md`.

### Fixed
- **PowerShell 5.1 compatibility:** the draft used the `??` null-coalescing
  operator, which does not parse at all on Windows PowerShell 5.1 — the
  version most Windows machines launch by default. All occurrences replaced;
  the script now parses and runs on 5.1 and 7+.
- **Reparse-point check could crash the run:** piping fsutil output through
  `Select-String` and calling `.ToString()` unconditionally threw when no tag
  line matched, aborting the diagnosis on exactly the files it targets.
- **One bad ACE could abort all permission checks:** an ACE whose identity
  cannot be translated (orphaned SID) now degrades to "this entry skipped"
  instead of making the whole section report "cannot read the ACL".
- **ACL identity comparison is now SID-string based**, and the Administrators
  check uses the well-known SID `S-1-5-32-544` instead of a name match that
  varies by Windows language.
- **Elevation check uses the `WindowsBuiltInRole` enum**, not the localized
  role name string.
- **Path normalization no longer uses `Resolve-Path`** (fails for not-yet
  created files, expands wildcards); relative paths are resolved against the
  caller's directory explicitly.
- **JSON output is always an array** — previously a single finding serialized
  as a bare object, breaking consumers.
- **BitLocker probe** now uses a mount point in the form the cmdlet expects
  (`C:` rather than `C:\`).
- **Case-sensitivity probe** matches fsutil's exact "is enabled" wording.

### Added
- EFS-encrypted file finding (an ACL Allow does not help without the cert).
- Single path component over 255 characters (a distinct limit from MAX_PATH).
- Alternate-data-stream colon detection in the file-name part.
- Non-empty directory finding for `-Op Delete`; existing-target note for
  `-Op Create`; parent-component-is-a-file finding.
- Controlled Folder Access **audit mode** is now reported instead of ignored.
- Process context finding now includes the PowerShell version.

## 1.0 — 2026-10-22

- Original WhyNot draft: ten check sections covering path syntax, existence,
  WOW64/UAC virtualization, Restart Manager locks, attributes/reparse points,
  NTFS permissions, integrity levels, Controlled Folder Access, volume/share
  quirks, and process context, with FATAL/LIKELY/INFO ranking and `-Json`.
