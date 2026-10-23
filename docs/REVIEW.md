# WhyNot 1.1 — audit of the original draft

Method: line-by-line review of the draft script against PowerShell 5.1/7
language rules and Windows API behavior, followed by parser validation and
path-logic smoke tests under PowerShell 7.4.6 on Linux. Every Windows-only
behavior is labeled **Unverified** until SEAN runs it on a real machine —
parser and Linux smoke results do not prove Windows runtime behavior.

## The one that mattered most

**The draft did not run on Windows PowerShell 5.1 at all.**
It used the null-coalescing operator (`??`) in two places. `??` is
PowerShell 7+ only; Windows PowerShell 5.1 — the `powershell.exe` still
installed and default-launched on every Windows 10/11 machine — refuses to
*parse* the file, so the tool died before its first check with a syntax
error, on exactly the machines its audience uses. Fixed by replacing both
uses with 5.1-compatible expressions, and guarded by a static test that
fails if `??`, `?.`, ternary, or `-Parallel` ever reappear in code lines.

## Bugs fixed (all in WhyNot.ps1, recorded in CHANGELOG 1.1)

| # | Draft behavior | Consequence | Fix | Status |
|---|---|---|---|---|
| 1 | `??` operator (2 uses) | Parse failure on PowerShell 5.1 | 5.1-compatible rewrites | Verified (parser + static suite) |
| 2 | `(fsutil ... \| Select-String 'Tag value').ToString()` | Null/array crash aborted the run on reparse points with no matching line (localized fsutil output included) | Guarded first-match extraction with fallback text | Verified statically; fsutil output itself Unverified |
| 3 | `.Translate()` inside the ACL Where-Object filter | One orphaned-SID ACE threw; catch reported the misleading "cannot even read the ACL" and dropped every permission finding | Per-ACE `Get-AceSidValue` with try/catch; identities compared as SID strings | Verified statically; Windows ACL runs Unverified |
| 4 | `$sids -contains $_.IdentityReference.Translate(...)` | SID object comparison unreliable | Compare `.Value` strings throughout | Verified statically |
| 5 | `IsInRole('Administrators')` | Role-name lookup is language-dependent; can misreport elevation on localized Windows | `WindowsBuiltInRole::Administrator` enum | Verified statically |
| 6 | "Administrators allowed" detected by name regex | Same localization problem in the ACL hint | Well-known SID `S-1-5-32-544` | Verified statically |
| 7 | Normalization via `Resolve-Path ... ?? $Path` | Fails for Create targets, expands wildcards, array paths throw in GetFullPath | Explicit rooted/relative `GetFullPath` against the caller's location | Verified (Linux smoke: relative + missing paths) |
| 8 | `$findings \| ConvertTo-Json` | One finding serialized as an object, zero as nothing — broke `-Json` consumers | `ConvertTo-Json -InputObject @($findings.ToArray())` | Verified (Linux smoke emitted a JSON array) |
| 9 | `Get-BitLockerVolume -MountPoint 'C:\'` | Wrong mount-point form | Trim trailing backslash (`C:`) | Unverified on Windows |
| 10 | Case-sensitivity: output `-match 'enabled'` | Loose match on fsutil wording | Match `'is enabled'` | Verified statically |
| 11 | Integrity-label regex `S:.*ML;.*;(HI\|SI)` | Greedy match across SDDL sections; missed full-SID label forms | Label-scoped pattern incl. `S-1-16-12288/16384` and low label `LW / S-1-16-4096` | Verified statically |
| 12 | Controlled Folder Access: only mode `1` handled | Audit mode (2) silently ignored | Audit mode reported as INFO with the enforcement warning | Verified statically |
| 13 | `Get-Item -Stream *` unguarded | Errors on volumes/streams that don't support it could pollute the run | try/catch around the Mark-of-the-Web lookup | Verified statically |
| 14 | WOW64 finding fired on any process bitness | Implied redirection even for 64-bit failing processes | Wording conditioned on the *failing* process being 32-bit | n/a (text) |

## Causes the draft missed (added)

- **EFS encryption** — with a deny-like symptom no ACL change cures.
- **One component > 255 chars** — fails even with long paths fully enabled.
- **ADS colon** in the name part — previously would have been misreported
  as a plain invalid character.
- **Non-empty directory** on Delete; **target already exists** on Create;
  **a parent component that is a file**.

## Still open / honestly unverified

- Full Windows run (5.1 and 7) across the test matrix: locked DLL,
  TrustedInstaller-owned file, CFA-protected folder, OneDrive placeholder,
  UNC path, FAT USB stick, low-integrity labeled file. This is SEAN's
  on-machine gate, same as every other project.
- Restart Manager struct layout is carried over from the draft unchanged;
  it follows the documented `RM_PROCESS_INFO` layout but has never been
  executed here.
- Effective-permission evaluation remains heuristic: generic rights
  (GenericRead/GenericAll), privilege bypasses (backup/restore), and share
  ACL intersection on the *server* side cannot be fully resolved from the
  client token. The findings say "no matching Allow ACE", not "impossible",
  for that reason.
