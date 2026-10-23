# WhyNot — the Windows "Access Denied" Explainer

## TL;DR

Windows tells you *that* a file operation failed (`Access is denied`, `0x80070005`, "the process cannot access the file") but never *why*. WhyNot is a single PowerShell script that takes a path and the operation you tried, runs the known failure causes in one pass, and tells you in plain English which one bit you — with the exact command that fixes it. No dependencies, no installation, and no administrator rights needed for most checks. Works on Windows PowerShell 5.1 and PowerShell 7+.

```powershell
.\WhyNot.ps1 "C:\dev\app\bin\Debug\MyApp.dll" -Op Delete
.\WhyNot.ps1 "C:\Program Files\MyApp\config.json" -Op Write -Json
```

## Why it exists

A failed file operation on Windows can have a dozen unrelated causes — a locked file, a deny entry in the ACL, a reserved DOS device name, a path one character over the old limit, a silent redirection to a per-user virtual store, ransomware protection, a cloud placeholder that was never downloaded. Each cause is diagnosable, but traditionally each one needs a different tool and a different piece of tribal knowledge. WhyNot encodes that knowledge in one place: it checks every cause, ranks what it finds **FATAL / LIKELY / INFO**, and prints the fix next to the finding.

WhyNot is **read-only**. It never changes the file, its permissions, or any setting — the fixes it prints are commands for you to run when you decide to.

## Example output

```text
WhyNot - why can't I DELETE "C:\dev\app\bin\Debug\MyApp.dll"?

  [FATAL ] File is locked by another process
           Open without share-delete/write by:
             PID 18244  Microsoft Visual Studio 2022  [C:\Program Files\...\devenv.exe]
           -> Close that process, or open with FILE_SHARE_DELETE, or use MoveFileEx(...)

  [LIKELY] Controlled Folder Access (ransomware protection)
           Path is in a protected folder and your app isn't allowlisted.
           -> Add-MpPreference -ControlledFolderAccessAllowedApplications "<your.exe>"

  [INFO  ] Your current context
           User: DESKTOP\jane  Elevated: False  64-bit process: True  Session: 1
```

## What it checks

1. **Path syntax traps** — reserved device names (`CON`, `NUL`, `COM1`…), trailing spaces/dots, invalid characters, alternate-data-stream colons, a single name component over 255 characters, and paths over MAX_PATH (including whether long paths are actually enabled *and* whether your app's manifest opts in).
2. **Existence and parent** — missing file, missing parent, a parent component that is actually a file, near-miss names that differ only by case or whitespace, an already-existing target for `Create`, and a non-empty directory for `Delete`.
3. **WOW64 and UAC virtualization** — System32 redirection for 32-bit processes, and silent write redirection to `%LOCALAPPDATA%\VirtualStore` for protected locations (including whether a virtualized copy already exists).
4. **Who has it open** — Restart Manager attribution: the exact processes holding the file, with PIDs and executable paths.
5. **Attributes and reparse points** — read-only attribute, EFS encryption, symlinks/junctions/cloud placeholders, files not yet downloaded, and Mark-of-the-Web.
6. **Effective NTFS permissions** — explicit DENY entries, missing Allow entries for the operation you asked about, TrustedInstaller ownership, the "Administrators are allowed but you are not elevated" case, and the easily missed rule that deletion also needs permission on the parent folder.
7. **Integrity levels** — Mandatory Integrity Control labels that block writes no matter what the ACL says.
8. **Security software** — Controlled Folder Access (enforced and audit modes), including Defender event-log confirmation when a block was recorded.
9. **Volume and share quirks** — non-NTFS volumes, a nearly full disk, a locked BitLocker volume, per-directory case sensitivity, and UNC paths (share + NTFS permissions combined, per-session mapped drives).
10. **Your process context** — user, elevation, bitness, session, and PowerShell version, so a "works for me" result can be compared honestly against a service or scheduled task running under a different token.

## Usage

```powershell
.\WhyNot.ps1 <Path> [-Op Read|Write|Delete|Create|Execute|Rename] [-Json]
```

- `-Op` defaults to `Write`.
- `-Json` emits the findings as a JSON array (always an array, even for zero or one finding) for use in scripts, CI logs, and bug reports.

## Requirements

- Windows 10 or later (also works on Windows Server equivalents).
- Windows PowerShell 5.1 **or** PowerShell 7+.
- Most checks need no elevation. A few results are necessarily "from this token's point of view" — that is stated in the context finding rather than hidden.

## Screenshots

WhyNot is a console tool; its "interface" is its output. A terminal capture of a real run will be added here after the first verified run on a Windows machine — until then, the example output above is representative and no placeholder images are used.

## Verification status

- **Verified:** the script parses with zero errors; a 14-point static acceptance suite passes (`tests/Test-WhyNotStatic.ps1`), including checks that no PowerShell 7-only syntax crept in; the path-syntax findings (reserved names, trailing dots, over-long components) were exercised end-to-end under PowerShell 7.
- **Unverified:** a full run on a real Windows machine under both Windows PowerShell 5.1 and PowerShell 7 — the Windows-only checks (Restart Manager, ACL evaluation, Defender, BitLocker, volume queries) can only be proven there. See `docs/REVIEW.md` for the audit trail.

## Roadmap

Ideas recorded for later versions, none of them required for the tool to be useful today:

- `-Registry` mode — the same diagnosis idea for registry key access failures.
- `-Pid <n>` — evaluate against another process's token, the most common reason a check "passes for me, fails as a service".
- `-Watch` mode — react to access-denied events as they happen and run the diagnosis immediately.

## License

MIT — see `LICENSE`.
