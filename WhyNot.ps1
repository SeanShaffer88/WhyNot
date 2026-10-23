<#
.SYNOPSIS
  WhyNot - Explains why a file/directory operation failed on Windows.
.DESCRIPTION
  Runs the known Windows file-system failure causes in one pass - path syntax
  traps, locks (Restart Manager), NTFS permissions, integrity levels, UAC
  virtualization, Controlled Folder Access, cloud placeholders, volume and
  share quirks - ranks them FATAL / LIKELY / INFO, and prints the exact fix
  for each one it finds.

  Compatible with Windows PowerShell 5.1 and PowerShell 7+. No dependencies.
  No administrator rights required for most checks.
.EXAMPLE
  .\WhyNot.ps1 "C:\Program Files\MyApp\config.json" -Op Write
  .\WhyNot.ps1 ".\build\output.dll" -Op Delete
  .\WhyNot.ps1 "C:\Windows\System32\drivers\etc\hosts" -Op Write -Json
.NOTES
  Version 1.1 - see CHANGELOG.md. Read-only: WhyNot never changes the file,
  its ACL, or any system setting; the fixes it prints are for you to run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position=0)][string]$Path,
    [ValidateSet('Read','Write','Delete','Create','Execute','Rename')][string]$Op = 'Write',
    [switch]$Json
)

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding($Severity, $Cause, $Detail, $Fix) {
    $findings.Add([pscustomobject]@{ Severity=$Severity; Cause=$Cause; Detail=$Detail; Fix=$Fix })
}

# Returns an ACE identity as a SID string ('S-1-5-...'), or $null when the
# identity cannot be translated (orphaned SID from a deleted account is the
# common case). One unresolvable ACE must never abort the whole ACL check.
function Get-AceSidValue($Ace) {
    try {
        $ref = $Ace.IdentityReference
        if ($ref -is [Security.Principal.SecurityIdentifier]) { return $ref.Value }
        return $ref.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

# ---------- Restart Manager P/Invoke: who has this file locked? ----------
if (-not ('WhyNot.RM' -as [type])) {
Add-Type -Namespace WhyNot -Name RM -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct RM_PROCESS_INFO {
  public RM_UNIQUE_PROCESS Process;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string strAppName;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)]  public string strServiceShortName;
  public int ApplicationType; public uint AppStatus; public uint TSSessionId; [MarshalAs(UnmanagedType.Bool)] public bool bRestartable; }
[DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
[DllImport("rstrtmgr.dll")] public static extern int RmEndSession(uint pSessionHandle);
[DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] public static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);
[DllImport("rstrtmgr.dll")] public static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
public static System.Collections.Generic.List<string> WhoLocks(string path) {
  var result = new System.Collections.Generic.List<string>();
  uint handle; string key = Guid.NewGuid().ToString();
  if (RmStartSession(out handle, 0, key) != 0) return result;
  try {
    if (RmRegisterResources(handle, 1, new[]{path}, 0, null, 0, null) != 0) return result;
    uint needed = 0, count = 0, reasons = 0;
    int rc = RmGetList(handle, out needed, ref count, null, ref reasons);
    if (rc == 234 && needed > 0) { // ERROR_MORE_DATA
      var info = new RM_PROCESS_INFO[needed]; count = needed;
      if (RmGetList(handle, out needed, ref count, info, ref reasons) == 0)
        for (int i = 0; i < count; i++) result.Add(info[i].Process.dwProcessId + "|" + info[i].strAppName);
    }
  } finally { RmEndSession(handle); }
  return result;
}
'@
}

# ---------- 0. Normalize ----------
# Resolve relative paths against the caller's directory explicitly.
# (Resolve-Path fails on paths that do not exist yet - exactly the -Op Create
# case - and expands wildcards, so it cannot be the normalizer.)
$raw = $Path
try {
    if ([System.IO.Path]::IsPathRooted($Path)) { $full = [System.IO.Path]::GetFullPath($Path) }
    else { $full = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path)) }
} catch { $full = $Path }
$leaf   = Split-Path $full -Leaf
$parent = Split-Path $full -Parent
$exists = Test-Path -LiteralPath $full
$isDir  = $false
if ($exists) { $isDir = (Get-Item -LiteralPath $full -Force).PSIsContainer }
# BuiltInRole enum, not the string 'Administrators': the string form is
# looked up by name and breaks on localized Windows installations.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------- 1. Path syntax traps ----------
$reserved = 'CON','PRN','AUX','NUL','COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9','LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9'
$stem = ($leaf -split '\.')[0]
if ($reserved -contains $stem.ToUpper()) {
    Add-Finding 'FATAL' 'Reserved device name' "'$stem' is a legacy DOS device name. Win32 maps it to a device regardless of extension or directory." "Rename the file, or access it via the NT namespace prefix: \\?\$full"
}
if ($leaf -match '[\s.]$') {
    Add-Finding 'FATAL' 'Trailing space or dot' "Win32 silently strips trailing dots/spaces, so you are operating on a *different* name than the one on disk." "Use the \\?\ prefix: \\?\$full  - or rename it from WSL/robocopy."
}
if ($leaf.Contains(':')) {
    Add-Finding 'INFO' 'Alternate data stream syntax' "A ':' in the file name part addresses an NTFS alternate data stream (name:stream), not a literal file name." 'If that was not intended, remove the colon - it is not a valid character in a plain file name.'
    $leaf = ($leaf -split ':')[0]
}
if ($leaf.Length -gt 255) {
    Add-Finding 'FATAL' 'Single name component too long' "The file name alone is $($leaf.Length) chars; one path component is limited to 255 chars regardless of long-path support." 'Shorten the file or folder name.'
}
$bad = [System.IO.Path]::GetInvalidFileNameChars() | Where-Object { $leaf.Contains($_) }
if ($bad) { Add-Finding 'FATAL' 'Invalid characters' "Filename contains: $($bad -join ' ')" 'Remove the characters; the API will reject this before touching disk.' }
if ($full.Length -ge 260) {
    $lpObj = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction SilentlyContinue
    $lp = 0
    if ($lpObj) { $lp = $lpObj.LongPathsEnabled }
    $detail = "Path is $($full.Length) chars (MAX_PATH is 260). LongPathsEnabled = $lp."
    $fix = if ($lp -eq 1) { 'Long paths are enabled OS-wide, but your app ALSO needs <longPathAware>true</longPathAware> in its manifest. .NET Core/5+ and Python 3.6+ are opted in; .NET Framework 4.6.1 and older and most C++ apps are not.' }
           else { 'Enable: Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem LongPathsEnabled 1  (+ app manifest), or prefix the path with \\?\' }
    Add-Finding 'LIKELY' 'Path exceeds MAX_PATH' $detail $fix
}

# ---------- 2. Existence & parent ----------
if (-not $exists -and $Op -eq 'Create') {
    if (Test-Path -LiteralPath $parent -PathType Leaf) {
        Add-Finding 'FATAL' 'A parent path component is a file' "'$parent' exists but is a file, not a directory, so nothing can be created under it." 'Fix the path - one of its folder names is actually a file on disk.'
    } elseif (-not (Test-Path -LiteralPath $parent)) {
        Add-Finding 'LIKELY' 'Parent directory missing' "'$parent' does not exist yet. That is normal for Create only if your code creates parents first." 'Create the parent directory first (ERROR_PATH_NOT_FOUND = 3, not 2).'
    }
}
if (-not $exists -and $Op -ne 'Create') {
    if (-not (Test-Path -LiteralPath $parent)) {
        Add-Finding 'FATAL' 'Parent directory missing' "'$parent' does not exist." 'Create the parent first (ERROR_PATH_NOT_FOUND = 3, not 2).'
    } else {
        $siblings = Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $leaf -or $_.Name.Trim() -ieq $leaf.Trim() }
        if ($siblings) { Add-Finding 'LIKELY' 'Near-miss filename' "Found '$($siblings[0].Name)' - differs only by case/whitespace. Is the volume case-sensitive?" "Check: fsutil file queryCaseSensitiveInfo `"$parent`"" }
        else { Add-Finding 'FATAL' 'File does not exist' "Nothing at '$full'." 'Verify the path. Check WOW64 redirection below if this is under System32.' }
    }
}
if ($exists -and $Op -eq 'Create') {
    Add-Finding 'INFO' 'Target already exists' 'The file is already there. Code that creates with CreateNew semantics fails with ERROR_FILE_EXISTS (80); Create/Truncate semantics succeed.' 'Decide which behavior you want and pick the matching creation disposition.'
}
if ($exists -and $isDir -and $Op -eq 'Delete') {
    $children = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue)
    if ($children.Count -gt 0) { Add-Finding 'LIKELY' 'Directory is not empty' "It still contains $($children.Count) item(s). A plain directory delete fails until it is empty." 'Delete or move the contents first, or use a recursive delete deliberately.' }
}

# ---------- 3. WOW64 / UAC virtualization ----------
if ($full -imatch '^[A-Z]:\\Windows\\System32') {
    Add-Finding 'INFO' 'WOW64 redirection zone' 'If the FAILING process is 32-bit on 64-bit Windows, it sees C:\Windows\SysWOW64 when it asks for System32, so the file it reports and the file you see here can differ.' 'From a 32-bit process use C:\Windows\Sysnative\... or call Wow64DisableWow64FsRedirection.'
}
if ($full -imatch '^[A-Z]:\\(Program Files|Program Files \(x86\)|Windows)\\' -and $Op -in 'Write','Create','Delete','Rename') {
    $vstore = Join-Path $env:LOCALAPPDATA "VirtualStore\$($full.Substring(3))"
    $vdetail = 'Non-elevated 32-bit apps without a manifest get writes silently redirected to %LOCALAPPDATA%\VirtualStore. Your "saved" file may be there.'
    if (Test-Path -LiteralPath $vstore) { $vdetail += " >>> A virtualized copy EXISTS at: $vstore" }
    Add-Finding 'LIKELY' 'Protected system location / UAC virtualization' $vdetail 'Write to %APPDATA% or %PROGRAMDATA% instead; or add requestedExecutionLevel to your manifest to disable virtualization and get an honest error.'
}

# ---------- 4. Who has it open? ----------
if ($exists -and -not $isDir -and $Op -in 'Write','Delete','Rename') {
    $lockers = [WhyNot.RM]::WhoLocks($full)
    if ($lockers.Count) {
        $list = $lockers | ForEach-Object { $lockPid, $lockName = $_ -split '\|'; $p = Get-Process -Id $lockPid -ErrorAction SilentlyContinue; "  PID $lockPid  $lockName  [$($p.Path)]" }
        Add-Finding 'FATAL' 'File is locked by another process' ("Open without share-delete/write by:`n" + ($list -join "`n")) 'Close that process, or open with FILE_SHARE_DELETE, or use MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT). Hint: Visual Studio, Defender, OneDrive and the Explorer preview pane are the usual suspects.'
    }
}

# ---------- 5. Attributes & reparse points ----------
if ($exists) {
    $item = Get-Item -LiteralPath $full -Force
    $a = $item.Attributes
    if ($a -band [IO.FileAttributes]::ReadOnly -and $Op -in 'Write','Delete') {
        Add-Finding 'FATAL' 'Read-only attribute' 'The +R attribute blocks DeleteFile and write opens even for Administrators.' "attrib -r `"$full`"   or   Set-ItemProperty -LiteralPath '$full' IsReadOnly `$false"
    }
    if ($a -band [IO.FileAttributes]::Encrypted) {
        Add-Finding 'LIKELY' 'EFS-encrypted file' 'The file is encrypted with EFS. Only the account that holds the encrypting certificate (or a recovery agent) can open it - an ACL Allow does not help.' 'Run cipher /d as the encrypting user to decrypt, or import that user''s EFS certificate (certmgr.msc).'
    }
    if ($a -band [IO.FileAttributes]::ReparsePoint) {
        $tagLine = fsutil reparsepoint query "$full" 2>$null | Select-String 'Tag value' | Select-Object -First 1
        $t = 'fsutil did not report a tag value'
        if ($tagLine) { $t = $tagLine.ToString() }
        Add-Finding 'INFO' 'Reparse point (symlink/junction/OneDrive/AppExecLink)' "Target behavior depends on the tag: $t" 'Operations may apply to the link rather than the target, or fail if the target is a cloud placeholder not yet hydrated. Try: attrib +P (pin) for OneDrive files.'
    }
    if ($a -band [IO.FileAttributes]::Offline -or ($a -band 0x400000)) {  # RECALL_ON_DATA_ACCESS
        Add-Finding 'LIKELY' 'Cloud placeholder (not downloaded)' 'OneDrive/cloud-files placeholder. Opening it triggers a hydration that can fail or block.' 'Mark "Always keep on this device", or open with FILE_FLAG_OPEN_NO_RECALL for metadata-only access.'
    }
    if (-not $isDir) {
        try {
            $motw = Get-Item -LiteralPath $full -Stream * -ErrorAction SilentlyContinue | Where-Object Stream -eq 'Zone.Identifier'
            if ($motw) { Add-Finding 'INFO' 'Mark-of-the-Web present' 'File was downloaded; SmartScreen/Office/PowerShell may refuse to execute or load it.' "Unblock-File -LiteralPath `"$full`"" }
        } catch {}
    }
}

# ---------- 6. Effective NTFS permissions ----------
$target = $full
if (-not $exists) { $target = $parent }
try {
    $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
    $me  = [Security.Principal.WindowsIdentity]::GetCurrent()
    # Compare identities as SID strings: NTAccount->SID translation can fail
    # per-ACE, and SID objects do not reliably survive -contains comparisons.
    $sidValues = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
    $need = switch ($Op) { 'Read'{'Read'} 'Execute'{'ReadAndExecute'} 'Write'{'Write'} 'Create'{'Write'} 'Delete'{'Delete'} 'Rename'{'Delete'} }
    $deny  = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny'  -and $sidValues -contains (Get-AceSidValue $_) -and ($_.FileSystemRights.ToString() -match $need -or $_.FileSystemRights.ToString() -match 'FullControl') })
    $allow = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $sidValues -contains (Get-AceSidValue $_) -and ($_.FileSystemRights.ToString() -match "$need|Modify|FullControl") })
    if ($deny.Count)  { Add-Finding 'FATAL' 'Explicit DENY ACE' ("Denied for: " + ($deny.IdentityReference -join ', ')) "icacls `"$target`" /remove:d `"$($deny[0].IdentityReference)`"" }
    elseif (-not $allow.Count) {
        $owner = $acl.Owner
        $adminAllowed = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and (Get-AceSidValue $_) -eq 'S-1-5-32-544' }).Count -gt 0
        $hint = if ($owner -match 'TrustedInstaller') { 'Owned by TrustedInstaller - this is a protected OS file. Do NOT take ownership in production; use the proper API (e.g. a per-user override location).' }
                elseif (-not $isAdmin -and $adminAllowed) { 'Administrators are allowed and you are not elevated. Re-run elevated, or adjust your installer to grant Users permission.' }
                else { "icacls `"$target`" /grant `"$($me.Name)`":(M)" }
        Add-Finding 'FATAL' "No '$need' permission in ACL" "Owner: $owner. Your token has no matching Allow ACE." $hint
    }
    if ($Op -in 'Delete','Rename' -and $exists) {
        $pacl = Get-Acl -LiteralPath $parent -ErrorAction SilentlyContinue
        $parentAllow = @()
        if ($pacl) { $parentAllow = @($pacl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $sidValues -contains (Get-AceSidValue $_) -and $_.FileSystemRights.ToString() -match 'DeleteSubdirectoriesAndFiles|Modify|FullControl' }) }
        if (-not $parentAllow.Count -and -not $allow.Count) {
            Add-Finding 'LIKELY' 'Delete requires parent permission too' 'Deletion needs DELETE on the file OR DELETE_CHILD on the parent directory. You have neither.' "icacls `"$parent`" /grant `"$($me.Name)`":(M)"
        }
    }
} catch { Add-Finding 'LIKELY' 'Cannot evaluate the ACL' $_.Exception.Message 'Either you lack READ_CONTROL (often a Deny ACE at work), or one ACE identity could not be resolved. Try reading it elevated with: icacls "<path>"' }

# ---------- 7. Integrity level ----------
if ($exists) {
    $sddl = (Get-Acl -LiteralPath $full -ErrorAction SilentlyContinue).Sddl
    if ($sddl -match '\(ML;;[^)]*;(HI|SI|S-1-16-12288|S-1-16-16384)\)') { Add-Finding 'LIKELY' 'High/System integrity label' 'Mandatory Integrity Control blocks writes from medium-integrity (normal) processes regardless of ACL.' 'Run elevated, or relabel: icacls <file> /setintegritylevel M' }
    if ($sddl -match '\(ML;;[^)]*;(LW|S-1-16-4096)\)' -and $Op -eq 'Read') { Add-Finding 'INFO' 'Low-integrity object' 'Readable, but sandboxed (AppContainer/IE Protected Mode) processes may be the intended writers.' '' }
}

# ---------- 8. Security software ----------
try {
    $pref = Get-MpPreference -ErrorAction Stop
    $cfa = $pref.EnableControlledFolderAccess
    if ($cfa -eq 1 -or $cfa -eq 2) {
        $protected = @($pref.ControlledFolderAccessProtectedFolders) + @("$env:USERPROFILE\Documents","$env:USERPROFILE\Pictures","$env:USERPROFILE\Desktop","$env:USERPROFILE\Videos","$env:USERPROFILE\Music","$env:USERPROFILE\Favorites")
        if ($protected | Where-Object { $_ -and $full.StartsWith($_, 'OrdinalIgnoreCase') } ) {
            if ($cfa -eq 2) {
                Add-Finding 'INFO' 'Controlled Folder Access is in AUDIT mode' 'This folder is protected, but CFA is only auditing: it would log, not block, writes by untrusted apps. If your app were untrusted and CFA were fully on, this path would be denied.' 'No action needed while auditing. Plan the allowlist entry before enabling CFA enforcement.'
            } else {
                $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1123,1124} -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object Message -match [regex]::Escape($leaf)
                $sev = 'LIKELY'
                if ($ev) { $sev = 'FATAL' }
                Add-Finding $sev 'Controlled Folder Access (ransomware protection)' ("Path is in a protected folder and your app isn't allowlisted." + $(if($ev){" Defender event 1123 confirms a block at $($ev[0].TimeCreated)."})) 'Add-MpPreference -ControlledFolderAccessAllowedApplications "<your.exe>"  - or ship your app signed; CFA trusts reputation.'
            }
        }
    }
} catch {}

# ---------- 9. Volume & share quirks ----------
$drive = [IO.Path]::GetPathRoot($full)
if ($drive -match '^\\\\') {
    Add-Finding 'INFO' 'UNC / network path' 'Permissions = Share ACL + NTFS ACL (the more restrictive of the two wins). Mapped drives are per-logon-session: an elevated or service process will NOT see your mapped letters.' 'Use the full UNC path from services/elevated code; check: net share (on the server), and EnableLinkedConnections for drive-letter sharing across elevation.'
} else {
    try {
        $vol = Get-Volume -DriveLetter $drive[0] -ErrorAction Stop
        if ($vol.FileSystem -notin 'NTFS','ReFS') { Add-Finding 'INFO' "Non-NTFS volume ($($vol.FileSystem))" 'FAT/exFAT: no ACLs, no symlinks, 4GB file limit, 2-second timestamp granularity, no case sensitivity flags.' '' }
        if ($vol.SizeRemaining -lt 50MB -and $Op -in 'Write','Create') { Add-Finding 'LIKELY' 'Disk nearly full' "$([math]::Round($vol.SizeRemaining/1MB)) MB free." 'ERROR_DISK_FULL (112) often surfaces as a generic IO failure in wrappers.' }
        $bl = Get-BitLockerVolume -MountPoint $drive.TrimEnd('\') -ErrorAction SilentlyContinue
        if ($bl -and $bl.LockStatus -eq 'Locked') { Add-Finding 'FATAL' 'BitLocker volume is locked' '' "Unlock-BitLocker -MountPoint $($drive.TrimEnd('\'))" }
    } catch {}
    if ($exists -and $isDir) {
        $cs = fsutil file queryCaseSensitiveInfo "$full" 2>$null
        if ($cs -match 'is enabled') { Add-Finding 'INFO' 'Case-sensitive directory' 'Per-directory case sensitivity is ON (WSL-created?). CreateFile("Foo") and CreateFile("foo") name different files here.' "fsutil file setCaseSensitiveInfo `"$full`" disable" }
    }
}

# ---------- 10. Process context ----------
Add-Finding 'INFO' 'Your current context' "User: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)  Elevated: $isAdmin  64-bit process: $([Environment]::Is64BitProcess)  Session: $((Get-Process -Id $PID).SessionId)  PowerShell: $($PSVersionTable.PSVersion)" 'If your app runs as a service (Session 0, LocalSystem/LocalService) its profile, mapped drives, and HKCU differ from what you see here.'

# ---------- Output ----------
if ($Json) { ConvertTo-Json -InputObject @($findings.ToArray()) -Depth 4; return }

$order = @{FATAL=0; LIKELY=1; INFO=2}
$sorted = $findings | Sort-Object { $order[$_.Severity] }
Write-Host "`nWhyNot - why can't I $($Op.ToUpper()) `"$full`"?`n" -ForegroundColor Cyan
if (-not ($sorted | Where-Object Severity -in 'FATAL','LIKELY')) {
    Write-Host "  No blocking cause found. The operation should succeed from THIS context." -ForegroundColor Green
    Write-Host "  If it still fails in your app, the difference is the app's token/session (see context below) or it's using a different path than you think - run a file-system trace filtered on non-success results for that path.`n" -ForegroundColor DarkGray
}
foreach ($f in $sorted) {
    $color = switch ($f.Severity) { 'FATAL'{'Red'} 'LIKELY'{'Yellow'} default{'DarkGray'} }
    Write-Host ("  [{0,-6}] {1}" -f $f.Severity, $f.Cause) -ForegroundColor $color
    if ($f.Detail) { $f.Detail -split "`n" | ForEach-Object { Write-Host "           $_" } }
    if ($f.Fix)    { Write-Host "           -> $($f.Fix)" -ForegroundColor Green }
    Write-Host ''
}
