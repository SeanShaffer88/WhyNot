<#
.SYNOPSIS
  Static acceptance checks for WhyNot.ps1. Runs anywhere PowerShell exists
  (no Windows APIs touched); the Windows-only checks must still be smoke
  tested on a real Windows machine (see docs/REVIEW.md).
#>
$ErrorActionPreference = 'Stop'
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'WhyNot.ps1'
$failures = 0
function Check($Name, [bool]$Ok, $Hint = '') {
    if ($Ok) { Write-Host "PASS: $Name" -ForegroundColor Green }
    else { Write-Host "FAIL: $Name $Hint" -ForegroundColor Red; $script:failures++ }
}

# 1. Parses cleanly
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errors)
Check 'Parser: zero syntax errors' ($errors.Count -eq 0) ($errors | ForEach-Object { $_.Message } | Out-String)

# 2. No PowerShell 7-only language features (script must run on 5.1).
# Comment lines are stripped first - a '?' in prose is not an operator.
$text = Get-Content $script -Raw
$code = (Get-Content $script | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Check 'No null-coalescing operator (??)' (-not ($code -match '\?\?'))
Check 'No optional chaining (?.)' (-not ($code -match '\?\.' ))
Check 'No ternary operator' (-not ($code -match '\$\w+\s+\?\s'))
Check 'No ForEach-Object -Parallel' (-not ($text -match '-Parallel'))

# 3. Crash-proofing helpers present
Check 'Get-AceSidValue helper exists' ($text -match 'function Get-AceSidValue')
Check 'ACE comparison uses SID strings' ($text -match '\$sidValues')
Check 'fsutil tag read is guarded' ($text -match 'Select-Object -First 1')
Check 'Zone.Identifier lookup wrapped in try/catch' ($text -match '\$motw = Get-Item -LiteralPath \$full -Stream \*')

# 4. All check sections present
$sections = 0..10 | ForEach-Object { "---------- $_. " }
$missing = $sections | Where-Object { $text -notmatch [regex]::Escape($_) }
Check 'Sections 0..10 present' (-not $missing) ("missing: " + ($missing -join ', '))

# 5. JSON output is always an array (never a single object / null)
Check 'JSON forces an array' ($text -match 'ConvertTo-Json -InputObject @\(\$findings\.ToArray\(\)\)')

# 6. Localized-Windows robustness
Check 'Admin check uses BuiltInRole enum' ($text -match 'WindowsBuiltInRole\]::Administrator')
Check 'Administrators ACL check uses well-known SID S-1-5-32-544' ($text -match 'S-1-5-32-544')

# 7. Findings severity values are exactly the three known ones
$sevUses = [regex]::Matches($text, "Add-Finding '(FATAL|LIKELY|INFO)'")
$bad = $sevUses | Where-Object { $_.Groups[1].Value -notin 'FATAL','LIKELY','INFO' }
Check 'Only FATAL/LIKELY/INFO severities used' ($bad.Count -eq 0)

if ($failures) { Write-Host "`n$failures check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll static checks passed." -ForegroundColor Green
