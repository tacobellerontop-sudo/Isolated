# Sandbox smoke tests on a real Windows machine (run in CI before every
# release). Each check launches a real sandbox and asserts what the program
# inside can and cannot do.
param([string]$Exe = "target\x86_64-pc-windows-msvc\release\isolated.exe")

$ErrorActionPreference = "Stop"
$Exe = (Resolve-Path $Exe).Path
$failures = 0

function Run-Sandboxed([string[]]$IsolatedArgs) {
    $p = Start-Process -FilePath $Exe -ArgumentList $IsolatedArgs -Wait -PassThru -WindowStyle Hidden
    return $p.ExitCode
}

function Check([string]$Name, [bool]$Ok) {
    if ($Ok) { Write-Host "PASS  $Name" } else { Write-Host "FAIL  $Name"; $script:failures++ }
}

$cmd = "$env:SystemRoot\System32\cmd.exe"
$curl = "$env:SystemRoot\System32\curl.exe"
$secretDir = Join-Path $env:USERPROFILE "isolated-smoke"
New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
$secret = Join-Path $secretDir "secret.txt"
Set-Content -Path $secret -Value "do not read me"

& $Exe --version | Out-Host

# PROBE (temporary): where do known folders point inside a sandbox?
$probeDir = Join-Path $env:USERPROFILE "isolated-probe"
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$probeOut = Join-Path $probeDir "out.txt"
$script = Join-Path $probeDir "probe.ps1"
Set-Content -Path $script -Value @"
`$o = @()
foreach (`$f in 'LocalApplicationData','ApplicationData','Programs','Desktop','UserProfile','StartMenu') { `$o += "`$f = " + [Environment]::GetFolderPath(`$f) }
`$o += "env LOCALAPPDATA = `$env:LOCALAPPDATA"
`$o += "env USERPROFILE = `$env:USERPROFILE"
try { New-Item -Path 'HKCU:\Software\IsolatedProbe' -Force -ErrorAction Stop | Out-Null; `$o += 'HKCU write OK' } catch { `$o += "HKCU write failed: `$_" }
try { `$t = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'probe.txt'; Set-Content `$t 'x' -ErrorAction Stop; `$o += "write known LocalAppData OK `$t" } catch { `$o += "write known LocalAppData failed: `$_" }
try { `$t = Join-Path `$env:LOCALAPPDATA 'probe.txt'; Set-Content `$t 'x' -ErrorAction Stop; `$o += "write env LOCALAPPDATA OK" } catch { `$o += "write env LOCALAPPDATA failed: `$_" }
Set-Content -Path '$probeOut' -Value (`$o -join "`r`n")
"@
$code = Run-Sandboxed @("run", "--rw", $probeDir, "--", $ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script)
Write-Host "PROBE exit $code"
Get-Content $probeOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "PROBE $_" }
$code = Run-Sandboxed @("run", "--compatible", "--accept-weaker", "--rw", $probeDir, "--", $ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script)
Write-Host "PROBE compatible exit $code"
Get-Content $probeOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "PROBE(c) $_" }

# 1. Files outside the sandbox are not readable.
$code = Run-Sandboxed @("run", "--", $cmd, "/d", "/c", "type `"$secret`"")
Check "user files are hidden by default (exit $code)" ($code -ne 0)

# 2. A granted folder is readable.
$code = Run-Sandboxed @("run", "--ro", $secretDir, "--", $cmd, "/d", "/c", "type `"$secret`"")
Check "granted read-only folder is readable (exit $code)" ($code -eq 0)

# 3. A read-only grant does not allow writing.
$code = Run-Sandboxed @("run", "--ro", $secretDir, "--", $cmd, "/d", "/c", "echo x> `"$secretDir\new.txt`"")
Check "read-only folder is not writable (exit $code)" (($code -ne 0) -or -not (Test-Path "$secretDir\new.txt"))

# 4. A read-write grant allows writing.
$code = Run-Sandboxed @("run", "--rw", $secretDir, "--", $cmd, "/d", "/c", "echo x> `"$secretDir\rw.txt`"")
Check "read-write folder is writable (exit $code)" (($code -eq 0) -and (Test-Path "$secretDir\rw.txt"))

# 5. Grants are removed after the sandbox exits.
$acl = (icacls $secretDir) -join "`n"
Check "temporary grants are removed afterwards" (-not ($acl -match "S-1-15-2-"))
$journal = Join-Path $env:LOCALAPPDATA "Isolated\journal"
$left = @(Get-ChildItem -Path $journal -Filter *.toml -ErrorAction SilentlyContinue).Count
Check "cleanup journal is empty ($left left)" ($left -eq 0)

# 6. No network by default; network when allowed.
$code = Run-Sandboxed @("run", "--", $curl, "-s", "-m", "15", "-o", "NUL", "https://github.com")
Check "network is blocked by default (exit $code)" ($code -ne 0)
# Write the page into a granted folder: the sandbox's working directory
# (System32 here) is read-only to it, which is what we want.
$page = Join-Path $secretDir "page.html"
$code = Run-Sandboxed @("run", "--net", "--rw", $secretDir, "--", $curl, "-s", "-m", "30", "-o", $page, "https://github.com")
Check "network works when allowed (exit $code)" (($code -eq 0) -and (Test-Path $page))

# 7. Child processes stay in the sandbox: a grandchild can't read the secret either.
$code = Run-Sandboxed @("run", "--", $cmd, "/d", "/c", "$cmd /d /c type `"$secret`"")
Check "child processes inherit the sandbox (exit $code)" ($code -ne 0)

# 8. Right-click menu registers and unregisters.
& $Exe register | Out-Null
Start-Sleep -Milliseconds 500
$reg = Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated\shell\01run\command"
Check "right-click menu is registered" $reg
& $Exe unregister | Out-Null
Start-Sleep -Milliseconds 500
Check "right-click menu is removed" (-not (Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated"))

Remove-Item -Recurse -Force $secretDir -ErrorAction SilentlyContinue
if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host "All smoke tests passed"
