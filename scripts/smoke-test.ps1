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

# 9. The sandbox's LocalAppData exists and is writable (Windows moves it for
#    AppContainers; installers and apps rely on it).
$code = Run-Sandboxed @("run", "--rw", $secretDir, "--", $cmd, "/d", "/c", "echo %LOCALAPPDATA%> `"$secretDir\lad.txt`" & echo x> `"%LOCALAPPDATA%\probe.txt`"")
Write-Host "LOCALAPPDATA in sandbox: $(Get-Content "$secretDir\lad.txt" -ErrorAction SilentlyContinue)"
Check "LocalAppData inside the sandbox is writable (exit $code)" ($code -eq 0)

# 10. Installing into a box keeps the app, and it runs again later.
$boxesDir = Join-Path $env:APPDATA "Isolated\boxes"
$instDir = Join-Path $env:RUNNER_TEMP "isolated-installers"
if (-not $env:RUNNER_TEMP) { $instDir = Join-Path $env:TEMP "isolated-installers" }
New-Item -ItemType Directory -Force -Path $instDir | Out-Null
$fake = Join-Path $instDir "fake-setup.cmd"
Set-Content -Path $fake -Value "@echo off`r`nmkdir `"%LOCALAPPDATA%\Programs\Fake`"`r`ncopy /y `"%SystemRoot%\System32\cmd.exe`" `"%LOCALAPPDATA%\Programs\Fake\fake.exe`"`r`n"
$code = Run-Sandboxed @("box", "install", "--no-net", "--box", "SmokeFake", "--", $fake)
$boxFile = Join-Path $boxesDir "SmokeFake.toml"
$boxText = (Get-Content $boxFile -Raw -ErrorAction SilentlyContinue)
Write-Host $boxText
Check "script installer saved its app in the box (exit $code)" (($code -eq 0) -and ($boxText -match "fake\.exe"))
$code = Run-Sandboxed @("box", "run", "SmokeFake", "fake", "/d", "/c", "exit 7")
Check "saved app runs from the box later (exit $code)" ($code -eq 7)
$code = Run-Sandboxed @("box", "run", "SmokeFake", "fake", "/d", "/c", "type `"$secret`"")
Check "apps in a box still can't read user files (exit $code)" ($code -ne 0)
$code = Run-Sandboxed @("box", "delete", "SmokeFake")
$left = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Packages") -Filter "isolated.box.SmokeFake*" -ErrorAction SilentlyContinue).Count
Check "deleting a box removes it and its files (exit $code, $left left)" (($code -eq 0) -and -not (Test-Path $boxFile) -and ($left -eq 0))

# 10b. Containers: an empty box made from scratch keeps what its apps save in
#      its own folder (not the real user folders), has internet, and the
#      internet switch blocks it again.
$code = Run-Sandboxed @("box", "create", "SmokeC")
Check "container is created (exit $code)" (($code -eq 0) -and (Test-Path (Join-Path $boxesDir "SmokeC.toml")))
$realDoc = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "isolated-creation.txt"
Remove-Item $realDoc -ErrorAction SilentlyContinue
$code = Run-Sandboxed @("container", "run", "SmokeC", $cmd, "/d", "/c", "echo made> %USERPROFILE%\Documents\isolated-creation.txt")
$pkg = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Packages") -Filter "isolated.box.SmokeC*" -ErrorAction SilentlyContinue | Select-Object -First 1
$inBox = $pkg -and (Test-Path (Join-Path $pkg.FullName "AC\Home\Documents\isolated-creation.txt"))
Check "a file an app saves lands in the container, not the PC (exit $code)" (($code -eq 0) -and $inBox -and -not (Test-Path $realDoc))
$code = Run-Sandboxed @("box", "run", "SmokeC", $cmd, "/d", "/c", "cd> %USERPROFILE%\cwd.txt")
$cwd = if ($pkg) { Get-Content (Join-Path $pkg.FullName "AC\Home\cwd.txt") -ErrorAction SilentlyContinue } else { "" }
Check "programs from the PC start in the container's user folder ($cwd)" ("$cwd" -match "\\AC\\Home$")
# Sandboxes cannot write to NUL, so save the page in the container's user
# folder, where programs from the PC start.
$code = Run-Sandboxed @("box", "run", "SmokeC", $curl, "-s", "-m", "30", "-o", "page.html", "https://github.com")
$page = if ($pkg) { Join-Path $pkg.FullName "AC\Home\page.html" } else { "" }
Check "container has internet and the download lands in it (exit $code)" (($code -eq 0) -and $page -and (Test-Path $page))
$code = Run-Sandboxed @("box", "net", "SmokeC", "off")
$code2 = Run-Sandboxed @("box", "run", "SmokeC", $curl, "-s", "-m", "15", "-o", "NUL", "https://github.com")
Check "internet switch blocks the container (exit $code, curl $code2)" (($code -eq 0) -and ($code2 -ne 0))
$code = Run-Sandboxed @("box", "run", "SmokeC", $cmd, "/d", "/c", "type `"$secret`"")
Check "apps in a container can't read user files (exit $code)" ($code -ne 0)
$code = Run-Sandboxed @("box", "delete", "SmokeC")
Check "container is deleted (exit $code)" (($code -eq 0) -and -not (Test-Path (Join-Path $boxesDir "SmokeC.toml")))

# 11. A real Inno Setup installer that asks for admin rights installs per-user
#     into a box, with its Start menu shortcut found.
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc -and (Get-Command choco -ErrorAction SilentlyContinue)) {
    choco install innosetup -y --no-progress | Out-Null
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ($iscc) {
    $iss = Join-Path $instDir "hello.iss"
    Set-Content -Path $iss -Value @"
[Setup]
AppName=Hello Smoke
AppVersion=1.0
DefaultDirName={autopf}\HelloSmoke
DefaultGroupName=Hello Smoke
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
OutputDir=$instDir
OutputBaseFilename=HelloSmokeSetup
DisableProgramGroupPage=yes
[Files]
Source: "$env:SystemRoot\System32\cmd.exe"; DestDir: "{app}"; DestName: "hello.exe"
[Icons]
Name: "{autoprograms}\Hello Smoke"; Filename: "{app}\hello.exe"
Name: "{autoprograms}\Uninstall Hello Smoke"; Filename: "{uninstallexe}"
"@
    & $iscc /Q $iss | Out-Host
    $setup = Join-Path $instDir "HelloSmokeSetup.exe"
    $code = Run-Sandboxed @("box", "install", "--no-net", "--box", "HelloSmoke", "--", $setup, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG")
    $boxFile = Join-Path $boxesDir "HelloSmoke.toml"
    $boxText = (Get-Content $boxFile -Raw -ErrorAction SilentlyContinue)
    Write-Host $boxText
    $ok = ($code -eq 0) -and ($boxText -match "Hello Smoke") -and ($boxText -match "hello\.exe")
    Check "Inno Setup installer installs into a box (exit $code)" $ok
    if (-not $ok) {
        Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Packages") -Filter "isolated.box.HelloSmoke*" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -Recurse -Path $_.FullName -Filter "Setup Log*.txt" -ErrorAction SilentlyContinue } |
            ForEach-Object { Write-Host "--- $($_.FullName)"; Get-Content $_.FullName | Out-Host }
        Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Packages") -Filter "isolated.box.HelloSmoke*" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -Recurse -File -Path $_.FullName -ErrorAction SilentlyContinue } |
            ForEach-Object { Write-Host "  file $($_.FullName)" }
    }
    $code = Run-Sandboxed @("box", "run", "HelloSmoke", "`"Hello Smoke`"", "/d", "/c", "exit 5")
    Check "Inno-installed app runs from its shortcut entry (exit $code)" ($code -eq 5)
    $uninst = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    Check "installer's uninstall entry is removed afterwards" (-not (Test-Path "$uninst\Hello Smoke_is1"))
    $regAcl = (Get-Acl $uninst).Access | Where-Object { $_.IdentityReference.Value -match "S-1-15-2-" }
    Check "registry grant is removed afterwards" (-not $regAcl)
    $drives = (Get-PSDrive -PSProvider FileSystem).Root -join " "
    Check "temporary drive letter is removed ($drives)" (-not ((subst) -match "isolated.box"))
    Run-Sandboxed @("box", "delete", "HelloSmoke") | Out-Null
} else {
    Write-Host "SKIP  Inno Setup is not available on this machine"
}

# 12. A real .msi package is unpacked into a box (no Windows Installer
#     service involved) and the program from its Start menu shortcut is saved.
$msi = Join-Path $instDir "7z2408-x64.msi"
& $curl -sSL -m 180 -o $msi "https://github.com/ip7z/7zip/releases/download/24.08/7z2408-x64.msi"
if ((Test-Path $msi) -and ((Get-Item $msi).Length -gt 1MB)) {
    $code = Run-Sandboxed @("box", "install", "--no-net", "--box", "SmokeMsi", "--", $msi)
    $boxFile = Join-Path $boxesDir "SmokeMsi.toml"
    $boxText = (Get-Content $boxFile -Raw -ErrorAction SilentlyContinue)
    Write-Host $boxText
    Check ".msi installer unpacks into a box (exit $code)" (($code -eq 0) -and ($boxText -match "7-Zip File Manager") -and ($boxText -match "7zFM\.exe"))
    $m = [regex]::Match("$boxText", 'path = ["'']([^"'']*7zFM\.exe)["'']')
    $sevenZip = (Join-Path (Split-Path ($m.Groups[1].Value -replace '\\\\', '\')) "7z.exe")
    Write-Host "7z.exe in the box: $sevenZip"
    $code = Run-Sandboxed @("box", "run", "SmokeMsi", $sevenZip, "i")
    Check "program unpacked from the .msi runs in its box (exit $code)" ($code -eq 0)
    $code = Run-Sandboxed @("box", "run", "SmokeMsi", $sevenZip, "l", $secret)
    Check "program from the .msi still can't read user files (exit $code)" ($code -ne 0)
    Run-Sandboxed @("box", "delete", "SmokeMsi") | Out-Null
} else {
    Write-Host "SKIP  could not download the 7-Zip .msi"
}

# 13. The "folders" profile asks for folders, but not when folders are given
#     on the command line. (A hang here means the picker opened.)
$p = Start-Process -FilePath $Exe -ArgumentList @("run", "--profile", "folders", "--ro", $secretDir, "--", $cmd, "/d", "/c", "type `"$secret`"") -PassThru -WindowStyle Hidden
if ($p.WaitForExit(60000)) {
    Check "folders profile with a given folder runs without asking (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
} else {
    $p.Kill()
    Check "folders profile with a given folder runs without asking (timed out)" $false
}
$p = Start-Process -FilePath $Exe -ArgumentList @("run", "--profile", "folders", "--no-ask", "--", $cmd, "/d", "/c", "type `"$secret`"") -PassThru -WindowStyle Hidden
if ($p.WaitForExit(60000)) {
    Check "folders profile without folders still hides user files (exit $($p.ExitCode))" ($p.ExitCode -ne 0)
} else {
    $p.Kill()
    Check "folders profile with --no-ask runs without asking (timed out)" $false
}

# 8. Right-click menu registers and unregisters.
& $Exe register | Out-Null
Start-Sleep -Milliseconds 500
$reg = Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated\shell\01run\command"
Check "right-click menu is registered" $reg
$folders = (Get-ItemProperty "HKCU:\Software\Classes\exefile\shell\Isolated\shell\03folders\command" -ErrorAction SilentlyContinue).'(default)'
Check "right-click menu has Run in Isolated with folders ($folders)" ("$folders" -match "--ask-folders")
$msiMenu = Test-Path "HKCU:\Software\Classes\Msi.Package\shell\Isolated\shell\06install\command"
Check "right-click menu has Install in Isolated for .msi files" $msiMenu
& $Exe unregister | Out-Null
Start-Sleep -Milliseconds 500
Check "right-click menu is removed" (-not (Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated"))

Remove-Item -Recurse -Force $secretDir -ErrorAction SilentlyContinue
if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host "All smoke tests passed"
