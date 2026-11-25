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

# The sandbox folder of a box (Packages\<container>), from "box files".
# isolated.exe is a GUI-subsystem program, so its output goes through a file.
function Box-Package([string]$Name) {
    $o = Join-Path $env:TEMP "isolated-box-files.txt"
    Start-Process -FilePath $Exe -ArgumentList @("box", "files", "`"$Name`"") -Wait -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError "$o.err" | Out-Null
    $h = (Get-Content $o -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $h) { return $null }
    return (Split-Path (Split-Path $h))
}


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
$fakePkg = Box-Package "SmokeFake"
Write-Host "SmokeFake sandbox folder: $fakePkg"
Check "new boxes get a short sandbox name ($fakePkg)" ("$fakePkg" -match "\\isolated\.b\.[0-9a-f]{8}$")
$code = Run-Sandboxed @("box", "delete", "SmokeFake")
$left = @(@($fakePkg) | Where-Object { $_ -and (Test-Path $_) }).Count
Check "deleting a box removes it and its files (exit $code, $left left)" (($code -eq 0) -and -not (Test-Path $boxFile) -and ($left -eq 0))

# 10b. Containers: an empty box made from scratch keeps what its apps save in
#      its own folder (not the real user folders), has internet, and the
#      internet switch blocks it again.
$code = Run-Sandboxed @("box", "create", "SmokeC")
Check "container is created (exit $code)" (($code -eq 0) -and (Test-Path (Join-Path $boxesDir "SmokeC.toml")))
$realDoc = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "isolated-creation.txt"
Remove-Item $realDoc -ErrorAction SilentlyContinue
$code = Run-Sandboxed @("container", "run", "SmokeC", $cmd, "/d", "/c", "echo made> %USERPROFILE%\Documents\isolated-creation.txt")
$pkg = Get-Item (Box-Package "SmokeC") -ErrorAction SilentlyContinue
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
        Get-Item (Box-Package "HelloSmoke") -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -Recurse -Path $_.FullName -Filter "Setup Log*.txt" -ErrorAction SilentlyContinue } |
            ForEach-Object { Write-Host "--- $($_.FullName)"; Get-Content $_.FullName | Out-Host }
        Get-Item (Box-Package "HelloSmoke") -ErrorAction SilentlyContinue |
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
    Check "temporary drive letter is removed ($drives)" (-not ((subst) -match "isolated\.b"))
    Run-Sandboxed @("box", "delete", "HelloSmoke") | Out-Null
} else {
    Write-Host "SKIP  Inno Setup is not available on this machine"
}

# 12. A real .msi package is unpacked into a box (no Windows Installer
#     service involved) and the program from its Start menu shortcut is saved.
$msi = Join-Path $instDir "7z2408-x64.msi"
$sevenZipWasThere = Test-Path "$env:ProgramFiles\7-Zip\7zFM.exe"
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

# 14. An isolated folder: a program inside it can read and change the other
#     files in the folder (and subfolders), and nothing outside it.
$isoDir = Join-Path $env:USERPROFILE "isolated-smoke-folder"
Remove-Item -Recurse -Force $isoDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$isoDir\bin", "$isoDir\data" | Out-Null
Copy-Item $cmd "$isoDir\bin\cmd.exe"
Set-Content -Path "$isoDir\data\in.txt" -Value "folder file"
$code = Run-Sandboxed @("folder", "add", $isoDir)
Check "folder add isolates a folder (exit $code)" ($code -eq 0)
$code = Run-Sandboxed @("run", "--", "$isoDir\bin\cmd.exe", "/d", "/c", "type `"$isoDir\data\in.txt`" > `"$isoDir\out.txt`"")
Check "program in an isolated folder can read and write the folder (exit $code)" (($code -eq 0) -and ((Get-Content "$isoDir\out.txt" -ErrorAction SilentlyContinue) -match "folder file"))
$code = Run-Sandboxed @("run", "--", "$isoDir\bin\cmd.exe", "/d", "/c", "type `"$secret`"")
Check "program in an isolated folder cannot read files outside it (exit $code)" ($code -ne 0)
# What a program in an isolated folder sees as its user folders (Unity games
# save to LocalAppDataLow and quit when they cannot).
Copy-Item $Exe "$isoDir\bin\probe.exe"
$code = Run-Sandboxed @("run", "--", "$isoDir\bin\probe.exe", "diag-folders", "$isoDir\diag.txt")
Write-Host "Known folders inside an isolated folder (exit $code):"
Get-Content "$isoDir\diag.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
# Games save deep below LocalLow; the sandbox's part of the path must stay
# short or their saves pass Windows' 260-character limit.
$lowPath = ((Get-Content "$isoDir\diag.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "^LocalAppDataLow = " }) -replace "^LocalAppDataLow = ", "" -replace " \(writable.*$", "")
Check "LocalLow path inside an isolated folder is short ($($lowPath.Length) chars)" (($lowPath.Length -gt 0) -and ($lowPath.Length -le 125))
foreach ($kf in @("LocalAppDataLow", "LocalAppData")) {
    $line = Get-Content "$isoDir\diag.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "^$kf = " }
    Check "$kf is the sandbox's own writable folder ($line)" (("$line" -match "writable: true") -and ("$line" -match "\\Packages\\isolated\."))
}
# Users add their existing saves through the folder's private files: what
# "folder files" calls App data must be the LocalLow the program sees.
# isolated.exe is a GUI-subsystem program: PowerShell neither waits for it
# nor captures its output with "&", so redirect to a file.
Start-Process -FilePath $Exe -ArgumentList @("folder", "files", "`"$isoDir`"") -Wait -NoNewWindow -RedirectStandardOutput "$isoDir\files.txt" -RedirectStandardError "$isoDir\files-err.txt" | Out-Null
$filesOut = @(Get-Content "$isoDir\files.txt", "$isoDir\files-err.txt" -ErrorAction SilentlyContinue)
Write-Host "folder files:"; $filesOut | ForEach-Object { Write-Host "    $_" }
$appData = (($filesOut | Where-Object { "$_" -match "^App data .*: " }) -replace "^App data .*?: ", "")
Check "folder files shows App data as the program's LocalLow ($appData)" (("$appData" -ne "") -and ("$appData" -ieq "$lowPath"))
if ("$appData" -ne "") {
    New-Item -ItemType Directory -Force -Path "$appData\SmokeCo\SmokeGame" | Out-Null
    Set-Content -Path "$appData\SmokeCo\SmokeGame\save.txt" -Value "old save"
    $code = Run-Sandboxed @("run", "--", "$isoDir\bin\cmd.exe", "/d", "/c", "type `"$lowPath\SmokeCo\SmokeGame\save.txt`" > `"$isoDir\save-out.txt`"")
    Check "program in an isolated folder reads a save added to its App data (exit $code)" ((Get-Content "$isoDir\save-out.txt" -ErrorAction SilentlyContinue) -match "old save")
}
$acl = (icacls $isoDir) -join "`n"
Check "isolated folder grants are removed afterwards" (-not ($acl -match "S-1-15-2-"))
$code = Run-Sandboxed @("folder", "remove", $isoDir)
Check "folder remove stops isolating (exit $code)" ($code -eq 0)
$code = Run-Sandboxed @("run", "--", "$isoDir\bin\cmd.exe", "/d", "/c", "echo x> `"$isoDir\after.txt`"")
Check "after folder remove the program can no longer change the folder (exit $code)" (-not (Test-Path "$isoDir\after.txt"))
Remove-Item -Recurse -Force $isoDir -ErrorAction SilentlyContinue

function Run-Timed([string[]]$IsolatedArgs, [int]$Seconds) {
    $quoted = $IsolatedArgs | ForEach-Object { if ($_ -eq "" -or $_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $p = Start-Process -FilePath $Exe -ArgumentList ($quoted -join " ") -PassThru -WindowStyle Hidden
    if ($p.WaitForExit($Seconds * 1000)) { return $p.ExitCode }
    $p.Kill()
    return "timeout"
}

# 15. A setup .exe that wraps .msi packages (a WiX bundle) is unpacked into
#     a box: it could not reach Windows Installer from inside the sandbox.
$burn = Join-Path $instDir "wix314.exe"
& $curl -sSL -m 300 -o $burn "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314.exe"
if ((Test-Path $burn) -and ((Get-Item $burn).Length -gt 10MB)) {
    $code = Run-Timed @("box", "install", "--no-net", "--box", "SmokeBurn", "--", $burn) 600
    $boxText = (Get-Content (Join-Path $boxesDir "SmokeBurn.toml") -Raw -ErrorAction SilentlyContinue)
    Write-Host $boxText
    Check "setup .exe wrapping .msi packages installs into a box (exit $code)" (("$code" -eq "0") -and ($boxText -match "path = "))
    $m = [regex]::Match("$boxText", 'path = ["'']([^"'']*\\(candle|light|heat)\.exe)["'']')
    if ($m.Success) {
        $tool = $m.Groups[1].Value -replace '\\\\', '\'
        $code = Run-Timed @("box", "run", "SmokeBurn", $tool, "-?") 120
        Check "program from the bundle runs in its box (exit $code)" ("$code" -ne "timeout")
    }
    Run-Sandboxed @("box", "delete", "SmokeBurn") | Out-Null
} else {
    Write-Host "SKIP  could not download the WiX bundle"
}

# 16. A setup program that hands an .msi to Windows Installer: the package
#     is caught while the setup runs and unpacked when Windows Installer
#     fails inside the sandbox.
if ((Test-Path $msi) -and ((Get-Item $msi).Length -gt 1MB)) {
    $wrap = Join-Path $instDir "msi-setup.cmd"
    Set-Content -Path $wrap -Value "@echo off`r`ncopy /y `"$msi`" `"%TEMP%\payload.msi`"`r`n`"%SystemRoot%\System32\msiexec.exe`" /i `"%TEMP%\payload.msi`" /qn`r`necho msiexec exit %ERRORLEVEL%> `"%USERPROFILE%\msiexec-exit.txt`"`r`ndel `"%TEMP%\payload.msi`"`r`n"
    $code = Run-Timed @("box", "install", "--no-net", "--box", "SmokeCatch", "--", $wrap) 600
    $boxText = (Get-Content (Join-Path $boxesDir "SmokeCatch.toml") -Raw -ErrorAction SilentlyContinue)
    Write-Host $boxText
    $pkgCatch = Box-Package "SmokeCatch"
    if ($pkgCatch) { Write-Host "Inside the sandbox: $(Get-Content (Join-Path $pkgCatch 'AC\Home\msiexec-exit.txt') -ErrorAction SilentlyContinue)" }
    Check "package handed to Windows Installer is caught and unpacked (exit $code)" (("$code" -eq "0") -and ($boxText -match "7zFM\.exe"))
    Check "Windows Installer did not install 7-Zip on the PC" (-not (Test-Path "$env:ProgramFiles\7-Zip\7zFM.exe") -or $sevenZipWasThere)
    Run-Sandboxed @("box", "delete", "SmokeCatch") | Out-Null
}

# 17. A portable app shipped as a .zip installs into a box.
$zipSrc = Join-Path $instDir "PortableTool"
New-Item -ItemType Directory -Force -Path "$zipSrc\data" | Out-Null
Copy-Item $cmd "$zipSrc\tool.exe"
Set-Content -Path "$zipSrc\data\readme.txt" -Value "hello"
$zip = Join-Path $instDir "PortableTool-1.0-win64.zip"
Compress-Archive -Path $zipSrc -DestinationPath $zip -Force
$code = Run-Sandboxed @("box", "install", "--no-net", "--box", "SmokeZip", "--", $zip)
$boxText = (Get-Content (Join-Path $boxesDir "SmokeZip.toml") -Raw -ErrorAction SilentlyContinue)
Write-Host $boxText
Check ".zip portable app installs into a box (exit $code)" (($code -eq 0) -and ($boxText -match "tool\.exe"))
$code = Run-Sandboxed @("box", "run", "SmokeZip", "tool", "/d", "/c", "exit 4")
Check "app from the .zip runs from its box (exit $code)" ($code -eq 4)

# 18. Apps in a box get the box's own copy of the folders shared by all
#     users, and HOME points into the box.
$pkgZip = Box-Package "SmokeZip"
$code = Run-Sandboxed @("box", "run", "SmokeZip", "tool", "/d", "/c", "echo %ProgramData%^|%PUBLIC%^|%HOME%> %USERPROFILE%\env.txt & echo x> %ProgramData%\probe.txt")
$envLine = Get-Content (Join-Path "$pkgZip" "AC\Home\env.txt") -ErrorAction SilentlyContinue
Write-Host "Box environment: $envLine"
Check "box apps can write their own ProgramData (exit $code)" (($code -eq 0) -and (Test-Path (Join-Path "$pkgZip" "AC\ProgramData\probe.txt")))
Check "HOME points into the box ($envLine)" ("$envLine" -match [regex]::Escape("$pkgZip"))
$code = Run-Sandboxed @("box", "run", "SmokeZip", $Exe, "diag-folders", "diag.txt")
Write-Host "Known folders inside a box (exit $code):"
Get-Content (Join-Path "$pkgZip" "AC\Home\diag.txt") -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
Run-Sandboxed @("box", "delete", "SmokeZip") | Out-Null

# 19. AI apps: runtimes they are built on work in a container with internet,
#     and keep their dotfolders inside it.
$code = Run-Sandboxed @("box", "create", "SmokeAI", "--net")
$pkgAI = Box-Package "SmokeAI"
$aiHome = Join-Path "$pkgAI" "AC\Home"
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if ($node -and (Test-Path $aiHome)) {
    Set-Content -Path "$aiHome\probe.js" -Value @'
const fs = require('fs'), os = require('os'), path = require('path');
fs.mkdirSync(path.join(os.homedir(), '.cache', 'probe'), { recursive: true });
fs.writeFileSync(path.join(os.homedir(), '.cache', 'probe', 'node.txt'), os.homedir());
fetch('https://github.com').then(r => process.exit(r.ok ? 0 : 9), e => { fs.writeFileSync('node-error.txt', String(e && (e.cause || e))); process.exit(8); });
'@
    $code = Run-Timed @("box", "run", "SmokeAI", $node, "probe.js") 120
    Write-Host "node error: $(Get-Content "$aiHome\node-error.txt" -ErrorAction SilentlyContinue)"
    if ("$code" -ne "0") {
        # The sandbox can read node.exe's own folder only when node is the
        # program started, so run a copy from inside the container to see
        # its error output.
        Copy-Item $node "$aiHome\node.exe"
        Run-Timed @("box", "run", "SmokeAI", $cmd, "/d", "/c", "node.exe probe.js > node-out.txt 2>&1") 120 | Out-Null
        Get-Content "$aiHome\node-out.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    node: $_" }
    }
}
if ($node -and (Test-Path $aiHome)) {
    Remove-Item "$aiHome\.cache\probe\node.txt" -ErrorAction SilentlyContinue
    $code = Run-Timed @("box", "run", "SmokeAI", $node, "--preserve-symlinks", "--preserve-symlinks-main", "probe.js") 120
    Write-Host "INFO  Node with --preserve-symlinks: exit $code, home file $(Test-Path "$aiHome\.cache\probe\node.txt")"
    Set-Content -Path "$aiHome\walk.js" -Value @'
const fs = require('fs'), path = require('path');
let p = process.cwd(), parts = [];
while (true) { parts.unshift(p); const q = path.dirname(p); if (q === p) break; p = q; }
const out = parts.map(x => { try { fs.lstatSync(x); return 'ok ' + x; } catch (e) { return e.code + ' ' + x; } });
try { out.push('realpath.native ' + fs.realpathSync.native(process.cwd())); } catch (e) { out.push('realpath.native ' + e.code); }
fs.writeFileSync('walk.txt', out.join('\n'));
'@
    Run-Timed @("box", "run", "SmokeAI", $node, "--preserve-symlinks", "--preserve-symlinks-main", "walk.js") 60 | Out-Null
    Write-Host "Which parent folders a sandboxed program can look at:"
    Get-Content "$aiHome\walk.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
}
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if ($python -and (Test-Path $aiHome)) {
    Set-Content -Path "$aiHome\probe.py" -Value @'
import pathlib, urllib.request, sys, traceback
d = pathlib.Path.home() / ".config" / "probe"
d.mkdir(parents=True, exist_ok=True)
(d / "python.txt").write_text(str(pathlib.Path.home()))
try:
    sys.exit(0 if urllib.request.urlopen("https://github.com", timeout=30).status == 200 else 9)
except Exception:
    pathlib.Path("python-error.txt").write_text(traceback.format_exc())
    sys.exit(8)
'@
    $code = Run-Timed @("box", "run", "SmokeAI", $python, "probe.py") 120
    Write-Host "python error: $(Get-Content "$aiHome\python-error.txt" -ErrorAction SilentlyContinue)"
    Check "Python runs in a container, reaches the internet, keeps ~/.config inside (exit $code)" (("$code" -eq "0") -and (Test-Path "$aiHome\.config\probe\python.txt"))
}
$code = Run-Timed @("box", "run", "SmokeAI", $Exe, "diag-loopback", "loop.txt") 60
$loop = (Get-Content "$aiHome\loop.txt" -ErrorAction SilentlyContinue) -join "; "
Write-Host "Loopback inside a container (exit $code): $loop"
Check "programs in a container can talk over localhost ($loop)" (("$loop" -match "same process: Ok") -and ("$loop" -match "other process: Ok\(Some\(0\)\)"))
$variants = @(
    @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "", ""),
    @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "--no-sandbox", ""),
    @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "--disable-crashpad-for-testing", ""),
    @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "--no-sandbox --disable-crashpad-for-testing", ""),
    @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "", "set CHROME_HEADLESS=1&")
)
foreach ($v in $variants) {
    $browser, $extra, $pre = $v
    if (-not (Test-Path $browser)) { continue }
    $name = Split-Path $browser -Leaf
    Remove-Item "$aiHome\shot.png", "$aiHome\b-out.txt" -ErrorAction SilentlyContinue
    $line = "$pre`"$browser`" --headless=new --disable-gpu --enable-logging=stderr --screenshot=shot.png --window-size=800,600 $extra https://example.com > b-out.txt 2>&1"
    $code = Run-Timed @("box", "run", "SmokeAI", $cmd, "/d", "/c", $line) 90
    Write-Host "INFO  Chromium ($name $pre $extra) in a container: exit $code, screenshot $(Test-Path "$aiHome\shot.png")"
    Get-Content "$aiHome\b-out.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "ERROR|FATAL|denied|failed" -and $_ -notmatch "oneauth|Edge LLM" } | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" }
}
# Electron, which most desktop AI apps are built on, unpacked from its .zip
# into a container like a portable app.
$ez = Join-Path $instDir "electron-v33.2.1-win32-x64.zip"
& $curl -sSL -m 300 -o $ez "https://github.com/electron/electron/releases/download/v33.2.1/electron-v33.2.1-win32-x64.zip"
if ((Test-Path $ez) -and ((Get-Item $ez).Length -gt 50MB)) {
    $code = Run-Timed @("box", "install", "--box", "SmokeAI", "--", $ez) 300
    $boxText = (Get-Content (Join-Path $boxesDir "SmokeAI.toml") -Raw -ErrorAction SilentlyContinue)
    $m = [regex]::Match("$boxText", 'path = ["'']([^"'']*\\electron\.exe)["'']')
    Write-Host "Electron unpacked (exit $code): $($m.Groups[1].Value)"
    New-Item -ItemType Directory -Force -Path "$aiHome\eapp" | Out-Null
    Set-Content -Path "$aiHome\eapp\package.json" -Value '{"name":"probe","main":"main.js"}'
    Set-Content -Path "$aiHome\eapp\main.js" -Value @'
const { app, BrowserWindow } = require('electron');
const fs = require('fs'), path = require('path'), os = require('os');
const target = process.argv.find((a) => a.endsWith('.txt')) || path.join(os.homedir(), 'electron.txt');
const out = (t) => fs.writeFileSync(target, t);
setTimeout(() => { out('timeout'); app.exit(4); }, 60000);
app.whenReady().then(async () => {
  const w = new BrowserWindow({ show: false });
  await w.loadURL('https://example.com');
  out('title ' + await w.webContents.executeJavaScript('document.title'));
  app.quit();
}).catch((e) => { out('error ' + e); app.exit(3); });
'@
    # Can a program inside the container start other programs stored in it?
    # (Electron apps start copies of themselves; CLI agents start tools.)
    $aiTemp = Join-Path (Split-Path $aiHome) "Temp"
    Copy-Item $node "$aiTemp\node4.exe"
    $electronPath = if ($m.Success) { $m.Groups[1].Value -replace '\\\\', '\' } else { "" }
    Set-Content -Path "$aiHome\spawn.py" -Value @"
import subprocess, os, shutil, traceback
res = []
def t(name, path, arg='-v'):
    try:
        r = subprocess.run([path, arg], capture_output=True, timeout=60)
        res.append(name + ': ok ' + str(r.returncode))
    except Exception as e:
        res.append(name + ': ' + repr(e))
home = os.environ['USERPROFILE']; temp = os.environ['TEMP']
t('outside copy in Home', home + r'\node.exe')
try:
    shutil.copy(home + r'\node.exe', home + r'\node2.exe'); t('inside copy in Home', home + r'\node2.exe')
    shutil.copy(home + r'\node.exe', temp + r'\node3.exe'); t('inside copy in Temp', temp + r'\node3.exe')
except Exception as e:
    res.append('copy: ' + repr(e))
t('outside copy in Temp', temp + r'\node4.exe')
t('system whoami', os.environ['SystemRoot'] + r'\System32\whoami.exe', '/user')
if r'$electronPath':
    t('unpacked electron', r'$electronPath', '--version')
open('spawn.txt', 'w').write('\n'.join(res))
"@
    $code = Run-Timed @("box", "run", "SmokeAI", $python, "spawn.py") 300
    Write-Host "Starting programs from inside a container (exit $code):"
    Get-Content "$aiHome\spawn.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
    foreach ($f in @("$aiHome\node.exe", "$aiHome\node2.exe", "$aiTemp\node3.exe", "$aiTemp\node4.exe")) { icacls $f | Out-Host; (Get-Acl $f -ErrorAction SilentlyContinue).Owner | Out-Host }
    $code = Run-Timed @("box", "run", "SmokeAI", "$aiHome\node.exe", "probe.js") 60
    Write-Host "INFO  node.exe copy started directly: exit $code"
    if ($m.Success) {
        $electron = $m.Groups[1].Value -replace '\\\\', '\'
        foreach ($extra in @("", "--no-sandbox")) {
            Remove-Item "$aiHome\electron.txt", "$aiHome\e-out.txt" -ErrorAction SilentlyContinue
            $code = Run-Timed @("box", "run", "SmokeAI", $cmd, "/d", "/c", "set ELECTRON_ENABLE_LOGGING=1& `"$electron`" $extra eapp > e-out.txt 2>&1") 120
            Write-Host "INFO  Electron ($extra) in a container: exit $code, result: $(Get-Content "$aiHome\electron.txt" -ErrorAction SilentlyContinue)"
            Get-Content "$aiHome\e-out.txt" -ErrorAction SilentlyContinue | Where-Object { $_ -match "ERROR|FATAL|denied|failed" } | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" }
        }
    }
} else {
    Write-Host "SKIP  could not download Electron"
}
# Node needs to see that C:\ and C:\Users are folders; system-compat lets
# sandboxes read only their attributes (the runner is an administrator).
if ($node -and (Test-Path $aiHome)) {
    & $Exe system-compat | Out-Host
    $acl = (Get-Acl "C:\").Access | Where-Object { "$($_.IdentityReference)" -match "APPLICATION PACKAGE" } | ForEach-Object { "$($_.FileSystemRights) $($_.InheritanceFlags)" }
    Write-Host "C:\ entries for app packages: $($acl -join '; ')"
    $code = Run-Timed @("box", "run", "SmokeAI", $node, "probe.js") 120
    Check "Node runs in a container after system-compat (exit $code)" ("$code" -eq "0")
    Set-Content -Path "$aiHome\spawn.js" -Value @'
const fs = require('fs');
const r = require('child_process').spawnSync(process.execPath, ['-e', 'console.log("child-ok")'], { encoding: 'utf8', timeout: 20000 });
fs.writeFileSync('node-spawn.txt', String(r.stdout || r.error));
'@
    $code = Run-Timed @("box", "run", "SmokeAI", $node, "spawn.js") 60
    Write-Host "INFO  Node child process with pipes in a container: exit $code, $(Get-Content "$aiHome\node-spawn.txt" -ErrorAction SilentlyContinue)"
}
# The compatible tier (low integrity, no AppContainer) can create named
# pipes, which Chromium, Electron and Node's child processes need.
$low = Join-Path $env:USERPROFILE "AppData\LocalLow\IsolatedSmoke"
New-Item -ItemType Directory -Force -Path $low | Out-Null
icacls $low /setintegritylevel "(OI)(CI)low" | Out-Null
if ($node) {
    Set-Content -Path "$low\spawn.js" -Value @'
const fs = require('fs'), path = require('path');
const r = require('child_process').spawnSync(process.execPath, ['-e', 'console.log("child-ok")'], { encoding: 'utf8', timeout: 30000 });
fs.writeFileSync(path.join(__dirname, 'node-low.txt'), String(r.stdout || r.error));
'@
    $code = Run-Timed @("run", "--compatible", "--accept-weaker", "--no-ask", "--", $node, "$low\spawn.js") 60
    $t = Get-Content "$low\node-low.txt" -ErrorAction SilentlyContinue
    Write-Host "INFO  Node with a child process in the compatible tier: exit $code, $t"
}
# Without --no-sandbox: Isolated should spot Chrome and Edge and add it.
foreach ($browser in @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Google\Chrome\Application\chrome.exe")) {
    if (-not (Test-Path $browser)) { continue }
    Remove-Item "$low\shot.png" -ErrorAction SilentlyContinue
    $code = Run-Timed @("run", "--compatible", "--accept-weaker", "--no-ask", "--", $browser, "--headless=new", "--disable-gpu", "--screenshot=$low\shot.png", "--window-size=800,600", "https://example.com") 90
    Check "$(Split-Path $browser -Leaf) runs in the compatible tier (exit $code)" (Test-Path "$low\shot.png")
}
foreach ($v in $variants) {
    $browser, $extra, $pre = $v
    if (-not (Test-Path $browser) -or $pre) { continue }
    Remove-Item "$low\shot.png" -ErrorAction SilentlyContinue
    $args2 = @("run", "--compatible", "--accept-weaker", "--no-ask", "--", $browser, "--headless=new", "--disable-gpu", "--screenshot=$low\shot.png", "--window-size=800,600")
    if ($extra) { $args2 += $extra -split " " }
    $args2 += "https://example.com"
    $code = Run-Timed $args2 90
    Write-Host "INFO  Chromium ($(Split-Path $browser -Leaf) $extra) in the compatible tier: exit $code, screenshot $(Test-Path "$low\shot.png")"
}
if ($m.Success) {
    $electron = $m.Groups[1].Value -replace '\\\\', '\'
    foreach ($extra in @("", "--no-sandbox")) {
        Remove-Item "$low\electron.txt" -ErrorAction SilentlyContinue
        Remove-Item "$low\e-log.txt" -ErrorAction SilentlyContinue
        $line = "$electron $extra --enable-logging=stderr --user-data-dir=$low\ud $aiHome\eapp $low\electron.txt > $low\e-log.txt 2>&1"
        $code = Run-Timed @("run", "--compatible", "--accept-weaker", "--no-ask", "--", "$env:SystemRoot\System32\cmd.exe", "/d", "/c", $line) 90
        Write-Host "INFO  Electron ($extra) in the compatible tier: exit $code, result: $(Get-Content "$low\electron.txt" -ErrorAction SilentlyContinue)"
        Get-Content "$low\e-log.txt" -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" }
    }
}
# Electron in a compatible box, the way users would run an AI desktop app:
# Isolated tells Chromium-based apps to skip their own sandbox there.
if ((Test-Path $ez) -and ((Get-Item $ez).Length -gt 50MB)) {
    $code = Run-Timed @("box", "install", "--profile", "compatible", "--accept-weaker", "--box", "SmokeLow", "--", $ez) 300
    $lowText = (Get-Content (Join-Path $boxesDir "SmokeLow.toml") -Raw -ErrorAction SilentlyContinue)
    $m3 = [regex]::Match("$lowText", 'path = ["'']([^"'']*\\electron\.exe)["'']')
    Write-Host "Electron in a compatible box (exit $code): $($m3.Groups[1].Value)"
    if ($m3.Success) {
        $le = $m3.Groups[1].Value -replace '\\\\', '\'
        Remove-Item "$low\electron-box.txt", "$low\e-box.log" -ErrorAction SilentlyContinue
        $code = Run-Timed @("box", "run", "--accept-weaker", "SmokeLow", $le, "$aiHome\eapp", "$low\electron-box.txt") 120
        $res = Get-Content "$low\electron-box.txt" -ErrorAction SilentlyContinue
        Write-Host "INFO  Electron in a compatible box: exit $code, result: $res"
    }
    Run-Sandboxed @("box", "delete", "SmokeLow") | Out-Null
}
Run-Sandboxed @("box", "delete", "SmokeAI") | Out-Null

# 20. A Tauri app's NSIS installer (Tauri apps run on WebView2). It quits at
#     once in a locked-down box (Isolated then offers the compatible tier)
#     and works in a compatible box.
$tauri = $null
try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/pot-app/pot-desktop/releases/latest" -TimeoutSec 60
    $asset = $rel.assets | Where-Object { $_.name -match "_x64-setup\.exe$" } | Select-Object -First 1
    if ($asset) {
        $tauri = Join-Path $instDir $asset.name
        & $curl -sSL -m 300 -o $tauri $asset.browser_download_url
    }
} catch { Write-Host "SKIP  could not look up a Tauri installer: $_" }
if ($tauri -and (Test-Path $tauri)) {
    foreach ($prof in @("strict", "compatible")) {
        $bn = "SmokeTauri-$prof"
        $code = Run-Timed @("box", "install", "--profile", $prof, "--accept-weaker", "--box", $bn, "--", $tauri, "/S") 300
        $t = Get-Content (Join-Path $boxesDir "$bn.toml") -Raw -ErrorAction SilentlyContinue
        $saved = [regex]::Matches("$t", 'path = ["'']([^"'']*)["'']') | ForEach-Object { $_.Groups[1].Value }
        Write-Host "Tauri NSIS installer in a $prof box: exit $code, apps: $($saved -join ', ')"
        $bf = (& $Exe box files $bn 2>$null | Select-Object -First 1)
        $exes = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Packages"), (Join-Path $env:USERPROFILE "AppData\LocalLow\Isolated") -Recurse -Filter "pot*.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        Write-Host "    pot exes in sandboxes: $($exes -join '; ')"
        Write-Host "    escaped to the real AppData: $(Test-Path (Join-Path $env:LOCALAPPDATA 'pot'))"
        if ($prof -eq "compatible") { Check "Tauri NSIS installer saves its app in a $prof box" ($saved.Count -gt 0) }
        Check "Tauri NSIS installer leaves nothing in the real AppData ($prof box)" (-not (Test-Path (Join-Path $env:LOCALAPPDATA 'pot')))
        Run-Sandboxed @("box", "delete", $bn) | Out-Null
    }
}

# 16. Windows of sandboxed apps are marked: "[Isolated]" in front of the
#     title, and a frame window that follows the active one.
Add-Type -Namespace Smoke -Name Win -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern System.IntPtr FindWindowW(string cls, string title);
'@
$env:ISOLATED_MARKER_TRACE = Join-Path $env:TEMP "isolated-marker.txt"
$watcher = Start-Process -FilePath $Exe -ArgumentList @("run", "--", "$env:SystemRoot\System32\notepad.exe") -PassThru
Remove-Item Env:ISOLATED_MARKER_TRACE
$title = ""
$frame = [System.IntPtr]::Zero
for ($i = 0; $i -lt 30 -and -not $title.StartsWith("[Isolated"); $i++) {
    Start-Sleep -Milliseconds 500
    $np = Get-Process notepad -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object -First 1
    if ($np) { $title = $np.MainWindowTitle }
    $frame = [Smoke.Win]::FindWindowW("IsolatedFrameF5B400", "Isolated")
}
Get-CimInstance Win32_Process -Filter "Name='notepad.exe' OR Name='isolated.exe'" | ForEach-Object { Write-Host "    $($_.ProcessId) parent $($_.ParentProcessId) $($_.CommandLine)" }
Write-Host "    watcher $($watcher.Id) exited: $($watcher.HasExited)"
Get-Content (Join-Path $env:TEMP "isolated-marker.txt") -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object { Write-Host "    $_" }
Check "sandboxed window title is tagged ($title)" ($title.StartsWith("[Isolated] "))
Check "sandbox window frame exists" ($frame -ne [System.IntPtr]::Zero)
Get-Process notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$watcher.WaitForExit(10000) | Out-Null
if (-not $watcher.HasExited) { $watcher.Kill() }

# 8. Right-click menu registers and unregisters.
& $Exe register | Out-Null
Start-Sleep -Milliseconds 500
$reg = Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated\shell\01run\command"
Check "right-click menu is registered" $reg
$folders = (Get-ItemProperty "HKCU:\Software\Classes\exefile\shell\Isolated\shell\03folders\command" -ErrorAction SilentlyContinue).'(default)'
Check "right-click menu has Run in Isolated with folders ($folders)" ("$folders" -match "--ask-folders")
$msiMenu = Test-Path "HKCU:\Software\Classes\Msi.Package\shell\Isolated\shell\06install\command"
Check "right-click menu has Install in Isolated for .msi files" $msiMenu
$folderMenu = (Get-ItemProperty "HKCU:\Software\Classes\Directory\shell\IsolatedFolder\command" -ErrorAction SilentlyContinue).'(default)'
Check "right-click menu has Isolate this folder on folders ($folderMenu)" ("$folderMenu" -match " folder ")
$bgMenu = Test-Path "HKCU:\Software\Classes\Directory\Background\shell\IsolatedFolder\command"
Check "right-click menu has Isolate this folder inside folders" $bgMenu
& $Exe unregister | Out-Null
Start-Sleep -Milliseconds 500
Check "right-click menu is removed" (-not (Test-Path "HKCU:\Software\Classes\exefile\shell\Isolated"))
Check "folder right-click menu is removed" (-not (Test-Path "HKCU:\Software\Classes\Directory\shell\IsolatedFolder"))

Remove-Item -Recurse -Force $secretDir -ErrorAction SilentlyContinue
if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host "All smoke tests passed"
