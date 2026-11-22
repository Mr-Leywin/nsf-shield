# NSF Shield build script
#   powershell -ExecutionPolicy Bypass -File build.ps1                      -> builds; portable zip + setup package + SHA256SUMS (dist\)
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Preview             -> also produces screenshots (build\screens)
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Check               -> only checks for compile errors
#   powershell -ExecutionPolicy Bypass -File build.ps1 -VerifyReproducible  -> two fresh UNSIGNED builds; NSFShield.exe, the ZIP and
#                                                                              the Setup are compared one by one (three-output check)
#   -NoSetup : do not produce the Inno Setup package (with -VerifyReproducible: exe and ZIP only, reported as partial)
#
# Reproducible build: csc -deterministic -pathmap, sorted source list, fixed file order and a fixed timestamp
# (SOURCE_DATE_EPOCH environment variable, otherwise the last commit time). Two builds of the same code give the same SHA-256.
# The ZIP and the Setup are made from one package tree (build\package\NSF Shield); SHA256SUMS lists the versioned ZIP, the
# Setup and then every file of that tree (ordinal order) and is checked against the tree and the ZIP after it is written.
#
# Signing hook (inactive for now): if the NSF_SIGN_ARGS environment variable is set, NSFShield.exe and the setup package
# are signed with signtool. Example (once a code signing certificate is available):
#   $env:NSF_SIGNTOOL  = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe'
#   $env:NSF_SIGN_ARGS = '/sha1 <certificate thumbprint> /fd sha256 /tr http://time.certum.pl /td sha256'
param([switch]$Preview, [switch]$Check, [switch]$NoSetup, [switch]$VerifyReproducible)
$ErrorActionPreference = 'Stop'
$root   = $PSScriptRoot
# official engine files (unmodified): GoodbyeDPI 0.2.3rc3, zapret v72.13 (winws), ByeDPI 0.17.3 (ciadpi);
# see third_party\<engine>\README.md
$tp     = Join-Path $root 'third_party\goodbyedpi'
$tz     = Join-Path $root 'third_party\zapret'
$tb     = Join-Path $root 'third_party\byedpi'
$build  = Join-Path $root 'build'
$dist   = Join-Path $root 'dist'
$appDir = Join-Path $build 'package\NSF Shield'
$utf8   = New-Object Text.UTF8Encoding $false

# ---------------------------------------------------------------- version: single source src\Program.cs
$prog = Get-Content (Join-Path $root 'src\Program.cs') -Raw -Encoding UTF8
function Get-Attr([string]$name) { [regex]::Match($prog, '\[assembly: ' + $name + '\("([^"]+)"\)\]').Groups[1].Value }
$asmVer  = Get-Attr 'AssemblyVersion'
$fileVer = Get-Attr 'AssemblyFileVersion'
$infoVer = Get-Attr 'AssemblyInformationalVersion'
if ($asmVer -notmatch '^\d+\.\d+\.\d+\.0$') { throw "src\Program.cs has an invalid AssemblyVersion: '$asmVer' (format: 1.0.0.0)" }
$version = $asmVer.Substring(0, $asmVer.Length - 2)
if ($fileVer -ne $asmVer -or $infoVer -ne $version) {
    throw "Version numbers do not match: AssemblyVersion=$asmVer, AssemblyFileVersion=$fileVer, AssemblyInformationalVersion=$infoVer"
}

# ---------------------------------------------------------------- fixed timestamp
$epoch = $env:SOURCE_DATE_EPOCH
if (-not $epoch) { try { $epoch = (& git -C $root log -1 --format=%ct 2>$null) | Select-Object -First 1 } catch { $epoch = $null } }
if (-not $epoch) { $epoch = '1767225600' }   # 2026-01-01 00:00:00 UTC
$stamp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$epoch)

# ---------------------------------------------------------------- compiler: the .NET SDK version in global.json
$sdkWant = $null
$gj = Join-Path $root 'global.json'
if (Test-Path $gj) { $sdkWant = (Get-Content $gj -Raw | ConvertFrom-Json).sdk.version }
$sdks = @(& dotnet --list-sdks 2>$null) | ForEach-Object {
    if ($_ -match '^(\S+)\s+\[(.+)\]\s*$') { [pscustomobject]@{ Version = $Matches[1]; Dir = (Join-Path $Matches[2] $Matches[1]) } }
} | Where-Object { Test-Path (Join-Path $_.Dir 'Roslyn\bincore\csc.dll') }
if (-not $sdks) { throw '.NET SDK not found (csc.dll). Install the .NET SDK from https://dot.net.' }
$sdk = $sdks | Where-Object { $_.Version -eq $sdkWant } | Select-Object -First 1
if (-not $sdk) {
    $sdk = $sdks | Sort-Object { [version]($_.Version -replace '-.*$', '') } | Select-Object -Last 1
    Write-Warning ".NET SDK $sdkWant not found; using $($sdk.Version) (the output may differ from CI)."
}
Write-Host ">> .NET SDK (csc): $($sdk.Version)"
$buildStart = (Get-Date).ToUniversalTime()
$csc = Join-Path $sdk.Dir 'Roslyn\bincore\csc.dll'
$fw = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
if (-not (Test-Path $fw)) { $fw = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319" }

New-Item -ItemType Directory -Force $build, $dist | Out-Null
$refs = 'mscorlib','System','System.Core','System.Drawing','System.Windows.Forms','System.Xml','System.Xml.Linq',
        'System.ServiceProcess','System.Management','System.Security',
        'System.Web.Extensions','System.IO.Compression','System.IO.Compression.FileSystem' | ForEach-Object { "-r:`"$fw\$_.dll`"" }
# source files in a fixed (ordinal) order
[string[]]$srcFiles = Get-ChildItem (Join-Path $root 'src') -Recurse -Filter *.cs | ForEach-Object { $_.FullName }
[Array]::Sort($srcFiles, [StringComparer]::Ordinal)
$src = $srcFiles | ForEach-Object { "`"$_`"" }

# en.json is embedded too: it is the fallback when the locales folder is missing or a key is not translated
function Invoke-Csc([string]$out, [string[]]$extra) {
    $rsp = Join-Path $build 'csc.rsp'
    $lines = @('-nologo','-nostdlib','-langversion:latest','-target:winexe','-optimize+','-debug-','-deterministic',
               "`"-pathmap:$root=/_/`"", '-platform:anycpu','-nowarn:CS0168,CS0219,CS1998,CS4014', "-out:`"$out`"",
               "`"-resource:$(Join-Path $root 'locales\en.json'),NSFShield.locales.en.json`"") + $extra + $refs + $src
    [IO.File]::WriteAllLines($rsp, $lines, $utf8)
    & dotnet $csc -noconfig "@$rsp"
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $out" }
}

# ---------------------------------------------------------------- signing hook (inactive)
$signArgs = $env:NSF_SIGN_ARGS
$signTool = $null
# the reproducibility proof is made with unsigned builds (a signature carries a timestamp); signed outputs are made afterwards
$signLater = $false
if ($VerifyReproducible -and $signArgs) { $signLater = $true; $signArgs = $null }
if ($signArgs) {
    $signTool = if ($env:NSF_SIGNTOOL) { $env:NSF_SIGNTOOL } else { (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
    if (-not $signTool -or -not (Test-Path $signTool)) { throw 'NSF_SIGN_ARGS is set but signtool.exe was not found (give its path with NSF_SIGNTOOL).' }
}
function Invoke-Sign([string]$file) {
    if (-not $signArgs) { return }
    Write-Host ">> Signing: $file"
    $p = Start-Process $signTool -ArgumentList "sign $signArgs `"$file`"" -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0) { throw "Could not sign: $file" }
    $p = Start-Process $signTool -ArgumentList "verify /pa `"$file`"" -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0) { throw "Signature could not be verified: $file" }
}

function Get-Sha256([string]$file) { (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() }

# runs a preview helper; old outputs are removed first and the exit code is checked (a failure is never hidden by a stale file)
function Invoke-Helper([string[]]$helperArgs, [string]$what, [string[]]$outputs) {
    foreach ($o in $outputs) { if (Test-Path $o) { Remove-Item -Recurse -Force $o } }
    $p = Start-Process $prevExe -ArgumentList $helperArgs -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0) { throw "$what failed (exit code $($p.ExitCode))." }
    foreach ($o in $outputs) { if (-not (Test-Path $o)) { throw "$what did not produce $o." } }
}

# ---------------------------------------------------------------- 0) the sign-in proxy recovery helper
# A tiny separate program (asInvoker, no reference besides mscorlib/System/System.Core, no script host): it restores the Windows
# proxy of the ByeDPI engine at the next sign-in after a power loss. It is built first and deterministically; its SHA-256 goes
# into NSFShield.exe (build\gen\BuildInfo.g.cs -> Integrity.Known), the package (bin), the ZIP, SHA256SUMS and the Setup.
$gen = Join-Path $build 'gen'
if (Test-Path $gen) { Remove-Item -Recurse -Force $gen }
New-Item -ItemType Directory -Force $gen | Out-Null
$recManifest = Join-Path $gen 'recovery.manifest'
$rmf = [IO.File]::ReadAllText((Join-Path $root 'recovery\recovery.manifest'))
$rmf = [regex]::Replace($rmf, '(<assemblyIdentity\s+version=")[^"]*(")', ('${1}' + $asmVer + '${2}'))
[IO.File]::WriteAllText($recManifest, $rmf, $utf8)
$recVer = Join-Path $gen 'RecoveryVersion.g.cs'
[IO.File]::WriteAllText($recVer, ("[assembly: System.Reflection.AssemblyVersion(`"$asmVer`")]`r`n" +
    "[assembly: System.Reflection.AssemblyFileVersion(`"$asmVer`")]`r`n[assembly: System.Reflection.AssemblyInformationalVersion(`"$version`")]`r`n"), $utf8)
$helperName = 'NSFShieldProxyRecovery.exe'
$helperExe = Join-Path $build $helperName
[string[]]$recSrc = @(Get-ChildItem (Join-Path $root 'recovery') -Filter *.cs | ForEach-Object { $_.FullName }) + @((Join-Path $root 'src\Core\ProxyRecovery.cs'), $recVer)
[Array]::Sort($recSrc, [StringComparer]::Ordinal)
$recRsp = Join-Path $build 'csc-recovery.rsp'
$recLines = @('-nologo','-nostdlib','-langversion:latest','-target:winexe','-optimize+','-debug-','-deterministic',
              "`"-pathmap:$root=/_/`"", '-platform:anycpu','-nowarn:CS0168,CS0219', "-out:`"$helperExe`"", "-win32manifest:`"$recManifest`"") +
            @('mscorlib','System','System.Core' | ForEach-Object { "-r:`"$fw\$_.dll`"" }) + @($recSrc | ForEach-Object { "`"$_`"" })
[IO.File]::WriteAllLines($recRsp, $recLines, $utf8)
Remove-Item $helperExe -ErrorAction SilentlyContinue
& dotnet $csc -noconfig "@$recRsp"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $helperExe)) { throw "Build failed: $helperExe" }
Invoke-Sign $helperExe
$helperSha = Get-Sha256 $helperExe
$buildInfo = Join-Path $gen 'BuildInfo.g.cs'
[IO.File]::WriteAllText($buildInfo, ("namespace NSFShield`r`n{`r`n    /// <summary>Generated by build.ps1 (do not edit).</summary>`r`n    static class BuildInfo`r`n    {`r`n" +
    "        /// <summary>SHA-256 of bin\$helperName of this build.</summary>`r`n        public const string RecoveryHelperSha256 = `"$helperSha`";`r`n    }`r`n}`r`n"), $utf8)
$src = @($src) + @("`"$buildInfo`"")
Write-Host ">> Recovery helper: $helperName ($helperSha)"

# ---------------------------------------------------------------- 1) preview build: icon, guide, scripts, screenshots
Write-Host '>> Building the preview...'
$prevExe = Join-Path $build 'NSFShield.preview.exe'
Invoke-Csc $prevExe @('-define:PREVIEW')
# the preview exe reads the language files next to it
$prevLoc = Join-Path $build 'locales'
New-Item -ItemType Directory -Force $prevLoc | Out-Null
Copy-Item (Join-Path $root 'locales\*.json') $prevLoc -Force
# the release check of the workflow, with a fake gh and local files (offline; nothing is sent or published)
$rc = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $root 'tests\release-check.Tests.ps1')`"" -Wait -NoNewWindow -PassThru
if ($rc.ExitCode -ne 0) { throw 'The offline tests of the release check failed (tests\release-check.Tests.ps1).' }
if ($Check) { Write-Host '>> No compile errors.'; return }

$ico = Join-Path $build 'app.ico'
Remove-Item $ico -ErrorAction SilentlyContinue
Invoke-Helper @('--make-icon', "`"$ico`"") 'The icon' @($ico)

if ($Preview) {
    Write-Host '>> Producing screenshots...'
    $shots = Join-Path $build 'screens'
    Remove-Item -Recurse -Force $shots -ErrorAction SilentlyContinue
    Start-Process $prevExe -ArgumentList '--screenshot', "`"$shots`"" -Wait
}

# ---------------------------------------------------------------- 2) release build (the manifest version is set to the exe version)
Write-Host ">> Building the app ($version)..."
if (Test-Path $appDir) { Remove-Item -Recurse -Force $appDir }
New-Item -ItemType Directory -Force $appDir | Out-Null
$manifest = Join-Path $build 'app.manifest'
$mf = [IO.File]::ReadAllText((Join-Path $root 'app.manifest'))
$mf = [regex]::Replace($mf, '(<assemblyIdentity\s+version=")[^"]*(")', ('${1}' + $asmVer + '${2}'))
[IO.File]::WriteAllText($manifest, $mf, $utf8)
$exePath = Join-Path $appDir 'NSFShield.exe'
Invoke-Csc $exePath @("-win32manifest:`"$manifest`"", "-win32icon:`"$ico`"")
Invoke-Sign $exePath

# ---------------------------------------------------------------- 3) engine files, licenses, languages, guide, backup scripts
foreach ($arch in 'x86','x86_64') {
    $dst = Join-Path $appDir "bin\$arch"
    New-Item -ItemType Directory -Force $dst | Out-Null
    Copy-Item (Join-Path $tp "$arch\*") $dst
}
# Zapret: winws + Cygwin DLL + its own WinDivert 2.2.2 + the fake payloads; ByeDPI: ciadpi (both 64-bit only)
$dz = Join-Path $appDir 'bin\zapret'
New-Item -ItemType Directory -Force (Join-Path $dz 'payloads') | Out-Null
Copy-Item (Join-Path $tz 'x86_64\*') $dz
Copy-Item (Join-Path $tz 'payloads\*') (Join-Path $dz 'payloads')
$db = Join-Path $appDir 'bin\byedpi'
New-Item -ItemType Directory -Force $db | Out-Null
Copy-Item (Join-Path $tb 'x86_64\*') $db
# the recovery helper of this build (its SHA-256 is the one embedded in NSFShield.exe)
Copy-Item $helperExe (Join-Path $appDir "bin\$helperName")
if ((Get-Sha256 (Join-Path $appDir "bin\$helperName")) -ne $helperSha) { throw 'The recovery helper in the package differs from the embedded hash.' }
$lic = Join-Path $appDir 'licenses'
New-Item -ItemType Directory -Force $lic | Out-Null
foreach ($src in (Join-Path $tp 'licenses'), (Join-Path $tz 'licenses'), (Join-Path $tb 'licenses')) {
    foreach ($f in Get-ChildItem $src -File) {
        if (Test-Path (Join-Path $lic $f.Name)) { throw "Two licence files have the same name: $($f.Name)" }
        Copy-Item $f.FullName $lic
    }
}
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $lic 'LICENSE-nsfshield.txt')
Copy-Item (Join-Path $root 'THIRD_PARTY_NOTICES.md') (Join-Path $lic 'THIRD_PARTY_NOTICES.md')
$loc = Join-Path $appDir 'locales'
New-Item -ItemType Directory -Force $loc | Out-Null
Copy-Item (Join-Path $root 'locales\*.json') $loc
$readme = Join-Path $root 'README.txt'
if (-not [IO.File]::ReadAllText($readme).StartsWith("NSF SHIELD $version`n")) { throw "README.txt must start with 'NSF SHIELD $version' (LF line endings)." }
Copy-Item $readme $appDir
# the bilingual guide and its two fixed entry pages (guide\en.html, guide\tr.html); the backup scripts
Invoke-Helper @('--export-guide', "`"$root\docs\Guide.html`"", "`"$appDir\Guide.html`"") 'The guide' @("$appDir\Guide.html", "$appDir\guide\en.html", "$appDir\guide\tr.html")
Invoke-Helper @('--export-scripts', "`"$appDir\scripts`"") 'The scripts' @("$appDir\scripts\01_turkey_recommended.cmd", "$appDir\scripts\README.txt")
# the package root and the list files are exactly what the setup script, the updater and the self-test expect
[string[]]$rootNow = Get-ChildItem $appDir | ForEach-Object { $_.Name }
[Array]::Sort($rootNow, [StringComparer]::Ordinal)
$rootWant = 'Guide.html|NSFShield.exe|README.txt|bin|guide|licenses|locales|scripts'
if (($rootNow -join '|') -ne $rootWant) { throw "Unexpected package root: $($rootNow -join ', ')" }
[string[]]$guideNow = Get-ChildItem (Join-Path $appDir 'guide') | ForEach-Object { $_.Name }
[Array]::Sort($guideNow, [StringComparer]::Ordinal)
if (($guideNow -join '|') -ne 'en.html|tr.html') { throw "Unexpected guide entry pages: $($guideNow -join ', ')" }
if (@(Get-ChildItem (Join-Path $appDir 'bin\zapret\payloads') -File).Count -ne 11) { throw 'The package must hold the 11 Zapret payloads.' }
# fixed timestamp on every file (for the zip and the setup package)
Get-ChildItem $appDir -Recurse -File | ForEach-Object { $_.CreationTimeUtc = $stamp.UtcDateTime; $_.LastWriteTimeUtc = $stamp.UtcDateTime }

# ---------------------------------------------------------------- 4) portable zip: fixed order, fixed time, '/' separator
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = Join-Path $dist "NSF-Shield-$version.zip"
Remove-Item $zip, "$zip.sha256" -ErrorAction SilentlyContinue
[string[]]$rels = Get-ChildItem $appDir -Recurse -File | ForEach-Object { $_.FullName.Substring($appDir.Length + 1).Replace('\', '/') }
[Array]::Sort($rels, [StringComparer]::Ordinal)
$fs = [IO.File]::Open($zip, [IO.FileMode]::CreateNew)
try {
    $za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    foreach ($rel in $rels) {
        $entry = $za.CreateEntry("NSF Shield/$rel", [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = $stamp
        $in = [IO.File]::OpenRead((Join-Path $appDir $rel))
        $out = $entry.Open()
        try { $in.CopyTo($out) } finally { $out.Dispose(); $in.Dispose() }
    }
    $za.Dispose()
} finally { $fs.Dispose() }
Write-Host ">> Zip: $zip"

# ---------------------------------------------------------------- 5) setup package (Inno Setup)
$setup = Join-Path $dist "NSF-Shield-$version-Setup.exe"
if (-not $NoSetup) {
    $iscc = @($env:ISCC, "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
              "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $iscc) {
        if ($env:CI) { throw 'Inno Setup (ISCC.exe) not found.' }
        Write-Warning 'Inno Setup (ISCC.exe) not found; setup package skipped. https://jrsoftware.org/isdl.php'
        $setup = $null
    } else {
        Write-Host '>> Building the setup package (Inno Setup)...'
        Remove-Item $setup -ErrorAction SilentlyContinue
        $t = $stamp.UtcDateTime
        $isccArgs = "/Q `"/DAppVersion=$version`" `"/DSourceDir=$appDir`" `"/DOutDir=$dist`" `"/DIconFile=$ico`" " +
                    "`"/DTouchDate=$($t.ToString('yyyy-MM-dd'))`" `"/DTouchTime=$($t.ToString('HH:mm'))`""
        if ($signArgs) { $isccArgs += " /DSIGN `"/Snsfsign=$signTool sign $signArgs `$f`"" }
        $isccArgs += " `"$(Join-Path $root 'installer\NSFShield.iss')`""
        # ISCC.exe carries no version resource: the version comes from the setup's uninstall entry of that folder
        $innoVer = 'unknown'
        foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
                       'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1') {
            $e = Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($e -and $e.InstallLocation -and ((Resolve-Path $e.InstallLocation -ErrorAction SilentlyContinue).Path.TrimEnd('\') -eq (Split-Path $iscc).TrimEnd('\'))) { $innoVer = $e.DisplayVersion; break }
        }
        Write-Host ">> Inno Setup (ISCC): $innoVer ($iscc)"
        $p = Start-Process $iscc -ArgumentList $isccArgs -Wait -NoNewWindow -PassThru
        if ($p.ExitCode -ne 0 -or -not (Test-Path $setup)) { throw 'The setup package could not be built.' }
        if ((Get-Item $setup).LastWriteTimeUtc -lt $buildStart) { throw 'The setup package is not from this build.' }
        Write-Host ">> Setup: $setup"
    }
} else { $setup = $null }

# ---------------------------------------------------------------- 6) SHA256SUMS: the ZIP, the Setup, then every package file
$sums = Join-Path $dist "NSF-Shield-$version.SHA256SUMS.txt"
if ((Get-Item $zip).LastWriteTimeUtc -lt $buildStart) { throw 'The ZIP is not from this build.' }
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("$(Get-Sha256 $zip)  $(Split-Path $zip -Leaf)")
if ($setup) { $lines.Add("$(Get-Sha256 $setup)  $(Split-Path $setup -Leaf)") }
foreach ($rel in $rels) {   # every real file of the package tree, ordinal order (the manifest itself is not in the tree)
    $lines.Add("$(Get-Sha256 (Join-Path $appDir $rel))  NSF Shield/$rel")
}
[IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"), $utf8)

# the manifest is read back: exactly the expected files, each path once, each hash recomputed; the ZIP equals the package tree
function Test-Manifest {
    $want = New-Object System.Collections.Generic.List[string]
    $want.Add((Split-Path $zip -Leaf))
    if ($setup) { $want.Add((Split-Path $setup -Leaf)) }
    foreach ($rel in $rels) { $want.Add("NSF Shield/$rel") }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $got = New-Object System.Collections.Generic.List[string]
    foreach ($l in ([IO.File]::ReadAllText($sums) -split "`n" | Where-Object { $_ -ne '' })) {
        if ($l -notmatch '^([0-9a-f]{64})  (.+)$') { throw "SHA256SUMS: malformed line: $l" }
        $h = $Matches[1]; $path = $Matches[2]
        if (-not $seen.Add($path)) { throw "SHA256SUMS: listed twice: $path" }
        $got.Add($path)
        $file = if ($path -eq (Split-Path $zip -Leaf)) { $zip } elseif ($setup -and $path -eq (Split-Path $setup -Leaf)) { $setup } else { Join-Path $appDir ($path.Substring(11).Replace('/', '\')) }
        if ((Get-Sha256 $file) -ne $h) { throw "SHA256SUMS: wrong hash for $path" }
    }
    if (($got -join "`n") -ne ($want -join "`n")) { throw 'SHA256SUMS does not list exactly the ZIP, the Setup and the package files in order.' }
    $za = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        [string[]]$names = $za.Entries | ForEach-Object { $_.FullName }
        [Array]::Sort($names, [StringComparer]::Ordinal)
        [string[]]$tree = $rels | ForEach-Object { "NSF Shield/$_" }
        if (($names -join "`n") -ne ($tree -join "`n")) { throw 'The ZIP does not hold exactly the package tree.' }
        $sha = [Security.Cryptography.SHA256]::Create()
        foreach ($e in $za.Entries) {
            $s = $e.Open()
            try { $hz = ([BitConverter]::ToString($sha.ComputeHash($s)) -replace '-', '').ToLowerInvariant() } finally { $s.Dispose() }
            if ($hz -ne (Get-Sha256 (Join-Path $appDir ($e.FullName.Substring(11).Replace('/', '\'))))) { throw "The ZIP entry differs from the package tree: $($e.FullName)" }
        }
    } finally { $za.Dispose() }
}
Test-Manifest
Write-Host ">> Done ($version). Hashes: $sums ($($lines.Count) lines, checked against the package tree and the ZIP)"
$lines | Select-Object -First 2 | ForEach-Object { Write-Host "   $_" }

# ---------------------------------------------------------------- 7) reproducibility check (optional)
# Two fresh UNSIGNED builds; NSFShield.exe, the ZIP and the Setup are compared one by one. Only when all three were built twice
# and are identical is the result a three-output check; a missing ISCC fails it, -NoSetup is reported as partial.
if ($VerifyReproducible) {
    if (-not $setup -and -not $NoSetup) { throw 'The three-output reproducibility check needs the Setup (Inno Setup / ISCC.exe not found).' }
    $first = [ordered]@{ 'NSFShield.exe' = (Get-Sha256 $exePath); $helperName = (Get-Sha256 (Join-Path $appDir "bin\$helperName")); (Split-Path $zip -Leaf) = (Get-Sha256 $zip) }
    if ($setup) { $first[(Split-Path $setup -Leaf)] = Get-Sha256 $setup }
    Write-Host '>> Reproducibility: second fresh unsigned build from the same source...'
    $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($NoSetup) { $childArgs += '-NoSetup' }
    $keepSign = $env:NSF_SIGN_ARGS
    $env:NSF_SIGN_ARGS = $null
    $childStart = (Get-Date).ToUniversalTime()
    try { & powershell @childArgs | Out-Null } finally { $env:NSF_SIGN_ARGS = $keepSign }
    if ($LASTEXITCODE -ne 0) { throw 'The second build failed.' }
    if ((Get-Item $zip).LastWriteTimeUtc -lt $childStart -or ($setup -and (Get-Item $setup).LastWriteTimeUtc -lt $childStart)) { throw 'The second build did not produce fresh packages.' }
    $second = [ordered]@{ 'NSFShield.exe' = (Get-Sha256 $exePath); $helperName = (Get-Sha256 (Join-Path $appDir "bin\$helperName")); (Split-Path $zip -Leaf) = (Get-Sha256 $zip) }
    if ($setup) { $second[(Split-Path $setup -Leaf)] = Get-Sha256 $setup }
    $bad = @()
    foreach ($k in $first.Keys) {
        $same = $first[$k] -eq $second[$k]
        Write-Host ("   {0,-34} {1}  {2}  {3}" -f $k, $(if ($same) { 'SAME     ' } else { 'DIFFERENT' }), $first[$k], $second[$k])
        if (-not $same) { $bad += $k }
    }
    if ($bad.Count -gt 0) { throw ('Not reproducible: ' + ($bad -join ', ')) }
    if ($setup) { Write-Host ">> Reproducible (three-output check): NSFShield.exe, the ZIP and the Setup (and $helperName) are identical in two fresh unsigned builds." }
    else { Write-Host '>> PARTIAL: NSFShield.exe and the ZIP are identical; the Setup was not built (-NoSetup), so this is not a three-output check.' }
    if ($signLater) {
        Write-Host '>> Signing is configured: building the signed release outputs (timestamped; not part of the reproducibility proof)...'
        & powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'The signed build failed.' }
    }
}
