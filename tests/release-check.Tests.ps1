# Offline tests of .github\scripts\release-check.ps1: a fake gh answers from local files and fixed texts; nothing is sent to
# GitHub and nothing is published. Run by build.ps1 (every build); prints "<n> OK / <m> FAIL" and exits 1 on a failure.
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$script = Join-Path $Root '.github\scripts\release-check.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('nsf-release-check-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$dist = Join-Path $tmp 'dist'
$remote = Join-Path $tmp 'remote'
New-Item -ItemType Directory -Force $dist, $remote | Out-Null
$ok = 0; $fail = 0
function Check([string]$name, [bool]$pass, [string]$detail = '') {
    if ($pass) { $script:ok++; Write-Host "OK   $name" } else { $script:fail++; Write-Host "FAIL $name $detail" }
}
try {
    $tag = 'v9.8.7'; $v = '9.8.7'
    $names = @("NSF-Shield-$v.zip", "NSF-Shield-$v-Setup.exe", "NSF-Shield-$v.SHA256SUMS.txt")
    foreach ($n in $names) { [IO.File]::WriteAllText((Join-Path $dist $n), "content of $n") }
    $zh = (Get-FileHash (Join-Path $dist $names[0]) -Algorithm SHA256).Hash.ToLowerInvariant()
    $sh = (Get-FileHash (Join-Path $dist $names[1]) -Algorithm SHA256).Hash.ToLowerInvariant()
    $goodBody = "SHA-256 ($($names[0])): ``$zh```n`nSHA-256 ($($names[1])): ``$sh``"

    # the fake gh: $state decides what the release API and the downloads answer; $track counts the calls
    $state = @{}
    $track = @{ Calls = 0; Created = $false }
    $fake = {
        param([string[]]$GhArgs)
        $track.Calls++
        if ($GhArgs[0] -eq 'api') {
            switch ($state.Mode) {
                'absent' { return @{ Code = 1; Out = 'gh: Not Found (HTTP 404)' } }
                'error' { return @{ Code = 1; Out = 'error connecting to api.github.com' } }
                'server' { return @{ Code = 1; Out = 'gh: Server Error (HTTP 502)' } }
                'garbage' { return @{ Code = 0; Out = '<html>not json</html>' } }
                default {
                    $o = [ordered]@{ tag_name = $tag; draft = [bool]$state.Draft; prerelease = [bool]$state.Pre; body = $state.Body }
                    return @{ Code = 0; Out = ($o | ConvertTo-Json) }
                }
            }
        }
        if ($GhArgs[0] -eq 'release' -and $GhArgs[1] -eq 'download') {
            $pattern = $GhArgs[[array]::IndexOf($GhArgs, '--pattern') + 1]
            $dir = $GhArgs[[array]::IndexOf($GhArgs, '--dir') + 1]
            $src = Join-Path $remote $pattern
            if (-not (Test-Path $src)) { return @{ Code = 1; Out = "no assets match the file pattern" } }
            Copy-Item $src (Join-Path $dir $pattern) -Force
            return @{ Code = 0; Out = '' }
        }
        if ($GhArgs[0] -eq 'release' -and $GhArgs[1] -eq 'create') { $track.Created = $true; return @{ Code = 0; Out = '' } }
        return @{ Code = 1; Out = 'unexpected call' }
    }
    function Run([hashtable]$s) {
        $track.Calls = 0
        foreach ($k in @($state.Keys)) { $state.Remove($k) }
        foreach ($k in $s.Keys) { $state[$k] = $s[$k] }
        Remove-Item (Join-Path $remote '*') -ErrorAction SilentlyContinue
        foreach ($n in $names) {
            if ($s.Missing -eq $n) { continue }
            $text = if ($s.Different -eq $n) { "other $n" } else { "content of $n" }
            [IO.File]::WriteAllText((Join-Path $remote $n), $text)
        }
        $global:LASTEXITCODE = 0
        try {
            & $script -Tag $tag -Dist $dist -Repo 'owner/repo' -Work $tmp -Gh $fake | Out-Null
            return @{ Exit = $LASTEXITCODE; Error = $null }
        } catch { return @{ Exit = -1; Error = $_.Exception.Message } }
    }

    $r = Run @{ Mode = 'absent' }
    Check 'no release yet (HTTP 404): exit 0, nothing else asked' ($r.Exit -eq 0 -and $track.Calls -eq 1 -and -not $track.Created) $r.Error
    $r = Run @{ Mode = 'error' }
    Check 'a failed query (no connection) is an error, never "no release"' ($r.Exit -eq -1 -and $r.Error -match 'could not be queried') $r.Error
    $r = Run @{ Mode = 'server' }
    Check 'a server error (HTTP 502) is an error, never "no release"' ($r.Exit -eq -1 -and $r.Error -match 'could not be queried') $r.Error
    $r = Run @{ Mode = 'garbage' }
    Check 'an answer that is not the release fails' ($r.Exit -eq -1) $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody }
    Check 'published with identical files: exit 10' ($r.Exit -eq 10) $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Draft = $true }
    Check 'a draft release fails (the updater would not see it)' ($r.Exit -eq -1 -and $r.Error -match 'draft') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Pre = $true }
    Check 'a pre-release fails' ($r.Exit -eq -1 -and $r.Error -match 'pre-release') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Missing = $names[0] }
    Check 'a missing ZIP fails' ($r.Exit -eq -1 -and $r.Error -match 'has no') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Missing = $names[1] }
    Check 'a missing Setup fails' ($r.Exit -eq -1 -and $r.Error -match 'has no') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Different = $names[2] }
    Check 'a different SHA256SUMS file fails' ($r.Exit -eq -1 -and $r.Error -match 'differs') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Different = $names[0] }
    Check 'a different ZIP fails' ($r.Exit -eq -1 -and $r.Error -match 'differs') $r.Error
    $r = Run @{ Mode = 'ok'; Body = $goodBody; Different = $names[1] }
    Check 'a different Setup fails' ($r.Exit -eq -1 -and $r.Error -match 'differs') $r.Error
    Check 'no test ever created a release' (-not $track.Created) ''
    $wf = [IO.File]::ReadAllText((Join-Path $Root '.github\workflows\build.yml'))
    Check 'the workflow uses the checked script before and after publishing' (([regex]::Matches($wf, 'release-check\.ps1')).Count -ge 2 -and $wf -match '-eq 10') ''
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
Write-Host "$ok OK / $fail FAIL"
if ($fail -gt 0 -or $ok -eq 0) { exit 1 }
exit 0
