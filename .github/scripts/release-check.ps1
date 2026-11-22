# Checks the GitHub release of a tag against this build (offline-testable: every GitHub call goes through -Gh).
#   exit 0  : no release of the tag exists yet (HTTP 404) - the workflow may create it
#   exit 10 : the release is published (not a draft, not a pre-release) and its three files (ZIP, Setup, SHA256SUMS) are
#             byte-identical to this build - nothing to do
#   throws  : a failed query (never taken for "no release"), a draft or pre-release, a missing or different file
# tests\release-check.Tests.ps1 runs it with a fake gh and local files (no GitHub call, nothing is published).
param(
    [Parameter(Mandatory = $true)] [string]$Tag,
    [Parameter(Mandatory = $true)] [string]$Dist,
    [string]$Repo = $env:GITHUB_REPOSITORY,
    [string]$Work = $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }),
    # gh: receives the argument list, returns @{ Code = <exit code>; Out = <stdout and stderr text> }
    [scriptblock]$Gh = {
        param([string[]]$GhArgs)
        $out = & gh @GhArgs 2>&1 | Out-String
        @{ Code = $LASTEXITCODE; Out = $out }
    }
)
$ErrorActionPreference = 'Stop'
$v = $Tag.TrimStart('v')
$files = @("NSF-Shield-$v.zip", "NSF-Shield-$v-Setup.exe", "NSF-Shield-$v.SHA256SUMS.txt")
foreach ($f in $files) { if (-not (Test-Path (Join-Path $Dist $f))) { throw "This build has no $f" } }
function Get-Sha([string]$p) { (Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant() }

# the release of this tag: "not found" (HTTP 404) and any other failure are told apart
$r = & $Gh @('api', "repos/$Repo/releases/tags/$Tag")
if ($r.Code -ne 0) {
    if ($r.Out -match 'HTTP 404') { Write-Host "No release of $Tag yet."; exit 0 }
    throw "The release of $Tag could not be queried (exit code $($r.Code)): $($r.Out.Trim())"
}
try { $rel = $r.Out | ConvertFrom-Json } catch { throw "The release of $Tag could not be read: $($_.Exception.Message)" }
if ($null -eq $rel -or [string]$rel.tag_name -ne $Tag) { throw "The answer is not the release of $Tag" }
# the app's updater reads releases/latest, which never lists a draft or a pre-release
if ($rel.draft -ne $false) { throw "The release of $Tag is a draft (or its state cannot be read)" }
if ($rel.prerelease -ne $false) { throw "The release of $Tag is a pre-release (or its state cannot be read)" }
# the three files: present and byte-identical to this build
$check = Join-Path $Work ('published-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $check | Out-Null
try {
    foreach ($f in $files) {
        $d = & $Gh @('release', 'download', $Tag, '--repo', $Repo, '--pattern', $f, '--dir', $check, '--clobber')
        $got = Join-Path $check $f
        if ($d.Code -ne 0 -or -not (Test-Path $got)) { throw "The published release has no $f" }
        $a = Get-Sha $got; $b = Get-Sha (Join-Path $Dist $f)
        if ($a -ne $b) { throw "The published $f differs from this build ($a / $b)" }
    }
} finally { Remove-Item -Recurse -Force $check -ErrorAction SilentlyContinue }
Write-Host "The release of $Tag is published with identical files."
exit 10
