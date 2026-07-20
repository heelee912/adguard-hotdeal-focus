#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cliPath = Join-Path $root 'scripts\adguard_windows_cli.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -ne 0) { throw 'CLI parser errors prevent v2 contract tests' }
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $statement.Extent.Text
    }
}

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false, $true)
$script:MaximumSourceBytes = 8MB
$script:ReaderGateProtocolVersion = 2
$script:ReaderGateGrant = 'GM_addElement'
$script:FreshInstallGmProperties = '{}'
$script:MarkerGateArtifactVersion = '2.0.2'
$script:MarkerGateSubscriptionUrl = ('https://github.com/heelee912/' +
    'adguard-hotdeal-focus/releases/download/gate-v2.0.2/filter.txt')
$UserscriptName = 'AdGuard Hotdeal Focus Reader Gate'
$FilterName = 'AdGuard Hotdeal Focus Marker Gate'
$ExpectedUserscriptSha256 = $null
$ExpectedFilterSha256 = $null
$ExpectedInstalledFilterRulesSha256 = $null
$ReleaseManifestSource = $null
$FilterUrl = $null
$UserscriptSource = $null

function Assert-Contract {
    param([Parameter(Mandatory = $true)][bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Pattern
    )
    try { & $Action; throw 'Expected contract failure was not raised' }
    catch {
        if ([string] $_.Exception.Message -notlike $Pattern) { throw }
    }
}

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hotdeal-focus-release-v2-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($temporary)
try {
    $validUserscriptText = @'
// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      2.1.0
// @match        https://www.algumon.com/*
// @match        https://*.clien.net/*
// @match        https://*.ppomppu.co.kr/*
// @match        https://*.ruliweb.com/*
// @match        https://*.quasarzone.com/*
// @match        https://*.eomisae.co.kr/*
// @match        https://*.zod.kr/*
// @match        https://*.arca.live/*
// @run-at       document-start
// @grant        GM_addElement
// @noframes
// ==/UserScript==
const PROTOCOL_VERSION = "2";
const ATTR = {
  lock: "data-hotdeal-focus-lock",
  ready: "data-hotdeal-focus-ready",
  keep: "data-hotdeal-focus-keep",
  protocol: "data-hotdeal-focus-protocol",
  shell: "data-hotdeal-focus-shell",
  deep: "data-hotdeal-focus-deep",
  role: "data-hotdeal-focus-role",
  state: "data-hotdeal-focus-state",
  status: "data-hotdeal-focus-status",
};
const CLASSES = "hdf-v2-lock hdf-v2-ready hdf-v2-keep hdf-v2-shell hdf-v2-deep hdf-v2-role-";
const selector = `style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]`;
const diagnostics = { protocolVersion: Number(PROTOCOL_VERSION) };
document.documentElement.setAttribute(ATTR.protocol, PROTOCOL_VERSION);
GM_addElement(document.documentElement, "style", {
  textContent: "html.hdf-v2-lock{display:none!important}",
  "data-hotdeal-focus-runtime-style": PROTOCOL_VERSION,
});
'@
    $validUserscriptPath = Join-Path $temporary 'reader-v2.user.js'
    [System.IO.File]::WriteAllText(
        $validUserscriptPath, $validUserscriptText, $script:Utf8NoBom)
    $userscript = Get-UserscriptSource -Source $validUserscriptPath
    Assert-Contract ($userscript.ProtocolVersion -eq 2) 'Reader protocol was not parsed as 2'
    Assert-Contract ($userscript.Grant -ceq 'GM_addElement') 'Reader grant was not exact'

    foreach ($invalidCase in @(
            [pscustomobject]@{
                Name = 'grant-none'
                Text = $validUserscriptText.Replace(
                    '// @grant        GM_addElement', '// @grant        none')
                Pattern = '*exactly one @grant GM_addElement*'
            },
            [pscustomobject]@{
                Name = 'extra-grant'
                Text = $validUserscriptText.Replace(
                    '// @grant        GM_addElement',
                    "// @grant        GM_addElement`n// @grant        none")
                Pattern = '*exactly one @grant GM_addElement*'
            },
            [pscustomobject]@{
                Name = 'protocol-v1'
                Text = $validUserscriptText.Replace(
                    'const PROTOCOL_VERSION = "2";',
                    'const PROTOCOL_VERSION = "1";')
                Pattern = '*exact protocol version 2*'
            },
            [pscustomobject]@{
                Name = 'diagnostics-v1'
                Text = $validUserscriptText.Replace(
                    'protocolVersion: Number(PROTOCOL_VERSION)',
                    'protocolVersion: 1')
                Pattern = '*diagnostics/runtime contract*'
            }
        )) {
        $path = Join-Path $temporary ($invalidCase.Name + '.user.js')
        [System.IO.File]::WriteAllText($path, $invalidCase.Text, $script:Utf8NoBom)
        Assert-ThrowsLike -Action { [void] (Get-UserscriptSource -Source $path) } `
            -Pattern $invalidCase.Pattern
    }

    $filterText = @'
! Title: AdGuard Hotdeal Focus Marker Gate
! Version: 2.0.2
! Hotdeal-Focus-Protocol: 2
example.com##html.hdf-v2-lock:not(.hdf-v2-ready[data-hotdeal-focus-ready="1"][data-hotdeal-focus-protocol="2"][data-hotdeal-focus-state="ready"][data-hotdeal-focus-status="ready"]) .hdf-v2-keep
example.com##[data-hotdeal-focus-keep][data-hotdeal-focus-shell][data-hotdeal-focus-deep][data-hotdeal-focus-role="body"].hdf-v2-shell.hdf-v2-deep.hdf-v2-role-body
'@
    $filterBytes = $script:Utf8NoBom.GetBytes($filterText)
    $filter = ConvertFrom-FilterSourceBytes -Bytes $filterBytes `
        -Url $script:MarkerGateSubscriptionUrl
    Assert-Contract ($filter.ProtocolVersion -eq 2) 'Filter protocol was not parsed as 2'

    $manifestPath = Join-Path $temporary 'release-manifest.json'
    $manifest = [ordered]@{
        schemaVersion = 1
        status = 'release-ready'
        releaseVersion = $userscript.Version
        protocolVersion = 2
        gateArtifactVersion = '2.0.2'
        filterSubscriptionUrl = $script:MarkerGateSubscriptionUrl
        artifacts = [ordered]@{
            'filter.txt' = [ordered]@{
                version = '2.0.2'
                sha256 = $filter.RawSha256
                installedRulesSha256 = $filter.SourceRulesSha256
            }
            'hotdeal-focus.user.js' = [ordered]@{
                version = $userscript.Version
                sha256 = $userscript.RawSha256
                canonicalTextSha256 = $userscript.Sha256
            }
        }
    }
    [System.IO.File]::WriteAllText(
        $manifestPath, ($manifest | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    $manifestContract = Get-ReleaseManifestContract -Source $manifestPath
    $ExpectedUserscriptSha256 = $userscript.Sha256
    $ExpectedFilterSha256 = $filter.RawSha256
    $ExpectedInstalledFilterRulesSha256 = $filter.SourceRulesSha256
    Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
        -DesiredUserscript $userscript -DesiredFilter $filter

    $manifest.protocolVersion = 1
    [System.IO.File]::WriteAllText(
        $manifestPath, ($manifest | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    Assert-ThrowsLike -Action {
        [void] (Get-ReleaseManifestContract -Source $manifestPath)
    } -Pattern '*exact protocol-2 gate contract*'
    $manifest.protocolVersion = 2

    $userscript.ProtocolVersion = 1
    Assert-ThrowsLike -Action {
        Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
            -DesiredUserscript $userscript -DesiredFilter $filter
    } -Pattern '*Userscript source*'
    $userscript.ProtocolVersion = 2
    $filter.ProtocolVersion = 1
    Assert-ThrowsLike -Action {
        Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
            -DesiredUserscript $userscript -DesiredFilter $filter
    } -Pattern '*Filter source*'

    [pscustomobject]@{
        ok = $true
        protocol = 2
        grant = $userscript.Grant
        cross_version_rejected = $true
    } | ConvertTo-Json
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        [System.IO.Directory]::Delete($temporary, $true)
    }
}
