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
$script:ReaderGateGrants = @(
    'GM_addElement', 'GM_getValue', 'GM_setValue', 'GM_deleteValue', 'window.onurlchange'
)
$script:ReleaseUserscriptUrl = ('https://heelee912.github.io/' +
    'adguard-hotdeal-focus/hotdeal-focus.user.js')
$script:FreshInstallGmProperties = '{}'
$UserscriptName = 'AdGuard Hotdeal Focus Reader Gate'
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
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
// @grant        window.onurlchange
// @downloadURL  https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// @updateURL    https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
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
    Assert-Contract (Test-ExactStringSequence -Left $userscript.Grants `
        -Right @(
                'GM_addElement', 'GM_getValue', 'GM_setValue', 'GM_deleteValue', 'window.onurlchange'
            )) 'Reader grants were not exact'
    Assert-Contract ($userscript.InstallUrl -ceq $script:ReleaseUserscriptUrl) `
        'Reader install URL was not exact'

    foreach ($invalidCase in @(
            [pscustomobject]@{
                Name = 'grant-none'
                Text = $validUserscriptText.Replace(
                    '// @grant        GM_addElement', '// @grant        none')
                Pattern = '*exact ordered grants*'
            },
            [pscustomobject]@{
                Name = 'grant-order'
                Text = $validUserscriptText.Replace(
                    '// @grant        GM_addElement',
                    '// @grant        __FIRST__').Replace(
                    '// @grant        window.onurlchange',
                    '// @grant        GM_addElement').Replace(
                    '// @grant        __FIRST__',
                    '// @grant        window.onurlchange')
                Pattern = '*exact ordered grants*'
            },
            [pscustomobject]@{
                Name = 'mutable-update-url'
                Text = $validUserscriptText.Replace(
                    '// @updateURL    https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js',
                    '// @updateURL    https://example.com/mutable.user.js')
                Pattern = '*exact release Userscript URL*'
            },
            [pscustomobject]@{
                Name = 'protocol-v1'
                Text = $validUserscriptText.Replace(
                    'const PROTOCOL_VERSION = "2";',
                    'const PROTOCOL_VERSION = "1";')
                Pattern = '*exact protocol version 2*'
            }
        )) {
        $path = Join-Path $temporary ($invalidCase.Name + '.user.js')
        [System.IO.File]::WriteAllText($path, $invalidCase.Text, $script:Utf8NoBom)
        Assert-ThrowsLike -Action { [void] (Get-UserscriptSource -Source $path) } `
            -Pattern $invalidCase.Pattern
    }

    $manifestPath = Join-Path $temporary 'release-manifest.json'
    $manifest = [ordered]@{
        schemaVersion = 2
        status = 'release-ready'
        releaseVersion = $userscript.Version
        protocolVersion = 2
        installUrl = $script:ReleaseUserscriptUrl
        generatorVersion = $userscript.Version
        rollback_of = $null
        configSha256 = ('a' * 64)
        coverage = [ordered]@{}
        promotion = $null
        artifacts = [ordered]@{
            'hotdeal-focus.user.js' = [ordered]@{
                version = $userscript.Version
                bytes = [long] $userscript.Bytes.Length
                sha256 = $userscript.RawSha256
                canonicalTextSha256 = $userscript.Sha256
            }
        }
        sourceIntegrity = [ordered]@{}
    }
    [System.IO.File]::WriteAllText(
        $manifestPath, ($manifest | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    $manifestContract = Get-ReleaseManifestContract -Source $manifestPath
    $ExpectedUserscriptSha256 = $userscript.Sha256
    Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
        -DesiredUserscript $userscript -DesiredFilter $null

    $manifest.installUrl = 'https://example.com/mutable.user.js'
    [System.IO.File]::WriteAllText(
        $manifestPath, ($manifest | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    Assert-ThrowsLike -Action {
        [void] (Get-ReleaseManifestContract -Source $manifestPath)
    } -Pattern '*standalone protocol-2 contract*'
    $manifest.installUrl = $script:ReleaseUserscriptUrl

    $manifest.artifacts['filter.txt'] = [ordered]@{ sha256 = ('b' * 64) }
    [System.IO.File]::WriteAllText(
        $manifestPath, ($manifest | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
    Assert-ThrowsLike -Action {
        [void] (Get-ReleaseManifestContract -Source $manifestPath)
    } -Pattern '*property set is not exact*'
    $manifest.artifacts.Remove('filter.txt')

    $userscript.ProtocolVersion = 1
    Assert-ThrowsLike -Action {
        Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
            -DesiredUserscript $userscript -DesiredFilter $null
    } -Pattern '*Userscript source*'

    [pscustomobject]@{
        ok = $true
        protocol = 2
        grants = @($script:ReaderGateGrants)
        public_artifacts = @('hotdeal-focus.user.js')
        cross_version_rejected = $true
    } | ConvertTo-Json -Depth 4
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        [System.IO.Directory]::Delete($temporary, $true)
    }
}
