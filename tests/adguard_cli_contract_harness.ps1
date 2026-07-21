#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cliPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\scripts\adguard_windows_cli.ps1'))
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cliPath, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -ne 0) { throw 'CLI parser errors prevent contract tests' }
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
$script:MarkerGateArtifactVersion = '2.0.2'
$script:MarkerGateSubscriptionUrl = ('https://github.com/heelee912/' +
    'adguard-hotdeal-focus/releases/download/gate-v2.0.2/filter.txt')
$script:AdGuardStateVisibilityMaxObservations = 6
$script:AdGuardStateVisibilityDelayMilliseconds = 0
$script:AdGuardStateVisibilityRequiredConsecutiveReads = 2
$script:FreshInstallGmProperties = '{}'
$script:TemporaryPaths = New-Object 'System.Collections.Generic.List[string]'
$script:StandardFilterType = 'Standard'
$script:FilterSubscriptionType = [string]
$script:HistoricalSnapshotRules = @()
$UserscriptName = 'AdGuard Hotdeal Focus Reader Gate'
$FilterName = 'AdGuard Hotdeal Focus Marker Gate'
$ExpectedUserscriptSha256 = $null
$ExpectedFilterSha256 = $null
$ExpectedInstalledFilterRulesSha256 = $null
$ReleaseManifestSource = $null
$FilterUrl = $null
$UserscriptSource = $null
$BackupRoot = $null
$ReferenceUserFilterSnapshot = $null
$ApproveExclusiveTargetMigration = $false

function Assert-Contract {
    param([Parameter(Mandatory = $true)][bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-ThrowsLike {
    param([Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Pattern)
    try { & $Action; throw 'Expected contract failure was not raised' }
    catch {
        if ([string] $_.Exception.Message -notlike $Pattern) { throw }
    }
}

# Windows PowerShell 5.1 exposes HttpContentHeaders.ContentLength as an unboxed
# Int64, while newer runtimes may retain nullable metadata. The size guard must
# accept either representation without dereferencing a non-existent .Value.
Assert-HttpsContentLengthWithinLimit -ContentLength $null
Assert-HttpsContentLengthWithinLimit -ContentLength ([long] 1024)
Assert-HttpsContentLengthWithinLimit -ContentLength ([Nullable[long]] 2048)
Assert-ThrowsLike -Action {
    Assert-HttpsContentLengthWithinLimit -ContentLength ($script:MaximumSourceBytes + 1)
} -Pattern '*exceeds the maximum size*'
Assert-ThrowsLike -Action {
    Assert-HttpsContentLengthWithinLimit -ContentLength 'not-a-number'
} -Pattern '*content length is invalid*'

function Copy-FilterState {
    param([Parameter(Mandatory = $true)] $State,
        [AllowNull()][Nullable[bool]] $Enabled,
        [AllowNull()][Nullable[bool]] $Trusted)
    return [pscustomobject]@{
        FilterId = [int] $State.FilterId
        IsEnabled = if ($null -eq $Enabled) { [bool] $State.IsEnabled } else { [bool] $Enabled }
        IsTrusted = if ($null -eq $Trusted) { [bool] $State.IsTrusted } else { [bool] $Trusted }
        IsCustom = $true
        IsEditable = $false
        Name = [string] $State.Name
        Version = [string] $State.Version
        SubscriptionUrl = [string] $State.SubscriptionUrl
        RulesSha256 = [string] $State.RulesSha256
        DisabledRulesSha256 = [string] $State.DisabledRulesSha256
    }
}

function Assert-FakeUserscriptWriteIntent {
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)][string] $Write
    )
    if (-not $State.IntentDirectory) { return }
    $writeIndex = @($State.UserscriptWrites).Count
    $expected = @($State.ExpectedWriteIntents)
    if ($writeIndex -ge $expected.Count -or
        [string] $expected[$writeIndex].Write -cne $Write) {
        throw "Fake userscript write occurred outside the expected transaction order: $Write"
    }
    $expectedEvent = [string] $expected[$writeIndex].Event
    $matchingEvents = @(Get-ChildItem -LiteralPath $State.IntentDirectory -File `
            -Filter 'journal-*.json' | ForEach-Object {
            try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json }
            catch { $null }
        } | Where-Object { $_ -and [string] $_.event -ceq $expectedEvent })
    if ($matchingEvents.Count -eq 0) {
        throw "Durable intent was not present before fake userscript write: $expectedEvent"
    }
}

function New-FakeClient {
    param([Parameter(Mandatory = $true)] $State)
    $client = [pscustomobject]@{ State = $State }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetAllFilterSubscriptions -Value {
        return @($this.State.UserFilter) + @($this.State.Filters)
    }
    Add-Member -InputObject $client -MemberType ScriptMethod `
        -Name GetInstalledFilterSubscriptions -Value {
        param($unused, $types)
        return @($this.State.Filters)
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetFilterSubscriptionRules -Value {
        param($filterId, $filterType)
        if ([int] $filterId -eq [int] $this.State.UserFilter.FilterId) {
            $this.State.UserRuleReadCount = [int] $this.State.UserRuleReadCount + 1
            if ([bool] $this.State.MutateUserOnEveryRead) {
                $this.State.UserDisabledRules = @($this.State.UserDisabledRules) + @(
                    [string] ($this.State.MutateUserRule + '-' + $this.State.UserRuleReadCount))
            }
            if ([int] $this.State.MutateUserOnReadNumber -eq $this.State.UserRuleReadCount) {
                $this.State.UserDisabledRules = @($this.State.UserDisabledRules) +
                    @([string] $this.State.MutateUserRule)
            }
            return [pscustomobject]@{
                Rules = @($this.State.UserRules)
                DisabledRules = @($this.State.UserDisabledRules)
            }
        }
        return $this.State.FilterRules[[string] ([int] $filterId)]
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscripts -Value {
        $this.State.UserscriptReadCount = [int] $this.State.UserscriptReadCount + 1
        if ([int] $this.State.UserscriptHiddenReadsRemaining -gt 0) {
            $this.State.UserscriptHiddenReadsRemaining = `
                [int] $this.State.UserscriptHiddenReadsRemaining - 1
            return @()
        }
        return @($this.State.Userscripts)
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscriptCode -Value {
        param($name, $includeMetadata)
        return [string] $this.State.UserscriptCode
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscriptGmProperties -Value {
        param($name)
        return [string] $this.State.UserscriptGmProperties
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscriptMeta -Value {
        param($path)
        $content = [System.IO.File]::ReadAllText([string] $path)
        $versionMatch = [regex]::Match(
            $content, '(?m)^//\s+@version\s+(?<value>\S+)\s*$')
        $nameMatch = [regex]::Match(
            $content, '(?m)^//\s+@name\s+(?<value>.+?)\s*$')
        $meta = [pscustomobject]@{
            Name = if ($nameMatch.Success) {
                $nameMatch.Groups['value'].Value.Trim()
            } else { [string] $UserscriptName }
            Version = if ($versionMatch.Success) {
                $versionMatch.Groups['value'].Value.Trim()
            } else { [string] $this.State.RestoreMetaVersion }
            Content = if ($null -ne $this.State.ParsedContentOverride) {
                [string] $this.State.ParsedContentOverride
            } else { $content }
            IsCustom = $false
            IsStyle = $false
        }
        $this.State.LastParsedMeta = $meta
        return $meta
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name InstallUserscriptFromMeta -Value {
        param($meta)
        Assert-FakeUserscriptWriteIntent -State $this.State -Write 'install'
        $this.State.UserscriptWrites = @($this.State.UserscriptWrites) + @('install')
        $receiptIsCustom = if ($null -ne $this.State.ReceiptIsCustomOverride) {
            [bool] $this.State.ReceiptIsCustomOverride
        } else { [bool] $meta.IsCustom }
        $receiptMeta = [pscustomobject]@{
            Name = [string] $meta.Name
            Version = [string] $meta.Version
            Content = [string] $meta.Content
            IsCustom = $receiptIsCustom
            IsStyle = [bool] $meta.IsStyle
        }
        $this.State.Userscripts = @([pscustomobject]@{
                Name = [string] $meta.Name
                Version = [string] $meta.Version
                IsCustom = $receiptIsCustom
                IsEnabled = [bool] $this.State.ReceiptInitialEnabled
                IsStyle = [bool] $meta.IsStyle
            })
        $this.State.UserscriptCode = [string] $meta.Content
        $this.State.UserscriptGmProperties = [string] $this.State.FreshInstallGmProperties
        return [pscustomobject]@{
            Meta = $receiptMeta
            IsEnabled = [bool] $this.State.ReceiptInitialEnabled
        }
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name UpdateUserscriptCode -Value {
        param($name, $content)
        Assert-FakeUserscriptWriteIntent -State $this.State -Write 'update-code'
        $this.State.UserscriptWrites = @($this.State.UserscriptWrites) + @('update-code')
        $this.State.UserscriptCode = [string] $content
        $versionMatch = [regex]::Match(
            [string] $content, '(?m)^//\s+@version\s+(?<value>\S+)\s*$')
        $this.State.Userscripts[0].Version = if ($versionMatch.Success) {
            $versionMatch.Groups['value'].Value.Trim()
        } else { [string] $this.State.NextUpdateVersion }
    }
    Add-Member -InputObject $client -MemberType ScriptMethod `
        -Name UpdateUserscriptGmProperties -Value {
        param($name, $gmProperties)
        Assert-FakeUserscriptWriteIntent -State $this.State -Write 'update-gm'
        $this.State.UserscriptWrites = @($this.State.UserscriptWrites) + @('update-gm')
        $this.State.UserscriptGmProperties = [string] $gmProperties
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name RemoveUserscript -Value {
        param($name)
        Assert-FakeUserscriptWriteIntent -State $this.State -Write 'remove'
        $this.State.UserscriptWrites = @($this.State.UserscriptWrites) + @('remove')
        $this.State.Userscripts = @()
        $this.State.UserscriptCode = ''
        $this.State.UserscriptGmProperties = ''
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name SetUserscriptStatus -Value {
        param($name, $enabled)
        Assert-FakeUserscriptWriteIntent -State $this.State -Write 'set-status'
        $this.State.UserscriptWrites = @($this.State.UserscriptWrites) + @('set-status')
        $this.State.Userscripts[0].IsEnabled = [bool] $enabled
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name EnableFilterRules -Value {
        param($filterId, $rules, $filterType)
        $enabled = @($rules | ForEach-Object { [string] $_ })
        $this.State.UserDisabledRules = @($this.State.UserDisabledRules | Where-Object {
                $enabled -cnotcontains [string] $_
            })
    }
    return $client
}

# Scope identifies possible conflicts but does not prove legacy provenance. Applying
# the exact snapshot delta therefore needs a separate, machine-visible approval.
$approvalPlan = [pscustomobject]@{ EnabledCandidateRules = @('target.example##.noise') }
Assert-ThrowsLike -Action {
    Assert-ExclusiveTargetMigrationAuthorized -Plan $approvalPlan
} -Pattern '*requires -ApproveExclusiveTargetMigration*'
$ApproveExclusiveTargetMigration = $true
Assert-ExclusiveTargetMigrationAuthorized -Plan $approvalPlan
$ApproveExclusiveTargetMigration = $false

function New-UserscriptSnapshot {
    param(
        [string] $Version,
        [bool] $Enabled,
        [string] $Code,
        [string] $GmProperties,
        [bool] $Custom = $true,
        [bool] $Style = $false
    )
    return [pscustomobject]@{
        Exists = $true
        Info = [pscustomobject]@{
            Name = $UserscriptName; Version = $Version; IsCustom = $Custom
            IsEnabled = $Enabled; IsStyle = $Style
        }
        Code = $Code
        GmProperties = $GmProperties
    }
}

$exclusive = Get-CosmeticRuleScopeAnalysis -Rule 'ruliweb.com,clien.net##.noise'
$mixed = Get-CosmeticRuleScopeAnalysis -Rule 'ruliweb.com,example.com##.noise'
$global = Get-CosmeticRuleScopeAnalysis -Rule '##.noise'
Assert-Contract ($exclusive.ScopeKind -ceq 'exclusive-target') 'exclusive scope misclassified'
Assert-Contract ($mixed.ScopeKind -ceq 'mixed-target') 'mixed scope misclassified'
Assert-Contract ($global.ScopeKind -ceq 'global') 'global scope misclassified'

# AdGuard 7.22 downgrades a changed local/manual executable script when its
# code is updated in place, so every changed executable entry is replaced.
# The independent GM value-store remains byte-exact across that replacement.
$beforeUserscript = New-UserscriptSnapshot -Version '1.0.0' -Enabled $false `
    -Code 'before-code' -GmProperties '{"saved":"before"}' -Custom $true
$userscriptPlan = [pscustomobject]@{
    userscript_after = [pscustomobject]@{
        exists = $true; name = $UserscriptName; version = '2.0.0'
        code_sha256 = Get-CanonicalTextSha256 -Text 'after-code'
        gm_properties_sha256 = Get-CanonicalTextSha256 -Text '{"saved":"before"}'
        fresh_install_gm_properties_sha256 = Get-CanonicalTextSha256 -Text '{}'
        enabled = $true; is_custom = $true; is_style = $false
        replacement_required = $true
    }
}
Assert-Contract (-not (Assert-UserscriptRestorePreconditions -Current $beforeUserscript `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan)) `
    'exact userscript before-state was not idempotent'
$userscriptPrefixes = @(
    (New-UserscriptSnapshot -Version '2.0.0' -Enabled $false -Code 'after-code' `
        -GmProperties '{}' -Custom $true),
    (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true -Code 'after-code' `
        -GmProperties '{"saved":"before"}' -Custom $true)
)
foreach ($prefix in $userscriptPrefixes) {
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $prefix `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan) `
        'authorized userscript crash prefix was rejected'
}
$invalidUserscript = New-UserscriptSnapshot -Version '2.0.0' -Enabled $false `
    -Code 'after-code' -GmProperties '{"saved":"tampered"}' -Custom $true
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptRestorePreconditions -Current $invalidUserscript `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan)
} -Pattern '*not an enumerated mutation-prefix*'
Assert-Contract (Assert-UserscriptRestorePreconditions -Current ([pscustomobject]@{
            Exists = $false; Info = $null; Code = $null; GmProperties = $null
        }) -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan) `
    'remove-before-executable-code replacement prefix was rejected'
$executableRollbackPrefixes = @(
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $false -Code 'before-code' `
        -GmProperties '{}' -Custom $true),
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $true -Code 'before-code' `
        -GmProperties '{"saved":"before"}' -Custom $true)
)
foreach ($prefix in $executableRollbackPrefixes) {
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $prefix `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan) `
        'authorized executable-code rollback prefix was rejected'
}

# A source-owned IsCustom=false entry is replaced, not updated in place. Every
# forward crash prefix and every resumable rollback-reinstall prefix is exact.
$beforeReclassification = New-UserscriptSnapshot -Version '1.0.0' -Enabled $false `
    -Code 'before-reclassification-code' `
    -GmProperties '{"saved":"reclassification"}' -Custom $false
$reclassificationPlan = [pscustomobject]@{
    userscript_after = [pscustomobject]@{
        exists = $true; name = $UserscriptName; version = '2.0.0'
        code_sha256 = Get-CanonicalTextSha256 -Text 'after-code'
        gm_properties_sha256 = `
            Get-CanonicalTextSha256 -Text '{"saved":"reclassification"}'
        fresh_install_gm_properties_sha256 = Get-CanonicalTextSha256 -Text '{}'
        enabled = $true; is_custom = $true; is_style = $false
        replacement_required = $true
    }
}
Assert-Contract (-not (Assert-UserscriptRestorePreconditions `
            -Current $beforeReclassification -BackupSnapshot $beforeReclassification `
            -TransactionPlan $reclassificationPlan)) `
    'exact noncustom before-state was not idempotent'
Assert-Contract (Assert-UserscriptRestorePreconditions -Current ([pscustomobject]@{
            Exists = $false; Info = $null; Code = $null; GmProperties = $null
        }) -BackupSnapshot $beforeReclassification `
        -TransactionPlan $reclassificationPlan) `
    'remove-before-reclassification prefix was rejected'
foreach ($gm in @('{}', '{"saved":"reclassification"}')) {
    foreach ($enabled in @($false, $true)) {
        $prefix = New-UserscriptSnapshot -Version '2.0.0' -Enabled $enabled `
            -Code 'after-code' -GmProperties $gm -Custom $true
        Assert-Contract (Assert-UserscriptRestorePreconditions -Current $prefix `
                -BackupSnapshot $beforeReclassification `
                -TransactionPlan $reclassificationPlan) `
            'authorized reclassification forward prefix was rejected'
    }
}
$rollbackPrefixes = @(
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $false `
        -Code 'before-reclassification-code' -GmProperties '{}' -Custom $false),
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
        -Code 'before-reclassification-code' -GmProperties '{}' -Custom $false),
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
        -Code 'before-reclassification-code' `
        -GmProperties '{"saved":"reclassification"}' -Custom $false)
)
foreach ($prefix in $rollbackPrefixes) {
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $prefix `
            -BackupSnapshot $beforeReclassification `
            -TransactionPlan $reclassificationPlan) `
        'authorized reclassification rollback prefix was rejected'
}
$tamperedReclassification = New-UserscriptSnapshot -Version '2.0.0' -Enabled $false `
    -Code 'after-code' -GmProperties '{"tampered":true}' -Custom $true
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptRestorePreconditions -Current $tamperedReclassification `
            -BackupSnapshot $beforeReclassification `
            -TransactionPlan $reclassificationPlan)
} -Pattern '*not an enumerated mutation-prefix*'

# New userscript creation may be exposed disabled or enabled by its atomic install.
$absentUserscript = [pscustomobject]@{
    Exists = $false; Info = $null; Code = $null; GmProperties = $null
}
$newUserscriptPlan = [pscustomobject]@{
    userscript_after = [pscustomobject]@{
        exists = $true; name = $UserscriptName; version = '2.0.0'
        code_sha256 = Get-CanonicalTextSha256 -Text 'after-code'
        gm_properties_sha256 = Get-CanonicalTextSha256 -Text '{}'
        fresh_install_gm_properties_sha256 = Get-CanonicalTextSha256 -Text '{}'
        enabled = $true; is_custom = $true; is_style = $false
        replacement_required = $false
    }
}
foreach ($enabled in @($false, $true)) {
    $created = New-UserscriptSnapshot -Version '2.0.0' -Enabled $enabled `
        -Code 'after-code' -GmProperties '{}' -Custom $true
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $created `
            -BackupSnapshot $absentUserscript -TransactionPlan $newUserscriptPlan) `
        'authorized userscript creation crash prefix was rejected'
}
$wrongClassificationPrefix = New-UserscriptSnapshot -Version '2.0.0' -Enabled $false `
    -Code 'after-code' -GmProperties '{}' -Custom $false
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptRestorePreconditions -Current $wrongClassificationPrefix `
            -BackupSnapshot $absentUserscript -TransactionPlan $newUserscriptPlan)
} -Pattern '*identity is not an authorized transaction prefix*'

$ruleA = 'ruliweb.com##.old-noise-a'
$ruleB = 'clien.net##.old-noise-b'
$ruleC = 'ppomppu.co.kr##.old-noise-c'
$unrelated = '||unrelated.example^'
$state = [pscustomobject]@{
    UserFilter = [pscustomobject]@{
        FilterId = [int]::MinValue; FilterType = 'Standard'; IsEditable = $true
        IsCustom = $true; Name = 'User rules'
    }
    UserRules = @($ruleA, $ruleB, $ruleC, $unrelated)
    UserDisabledRules = @()
    UserRuleReadCount = 0
    MutateUserOnReadNumber = -1
    MutateUserOnEveryRead = $false
    MutateUserRule = $ruleC
    UserscriptReadCount = 0
    UserscriptHiddenReadsRemaining = 0
    ReceiptIsCustomOverride = $null
    ReceiptInitialEnabled = $false
    FreshInstallGmProperties = '{}'
    RestoreMetaVersion = '1.0.0'
    NextUpdateVersion = '2.0.0'
    ParsedContentOverride = $null
    LastParsedMeta = $null
    UserscriptWrites = @()
    IntentDirectory = $null
    ExpectedWriteIntents = @()
    Userscripts = @()
    UserscriptCode = ''
    UserscriptGmProperties = ''
    Filters = @()
    FilterRules = @{}
}
$client = New-FakeClient -State $state

# Standalone deployment protects the exact User filter bytes and every installed
# standard-filter subscription inventory without classifying or mutating rules.
$unrelatedFilter = [pscustomobject]@{
    FilterId = 42; FilterType = 'Standard'; IsEnabled = $true; IsTrusted = $false
    IsCustom = $false; IsEditable = $false; Name = 'Unrelated privacy filter'
    Version = '7.0.0'; SubscriptionUrl = 'https://filters.example/privacy.txt'
}
$state.Filters = @($unrelatedFilter)
$state.FilterRules['42'] = [pscustomobject]@{
    Rules = @('||tracker.example^', 'example.net##.sponsor')
    DisabledRules = @('example.net##.sponsor')
}
$protectedStable = Get-StableProtectedFilterStateEvidence -Client $client
$protectedRecord = ConvertTo-ProtectedFilterStateManifestRecord `
    -StableEvidence $protectedStable
$protectedBackup = [pscustomobject]@{ Manifest = [pscustomobject]@{
        protected_filter_state = $protectedRecord } }
$protectedCurrent = Assert-ProtectedFilterStateEqualsBackup -Client $client `
    -Backup $protectedBackup -Phase 'contract no-op'
Assert-Contract ([int] $protectedCurrent.subscription_inventory.count -eq 1) `
    'unrelated subscription inventory count was not exact'
Assert-Contract ([long] $protectedCurrent.subscription_inventory.bytes -gt 0) `
    'unrelated subscription inventory byte evidence was empty'
$state.FilterRules['42'].Rules = @('||tracker.example^', 'example.net##.changed')
Assert-ThrowsLike -Action {
    [void] (Assert-ProtectedFilterStateEqualsBackup -Client $client `
            -Backup $protectedBackup -Phase 'contract tamper')
} -Pattern '*subscription inventory changed*'
$state.FilterRules['42'].Rules = @('||tracker.example^', 'example.net##.sponsor')
$state.UserRules = @($ruleA, $ruleB, $ruleC, '||changed.example^')
Assert-ThrowsLike -Action {
    [void] (Assert-ProtectedFilterStateEqualsBackup -Client $client `
            -Backup $protectedBackup -Phase 'contract User-filter tamper')
} -Pattern '*User filter or subscription inventory changed*'
$state.UserRules = @($ruleA, $ruleB, $ruleC, $unrelated)
$state.Filters = @()
$state.FilterRules = @{}

# GetUserscriptMeta's local-source IsCustom=false value is promoted only after
# name, version, style, and authenticated content validation all succeed.
$manualSourceText = @'
// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @version      2.0.0
// ==/UserScript==
manual-body
'@
$manualSource = [pscustomobject]@{
    Bytes = $script:Utf8NoBom.GetBytes($manualSourceText)
    Text = $manualSourceText
    Name = $UserscriptName
    Version = '2.0.0'
    TempPath = $null
    Meta = $null
}
$state.RestoreMetaVersion = '2.0.0'
$preparedManualSource = Prepare-UserscriptMeta -Client $client -Source $manualSource
Assert-Contract ([bool] $preparedManualSource.Meta.IsCustom) `
    'authenticated manual userscript was not promoted to IsCustom=true'
[System.IO.File]::Delete([string] $preparedManualSource.TempPath)
$state.ParsedContentOverride = 'tampered-parser-content'
$tamperedManualSource = [pscustomobject]@{
    Bytes = $script:Utf8NoBom.GetBytes($manualSourceText)
    Text = $manualSourceText
    Name = $UserscriptName
    Version = '2.0.0'
    TempPath = $null
    Meta = $null
}
Assert-ThrowsLike -Action {
    [void] (Prepare-UserscriptMeta -Client $client -Source $tamperedManualSource)
} -Pattern '*differs from the authenticated source*'
Assert-Contract (-not [bool] $state.LastParsedMeta.IsCustom) `
    'classification changed before authenticated content validation completed'
[System.IO.File]::Delete([string] $tamperedManualSource.TempPath)
$state.ParsedContentOverride = $null
$state.RestoreMetaVersion = '1.0.0'

# Exact full-code and independent GM value-store checks reject stale installs.
$desiredUserscript = [pscustomobject]@{
    Name = $UserscriptName; Version = '2.0.0'; MetadataBlock = 'source-metadata-block'
    FreshInstallGmProperties = '{}'
    FreshInstallGmPropertiesSha256 = Get-CanonicalTextSha256 -Text '{}'
    Meta = [pscustomobject]@{
        Name = $UserscriptName; Version = '2.0.0'; Content = 'desired-code'
        IsCustom = $true; IsStyle = $false
    }
}
$freshPostState = Get-ExpectedUserscriptPostState `
    -Snapshot $absentUserscript -Desired $desiredUserscript
$sameBodyDowngrade = [pscustomobject]@{
    Name = $UserscriptName; Version = '1.0.0'; MetadataBlock = 'source-metadata-block'
    FreshInstallGmProperties = '{}'
    FreshInstallGmPropertiesSha256 = Get-CanonicalTextSha256 -Text '{}'
    Meta = [pscustomobject]@{ Content = 'desired-code'; IsCustom = $true; IsStyle = $false }
}
Assert-ThrowsLike -Action {
    Assert-UserscriptMutationPreconditions `
        -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
            -Code 'desired-code' -GmProperties '{}') `
        -Desired $sameBodyDowngrade
} -Pattern '*version downgrade is forbidden*'
# Same-version source validation deliberately ignores independent GM_* values.
Assert-UserscriptMutationPreconditions `
    -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
        -Code 'desired-code' -GmProperties '{"user":"value"}') `
    -Desired $desiredUserscript
Assert-UserscriptMutationPreconditions `
    -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
        -Code 'desired-code' -GmProperties '{}') `
    -Desired $desiredUserscript
$ownedSource = @'
// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      1.0.0
// @downloadURL  https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// @updateURL    https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// ==/UserScript==
'@
$ownedNonCustom = New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
    -Code $ownedSource -GmProperties '{}'
$ownedNonCustom.Info.IsCustom = $false
Assert-UserscriptMutationPreconditions -Snapshot $ownedNonCustom -Desired $desiredUserscript
$unownedNonCustom = New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
    -Code 'same-name-but-unowned' -GmProperties '{}'
$unownedNonCustom.Info.IsCustom = $false
Assert-ThrowsLike -Action {
    Assert-UserscriptMutationPreconditions -Snapshot $unownedNonCustom `
        -Desired $desiredUserscript
} -Pattern '*lacks exact Reader Gate ownership metadata*'

# Legacy migration uses this same exact-source installed-state check before it
# may plan, back up, or disable any User-filter rule.
$disabledRulesBeforeMigrationPrecondition = @($state.UserDisabledRules)
$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGmProperties = ''
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
} -Pattern '*observed_count=0*'
$state.Userscripts = @((New-UserscriptSnapshot -Version '2.0.0' -Enabled $false `
            -Code '' -GmProperties '' -Custom $true).Info)
$state.UserscriptCode = 'desired-code'
$state.UserscriptGmProperties = '{"preserved":"migration"}'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
} -Pattern '*observed_enabled=false*'
$disabledMigrationSnapshot = Get-UserscriptSnapshot -Client $client
Assert-ThrowsLike -Action {
    Assert-BackupUserscriptMatchesDesired -Snapshot $disabledMigrationSnapshot `
        -Desired $desiredUserscript
} -Pattern '*exact enabled desired userscript*'
$state.Userscripts[0].IsEnabled = $true
$state.UserscriptCode = 'wrong-migration-code'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
} -Pattern '*code SHA-256 does not match*'
$state.UserscriptCode = 'desired-code'
$validMigrationSnapshot = Get-UserscriptSnapshot -Client $client
Assert-BackupUserscriptMatchesDesired -Snapshot $validMigrationSnapshot `
    -Desired $desiredUserscript
$unchangedProof = Assert-LegacyMigrationUserscriptUnchanged -Client $client `
    -BackupSnapshot $validMigrationSnapshot -DesiredUserscript $desiredUserscript
Assert-Contract ([bool] $unchangedProof.verified) `
    'exact migration Userscript unchanged proof was not emitted'
$state.UserscriptGmProperties = '{"externally":"changed"}'
Assert-ThrowsLike -Action {
    [void] (Assert-LegacyMigrationUserscriptUnchanged -Client $client `
            -BackupSnapshot $validMigrationSnapshot `
            -DesiredUserscript $desiredUserscript)
} -Pattern '*changed during legacy migration*'
$state.UserscriptGmProperties = [string] $validMigrationSnapshot.GmProperties
Assert-Contract (Test-ExactStringMultiset -Left $disabledRulesBeforeMigrationPrecondition `
        -Right $state.UserDisabledRules) `
    'failed migration Userscript preconditions changed User-filter state'

$state.Userscripts = @((New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
            -Code '' -GmProperties '' -Custom $true).Info)
$state.UserscriptCode = 'stale-code'
$state.UserscriptGmProperties = '{"stale":true}'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript `
            -ExpectedPostState $freshPostState)
} -Pattern '*version does not match*'
$state.Userscripts[0].Version = '2.0.0'
$state.UserscriptCode = 'desired-code'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript `
            -ExpectedPostState $freshPostState)
} -Pattern '*GM value-store SHA-256*'
$state.UserscriptGmProperties = '{}'
$state.Userscripts[0].IsCustom = $false
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript `
            -ExpectedPostState $freshPostState)
} -Pattern '*not selected as an executable custom extension*'
$state.Userscripts[0].IsCustom = $true
$state.UserscriptReadCount = 0
$state.UserscriptHiddenReadsRemaining = 2
$installedUserscript = Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript `
    -ExpectedPostState $freshPostState
Assert-Contract ($installedUserscript.InstalledCodeSha256 -ceq
        (Get-CanonicalTextSha256 -Text 'desired-code')) 'installed code hash was not exposed'
Assert-Contract ([int] $installedUserscript.VisibilityObservationCount -eq 4) `
    'transient userscript visibility was not retried until two exact consecutive reads'
Assert-Contract ([int] $state.UserscriptReadCount -eq 4) `
    'userscript visibility retry count was not bounded and observable'
$state.UserscriptGmProperties = '{"preserved":"standalone-verify"}'
$state.UserscriptReadCount = 0
$standaloneVerified = Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript
Assert-Contract ($standaloneVerified.InstalledGmPropertiesSha256 -ceq
        (Get-CanonicalTextSha256 -Text $state.UserscriptGmProperties)) `
    'standalone verification did not report the preserved GM value-store hash'
$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGmProperties = ''
$state.UserscriptHiddenReadsRemaining = 0

# An authenticated manual install must request, receive, and converge on the
# executable IsCustom=true classification.
[void] (Invoke-UserscriptMutation -Client $client -Snapshot $absentUserscript `
        -Desired $desiredUserscript -JournalDirectory $null)
Assert-Contract ([bool] $state.Userscripts[0].IsCustom) `
    'authenticated manual install did not converge on IsCustom=true'
$state.Userscripts = @()
$state.UserscriptCode = ''
$state.ReceiptIsCustomOverride = $false
Assert-ThrowsLike -Action {
    [void] (Invoke-UserscriptMutation -Client $client -Snapshot $absentUserscript `
            -Desired $desiredUserscript -JournalDirectory $null)
} -Pattern '*installation receipt differs from the exact source*'
$state.ReceiptIsCustomOverride = $null
$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGmProperties = ''

# A changed executable custom script uses remove -> install, never the broken
# UpdateUserscriptCode path. Both the forward update and rollback preserve
# the saved GM values and executable classification.
$executableUpdateSnapshot = New-UserscriptSnapshot -Version '1.0.0' `
    -Enabled $false -Code 'before-code' -GmProperties '{"saved":"before"}' -Custom $true
$state.Userscripts = @($executableUpdateSnapshot.Info)
$state.UserscriptCode = $executableUpdateSnapshot.Code
$state.UserscriptGmProperties = $executableUpdateSnapshot.GmProperties
$state.UserscriptWrites = @()
$executableForwardJournal = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hdf-executable-forward-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($executableForwardJournal)
$state.IntentDirectory = $executableForwardJournal
$state.ExpectedWriteIntents = @(
    [pscustomobject]@{ Write = 'remove'; Event = 'intent-userscript-replacement-remove' },
    [pscustomobject]@{ Write = 'install'; Event = 'intent-userscript-install' },
    [pscustomobject]@{ Write = 'update-gm'; Event = 'intent-userscript-replacement-restore-gm' },
    [pscustomobject]@{ Write = 'set-status'; Event = 'intent-userscript-enable' }
)
try {
    [void] (Invoke-UserscriptMutation -Client $client `
            -Snapshot $executableUpdateSnapshot -Desired $desiredUserscript `
            -JournalDirectory $executableForwardJournal)
}
finally {
    $state.IntentDirectory = $null
    $state.ExpectedWriteIntents = @()
    [System.IO.Directory]::Delete($executableForwardJournal, $true)
}
Assert-Contract ([bool] $state.Userscripts[0].IsCustom) `
    'changed executable userscript lost IsCustom during replacement'
Assert-Contract ([string] $state.UserscriptGmProperties -ceq '{"saved":"before"}') `
    'changed executable userscript did not preserve GM values'
Assert-Contract (Test-ExactStringSequence -Left $state.UserscriptWrites `
        -Right @('remove', 'install', 'update-gm', 'set-status')) `
    'changed executable userscript did not use replacement order'

$state.UserscriptWrites = @()
$executableRollbackJournal = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hdf-executable-rollback-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($executableRollbackJournal)
$state.IntentDirectory = $executableRollbackJournal
$state.ExpectedWriteIntents = @(
    [pscustomobject]@{ Write = 'remove'; Event = 'intent-rollback-userscript-replacement-remove' },
    [pscustomobject]@{ Write = 'install'; Event = 'intent-rollback-userscript-replacement-install' },
    [pscustomobject]@{ Write = 'update-gm'; Event = 'intent-rollback-userscript-gm' },
    [pscustomobject]@{ Write = 'set-status'; Event = 'intent-rollback-userscript-status' }
)
try {
    Restore-UserscriptSnapshot -Client $client -Snapshot $executableUpdateSnapshot `
        -JournalDirectory $executableRollbackJournal
}
finally {
    $state.IntentDirectory = $null
    $state.ExpectedWriteIntents = @()
    [System.IO.Directory]::Delete($executableRollbackJournal, $true)
}
$restoredExecutable = Get-UserscriptSnapshot -Client $client
Assert-Contract (Test-UserscriptSnapshotExact -Left $restoredExecutable `
        -Right $executableUpdateSnapshot) `
    'changed executable userscript rollback was not exact'

$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGmProperties = ''
$state.UserscriptWrites = @()

# A source-owned false classification is transactionally replaced and retains
# its independent GM values. Rollback reinstalls the exact original class.
$reclassificationSnapshot = New-UserscriptSnapshot -Version '1.0.0' `
    -Enabled $true -Code $ownedSource -GmProperties '{"persisted":1}' -Custom $false
$state.Userscripts = @($reclassificationSnapshot.Info)
$state.UserscriptCode = $reclassificationSnapshot.Code
$state.UserscriptGmProperties = $reclassificationSnapshot.GmProperties
$state.UserscriptWrites = @()
$forwardJournal = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hdf-reclass-forward-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($forwardJournal)
$state.IntentDirectory = $forwardJournal
$state.ExpectedWriteIntents = @(
    [pscustomobject]@{ Write = 'remove'; Event = 'intent-userscript-replacement-remove' },
    [pscustomobject]@{ Write = 'install'; Event = 'intent-userscript-install' },
    [pscustomobject]@{
        Write = 'update-gm'; Event = 'intent-userscript-replacement-restore-gm'
    },
    [pscustomobject]@{ Write = 'set-status'; Event = 'intent-userscript-enable' }
)
try {
    [void] (Invoke-UserscriptMutation -Client $client `
            -Snapshot $reclassificationSnapshot -Desired $desiredUserscript `
            -JournalDirectory $forwardJournal)
}
finally {
    $state.IntentDirectory = $null
    $state.ExpectedWriteIntents = @()
    [System.IO.Directory]::Delete($forwardJournal, $true)
}
Assert-Contract ([bool] $state.Userscripts[0].IsCustom) `
    'owned noncustom userscript was not reclassified by replacement'
Assert-Contract ([string] $state.UserscriptGmProperties -ceq '{"persisted":1}') `
    'reclassification did not restore independent GM values'
Assert-Contract (Test-ExactStringSequence -Left $state.UserscriptWrites `
        -Right @('remove', 'install', 'update-gm', 'set-status')) `
    'reclassification writes were not executed in the exact transaction order'

$state.UserscriptWrites = @()
$rollbackJournal = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hdf-reclass-rollback-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($rollbackJournal)
$state.IntentDirectory = $rollbackJournal
$state.ExpectedWriteIntents = @(
    [pscustomobject]@{
        Write = 'remove'; Event = 'intent-rollback-userscript-replacement-remove'
    },
    [pscustomobject]@{
        Write = 'install'; Event = 'intent-rollback-userscript-replacement-install'
    },
    [pscustomobject]@{ Write = 'update-gm'; Event = 'intent-rollback-userscript-gm' },
    [pscustomobject]@{ Write = 'set-status'; Event = 'intent-rollback-userscript-status' }
)
try {
    Restore-UserscriptSnapshot -Client $client -Snapshot $reclassificationSnapshot `
        -JournalDirectory $rollbackJournal
}
finally {
    $state.IntentDirectory = $null
    $state.ExpectedWriteIntents = @()
    [System.IO.Directory]::Delete($rollbackJournal, $true)
}
$restoredFalse = Get-UserscriptSnapshot -Client $client
Assert-Contract (Test-UserscriptSnapshotExact -Left $restoredFalse `
        -Right $reclassificationSnapshot) `
    'rollback did not exactly restore original IsCustom=false snapshot'
Assert-Contract (Test-ExactStringSequence -Left $state.UserscriptWrites `
        -Right @('remove', 'install', 'update-gm', 'set-status')) `
    'false-classification rollback did not use exact replacement order'

$originalTrueSnapshot = New-UserscriptSnapshot -Version '1.0.0' `
    -Enabled $false -Code $ownedSource -GmProperties '{"original":true}' -Custom $true
$state.Userscripts = @((New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
            -Code '' -GmProperties '' -Custom $false).Info)
$state.UserscriptCode = $ownedSource
$state.UserscriptGmProperties = '{}'
$state.UserscriptWrites = @()
Restore-UserscriptSnapshot -Client $client -Snapshot $originalTrueSnapshot `
    -JournalDirectory $null
$restoredTrue = Get-UserscriptSnapshot -Client $client
Assert-Contract (Test-UserscriptSnapshotExact -Left $restoredTrue `
        -Right $originalTrueSnapshot) `
    'rollback did not exactly restore original IsCustom=true snapshot'

$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGmProperties = ''
$state.UserscriptWrites = @()

# Filter creation and each subsequent disable are accepted only in API order.
$oldRulesSha = Get-RuleListSha256 -Rules @('old.example##.gate')
$emptyDisabledSha = Get-RuleMultisetSha256 -Rules @()
$old1 = [pscustomobject]@{
    FilterId = 10; IsEnabled = $true; IsTrusted = $false; IsCustom = $true; IsEditable = $false
    Name = $FilterName; Version = '1.0.0'; SubscriptionUrl = 'https://example.com/v1/filter.txt'
    RulesSha256 = $oldRulesSha; DisabledRulesSha256 = $emptyDisabledSha
}
$old2 = [pscustomobject]@{
    FilterId = 20; IsEnabled = $true; IsTrusted = $true; IsCustom = $true; IsEditable = $false
    Name = $FilterName; Version = '1.1.0'; SubscriptionUrl = 'https://example.com/v1.1/filter.txt'
    RulesSha256 = $oldRulesSha; DisabledRulesSha256 = $emptyDisabledSha
}
$desiredRulesSha = Get-RuleListSha256 -Rules @('example.com##.gate')
$newFilter = [pscustomobject]@{
    FilterId = 77; IsEnabled = $false; IsTrusted = $false; IsCustom = $true; IsEditable = $false
    Name = $FilterName; Version = '2.0.0'; SubscriptionUrl = 'https://example.com/v2/filter.txt'
    RulesSha256 = $desiredRulesSha; DisabledRulesSha256 = $emptyDisabledSha
}
$beforeFilters = [pscustomobject]@{ States = @($old1, $old2) }
$sameVersionMirror = [pscustomobject]@{
    FilterId = 30; IsEnabled = $true; IsTrusted = $true; IsCustom = $true; IsEditable = $false
    Name = $FilterName; Version = '2.0.0'
    SubscriptionUrl = 'https://mirror.example/filter.txt'
    RulesSha256 = $desiredRulesSha; DisabledRulesSha256 = $emptyDisabledSha
}
$ExpectedInstalledFilterRulesSha256 = $desiredRulesSha
Assert-FilterSnapshotMutationPreconditions `
    -Snapshot ([pscustomobject]@{ States = @($sameVersionMirror) }) `
    -Desired ([pscustomobject]@{ Url = 'https://example.com/v2/filter.txt'; Version = '2.0.0' })
$sameVersionWrongHash = Copy-FilterState $sameVersionMirror $null $null
$sameVersionWrongHash.RulesSha256 = Get-RuleListSha256 -Rules @('changed.example##.gate')
Assert-ThrowsLike -Action {
    Assert-FilterSnapshotMutationPreconditions `
        -Snapshot ([pscustomobject]@{ States = @($sameVersionWrongHash) }) `
        -Desired ([pscustomobject]@{ Url = 'https://example.com/v2/filter.txt'; Version = '2.0.0' })
} -Pattern '*not the exact equivalent gate artifact*'
$filterTransaction = [pscustomobject]@{ filter_after = [pscustomobject]@{
        exists = $true; name = $FilterName; version = '2.0.0'
        subscription_url = 'https://example.com/v2/filter.txt'; raw_sha256 = ('b' * 64)
        installed_rules_sha256 = $desiredRulesSha; disabled_rules_sha256 = $emptyDisabledSha
        enabled = $true; trusted = $true; is_custom = $true; is_editable = $false
    } }
$filterPrefixes = @(
    [pscustomobject]@{ States = @($old1, $old2) },
    [pscustomobject]@{ States = @($old1, $old2, (Copy-FilterState $newFilter $false $false)) },
    [pscustomobject]@{ States = @($old1, $old2, (Copy-FilterState $newFilter $true $false)) },
    [pscustomobject]@{ States = @($old1, $old2, (Copy-FilterState $newFilter $true $true)) },
    [pscustomobject]@{ States = @((Copy-FilterState $old1 $false $null), $old2,
            (Copy-FilterState $newFilter $true $true)) },
    [pscustomobject]@{ States = @((Copy-FilterState $old1 $false $null),
            (Copy-FilterState $old2 $false $null), (Copy-FilterState $newFilter $true $true)) }
)
for ($index = 0; $index -lt $filterPrefixes.Count; $index++) {
    $plan = Assert-FilterRestorePreconditions -CurrentSnapshot $filterPrefixes[$index] `
        -BackupSnapshot $beforeFilters -TransactionPlan $filterTransaction
    Assert-Contract ((-not $plan.NeedsRestore) -eq ($index -eq 0)) `
        'filter crash prefix restore flag was incorrect'
}
$outOfOrderFilter = [pscustomobject]@{ States = @($old1,
        (Copy-FilterState $old2 $false $null), (Copy-FilterState $newFilter $true $true)) }
Assert-ThrowsLike -Action {
    [void] (Assert-FilterRestorePreconditions -CurrentSnapshot $outOfOrderFilter `
            -BackupSnapshot $beforeFilters -TransactionPlan $filterTransaction)
} -Pattern '*not an enumerated mutation-prefix*'

# A disabled rule in the trusted target filter is always a verification failure.
$state.Filters = @([pscustomobject]@{
        FilterId = 77; IsEnabled = $true; IsTrusted = $true; IsCustom = $true
        IsEditable = $false; Name = $FilterName; Version = '2.0.0'
        SubscriptionUrl = 'https://example.com/v2/filter.txt'; FilterType = 'Standard'
    })
$state.FilterRules['77'] = [pscustomobject]@{
    Rules = @('example.com##.gate', 'example.com##.keep')
    DisabledRules = @('example.com##.keep')
}
$ExpectedInstalledFilterRulesSha256 = Get-RuleListSha256 -Rules $state.FilterRules['77'].Rules
$desiredFilter = [pscustomobject]@{
    Url = 'https://example.com/v2/filter.txt'; Version = '2.0.0'
}
Assert-ThrowsLike -Action {
    [void] (Assert-FilterInstalled -Client $client -Desired $desiredFilter)
} -Pattern '*contains disabled rules*'
$state.Filters = @()
$state.FilterRules = @{}

# Complete-state reads absorb one cache transition but reject continuous TOCTOU changes.
$state.UserRuleReadCount = 0
$state.MutateUserOnReadNumber = 2
$stableAfterTransition = Get-StableCompleteTargetStateSnapshot `
    -Client $client -ExactFilterUrl $null
Assert-Contract ([int] $stableAfterTransition.ObservationCount -eq 3) `
    'one transient state transition did not converge on two consecutive exact reads'
$state.UserDisabledRules = @()
$state.UserRuleReadCount = 0
$state.MutateUserOnReadNumber = -1
$state.MutateUserOnEveryRead = $true
Assert-ThrowsLike -Action {
    [void] (Get-StableCompleteTargetStateSnapshot -Client $client -ExactFilterUrl $null)
} -Pattern '*were not identical within*'
$state.MutateUserOnEveryRead = $false
$state.UserDisabledRules = @()
$state.UserRuleReadCount = 0
$beforeComplete = Get-CompleteTargetStateSnapshot -Client $client -ExactFilterUrl $null
$beforeCompleteSha = Get-CompleteTargetStateSha256 -Snapshot $beforeComplete
$prewriteBackup = [pscustomobject]@{ Manifest = [pscustomobject]@{
        complete_target_state = [pscustomobject]@{ read_2_sha256 = $beforeCompleteSha } } }
$state.UserDisabledRules = @($ruleA)
Assert-ThrowsLike -Action {
    [void] (Assert-CurrentStateEqualsBackup -Client $client -Backup $prewriteBackup `
            -ExactFilterUrl $null)
} -Pattern '*changed after backup*'
$state.UserDisabledRules = @()

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) (
    'hotdeal-focus-contract-' + [Guid]::NewGuid().ToString('N'))
[void] [System.IO.Directory]::CreateDirectory($temporary)
try {
    # Parse the actual release artifacts through the same source contracts.
    $ExpectedUserscriptSha256 = $null
    $builtUserscript = Get-UserscriptSource -Source (
        (Join-Path $PSScriptRoot '..\hotdeal-focus.user.js'))
    Assert-Contract (Test-ExactStringSequence -Left $builtUserscript.Grants `
            -Right @(
                'GM_addElement', 'GM_getValue', 'GM_setValue', 'GM_deleteValue', 'window.onurlchange'
            )) `
        'actual release Userscript grants are not exact'
    Assert-Contract ($builtUserscript.InstallUrl -ceq $script:ReleaseUserscriptUrl) `
        'actual release Userscript install URL is not exact'

    # A schema-v2 backup is accepted only when its payloads reconstruct the
    # complete-state hash committed by two identical reads.
    $validationId = 'fixture-backup-v2'
    $validationDir = Join-Path $temporary $validationId
    [void] [System.IO.Directory]::CreateDirectory($validationDir)
    $rulesPayload = Write-BackupPayload -Directory $validationDir `
        -RelativePath 'user-filter.rules.txt' `
        -Content ($ruleA + "`n" + $ruleB + "`n" + $ruleC + "`n" + $unrelated) `
        -Role 'user-filter-rules'
    $disabledPayload = Write-BackupPayload -Directory $validationDir `
        -RelativePath 'user-filter.disabled-rules.txt' -Content '' `
        -Role 'user-filter-disabled-rules'
    $fixtureState = [pscustomobject]@{
        UserFilter = $state.UserFilter
        UserRules = [pscustomobject]@{ Rules = @($state.UserRules); DisabledRules = @() }
        UserscriptSnapshot = $absentUserscript
        FilterEntries = @()
    }
    $fixtureStateSha = Get-CompleteTargetStateSha256 -Snapshot $fixtureState
    $fixtureManifest = [ordered]@{
        schema_version = 2; backup_id = $validationId; tool_version = 'test'
        created_utc = [DateTime]::UtcNow.ToString('o'); complete_marker = 'backup-complete.json'
        payloads = @($rulesPayload, $disabledPayload)
        user_filter = [ordered]@{
            filter_id = [int]::MinValue; name = 'User rules'; filter_type = 'Standard'
            is_editable = $true; is_custom = $true
            rule_count = 4; disabled_rule_count = 0
            rules_sha256 = Get-RuleListSha256 -Rules $state.UserRules
            disabled_rules_sha256 = Get-RuleMultisetSha256 -Rules @()
            rules_payload = $rulesPayload.path
            disabled_rules_payload = $disabledPayload.path
        }
        target_userscript = $null; target_filters = @()
        complete_target_state = [ordered]@{
            read_1_sha256 = $fixtureStateSha; read_2_sha256 = $fixtureStateSha
            identical = $true
        }
    }
    $fixtureManifestPath = Join-Path $validationDir 'backup-manifest.json'
    Write-Utf8FileNew -Path $fixtureManifestPath `
        -Content ($fixtureManifest | ConvertTo-Json -Depth 10)
    $fixtureManifestBytes = [System.IO.File]::ReadAllBytes($fixtureManifestPath)
    $fixtureComplete = [ordered]@{
        schema_version = 1; backup_schema_version = 2; backup_id = $validationId
        complete = $true; manifest_path = 'backup-manifest.json'
        manifest_bytes = $fixtureManifestBytes.Length
        manifest_raw_sha256 = Get-Sha256Hex -Bytes $fixtureManifestBytes
    }
    Write-Utf8FileNew -Path (Join-Path $validationDir 'backup-complete.json') `
        -Content ($fixtureComplete | ConvertTo-Json -Depth 4)
    $validatedFixture = Get-ValidatedBackup -Path $validationDir
    Assert-Contract (@($validatedFixture.UserRules).Count -eq 4) `
        'schema-v2 backup did not validate'
    [System.IO.File]::AppendAllText((Join-Path $validationDir 'user-filter.rules.txt'),
        'tamper', $script:Utf8NoBom)
    Assert-ThrowsLike -Action { [void] (Get-ValidatedBackup -Path $validationDir) } `
        -Pattern '*failed raw byte validation*'

    # Every one-rule legacy mutation prefix is recoverable; an out-of-order
    # subset is not.
    Write-Utf8FileNew -Path (Join-Path $temporary 'backup-manifest.json') -Content '{}'
    $candidateRecords = for ($index = 0; $index -lt 3; $index++) {
        [pscustomobject]@{
            ZeroBasedIndex = $index; IsDisabled = $false
            Public = [pscustomobject]@{
                rule_sha256 = Get-CanonicalTextSha256 -Text $state.UserRules[$index]
            }
        }
    }
    $journalMigration = [pscustomobject]@{
        Filter = $state.UserFilter; CandidateRecords = @($candidateRecords)
    }
    Initialize-TransactionJournal -Directory $temporary -CommandName 'migrate-legacy' `
        -DesiredUserscript $null -BeforeUserscriptSnapshot $null `
        -DesiredFilter $null -MigrationPlan $journalMigration
    $manifestBytes = [System.IO.File]::ReadAllBytes(
        (Join-Path $temporary 'backup-manifest.json'))
    $validatedJournal = Get-ValidatedTransactionPlan -Directory $temporary `
        -ManifestSha256 (Get-Sha256Hex -Bytes $manifestBytes)
    $backup = [pscustomobject]@{
        Directory = $temporary
        Manifest = [pscustomobject]@{ user_filter = [pscustomobject]@{
                filter_id = [int]::MinValue } }
        UserRules = @($state.UserRules)
        UserDisabledRules = @()
        UserscriptSnapshot = $absentUserscript
        FilterSnapshot = [pscustomobject]@{ States = @() }
        TransactionPlan = $validatedJournal
    }
    for ($prefixLength = 0; $prefixLength -le 3; $prefixLength++) {
        if ($prefixLength -eq 0) {
            $state.UserDisabledRules = [string[]]::new(0)
        } else {
            $state.UserDisabledRules = @($state.UserRules[0..($prefixLength - 1)])
        }
        try { $restorePlan = Get-BackupRestorePlan -Client $client -Backup $backup }
        catch {
            $debugCurrent = $client.GetFilterSubscriptionRules(
                $state.UserFilter.FilterId, $script:StandardFilterType)
            $debugExtras = @(Get-CurrentOnlyRules -Baseline $backup.UserDisabledRules `
                    -Current $debugCurrent.DisabledRules)
            $debugAllowed = @(Get-AllowedLegacyRestoreDelta -Backup $backup)
            throw ("legacy prefix $prefixLength failed: $($_.Exception.Message); " +
                "current=$(@($debugCurrent.DisabledRules).Count), " +
                "extras=$($debugExtras.Count), allowed=$($debugAllowed.Count)")
        }
        Assert-Contract (@($restorePlan.DisabledRulesToEnable).Count -eq $prefixLength) `
            "legacy crash prefix $prefixLength was not planned exactly: $(@($restorePlan.DisabledRulesToEnable).Count)"
    }
    $state.UserDisabledRules = @($ruleB)
    Assert-ThrowsLike -Action {
        [void] (Get-BackupRestorePlan -Client $client -Backup $backup)
    } -Pattern '*not an exact ordered migration-prefix*'
    $state.UserDisabledRules = @($ruleA, $ruleB, $ruleC)
    $restorePlan = Get-BackupRestorePlan -Client $client -Backup $backup
    Invoke-BackupRestore -Client $client -Backup $backup -Plan $restorePlan
    Assert-Contract (@($state.UserDisabledRules).Count -eq 0) 'legacy delta was not restored'
    $again = Get-BackupRestorePlan -Client $client -Backup $backup
    Assert-Contract ([bool] $again.IsAlreadyRestored) 'restore is not idempotent'
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        [System.IO.Directory]::Delete($temporary, $true)
    }
}

[ordered]@{
    ok = $true
    tests = @('scope-classification', 'userscript-all-crash-prefixes',
        'userscript-authenticated-custom-promotion',
        'migration-authenticated-userscript-precondition',
        'userscript-owned-noncustom-reclassification-and-exact-rollback',
        'userscript-visibility-convergence', 'filter-all-crash-prefixes',
        'disabled-filter-rule-rejection', 'inter-read-mutation-rejection',
        'prewrite-mutation-rejection', 'actual-release-source-contract',
        'backup-complete-state-hash', 'backup-raw-hash-tamper',
        'https-content-length-runtime-shapes', 'durable-journal',
        'legacy-all-crash-prefixes', 'idempotent-restore')
} | ConvertTo-Json -Depth 3
