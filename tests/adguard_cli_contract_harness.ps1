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
        return @($this.State.Userscripts)
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscriptCode -Value {
        param($name, $includeMetadata)
        return [string] $this.State.UserscriptCode
    }
    Add-Member -InputObject $client -MemberType ScriptMethod -Name GetUserscriptGmProperties -Value {
        param($name)
        return [string] $this.State.UserscriptGm
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
    param([string] $Version, [bool] $Enabled, [string] $Code, [string] $Gm)
    return [pscustomobject]@{
        Exists = $true
        Info = [pscustomobject]@{
            Name = $UserscriptName; Version = $Version; IsCustom = $true
            IsEnabled = $Enabled; IsStyle = $false
        }
        Code = $Code
        Gm = $Gm
    }
}

$exclusive = Get-CosmeticRuleScopeAnalysis -Rule 'ruliweb.com,clien.net##.noise'
$mixed = Get-CosmeticRuleScopeAnalysis -Rule 'ruliweb.com,example.com##.noise'
$global = Get-CosmeticRuleScopeAnalysis -Rule '##.noise'
Assert-Contract ($exclusive.ScopeKind -ceq 'exclusive-target') 'exclusive scope misclassified'
Assert-Contract ($mixed.ScopeKind -ceq 'mixed-target') 'mixed scope misclassified'
Assert-Contract ($global.ScopeKind -ceq 'global') 'global scope misclassified'

# Existing-userscript mutation has exactly three API prefixes.
$beforeUserscript = New-UserscriptSnapshot -Version '1.0.0' -Enabled $false `
    -Code 'before-code' -Gm 'before-gm'
$userscriptPlan = [pscustomobject]@{
    userscript_after = [pscustomobject]@{
        exists = $true; name = $UserscriptName; version = '2.0.0'
        code_sha256 = Get-CanonicalTextSha256 -Text 'after-code'
        gm_sha256 = Get-CanonicalTextSha256 -Text 'after-gm'
        enabled = $true; is_custom = $true; is_style = $false
    }
}
Assert-Contract (-not (Assert-UserscriptRestorePreconditions -Current $beforeUserscript `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan)) `
    'exact userscript before-state was not idempotent'
$userscriptPrefixes = @(
    (New-UserscriptSnapshot -Version '1.0.0' -Enabled $false -Code 'after-code' -Gm 'before-gm'),
    (New-UserscriptSnapshot -Version '2.0.0' -Enabled $false -Code 'after-code' -Gm 'after-gm'),
    (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true -Code 'after-code' -Gm 'after-gm')
)
foreach ($prefix in $userscriptPrefixes) {
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $prefix `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan) `
        'authorized userscript crash prefix was rejected'
}
$invalidUserscript = New-UserscriptSnapshot -Version '2.0.0' -Enabled $false `
    -Code 'before-code' -Gm 'after-gm'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptRestorePreconditions -Current $invalidUserscript `
            -BackupSnapshot $beforeUserscript -TransactionPlan $userscriptPlan)
} -Pattern '*not an enumerated mutation-prefix*'

# New userscript creation may be exposed disabled or enabled by its atomic install.
$absentUserscript = [pscustomobject]@{ Exists = $false; Info = $null; Code = $null; Gm = $null }
foreach ($enabled in @($false, $true)) {
    $created = New-UserscriptSnapshot -Version '2.0.0' -Enabled $enabled `
        -Code 'after-code' -Gm 'after-gm'
    Assert-Contract (Assert-UserscriptRestorePreconditions -Current $created `
            -BackupSnapshot $absentUserscript -TransactionPlan $userscriptPlan) `
        'authorized userscript creation crash prefix was rejected'
}

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
    MutateUserRule = $ruleC
    Userscripts = @()
    UserscriptCode = ''
    UserscriptGm = ''
    Filters = @()
    FilterRules = @{}
}
$client = New-FakeClient -State $state

# Exact code and canonical GM checks reject stale same-name installations.
$desiredUserscript = [pscustomobject]@{
    Name = $UserscriptName; Version = '2.0.0'; Metadata = 'desired-gm'
    Meta = [pscustomobject]@{ Content = 'desired-code' }
}
$sameBodyDowngrade = [pscustomobject]@{
    Name = $UserscriptName; Version = '1.0.0'; Metadata = 'desired-gm'
    Meta = [pscustomobject]@{ Content = 'desired-code' }
}
Assert-ThrowsLike -Action {
    Assert-UserscriptMutationPreconditions `
        -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
            -Code 'desired-code' -Gm 'desired-gm') `
        -Desired $sameBodyDowngrade
} -Pattern '*version downgrade is forbidden*'
$sameVersionGmChange = [pscustomobject]@{
    Name = $UserscriptName; Version = '2.0.0'; Metadata = 'changed-gm'
    Meta = [pscustomobject]@{ Content = 'desired-code' }
}
Assert-ThrowsLike -Action {
    Assert-UserscriptMutationPreconditions `
        -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
            -Code 'desired-code' -Gm 'desired-gm') `
        -Desired $sameVersionGmChange
} -Pattern '*without a strictly newer version*'
Assert-UserscriptMutationPreconditions `
    -Snapshot (New-UserscriptSnapshot -Version '2.0.0' -Enabled $true `
        -Code 'desired-code' -Gm 'desired-gm') `
    -Desired $desiredUserscript
$state.Userscripts = @((New-UserscriptSnapshot -Version '1.0.0' -Enabled $true `
            -Code '' -Gm '').Info)
$state.UserscriptCode = 'stale-code'
$state.UserscriptGm = 'stale-gm'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
} -Pattern '*version does not match*'
$state.Userscripts[0].Version = '2.0.0'
$state.UserscriptCode = 'desired-code'
Assert-ThrowsLike -Action {
    [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
} -Pattern '*GM metadata SHA-256*'
$state.UserscriptGm = 'desired-gm'
$installedUserscript = Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript
Assert-Contract ($installedUserscript.InstalledCodeSha256 -ceq
        (Get-CanonicalTextSha256 -Text 'desired-code')) 'installed code hash was not exposed'
$state.Userscripts = @()
$state.UserscriptCode = ''
$state.UserscriptGm = ''

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

# Complete-state double read and prewrite compare reject TOCTOU changes.
$state.UserRuleReadCount = 0
$state.MutateUserOnReadNumber = 2
Assert-ThrowsLike -Action {
    [void] (Get-StableCompleteTargetStateSnapshot -Client $client -ExactFilterUrl $null)
} -Pattern '*were not identical*'
$state.UserDisabledRules = @()
$state.UserRuleReadCount = 0
$state.MutateUserOnReadNumber = -1
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
    $manifestPath = Join-Path $PSScriptRoot '..\release-manifest.json'
    $manifestContract = Get-ReleaseManifestContract -Source $manifestPath
    $ExpectedUserscriptSha256 = $manifestContract.UserscriptCanonicalTextSha256
    $ExpectedFilterSha256 = $manifestContract.FilterRawSha256
    $ExpectedInstalledFilterRulesSha256 = $manifestContract.FilterInstalledRulesSha256
    $builtUserscript = Get-UserscriptSource -Source (
        (Join-Path $PSScriptRoot '..\hotdeal-focus.user.js'))
    $filterBytes = [System.IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..\filter.txt'))
    $builtFilter = ConvertFrom-FilterSourceBytes -Bytes $filterBytes `
        -Url $manifestContract.FilterSubscriptionUrl
    Assert-ReleaseInputsMatchManifest -ManifestContract $manifestContract `
        -DesiredUserscript $builtUserscript -DesiredFilter $builtFilter
    Assert-Contract ($builtFilter.Name -ceq $FilterName) `
        'actual built filter does not satisfy the CLI Title contract'

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
        -DesiredUserscript $null -DesiredFilter $null -MigrationPlan $journalMigration
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
        'userscript-stale-and-gm-rejection', 'filter-all-crash-prefixes',
        'disabled-filter-rule-rejection', 'inter-read-mutation-rejection',
        'prewrite-mutation-rejection', 'actual-release-source-contract',
        'backup-complete-state-hash', 'backup-raw-hash-tamper',
        'https-content-length-runtime-shapes', 'durable-journal',
        'legacy-all-crash-prefixes', 'idempotent-restore')
} | ConvertTo-Json -Depth 3
