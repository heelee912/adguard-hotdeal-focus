#requires -Version 5.1
<#
.SYNOPSIS
Safely inspects, backs up, deploys, and verifies Hotdeal Focus in AdGuard for Windows.

.DESCRIPTION
This command uses AdGuard's own authenticated UiApplicationApiClient. It never edits
AdGuard databases or ACLs, never overwrites the User filter, and never stops the
AdGuard service. The explicit migrate-legacy command can only disable the exact,
preconditioned current-snapshot rules whose cosmetic scope is exclusive to the seven
target domains, and can re-enable that exact transaction delta during rollback. Scope
does not prove rule provenance, so applying that migration requires a second approval
switch after reviewing its hash/index-only WhatIf plan.
Every API client is disconnected with Disconnect(false, true).

Mutating commands require -Apply. A deploy installs and enables the userscript,
reversibly disables the explicitly approved exclusive-target snapshot rules, and only
then installs or enables the
marker-only custom filter. Existing target subscriptions are disabled, not deleted,
so a failed deployment can roll back without reconstructing an old remote filter.
Schema-v2 backups contain raw payload hashes and an atomic complete marker. Each
mutation writes an append-only transaction journal. restore-backup accepts only an
exact authorized before/after state and is safe to repeat. Legacy schema-v1 backups
remain untouched but are not auto-restored because they lack these proofs.

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 inspect

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 backup

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 restore-backup `
  -BackupPath <completed-schema-v2-backup-directory> -WhatIf

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 restore-backup `
  -BackupPath <completed-schema-v2-backup-directory> -Apply

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 migrate-legacy -WhatIf

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 migrate-legacy `
  -ApproveExclusiveTargetMigration -Apply

.EXAMPLE
powershell.exe -NoProfile -File .\scripts\adguard_windows_cli.ps1 deploy `
  -UserscriptSource .\hotdeal-focus.user.js `
  -FilterUrl https://github.com/heelee912/adguard-hotdeal-focus/releases/download/gate-v2.0.2/filter.txt `
  -ReleaseManifestSource https://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json `
  -ExpectedUserscriptSha256 <canonical-text-sha256> `
  -ExpectedFilterSha256 <raw-file-sha256> `
  -ExpectedInstalledFilterRulesSha256 <canonical-installed-rules-sha256> `
  -ApproveExclusiveTargetMigration `
  -Apply
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('inspect', 'backup', 'restore-backup', 'install-userscript',
        'migrate-legacy', 'install-filter', 'deploy', 'verify',
        'csp-probe-inspect', 'csp-probe-install', 'csp-probe-restore')]
    [string] $Command,

    [string] $UserscriptSource,

    [string] $FilterUrl,

    [string] $ReleaseManifestSource,

    [ValidateNotNullOrEmpty()]
    [string] $UserscriptName = 'AdGuard Hotdeal Focus Reader Gate',

    [ValidateNotNullOrEmpty()]
    [string] $FilterName = 'AdGuard Hotdeal Focus Marker Gate',

    [string] $ExpectedUserscriptSha256,

    [string] $ExpectedFilterSha256,

    [string] $ExpectedInstalledFilterRulesSha256,

    [string] $BackupRoot,

    [string] $BackupPath,

    [string] $ReferenceUserFilterSnapshot,

    [switch] $ApproveExclusiveTargetMigration,

    [string] $EvidencePath,

    [ValidateRange(1, 120)]
    [int] $NetworkTimeoutSeconds = 30,

    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '0.5.6'
$script:MaximumSourceBytes = 8MB
$script:AdGuardInstallDirectory = $null
$script:AdGuardProcess = $null
$script:UiWasStarted = $false
$script:ApiClientType = $null
$script:HubType = $null
$script:FilterSubscriptionType = $null
$script:StandardFilterType = $null
$script:TemporaryPaths = New-Object 'System.Collections.Generic.List[string]'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false, $true)
$script:LastConflictReport = $null
$script:LastUserFilterEvidence = $null
$script:EvidenceAttempted = $false
$script:HistoricalSnapshotRules = @()
$script:RecoveryBackupPath = $null
$script:RecoveryCommand = $null
$script:ReaderGateProtocolVersion = 2
$script:ReaderGateGrant = 'GM_addElement'
$script:MarkerGateArtifactVersion = '2.0.2'
$script:MarkerGateSubscriptionUrl = ('https://github.com/heelee912/' +
    'adguard-hotdeal-focus/releases/download/gate-v2.0.2/filter.txt')
$script:CspProbeUserscriptName = 'AdGuard Hotdeal Focus CSP Probe'
$script:CspProbeUserscriptVersion = '1.2.0'
$script:CspProbeFilterName = 'AdGuard Hotdeal Focus CSP Probe Sentinel'
$script:CspProbeEndpoint = ('https://testcases.agrd.dev/userscripts-csp/' +
    'header-csp-default-src-none')
$script:CspProbeSourceSha256 = '3797355e3257c4f2ad67cca61af1cb182b377c9b91a47b76c48cb559547d842a'
$script:AdGuardStateVisibilityMaxObservations = 20
$script:AdGuardStateVisibilityDelayMilliseconds = 250
$script:AdGuardStateVisibilityRequiredConsecutiveReads = 2
$script:FreshInstallGmProperties = '{}'

function Write-JsonResult {
    param([Parameter(Mandatory = $true)] $Value)
    $json = $Value | ConvertTo-Json -Depth 12
    if ($EvidencePath -and -not $script:EvidenceAttempted) {
        $script:EvidenceAttempted = $true
        $resolvedEvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
        if (Test-Path -LiteralPath $resolvedEvidencePath) {
            throw "EvidencePath already exists; refusing to overwrite evidence"
        }
        $parent = [System.IO.Path]::GetDirectoryName($resolvedEvidencePath)
        if ([string]::IsNullOrWhiteSpace($parent)) {
            throw "EvidencePath must include a parent directory"
        }
        [void] [System.IO.Directory]::CreateDirectory($parent)
        $temporaryEvidencePath = Join-Path $parent (
            '.' + [System.IO.Path]::GetFileName($resolvedEvidencePath) + '.' +
            [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            Write-Utf8FileNew -Path $temporaryEvidencePath -Content $json
            [System.IO.File]::Move($temporaryEvidencePath, $resolvedEvidencePath)
        }
        finally {
            if (Test-Path -LiteralPath $temporaryEvidencePath -PathType Leaf) {
                [System.IO.File]::Delete($temporaryEvidencePath)
            }
        }
    }
    $json
}

function Write-Utf8FileNew {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Content
    )
    $bytes = $script:Utf8NoBom.GetBytes($Content)
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]] $Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function ConvertTo-CanonicalText {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Text)
    $canonical = $Text.TrimStart([char]0xFEFF).Replace("`r`n", "`n").Replace("`r", "`n")
    return $canonical.TrimEnd("`n")
}

function Get-CanonicalTextSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Text)
    return Get-Sha256Hex -Bytes $script:Utf8NoBom.GetBytes((ConvertTo-CanonicalText -Text $Text))
}

function Get-RuleListSha256 {
    param([AllowNull()] $Rules)
    $items = @($Rules | ForEach-Object { [string] $_ })
    return Get-CanonicalTextSha256 -Text ($items -join "`n")
}

function Get-HotdealTargetDomains {
    return @(
        'clien.net',
        'ppomppu.co.kr',
        'ruliweb.com',
        'quasarzone.com',
        'eomisae.co.kr',
        'zod.kr',
        'arca.live'
    )
}

function Get-TargetDomainForHostToken {
    param([Parameter(Mandatory = $true)][string] $Token)
    $normalizedHost = $Token.Trim().TrimEnd('.').ToLowerInvariant()
    if ($normalizedHost.StartsWith('*.')) { $normalizedHost = $normalizedHost.Substring(2) }
    foreach ($domain in Get-HotdealTargetDomains) {
        if ($normalizedHost -ceq $domain -or
            $normalizedHost.EndsWith('.' + $domain, [StringComparison]::Ordinal)) {
            return $domain
        }
    }
    return $null
}

function Get-CosmeticRuleScopeAnalysis {
    param([Parameter(Mandatory = $true)][string] $Rule)

    $operators = @(
        [pscustomobject]@{ Token = '#@$?#'; Kind = 'extended-css-injection-exception'; Exception = $true },
        [pscustomobject]@{ Token = '#@?#'; Kind = 'extended-css-exception'; Exception = $true },
        [pscustomobject]@{ Token = '#@$#'; Kind = 'css-injection-exception'; Exception = $true },
        [pscustomobject]@{ Token = '#@%#'; Kind = 'scriptlet-exception'; Exception = $true },
        [pscustomobject]@{ Token = '#@#'; Kind = 'cosmetic-exception'; Exception = $true },
        [pscustomobject]@{ Token = '#$?#'; Kind = 'extended-css-injection'; Exception = $false },
        [pscustomobject]@{ Token = '#?#'; Kind = 'extended-css'; Exception = $false },
        [pscustomobject]@{ Token = '#$#'; Kind = 'css-injection'; Exception = $false },
        [pscustomobject]@{ Token = '#%#'; Kind = 'scriptlet'; Exception = $false },
        [pscustomobject]@{ Token = '##'; Kind = 'cosmetic'; Exception = $false }
    )
    $selected = $null
    $operatorIndex = -1
    foreach ($operator in $operators) {
        $candidateIndex = $Rule.IndexOf($operator.Token, [StringComparison]::Ordinal)
        if ($candidateIndex -ge 0 -and ($operatorIndex -lt 0 -or $candidateIndex -lt $operatorIndex)) {
            $selected = $operator
            $operatorIndex = $candidateIndex
        }
    }
    if (-not $selected) {
        return [pscustomobject]@{
            IsCosmetic = $false; IsException = $false; Kind = 'non-cosmetic'
            ScopeKind = 'not-applicable'; TargetDomains = @()
        }
    }

    $scope = $Rule.Substring(0, $operatorIndex).Trim()
    if (-not $scope) {
        return [pscustomobject]@{
            IsCosmetic = $true; IsException = $selected.Exception; Kind = $selected.Kind
            ScopeKind = 'global'; TargetDomains = @()
        }
    }

    $tokens = @()
    if ($scope.StartsWith('[$domain=', [StringComparison]::OrdinalIgnoreCase)) {
        $domainMatch = [regex]::Match(
            $scope,
            '^\[\$domain=(?<domains>[^,\]]+)(?:,[^\]]+)?\]$',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if (-not $domainMatch.Success) {
            return [pscustomobject]@{
                IsCosmetic = $true; IsException = $selected.Exception; Kind = $selected.Kind
                ScopeKind = 'mixed-or-unsupported'; TargetDomains = @()
            }
        }
        $tokens = @($domainMatch.Groups['domains'].Value -split '\|')
    } else {
        $tokens = @($scope -split ',')
    }

    $targetDomains = New-Object 'System.Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    $hasOther = $false
    foreach ($rawToken in $tokens) {
        $token = $rawToken.Trim()
        if (-not $token -or $token.StartsWith('~') -or $token.Contains('$') -or
            $token.Contains('/') -or $token.Contains(':')) {
            $hasOther = $true
            continue
        }
        $target = Get-TargetDomainForHostToken -Token $token
        if ($target) { [void] $targetDomains.Add($target) } else { $hasOther = $true }
    }
    $targetArray = @($targetDomains | Sort-Object)
    $scopeKind = if ($targetArray.Count -gt 0 -and -not $hasOther) {
        'exclusive-target'
    } elseif ($targetArray.Count -gt 0) {
        'mixed-target'
    } else {
        'other'
    }
    return [pscustomobject]@{
        IsCosmetic = $true
        IsException = [bool] $selected.Exception
        Kind = [string] $selected.Kind
        ScopeKind = $scopeKind
        TargetDomains = $targetArray
    }
}

function Get-LegacyHotdealConflictReport {
    param(
        [Parameter(Mandatory = $true)] $FilterRules,
        [AllowNull()] $HistoricalRules
    )

    $disabled = New-Object 'System.Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($rule in @($FilterRules.DisabledRules)) {
        [void] $disabled.Add([string] $rule)
    }
    $historicalRulesSet = New-Object 'System.Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($rule in @($HistoricalRules)) {
        [void] $historicalRulesSet.Add([string] $rule)
    }

    $conflicts = @()
    $excludedExceptions = @()
    $globalCosmeticRules = @()
    $unsupportedScopeRules = @()
    $rules = @($FilterRules.Rules | ForEach-Object { [string] $_ })
    for ($index = 0; $index -lt $rules.Count; $index++) {
        $rule = $rules[$index]
        $analysis = Get-CosmeticRuleScopeAnalysis -Rule $rule
        if (-not $analysis.IsCosmetic) { continue }
        $record = [pscustomobject][ordered]@{
            one_based_index = $index + 1
            rule_sha256 = Get-CanonicalTextSha256 -Text $rule
            operator_kind = $analysis.Kind
            scope_kind = $analysis.ScopeKind
            target_domains = @($analysis.TargetDomains)
            disabled = $disabled.Contains($rule)
            historical_snapshot_match = $historicalRulesSet.Contains($rule)
        }
        if ($analysis.ScopeKind -ceq 'global') {
            $globalCosmeticRules += $record
            continue
        }
        if ($analysis.ScopeKind -ceq 'mixed-or-unsupported') {
            $unsupportedScopeRules += $record
            continue
        }
        if ($analysis.ScopeKind -notin @('exclusive-target', 'mixed-target')) { continue }
        if ($analysis.IsException) {
            $excludedExceptions += $record
        } else {
            $conflicts += $record
        }
    }

    $enabledConflicts = @($conflicts | Where-Object { -not $_.disabled })
    $enabledExceptions = @($excludedExceptions | Where-Object { -not $_.disabled })
    $enabledExclusive = @($enabledConflicts | Where-Object {
            $_.scope_kind -ceq 'exclusive-target'
        })
    $enabledMixed = @($enabledConflicts | Where-Object {
            $_.scope_kind -ceq 'mixed-target'
        })
    $enabledExclusiveExceptions = @($enabledExceptions | Where-Object {
            $_.scope_kind -ceq 'exclusive-target'
        })
    $enabledMixedExceptions = @($enabledExceptions | Where-Object {
            $_.scope_kind -ceq 'mixed-target'
        })
    $enabledExclusiveAll = @($enabledExclusive) + @($enabledExclusiveExceptions)
    $enabledMixedAll = @($enabledMixed) + @($enabledMixedExceptions)
    $enabledTargetAll = @($enabledConflicts) + @($enabledExceptions)
    $domainCounts = [ordered]@{}
    foreach ($domain in Get-HotdealTargetDomains) {
        $domainCounts[$domain] = @($conflicts | Where-Object {
                $_.target_domains -contains $domain
            }).Count
    }
    return [ordered]@{
        index_definition = 'one-based index in UiApplicationApiClient GetFilterSubscriptionRules().Rules order'
        user_filter_rule_count = $rules.Count
        target_scoped_nonexception_rule_count = $conflicts.Count
        target_scoped_rule_count_including_exceptions = $conflicts.Count +
            $excludedExceptions.Count
        enabled_conflict_count = $enabledConflicts.Count
        enabled_exclusive_target_count = $enabledExclusive.Count
        enabled_exclusive_target_exception_count = $enabledExclusiveExceptions.Count
        enabled_exclusive_target_rule_count = $enabledExclusiveAll.Count
        enabled_target_rule_count_including_exceptions = $enabledTargetAll.Count
        enabled_mixed_target_count = $enabledMixed.Count
        enabled_mixed_target_exception_count = $enabledMixedExceptions.Count
        enabled_mixed_target_rule_count = $enabledMixedAll.Count
        excluded_exception_count = $excludedExceptions.Count
        global_cosmetic_count = $globalCosmeticRules.Count
        unsupported_scope_cosmetic_count = $unsupportedScopeRules.Count
        has_enabled_conflict = $enabledTargetAll.Count -gt 0
        migration_candidate_count = $enabledExclusiveAll.Count
        migration_blocked_by_mixed_scope = $enabledMixedAll.Count -gt 0
        deploy_blocked = $enabledTargetAll.Count -gt 0
        counts_by_target_domain = $domainCounts
        rules = $conflicts
        excluded_exception_rules = $excludedExceptions
        global_cosmetic_rules = $globalCosmeticRules
        unsupported_scope_cosmetic_rules = $unsupportedScopeRules
        migration_performed = $false
        user_filter_modified = $false
    }
}

function Get-ReferenceUserFilterSnapshotPath {
    if ($ReferenceUserFilterSnapshot) {
        return (Resolve-Path -LiteralPath $ReferenceUserFilterSnapshot -ErrorAction Stop).ProviderPath
    }
    $workspaceCandidate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
                '..\..\adguard-user-rules-before-20260719.txt'))
    if (Test-Path -LiteralPath $workspaceCandidate -PathType Leaf) {
        return $workspaceCandidate
    }
    return $null
}

function Get-ReferenceUserFilterEvidence {
    $path = Get-ReferenceUserFilterSnapshotPath
    if (-not $path) { return $null }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = ConvertFrom-StrictUtf8 -Bytes $bytes
    $normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $lines = @($normalized.Split([string[]] @("`n"), [StringSplitOptions]::None))
    if ($lines.Count -gt 0 -and $lines[-1] -eq '') {
        $lines = @($lines[0..($lines.Count - 2)])
    }
    $rules = @($lines | Where-Object { $_ -and -not $_.StartsWith('!') })
    $comments = @($lines | Where-Object { $_.StartsWith('!') })
    $blanks = @($lines | Where-Object { -not $_ })
    $syntheticRules = [pscustomobject]@{ Rules = $rules; DisabledRules = @() }
    $script:HistoricalSnapshotRules = $rules
    return [ordered]@{
        role = 'historical-only-non-authoritative'
        authoritative = $false
        path = $path
        captured_last_write_utc = (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('o')
        count_definition = [ordered]@{
            physical_line_count = 'UTF-8 text lines, terminal newline excluded'
            semantic_rule_count = 'nonblank lines not beginning with !'
            comment_count = 'lines beginning with !'
            blank_count = 'empty lines'
        }
        physical_line_count = $lines.Count
        semantic_rule_count = $rules.Count
        comment_count = $comments.Count
        blank_count = $blanks.Count
        raw_file_sha256 = Get-Sha256Hex -Bytes $bytes
        canonical_all_lines_sha256 = Get-CanonicalTextSha256 -Text $text
        canonical_semantic_rules_sha256 = Get-RuleListSha256 -Rules $rules
        legacy_hotdeal_conflicts = Get-LegacyHotdealConflictReport `
            -FilterRules $syntheticRules -HistoricalRules $rules
    }
}

function Get-UserFilterEvidence {
    param([Parameter(Mandatory = $true)] $Client)
    $userFilter = Get-UserFilter -Client $Client
    $first = $Client.GetFilterSubscriptionRules(
        $userFilter.FilterId,
        $script:StandardFilterType
    )
    $second = $Client.GetFilterSubscriptionRules(
        $userFilter.FilterId,
        $script:StandardFilterType
    )
    $firstRulesHash = Get-RuleListSha256 -Rules $first.Rules
    $secondRulesHash = Get-RuleListSha256 -Rules $second.Rules
    $firstDisabledHash = Get-RuleListSha256 -Rules $first.DisabledRules
    $secondDisabledHash = Get-RuleListSha256 -Rules $second.DisabledRules
    $stable = @($first.Rules).Count -eq @($second.Rules).Count -and
        @($first.DisabledRules).Count -eq @($second.DisabledRules).Count -and
        $firstRulesHash -ceq $secondRulesHash -and
        $firstDisabledHash -ceq $secondDisabledHash
    $reference = Get-ReferenceUserFilterEvidence
    $referenceMatches = $null
    if ($reference) {
        $referenceMatches = $reference.semantic_rule_count -eq @($second.Rules).Count -and
            $reference.canonical_semantic_rules_sha256 -ceq $secondRulesHash
    }
    $conflictReport = Get-LegacyHotdealConflictReport -FilterRules $second `
        -HistoricalRules $script:HistoricalSnapshotRules
    $report = [ordered]@{
        authority = 'current-stable-uiapplication-api-snapshot'
        authoritative = $stable
        filter_id = [int] $userFilter.FilterId
        name = [string] $userFilter.Name
        filter_type = [string] $userFilter.FilterType
        api_count_definition = [ordered]@{
            rule_count = 'GetFilterSubscriptionRules().Rules collection items'
            disabled_rule_count = 'GetFilterSubscriptionRules().DisabledRules collection items'
            filter_count = 'one editable custom Standard subscription with reserved id Int32.MinValue or 0'
        }
        api_read_1 = [ordered]@{
            rule_count = @($first.Rules).Count
            disabled_rule_count = @($first.DisabledRules).Count
            canonical_rules_sha256 = $firstRulesHash
            canonical_disabled_rules_sha256 = $firstDisabledHash
        }
        api_read_2 = [ordered]@{
            rule_count = @($second.Rules).Count
            disabled_rule_count = @($second.DisabledRules).Count
            canonical_rules_sha256 = $secondRulesHash
            canonical_disabled_rules_sha256 = $secondDisabledHash
        }
        two_read_stable = $stable
        legacy_hotdeal_conflicts = $conflictReport
        reference_snapshot = $reference
        reference_semantic_rules_match_api = $referenceMatches
        discrepancy_classification = if ($reference -and -not $referenceMatches) {
            'expected historical mismatch; snapshot is non-authoritative and current stable API state wins'
        } elseif ($referenceMatches) {
            'semantic rule sets match'
        } else {
            'no reference snapshot supplied'
        }
        historical_snapshot_mismatch_is_blocking = $false
        install_safe = $stable -and -not $conflictReport.deploy_blocked
    }
    $script:LastUserFilterEvidence = $report
    $script:LastConflictReport = $report.legacy_hotdeal_conflicts
    return [pscustomobject]@{ Report = $report; Rules = $second; Filter = $userFilter }
}

function Assert-UserFilterEvidenceSafe {
    param([Parameter(Mandatory = $true)] $Client)
    $evidence = Get-UserFilterEvidence -Client $Client
    if (-not $evidence.Report.two_read_stable) {
        throw "Two consecutive read-only User filter API snapshots were not identical"
    }
    return $evidence
}

function Assert-NoLegacyHotdealConflict {
    param([Parameter(Mandatory = $true)] $Client)
    $evidence = Assert-UserFilterEvidenceSafe -Client $Client
    $report = $evidence.Report.legacy_hotdeal_conflicts
    $script:LastConflictReport = $report
    if ($report.has_enabled_conflict) {
        throw ("User filter still contains " +
            "$($report.enabled_exclusive_target_rule_count) enabled exclusive-target and " +
            "$($report.enabled_mixed_target_rule_count) enabled mixed-target rule(s), " +
            "including exceptions. Exclusive rules require exact reversible migration; " +
            "mixed-target rules are preserved and block deployment until the user splits " +
            "or disables them explicitly")
    }
    return $report
}

function Test-ExactStringSequence {
    param(
        [AllowNull()] $Left,
        [AllowNull()] $Right
    )
    $leftItems = if ($null -eq $Left) { @() } else {
        @($Left | ForEach-Object { [string] $_ })
    }
    $rightItems = if ($null -eq $Right) { @() } else {
        @($Right | ForEach-Object { [string] $_ })
    }
    if ($leftItems.Count -ne $rightItems.Count) { return $false }
    for ($index = 0; $index -lt $leftItems.Count; $index++) {
        if ($leftItems[$index] -cne $rightItems[$index]) { return $false }
    }
    return $true
}

function Test-ExactStringMultiset {
    param(
        [AllowNull()] $Left,
        [AllowNull()] $Right
    )
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new(
        [StringComparer]::Ordinal)
    $leftItems = if ($null -eq $Left) { @() } else {
        @($Left | ForEach-Object { [string] $_ })
    }
    $rightItems = if ($null -eq $Right) { @() } else {
        @($Right | ForEach-Object { [string] $_ })
    }
    foreach ($item in $leftItems) {
        if ($counts.ContainsKey($item)) {
            $counts[$item] = $counts[$item] + 1
        } else {
            $counts.Add($item, 1)
        }
    }
    foreach ($item in $rightItems) {
        if (-not $counts.ContainsKey($item)) { return $false }
        $remaining = $counts[$item] - 1
        if ($remaining -lt 0) { return $false }
        if ($remaining -eq 0) { [void] $counts.Remove($item) } else {
            $counts[$item] = $remaining
        }
    }
    return $counts.Count -eq 0
}

function Get-RuleMultisetSha256 {
    param([AllowNull()] $Rules)
    $hashes = [System.Collections.Generic.List[string]]::new()
    $items = if ($null -eq $Rules) { @() } else {
        @($Rules | ForEach-Object { [string] $_ })
    }
    foreach ($rule in $items) {
        $hashes.Add((Get-CanonicalTextSha256 -Text $rule))
    }
    $hashes.Sort([StringComparer]::Ordinal)
    return Get-CanonicalTextSha256 -Text (@($hashes) -join "`n")
}

function Get-ProtectedRulesByCandidateIndexes {
    param(
        [Parameter(Mandatory = $true)] $Rules,
        [AllowNull()] $CandidateZeroBasedIndexes
    )
    $candidateIndexes = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($index in @($CandidateZeroBasedIndexes)) {
        [void] $candidateIndexes.Add([int] $index)
    }
    $items = @($Rules | ForEach-Object { [string] $_ })
    $protectedRules = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $items.Count; $index++) {
        if (-not $candidateIndexes.Contains($index)) { $protectedRules.Add($items[$index]) }
    }
    return @($protectedRules)
}

function New-StringList {
    param([AllowNull()] $Values)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @($Values | ForEach-Object { [string] $_ })) {
        $list.Add($value)
    }
    return ,$list
}

function Get-LegacyMigrationPlan {
    param(
        [AllowNull()] $Client,
        [AllowNull()] $EvidenceOverride
    )

    $evidence = if ($EvidenceOverride) { $EvidenceOverride } else {
        if (-not $Client) { throw "Legacy migration planning requires a client or backup evidence" }
        Assert-UserFilterEvidenceSafe -Client $Client
    }
    $rules = @($evidence.Rules.Rules | ForEach-Object { [string] $_ })
    $disabledRules = @($evidence.Rules.DisabledRules | ForEach-Object { [string] $_ })
    $disabled = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $disabledRules) { [void] $disabled.Add($rule) }

    $allCandidates = [System.Collections.Generic.List[object]]::new()
    $candidateIndexes = [System.Collections.Generic.List[int]]::new()
    $enabledCandidateRules = [System.Collections.Generic.List[string]]::new()
    $candidateRuleUniqueness = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $blockReasons = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $rules.Count; $index++) {
        $rule = $rules[$index]
        $analysis = Get-CosmeticRuleScopeAnalysis -Rule $rule
        if (-not $analysis.IsCosmetic -or $analysis.ScopeKind -cne 'exclusive-target') {
            continue
        }
        if (-not $candidateRuleUniqueness.Add($rule)) {
            $blockReasons.Add('duplicate-target-rule-text')
        }
        $isDisabled = $disabled.Contains($rule)
        $record = [pscustomobject]@{
            ZeroBasedIndex = $index
            Rule = $rule
            IsDisabled = $isDisabled
            Public = [ordered]@{
                one_based_index = $index + 1
                rule_sha256 = Get-CanonicalTextSha256 -Text $rule
                operator_kind = $analysis.Kind
                is_exception = [bool] $analysis.IsException
                scope_kind = $analysis.ScopeKind
                target_domains = @($analysis.TargetDomains)
                disabled_before = $isDisabled
            }
        }
        $allCandidates.Add($record)
        $candidateIndexes.Add($index)
        if (-not $isDisabled) { $enabledCandidateRules.Add($rule) }
    }

    $protectedRules = @(Get-ProtectedRulesByCandidateIndexes -Rules $rules `
            -CandidateZeroBasedIndexes $candidateIndexes)
    $conflicts = $evidence.Report.legacy_hotdeal_conflicts

    # The authoritative two-read snapshot discovers the transaction at execution time.
    # No historical count or fingerprint is trusted. Only exclusive seven-domain scope
    # rules are candidates; mixed, global, and non-target rules remain protected.
    $candidateRules = @($allCandidates | ForEach-Object { $_.Rule })
    $candidateMultisetSha256 = Get-RuleMultisetSha256 -Rules $candidateRules
    $mixedTargetRules = @(@($conflicts.rules) + @($conflicts.excluded_exception_rules) |
        Where-Object {
            $_.scope_kind -ceq 'mixed-target'
        })
    $mixedTargetCount = $mixedTargetRules.Count
    $protectedKnownKinds = $mixedTargetCount +
        $conflicts.global_cosmetic_count + $conflicts.unsupported_scope_cosmetic_count
    $protectedOtherCount = [Math]::Max(0, $protectedRules.Count - $protectedKnownKinds)
    $candidateExceptionCount = @($allCandidates | Where-Object {
            $_.Public.is_exception
        }).Count
    $operatorCounts = [ordered]@{}
    foreach ($candidate in @($allCandidates)) {
        $kind = [string] $candidate.Public.operator_kind
        if ($operatorCounts.Contains($kind)) {
            $operatorCounts[$kind] = [int] $operatorCounts[$kind] + 1
        } else {
            $operatorCounts[$kind] = 1
        }
    }

    $publicReport = [ordered]@{
        authority = 'current-stable-uiapplication-api-snapshot'
        historical_snapshot_is_authoritative = $false
        index_definition = 'one-based index in authoritative Rules collection order'
        discovery_policy = [ordered]@{
            target_domains = Get-HotdealTargetDomains
            candidate_scope = 'exclusive-target'
            included = 'blocking and exception cosmetic/ExtendedCSS/CSS-injection/scriptlet rules'
            protected = 'global, mixed-target, unsupported-scope, and non-target rules'
            historical_count_or_fingerprint_required = $false
        }
        before = [ordered]@{
            total_rule_count = $rules.Count
            ordered_rules_sha256 = Get-RuleListSha256 -Rules $rules
            disabled_rule_count = $disabledRules.Count
            disabled_rules_multiset_sha256 = Get-RuleMultisetSha256 -Rules $disabledRules
            exclusive_target_rule_count = $allCandidates.Count
            candidate_rules_multiset_sha256 = $candidateMultisetSha256
            candidate_blocking_rule_count = $allCandidates.Count - $candidateExceptionCount
            candidate_exception_rule_count = $candidateExceptionCount
            candidate_counts_by_operator = $operatorCounts
            enabled_migration_candidate_count = $enabledCandidateRules.Count
            already_disabled_target_rule_count = $allCandidates.Count - $enabledCandidateRules.Count
            protected_rule_count = $protectedRules.Count
            protected_ordered_sha256 = Get-RuleListSha256 -Rules $protectedRules
        }
        candidates = @($allCandidates | ForEach-Object { $_.Public })
        protected = [ordered]@{
            total_rule_count = $protectedRules.Count
            ordered_sha256 = Get-RuleListSha256 -Rules $protectedRules
            mixed_target_rule_count = $mixedTargetCount
            enabled_mixed_target_rule_count = $conflicts.enabled_mixed_target_rule_count
            mixed_target_exception_rule_count = @($mixedTargetRules | Where-Object {
                    $_.operator_kind -like '*exception'
                }).Count
            global_cosmetic_rule_count = $conflicts.global_cosmetic_count
            unsupported_scope_cosmetic_rule_count = $conflicts.unsupported_scope_cosmetic_count
            network_and_truly_unrelated_rule_count = $protectedOtherCount
            mutation_policy = 'preserve exact order and bytes'
        }
        exact_precondition_satisfied = $blockReasons.Count -eq 0
        migration_required = $enabledCandidateRules.Count -gt 0
        block_reasons = @($blockReasons | Select-Object -Unique)
        plaintext_rules_emitted = $false
    }
    $conflicts.migration_plan = $publicReport
    $script:LastConflictReport = $conflicts
    $script:LastUserFilterEvidence = $evidence.Report

    return [pscustomobject]@{
        CanMigrate = $blockReasons.Count -eq 0
        Filter = $evidence.Filter
        BeforeRules = $rules
        BeforeDisabledRules = $disabledRules
        CandidateRecords = @($allCandidates)
        CandidateZeroBasedIndexes = @($candidateIndexes)
        EnabledCandidateRules = @($enabledCandidateRules)
        ProtectedRules = $protectedRules
        PublicReport = $publicReport
    }
}

function Get-LegacyMigrationPlanFromBackup {
    param([Parameter(Mandatory = $true)] $Backup)
    $ruleState = [pscustomobject]@{
        Rules = @($Backup.UserRules)
        DisabledRules = @($Backup.UserDisabledRules)
    }
    $conflicts = Get-LegacyHotdealConflictReport -FilterRules $ruleState `
        -HistoricalRules $script:HistoricalSnapshotRules
    $evidence = [pscustomobject]@{
        Filter = [pscustomobject]@{
            FilterId = [int] $Backup.Manifest.user_filter.filter_id
        }
        Rules = $ruleState
        Report = [pscustomobject]@{
            legacy_hotdeal_conflicts = $conflicts
        }
    }
    return Get-LegacyMigrationPlan -Client $null -EvidenceOverride $evidence
}

function Assert-LegacyMigrationPlanCurrent {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Plan
    )
    if (-not $Plan.CanMigrate) {
        throw ("Legacy migration exact precondition failed: " +
            (@($Plan.PublicReport.block_reasons) -join ', '))
    }
    $fresh = $Client.GetFilterSubscriptionRules(
        $Plan.Filter.FilterId,
        $script:StandardFilterType
    )
    $freshRules = @($fresh.Rules | ForEach-Object { [string] $_ })
    $freshDisabled = @($fresh.DisabledRules | ForEach-Object { [string] $_ })
    if (-not (Test-ExactStringSequence -Left $Plan.BeforeRules -Right $freshRules)) {
        throw "User filter Rules changed after the authoritative migration plan was created"
    }
    if (-not (Test-ExactStringMultiset -Left $Plan.BeforeDisabledRules -Right $freshDisabled)) {
        throw "User filter DisabledRules changed after the authoritative migration plan was created"
    }
    foreach ($candidate in @($Plan.CandidateRecords)) {
        $index = [int] $candidate.ZeroBasedIndex
        if ($index -lt 0 -or $index -ge $freshRules.Count -or
            $freshRules[$index] -cne $candidate.Rule -or
            (Get-CanonicalTextSha256 -Text $freshRules[$index]) -cne
                $candidate.Public.rule_sha256) {
            throw "A legacy migration candidate failed its exact index and SHA-256 precondition"
        }
    }
    $freshProtected = @(Get-ProtectedRulesByCandidateIndexes -Rules $freshRules `
            -CandidateZeroBasedIndexes $Plan.CandidateZeroBasedIndexes)
    if (-not (Test-ExactStringSequence -Left $Plan.ProtectedRules -Right $freshProtected)) {
        throw "Protected User filter rules changed after the migration plan was created"
    }
    return $fresh
}

function Assert-LegacyMigrationPostState {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Plan,
        [Parameter(Mandatory = $true)] $ChangedRules
    )
    $after = $Client.GetFilterSubscriptionRules(
        $Plan.Filter.FilterId,
        $script:StandardFilterType
    )
    $afterRules = @($after.Rules | ForEach-Object { [string] $_ })
    $afterDisabled = @($after.DisabledRules | ForEach-Object { [string] $_ })
    if (-not (Test-ExactStringSequence -Left $Plan.BeforeRules -Right $afterRules)) {
        throw "Legacy migration changed the User filter Rules collection"
    }
    $expectedDisabled = @($Plan.BeforeDisabledRules) + @($ChangedRules)
    if (-not (Test-ExactStringMultiset -Left $expectedDisabled -Right $afterDisabled)) {
        throw "Legacy migration did not produce the exact expected DisabledRules set"
    }
    $afterDisabledSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($rule in $afterDisabled) { [void] $afterDisabledSet.Add($rule) }
    foreach ($candidate in @($Plan.CandidateRecords)) {
        if (-not $afterDisabledSet.Contains($candidate.Rule)) {
            throw "A target legacy rule remained enabled after migration"
        }
    }
    $afterProtected = @(Get-ProtectedRulesByCandidateIndexes -Rules $afterRules `
            -CandidateZeroBasedIndexes $Plan.CandidateZeroBasedIndexes)
    if (-not (Test-ExactStringSequence -Left $Plan.ProtectedRules -Right $afterProtected)) {
        throw "Legacy migration changed a protected User filter rule"
    }
    $conflicts = Get-LegacyHotdealConflictReport -FilterRules $after `
        -HistoricalRules $script:HistoricalSnapshotRules
    if ($conflicts.enabled_exclusive_target_rule_count -ne 0) {
        throw "Exclusive-target legacy rules remain enabled after migration"
    }
    return [ordered]@{
        verified = $true
        total_rule_count = $afterRules.Count
        ordered_rules_sha256 = Get-RuleListSha256 -Rules $afterRules
        disabled_rule_count = $afterDisabled.Count
        disabled_rules_multiset_sha256 = Get-RuleMultisetSha256 -Rules $afterDisabled
        exact_disabled_delta_count = @($ChangedRules).Count
        protected_rule_count = $afterProtected.Count
        protected_ordered_sha256 = Get-RuleListSha256 -Rules $afterProtected
        enabled_exclusive_target_rule_count = $conflicts.enabled_exclusive_target_rule_count
        protected_enabled_mixed_target_rule_count = $conflicts.enabled_mixed_target_rule_count
        plaintext_rules_emitted = $false
    }
}

function Restore-LegacyMigration {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Transaction,
        [AllowNull()][string] $JournalDirectory
    )
    $rollbackRules = @($Transaction.ChangedRules)
    [array]::Reverse($rollbackRules)
    foreach ($rule in $rollbackRules) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-rollback-legacy-enable' `
                -Details ([ordered]@{
                        rule_sha256 = Get-CanonicalTextSha256 -Text ([string] $rule)
                    })
        }
        $Client.EnableFilterRules(
            $Transaction.Plan.Filter.FilterId,
            (New-StringList -Values @([string] $rule)),
            $script:StandardFilterType
        )
    }
    $restored = $Client.GetFilterSubscriptionRules(
        $Transaction.Plan.Filter.FilterId,
        $script:StandardFilterType
    )
    if (-not (Test-ExactStringSequence -Left $Transaction.Plan.BeforeRules `
            -Right $restored.Rules) -or
        -not (Test-ExactStringMultiset -Left $Transaction.Plan.BeforeDisabledRules `
            -Right $restored.DisabledRules)) {
        throw "Legacy migration rollback did not restore the exact pre-migration state"
    }
}

function Invoke-LegacyMigration {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Plan,
        [AllowNull()][string] $JournalDirectory,
        [switch] $CurrentMatchesBackup
    )
    if (-not $CurrentMatchesBackup) {
        [void] (Assert-LegacyMigrationPlanCurrent -Client $Client -Plan $Plan)
    }
    $changedRules = @($Plan.EnabledCandidateRules)
    $transaction = [pscustomobject]@{
        Plan = $Plan
        ChangedRules = $changedRules
        PublicReport = $null
    }
    if ($changedRules.Count -eq 0) {
        $transaction.PublicReport = [ordered]@{
            changed = $false
            reason = 'no-enabled-legacy-rules'
            plan = $Plan.PublicReport
            plaintext_rules_emitted = $false
        }
        return $transaction
    }

    try {
        for ($index = 0; $index -lt $changedRules.Count; $index++) {
            $rule = [string] $changedRules[$index]
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-legacy-disable-rule' `
                    -Details ([ordered]@{
                            zero_based_transaction_index = $index
                            rule_sha256 = Get-CanonicalTextSha256 -Text $rule
                        })
            }
            $Client.DisableFilterRules(
                $Plan.Filter.FilterId,
                (New-StringList -Values @($rule)),
                $script:StandardFilterType
            )
        }
        $post = Assert-LegacyMigrationPostState -Client $Client -Plan $Plan `
            -ChangedRules $changedRules
        $transaction.PublicReport = [ordered]@{
            changed = $true
            plan = $Plan.PublicReport
            postcondition = $post
            rollback_method = 'EnableFilterRules(exact transaction delta)'
            plaintext_rules_emitted = $false
        }
        return $transaction
    }
    catch {
        $originalMessage = [string] $_.Exception.Message
        try {
            Restore-LegacyMigration -Client $Client -Transaction $transaction `
                -JournalDirectory $JournalDirectory
        }
        catch {
            throw "Legacy migration failed and EnableFilterRules rollback was incomplete"
        }
        throw "Legacy migration failed after exact automatic rollback: $originalMessage"
    }
}

function Assert-Sha256Value {
    param(
        [AllowNull()][string] $Value,
        [Parameter(Mandatory = $true)][string] $Name
    )
    if ($Value -and $Value -notmatch '\A[0-9a-fA-F]{64}\z') {
        throw "$Name must be exactly 64 hexadecimal characters"
    }
}

function Test-PublicIpAddress {
    param([Parameter(Mandatory = $true)][System.Net.IPAddress] $Address)

    if ([System.Net.IPAddress]::IsLoopback($Address)) { return $false }
    if ($Address.Equals([System.Net.IPAddress]::Any) -or
        $Address.Equals([System.Net.IPAddress]::IPv6Any) -or
        $Address.Equals([System.Net.IPAddress]::IPv6None)) { return $false }

    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($Address.IsIPv6LinkLocal -or $Address.IsIPv6SiteLocal -or $Address.IsIPv6Multicast) {
            return $false
        }
        if ($Address.IsIPv4MappedToIPv6) {
            return Test-PublicIpAddress -Address $Address.MapToIPv4()
        }
        $bytes = $Address.GetAddressBytes()
        if (($bytes[0] -band 0xFE) -eq 0xFC) { return $false }
        return $true
    }

    $octets = $Address.GetAddressBytes()
    $first = [int] $octets[0]
    $second = [int] $octets[1]
    if ($first -eq 0 -or $first -eq 10 -or $first -eq 127 -or $first -ge 224) { return $false }
    if ($first -eq 100 -and $second -ge 64 -and $second -le 127) { return $false }
    if ($first -eq 169 -and $second -eq 254) { return $false }
    if ($first -eq 172 -and $second -ge 16 -and $second -le 31) { return $false }
    if ($first -eq 192 -and $second -eq 168) { return $false }
    if ($first -eq 198 -and ($second -eq 18 -or $second -eq 19)) { return $false }
    return $true
}

function Assert-PublicHttpsUri {
    param([Parameter(Mandatory = $true)][string] $Value)

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref] $uri)) {
        throw "Source URL is not an absolute URI"
    }
    if ($uri.Scheme -cne 'https') { throw "Source URL must use HTTPS" }
    if ($uri.UserInfo -or $uri.Fragment) { throw "Source URL must not contain credentials or a fragment" }
    if ([string]::IsNullOrWhiteSpace($uri.DnsSafeHost)) { throw "Source URL has no host" }

    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($uri.DnsSafeHost))
    }
    catch {
        throw "Source host could not be resolved"
    }
    if ($addresses.Count -eq 0) { throw "Source host resolved to no addresses" }
    foreach ($address in $addresses) {
        if (-not (Test-PublicIpAddress -Address $address)) {
            throw "Source host resolved to a non-public address"
        }
    }
    return $uri
}

function Assert-HttpsContentLengthWithinLimit {
    param([Parameter()][AllowNull()][object] $ContentLength)

    if ($null -eq $ContentLength) { return }
    try {
        $length = [System.Convert]::ToInt64(
            $ContentLength, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw "HTTPS source content length is invalid"
    }
    if ($length -lt 0) { throw "HTTPS source content length is invalid" }
    if ($length -gt $script:MaximumSourceBytes) {
        throw "HTTPS source exceeds the maximum size"
    }
}

function Read-HttpsBytes {
    param([Parameter(Mandatory = $true)][string] $Url)

    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $http = [System.Net.Http.HttpClient]::new($handler)
    $http.Timeout = [TimeSpan]::FromSeconds($NetworkTimeoutSeconds)
    $http.DefaultRequestHeaders.UserAgent.ParseAdd("adguard-hotdeal-focus-cli/$($script:ToolVersion)")
    try {
        $current = Assert-PublicHttpsUri -Value $Url
        for ($redirect = 0; $redirect -le 5; $redirect++) {
            $response = $http.GetAsync(
                $current,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            try {
                $status = [int] $response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308)) {
                    if ($redirect -eq 5 -or -not $response.Headers.Location) {
                        throw "HTTPS source exceeded the redirect limit"
                    }
                    $next = New-Object Uri($current, $response.Headers.Location)
                    $current = Assert-PublicHttpsUri -Value $next.AbsoluteUri
                    continue
                }
                if (-not $response.IsSuccessStatusCode) {
                    throw "HTTPS source returned status $status"
                }
                Assert-HttpsContentLengthWithinLimit `
                    -ContentLength $response.Content.Headers.ContentLength

                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = New-Object System.IO.MemoryStream
                try {
                    $buffer = New-Object byte[] 32768
                    while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($outputStream.Length + $read -gt $script:MaximumSourceBytes) {
                            throw "HTTPS source exceeds the maximum size"
                        }
                        $outputStream.Write($buffer, 0, $read)
                    }
                    return $outputStream.ToArray()
                }
                finally {
                    $inputStream.Dispose()
                    $outputStream.Dispose()
                }
            }
            finally {
                $response.Dispose()
            }
        }
    }
    finally {
        $http.Dispose()
        $handler.Dispose()
    }
    throw "HTTPS source could not be downloaded"
}

function Read-SourceBytes {
    param([Parameter(Mandatory = $true)][string] $Source)

    # A rooted Windows path such as C:\release\file is parsed by System.Uri as
    # scheme "c". Resolve an existing filesystem path before URI classification.
    if (Test-Path -LiteralPath $Source) {
        $resolved = Resolve-Path -LiteralPath $Source -ErrorAction Stop
        $item = Get-Item -LiteralPath $resolved.ProviderPath -ErrorAction Stop
        if ($item.PSIsContainer) { throw "Source path is a directory" }
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Source path must not be a reparse point"
        }
        if ($item.Length -gt $script:MaximumSourceBytes) {
            throw "Source file exceeds the maximum size"
        }
        return [System.IO.File]::ReadAllBytes($item.FullName)
    }

    $uri = $null
    if ([Uri]::TryCreate($Source, [UriKind]::Absolute, [ref] $uri) -and $uri.Scheme) {
        if ($uri.Scheme -cne 'https') { throw "Remote sources must use HTTPS" }
        return Read-HttpsBytes -Url $Source
    }

    throw "Source path does not exist"
}

function ConvertFrom-StrictUtf8 {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]] $Bytes)
    try {
        $text = $script:Utf8NoBom.GetString($Bytes)
    }
    catch {
        throw "Source is not valid UTF-8"
    }
    if ($text.IndexOf([char]0) -ge 0) { throw "Source contains a NUL character" }
    return $text.TrimStart([char]0xFEFF)
}

function Get-UserscriptSource {
    param([Parameter(Mandatory = $true)][string] $Source)

    $bytes = Read-SourceBytes -Source $Source
    $text = ConvertFrom-StrictUtf8 -Bytes $bytes
    foreach ($placeholder in @(
        '__HOTDEAL_FOCUS_DOWNLOAD_URL__',
        '__HOTDEAL_FOCUS_UPDATE_URL__',
        '__HOTDEAL_FOCUS_OWNER__'
    )) {
        if ($text.Contains($placeholder)) {
            throw "Userscript contains unresolved release placeholder: $placeholder"
        }
    }

    $startMarker = '// ==UserScript=='
    $endMarker = '// ==/UserScript=='
    $start = $text.IndexOf($startMarker, [StringComparison]::Ordinal)
    $end = $text.IndexOf($endMarker, [StringComparison]::Ordinal)
    if ($start -lt 0 -or $end -lt $start -or
        @([regex]::Matches($text, [regex]::Escape($startMarker))).Count -ne 1 -or
        @([regex]::Matches($text, [regex]::Escape($endMarker))).Count -ne 1) {
        throw "Userscript metadata block is not exact"
    }
    if ($text.Substring(0, $start).Trim().Length -ne 0) {
        throw "Userscript metadata must be the first content in the file"
    }
    $metadataEnd = $end + $endMarker.Length
    $metadata = $text.Substring($start, $metadataEnd - $start)
    $code = $text.Substring($metadataEnd)
    if ($code.StartsWith("`r`n")) { $code = $code.Substring(2) }
    elseif ($code.StartsWith("`n")) { $code = $code.Substring(1) }

    $nameMatch = [regex]::Match($metadata, '(?m)^//\s+@name\s+(?<value>.+?)\s*$')
    $versionMatch = [regex]::Match($metadata, '(?m)^//\s+@version\s+(?<value>\S+)\s*$')
    if (-not $nameMatch.Success -or -not $versionMatch.Success -or
        @([regex]::Matches($metadata, '(?m)^//\s+@name\s+\S.*$')).Count -ne 1 -or
        @([regex]::Matches($metadata, '(?m)^//\s+@version\s+\S+\s*$')).Count -ne 1) {
        throw "Userscript must declare @name and @version"
    }
    $name = $nameMatch.Groups['value'].Value.Trim()
    $version = $versionMatch.Groups['value'].Value.Trim()
    if ($name -cne $UserscriptName) {
        throw "Userscript @name does not equal the configured target name"
    }
    $runAtDirectives = @([regex]::Matches(
            $metadata, '(?m)^//\s+@run-at\s+(?<value>\S+)\s*$'))
    $grantDirectives = @([regex]::Matches(
            $metadata, '(?m)^//\s+@grant\s+(?<value>\S+)\s*$'))
    $noframesDirectives = @([regex]::Matches(
            $metadata, '(?m)^//\s+@noframes\s*$'))
    if ($runAtDirectives.Count -ne 1 -or
        $runAtDirectives[0].Groups['value'].Value -cne 'document-start' -or
        $grantDirectives.Count -ne 1 -or
        $grantDirectives[0].Groups['value'].Value -cne $script:ReaderGateGrant -or
        $noframesDirectives.Count -ne 1) {
        throw ("Reader Gate v2 must declare exactly one document-start, one @noframes, " +
            "and exactly one @grant GM_addElement")
    }
    foreach ($hostToken in @('algumon.com', 'clien.net', 'ppomppu.co.kr', 'ruliweb.com',
            'quasarzone.com', 'eomisae.co.kr', 'zod.kr', 'arca.live')) {
        if (-not $metadata.Contains($hostToken)) {
            throw "Userscript is missing required match scope: $hostToken"
        }
    }
    foreach ($marker in @('data-hotdeal-focus-ready', 'data-hotdeal-focus-keep',
            'data-hotdeal-focus-protocol', 'data-hotdeal-focus-lock',
            'data-hotdeal-focus-shell', 'data-hotdeal-focus-deep',
            'data-hotdeal-focus-role', 'data-hotdeal-focus-state',
            'data-hotdeal-focus-status')) {
        if (-not $code.Contains($marker)) { throw "Userscript is missing protocol marker: $marker" }
    }
    $protocolDeclarations = @([regex]::Matches(
            $code,
            '(?m)^\s*const\s+PROTOCOL_VERSION\s*=\s*"(?<value>\d+)";\s*$'
        ))
    if ($protocolDeclarations.Count -ne 1 -or
        [int] $protocolDeclarations[0].Groups['value'].Value -ne
            $script:ReaderGateProtocolVersion) {
        throw "Reader Gate userscript must declare exact protocol version 2"
    }
    foreach ($contractToken in @(
            'protocolVersion: Number(PROTOCOL_VERSION)',
            'setAttribute(ATTR.protocol, PROTOCOL_VERSION)',
            'data-hotdeal-focus-runtime-style',
            'style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]',
            'hdf-v2-lock',
            'hdf-v2-ready',
            'hdf-v2-keep',
            'hdf-v2-shell',
            'hdf-v2-deep',
            'hdf-v2-role-',
            'GM_addElement('
        )) {
        if (-not $code.Contains($contractToken)) {
            throw "Reader Gate v2 is missing diagnostics/runtime contract: $contractToken"
        }
    }
    if (@([regex]::Matches(
                $code,
                [regex]::Escape('protocolVersion: Number(PROTOCOL_VERSION)')
            )).Count -ne 1) {
        throw "Reader Gate v2 diagnostics protocol marker is not unique"
    }

    foreach ($urlMatch in [regex]::Matches(
            $metadata,
            '(?m)^//\s+@(downloadURL|updateURL)\s+(?<value>\S+)\s*$')) {
        [void] (Assert-PublicHttpsUri -Value $urlMatch.Groups['value'].Value)
    }

    if ($ExpectedUserscriptSha256) {
        $actual = Get-CanonicalTextSha256 -Text $text
        if ($actual -cne $ExpectedUserscriptSha256.ToLowerInvariant()) {
            throw "Userscript canonical SHA-256 does not match the expected value"
        }
    }

    return [pscustomobject]@{
        Bytes = $bytes
        RawSha256 = Get-Sha256Hex -Bytes $bytes
        Text = $text
        MetadataBlock = $metadata
        Code = $code
        Name = $name
        Version = $version
        ProtocolVersion = $script:ReaderGateProtocolVersion
        Grant = $script:ReaderGateGrant
        Sha256 = Get-CanonicalTextSha256 -Text $text
        MetadataSha256 = Get-CanonicalTextSha256 -Text $metadata
        CodeSha256 = Get-CanonicalTextSha256 -Text $code
        FreshInstallGmProperties = $script:FreshInstallGmProperties
        FreshInstallGmPropertiesSha256 = Get-CanonicalTextSha256 `
            -Text $script:FreshInstallGmProperties
        TempPath = $null
        Meta = $null
    }
}

function Get-CspProbeUserscriptText {
    $path = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'csp-probe.user.js'))
    $expectedParent = [System.IO.Path]::GetFullPath($PSScriptRoot)
    if ([System.IO.Path]::GetDirectoryName($path) -cne $expectedParent) {
        throw "Fixed CSP probe path escaped the CLI script directory"
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and
        -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and
        [long] $item.Length -gt 0 -and [long] $item.Length -le 64KB) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        return $script:Utf8NoBom.GetString($bytes)
    }
    throw "Fixed CSP probe source is not one bounded regular file"
}

function Get-CspProbeUserscriptSource {
    $text = Get-CspProbeUserscriptText
    $bytes = $script:Utf8NoBom.GetBytes($text)
    $rawSha = Get-Sha256Hex -Bytes $bytes
    if ($rawSha -cne $script:CspProbeSourceSha256) {
        throw "Built-in CSP probe source SHA-256 differs from its pinned contract"
    }

    $startMarker = '// ==UserScript=='
    $endMarker = '// ==/UserScript=='
    $start = $text.IndexOf($startMarker, [StringComparison]::Ordinal)
    $end = $text.IndexOf($endMarker, [StringComparison]::Ordinal)
    if ($start -ne 0 -or $end -le $start) {
        throw "Built-in CSP probe metadata block is malformed"
    }
    $metadataEnd = $end + $endMarker.Length
    $metadata = $text.Substring(0, $metadataEnd)
    $code = $text.Substring($metadataEnd)
    if ($code.StartsWith("`n")) { $code = $code.Substring(1) }

    $matchDirectives = @([regex]::Matches(
            $metadata,
            '(?m)^//\s+@match\s+(?<value>\S+)\s*$'
        ))
    $grantDirectives = @([regex]::Matches(
            $metadata,
            '(?m)^//\s+@grant\s+(?<value>\S+)\s*$'
        ))
    if ($matchDirectives.Count -ne 1 -or
        $matchDirectives[0].Groups['value'].Value -cne
            'https://testcases.agrd.dev/userscripts-csp/header-csp-default-src-none') {
        throw "Built-in CSP probe must have one exact @match directive"
    }
    if ($grantDirectives.Count -ne 1 -or
        $grantDirectives[0].Groups['value'].Value -cne 'GM_addElement' -or
        $metadata -notmatch '(?m)^//\s+@run-at\s+document-start\s*$' -or
        $metadata -notmatch '(?m)^//\s+@noframes\s*$') {
        throw "Built-in CSP probe metadata privileges differ from the fixed contract"
    }
    if ($metadata -match ('(?m)^//\s+@(connect|downloadURL|exclude|exclude-match|' +
            'include|require|resource|updateURL)\b')) {
        throw "Built-in CSP probe contains a forbidden external capability"
    }
    foreach ($networkToken in @(
            'fetch(', 'GM_xmlhttpRequest', 'navigator.sendBeacon',
            'WebSocket(', 'XMLHttpRequest'
        )) {
        if ($code.Contains($networkToken)) {
            throw "Built-in CSP probe contains a forbidden network API"
        }
    }
    if (-not $code.Contains('GM_addElement(parent, "style", {') -or
        $code.Contains('GM_addElement(parent, "style", { nonce') -or
        $code.Contains('GM_addElement(parent, "style", { "data-source"')) {
        throw "Built-in CSP probe GM_addElement call differs from the fixed contract"
    }
    $endpointGuard = 'if (location.href !== EXPECTED_URL) {'
    $endpointLiteral = 'const EXPECTED_URL = "' + $script:CspProbeEndpoint + '";'
    if (-not $code.Contains($endpointLiteral) -or -not $code.Contains($endpointGuard) -or
        $code.IndexOf($endpointLiteral, [StringComparison]::Ordinal) -gt
            $code.IndexOf('const setBoolean', [StringComparison]::Ordinal)) {
        throw "Built-in CSP probe is not guarded by the exact endpoint before DOM mutation"
    }

    return [pscustomobject]@{
        Bytes = $bytes
        RawSha256 = $rawSha
        Text = $text
        MetadataBlock = $metadata
        Code = $code
        Name = $script:CspProbeUserscriptName
        Version = $script:CspProbeUserscriptVersion
        Sha256 = Get-CanonicalTextSha256 -Text $text
        MetadataSha256 = Get-CanonicalTextSha256 -Text $metadata
        CodeSha256 = Get-CanonicalTextSha256 -Text $code
        FreshInstallGmProperties = $script:FreshInstallGmProperties
        FreshInstallGmPropertiesSha256 = Get-CanonicalTextSha256 `
            -Text $script:FreshInstallGmProperties
        TempPath = $null
        Meta = $null
    }
}

function Get-FilterSource {
    param([Parameter(Mandatory = $true)][string] $Url)

    [void] (Assert-PublicHttpsUri -Value $Url)
    $bytes = Read-HttpsBytes -Url $Url
    return ConvertFrom-FilterSourceBytes -Bytes $bytes -Url $Url
}

function ConvertFrom-FilterSourceBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]] $Bytes,
        [Parameter(Mandatory = $true)][string] $Url
    )

    $text = ConvertFrom-StrictUtf8 -Bytes $bytes
    if ($text.Contains('__HOTDEAL_FOCUS_')) { throw "Filter contains unresolved release placeholders" }
    $protocolMatches = @([regex]::Matches(
            $text,
            '(?m)^!\s*Hotdeal-Focus-Protocol:\s*(?<value>\d+)\s*$'))
    if ($protocolMatches.Count -ne 1 -or
        [int] $protocolMatches[0].Groups['value'].Value -ne
            $script:ReaderGateProtocolVersion) {
        throw "Filter is not the exact protocol-2 Hotdeal Focus marker gate"
    }
    $titleMatches = @([regex]::Matches(
            $text, '(?m)^!\s*Title:\s*(?<value>.+?)\s*$'))
    $versionMatches = @([regex]::Matches(
            $text, '(?m)^!\s*Version:\s*(?<value>\S+)\s*$'))
    if ($titleMatches.Count -ne 1 -or $versionMatches.Count -ne 1) {
        throw "Filter must declare Title and Version metadata"
    }
    $title = $titleMatches[0].Groups['value'].Value.Trim()
    if ($title -cne $FilterName -or
        $versionMatches[0].Groups['value'].Value.Trim() -cne
            $script:MarkerGateArtifactVersion) {
        throw "Filter Title or Version does not equal the protocol-2 marker gate contract"
    }
    $sourceRules = @($text -split "`r?`n" | Where-Object {
            $_.Trim().Length -gt 0 -and -not $_.TrimStart().StartsWith('!')
        } | ForEach-Object { [string] $_ })
    $sourceRulesText = $sourceRules -join "`n"
    foreach ($marker in @('hdf-v2-lock', 'hdf-v2-ready', 'hdf-v2-keep',
            'hdf-v2-shell', 'hdf-v2-deep', 'hdf-v2-role-',
            'data-hotdeal-focus-ready="1"', 'data-hotdeal-focus-keep',
            'data-hotdeal-focus-protocol="2"', 'data-hotdeal-focus-shell',
            'data-hotdeal-focus-deep', 'data-hotdeal-focus-role="',
            'data-hotdeal-focus-state="ready"',
            'data-hotdeal-focus-status="ready"')) {
        if (-not $sourceRulesText.Contains($marker)) {
            throw "Filter is missing protocol-2 class/attribute marker: $marker"
        }
    }
    if ($sourceRulesText.Contains('data-hotdeal-focus-protocol="1"')) {
        throw "Protocol-2 filter contains a protocol-1 marker"
    }
    $ruleCount = $sourceRules.Count
    if ($ruleCount -lt 2) { throw "Filter contains too few protocol rules" }
    $sourceRulesSha = Get-RuleListSha256 -Rules $sourceRules
    if ($ExpectedInstalledFilterRulesSha256 -and
        $sourceRulesSha -cne $ExpectedInstalledFilterRulesSha256.ToLowerInvariant()) {
        throw "Expected installed rules SHA-256 does not match the verified filter rule lines"
    }

    $rawSha = Get-Sha256Hex -Bytes $bytes
    if ($ExpectedFilterSha256 -and $rawSha -cne $ExpectedFilterSha256.ToLowerInvariant()) {
        throw "Filter raw-file SHA-256 does not match the expected value"
    }
    return [pscustomobject]@{
        Bytes = $bytes
        Text = $text
        Name = $title
        Version = $versionMatches[0].Groups['value'].Value.Trim()
        ProtocolVersion = [int] $protocolMatches[0].Groups['value'].Value
        RuleCount = $ruleCount
        SourceRulesSha256 = $sourceRulesSha
        RawSha256 = $rawSha
        Url = ([Uri] $Url).AbsoluteUri
        MetaSet = $null
    }
}

function Get-DefaultReleaseManifestSource {
    if ($ReleaseManifestSource) { return $ReleaseManifestSource }
    foreach ($source in @($FilterUrl, $UserscriptSource)) {
        if (-not $source) { continue }
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            $resolved = (Resolve-Path -LiteralPath $source -ErrorAction Stop).ProviderPath
            return Join-Path ([System.IO.Path]::GetDirectoryName($resolved)) `
                'release-manifest.json'
        }
        $uri = $null
        if ([Uri]::TryCreate($source, [UriKind]::Absolute, [ref] $uri) -and $uri.Scheme) {
            if ($uri.Scheme -cne 'https') { continue }
            return ([Uri]::new($uri, 'release-manifest.json')).AbsoluteUri
        }
    }
    throw "A release manifest source could not be derived"
}

function Get-ReleaseManifestContract {
    param([Parameter(Mandatory = $true)][string] $Source)
    $bytes = Read-SourceBytes -Source $Source
    $text = ConvertFrom-StrictUtf8 -Bytes $bytes
    try { $manifest = $text | ConvertFrom-Json }
    catch { throw "Release manifest is malformed JSON" }
    Assert-JsonProperties -Value $manifest -Names @('schemaVersion', 'releaseVersion',
        'protocolVersion', 'gateArtifactVersion', 'filterSubscriptionUrl',
        'status', 'artifacts') -Label 'release manifest'
    if ([int] $manifest.schemaVersion -ne 1 -or
        [string] $manifest.status -cne 'release-ready') {
        throw "Release manifest is not a release-ready schema-v1 document"
    }
    $filterEntry = $manifest.artifacts.'filter.txt'
    $userscriptEntry = $manifest.artifacts.'hotdeal-focus.user.js'
    if (-not $filterEntry -or -not $userscriptEntry) {
        throw "Release manifest is missing required public artifacts"
    }
    Assert-JsonProperties -Value $filterEntry -Names @(
        'version', 'sha256', 'installedRulesSha256') `
        -Label 'release manifest filter artifact'
    Assert-JsonProperties -Value $userscriptEntry -Names @(
        'version', 'sha256', 'canonicalTextSha256') `
        -Label 'release manifest userscript artifact'
    $gateArtifactVersion = [string] $manifest.gateArtifactVersion
    $filterSubscriptionUrl = [string] $manifest.filterSubscriptionUrl
    $protocolValue = $manifest.protocolVersion
    $protocolIsInteger = $protocolValue -is [int] -or $protocolValue -is [long]
    $protocolVersion = if ($protocolIsInteger) { [int] $protocolValue } else { -1 }
    if ($gateArtifactVersion -cne $script:MarkerGateArtifactVersion -or
        [string] $filterEntry.version -cne $gateArtifactVersion -or
        [string] $userscriptEntry.version -cne [string] $manifest.releaseVersion -or
        -not $protocolIsInteger -or
        $protocolVersion -ne $script:ReaderGateProtocolVersion -or
        $filterSubscriptionUrl -cne $script:MarkerGateSubscriptionUrl -or
        (Assert-PublicHttpsUri -Value $filterSubscriptionUrl).AbsoluteUri -cne
            $filterSubscriptionUrl) {
        throw "Release manifest is not the exact protocol-2 gate contract"
    }
    foreach ($entry in @(
            [pscustomobject]@{ Value = [string] $filterEntry.sha256; Name = 'filter sha256' },
            [pscustomobject]@{ Value = [string] $filterEntry.installedRulesSha256;
                Name = 'filter installedRulesSha256' },
            [pscustomobject]@{ Value = [string] $userscriptEntry.sha256;
                Name = 'userscript sha256' },
            [pscustomobject]@{ Value = [string] $userscriptEntry.canonicalTextSha256;
                Name = 'userscript canonicalTextSha256' })) {
        Assert-Sha256Value -Value $entry.Value -Name $entry.Name
        if (-not $entry.Value) { throw "$($entry.Name) is empty" }
    }
    return [pscustomobject]@{
        Source = $Source
        RawSha256 = Get-Sha256Hex -Bytes $bytes
        ReleaseVersion = [string] $manifest.releaseVersion
        ProtocolVersion = $protocolVersion
        GateArtifactVersion = $gateArtifactVersion
        FilterSubscriptionUrl = $filterSubscriptionUrl
        FilterRawSha256 = ([string] $filterEntry.sha256).ToLowerInvariant()
        FilterInstalledRulesSha256 = (
            [string] $filterEntry.installedRulesSha256).ToLowerInvariant()
        UserscriptRawSha256 = ([string] $userscriptEntry.sha256).ToLowerInvariant()
        UserscriptCanonicalTextSha256 = (
            [string] $userscriptEntry.canonicalTextSha256).ToLowerInvariant()
    }
}

function Assert-ReleaseInputsMatchManifest {
    param(
        [Parameter(Mandatory = $true)] $ManifestContract,
        [AllowNull()] $DesiredUserscript,
        [AllowNull()] $DesiredFilter
    )
    if ($DesiredUserscript) {
        if ($ExpectedUserscriptSha256.ToLowerInvariant() -cne
                $ManifestContract.UserscriptCanonicalTextSha256 -or
            $DesiredUserscript.Sha256 -cne $ManifestContract.UserscriptCanonicalTextSha256 -or
            $DesiredUserscript.RawSha256 -cne $ManifestContract.UserscriptRawSha256 -or
            $DesiredUserscript.Version -cne $ManifestContract.ReleaseVersion -or
            $DesiredUserscript.ProtocolVersion -ne $ManifestContract.ProtocolVersion -or
            $DesiredUserscript.Grant -cne $script:ReaderGateGrant) {
            throw "Userscript source or expected hash differs from the release manifest"
        }
    }
    if ($DesiredFilter) {
        if ($ExpectedFilterSha256.ToLowerInvariant() -cne $ManifestContract.FilterRawSha256 -or
            $ExpectedInstalledFilterRulesSha256.ToLowerInvariant() -cne
                $ManifestContract.FilterInstalledRulesSha256 -or
            $DesiredFilter.RawSha256 -cne $ManifestContract.FilterRawSha256 -or
            $DesiredFilter.SourceRulesSha256 -cne
                $ManifestContract.FilterInstalledRulesSha256 -or
            $DesiredFilter.Url -cne $ManifestContract.FilterSubscriptionUrl -or
            $DesiredFilter.Version -cne $ManifestContract.GateArtifactVersion -or
            $DesiredFilter.ProtocolVersion -ne $ManifestContract.ProtocolVersion) {
            throw "Filter source or expected hashes differ from the release manifest"
        }
    }
}

function Initialize-NativeMemoryType {
    if ('HotdealFocus.NativeMemory' -as [type]) { return }

    $source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace HotdealFocus {
    public sealed class RemoteReference {
        public ulong Address { get; private set; }
        public ulong Value { get; private set; }
        public RemoteReference(ulong address, ulong value) { Address = address; Value = value; }
    }

    public sealed class NativeMemory : IDisposable {
        const uint ProcessQueryInformation = 0x0400;
        const uint ProcessVmRead = 0x0010;
        const uint MemCommit = 0x1000;
        const uint MemPrivate = 0x20000;
        const uint PageGuard = 0x0100;
        const uint PageNoAccess = 0x0001;
        const int ChunkBytes = 4 * 1024 * 1024;

        [StructLayout(LayoutKind.Sequential)]
        struct MemoryBasicInformation {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] buffer,
            IntPtr size, out IntPtr bytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address,
            out MemoryBasicInformation information, IntPtr length);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(IntPtr process, out bool isWow64);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        IntPtr handle;

        public NativeMemory(int processId) {
            handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, processId);
            if (handle == IntPtr.Zero) {
                throw new InvalidOperationException(
                    "Cannot open the AdGuard UI process for read-only inspection; win32=" +
                    Marshal.GetLastWin32Error());
            }
            if (Environment.Is64BitOperatingSystem) {
                bool targetWow64;
                bool currentWow64;
                if (!IsWow64Process(handle, out targetWow64) ||
                    !IsWow64Process(System.Diagnostics.Process.GetCurrentProcess().Handle,
                        out currentWow64) || targetWow64 != currentWow64) {
                    Dispose();
                    throw new InvalidOperationException(
                        "PowerShell and the AdGuard UI process must have the same bitness");
                }
            }
        }

        public void Dispose() {
            if (handle != IntPtr.Zero) {
                CloseHandle(handle);
                handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~NativeMemory() { Dispose(); }

        static ulong ToUInt64(IntPtr value) {
            return unchecked((ulong)value.ToInt64());
        }

        byte[] ReadExact(ulong address, int count) {
            byte[] buffer = new byte[count];
            IntPtr bytesRead;
            if (!ReadProcessMemory(handle, new IntPtr(unchecked((long)address)), buffer,
                    new IntPtr(count), out bytesRead) || bytesRead.ToInt64() != count) {
                throw new InvalidOperationException(
                    "Remote memory changed during credential discovery");
            }
            return buffer;
        }

        public ulong ReadPointer(ulong address) {
            byte[] bytes = ReadExact(address, IntPtr.Size);
            return IntPtr.Size == 8 ? BitConverter.ToUInt64(bytes, 0) :
                BitConverter.ToUInt32(bytes, 0);
        }

        public string ReadManagedString(ulong address, int dataOffset, int maximumChars) {
            if (address == 0) return null;
            int length = BitConverter.ToInt32(ReadExact(address + 8, 4), 0);
            if (length < 0 || length > maximumChars) {
                throw new InvalidOperationException("Remote string failed structural validation");
            }
            return Encoding.Unicode.GetString(
                ReadExact(address + (ulong)dataOffset, checked(length * 2)));
        }

        static int[] BuildSkipTable(byte[] needle) {
            int[] skip = new int[256];
            for (int i = 0; i < skip.Length; i++) skip[i] = needle.Length;
            for (int i = 0; i < needle.Length - 1; i++) {
                skip[needle[i]] = needle.Length - i - 1;
            }
            return skip;
        }

        static void Search(byte[] haystack, byte[] needle, ulong baseAddress,
                HashSet<ulong> results, int maximumMatches) {
            if (needle.Length == 0 || haystack.Length < needle.Length) return;
            int[] skip = BuildSkipTable(needle);
            int index = 0;
            while (index <= haystack.Length - needle.Length && results.Count < maximumMatches) {
                int compared = needle.Length - 1;
                while (compared >= 0 && haystack[index + compared] == needle[compared]) compared--;
                if (compared < 0) {
                    results.Add(baseAddress + (ulong)index);
                    index++;
                } else {
                    index += Math.Max(1, skip[haystack[index + needle.Length - 1]]);
                }
            }
        }

        public List<ulong> FindBytes(byte[] needle, int maximumMatches) {
            HashSet<ulong> results = new HashSet<ulong>();
            ulong cursor = 0;
            ulong limit = IntPtr.Size == 8 ? 0x00007fffffff0000UL : 0x7fff0000UL;
            int informationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));
            while (cursor < limit && results.Count < maximumMatches) {
                MemoryBasicInformation information;
                IntPtr queried = VirtualQueryEx(handle,
                    new IntPtr(unchecked((long)cursor)), out information,
                    new IntPtr(informationSize));
                if (queried == IntPtr.Zero) break;
                ulong start = ToUInt64(information.BaseAddress);
                ulong size = information.RegionSize.ToUInt64();
                ulong next = start + size;
                if (next <= cursor) break;

                uint baseProtection = information.Protect & 0xff;
                if (information.State == MemCommit && information.Type == MemPrivate &&
                    (information.Protect & PageGuard) == 0 && baseProtection != PageNoAccess) {
                    long offset = 0;
                    byte[] carry = new byte[Math.Max(0, needle.Length - 1)];
                    int carryCount = 0;
                    while ((ulong)offset < size && results.Count < maximumMatches) {
                        int wanted = (int)Math.Min((ulong)ChunkBytes, size - (ulong)offset);
                        byte[] raw = new byte[wanted];
                        IntPtr bytesRead;
                        bool read = ReadProcessMemory(handle,
                            new IntPtr(unchecked((long)(start + (ulong)offset))), raw,
                            new IntPtr(wanted), out bytesRead);
                        int count = (int)Math.Max(0, bytesRead.ToInt64());
                        if (read && count > 0) {
                            byte[] scan = new byte[carryCount + count];
                            if (carryCount > 0) Buffer.BlockCopy(carry, 0, scan, 0, carryCount);
                            Buffer.BlockCopy(raw, 0, scan, carryCount, count);
                            Search(scan, needle, start + (ulong)offset - (ulong)carryCount,
                                results, maximumMatches);
                            carryCount = Math.Min(carry.Length, scan.Length);
                            if (carryCount > 0) {
                                Buffer.BlockCopy(scan, scan.Length - carryCount, carry, 0,
                                    carryCount);
                            }
                        } else {
                            carryCount = 0;
                        }
                        offset += wanted;
                    }
                }
                cursor = next;
            }
            return new List<ulong>(results);
        }

        public List<ulong> FindManagedStrings(string value, int dataOffset,
                int maximumMatches) {
            List<ulong> results = new List<ulong>();
            foreach (ulong hit in FindBytes(Encoding.Unicode.GetBytes(value),
                    maximumMatches * 8)) {
                if (hit < (ulong)dataOffset) continue;
                ulong objectAddress = hit - (ulong)dataOffset;
                try {
                    if (ReadManagedString(objectAddress, dataOffset, 4096) == value) {
                        results.Add(objectAddress);
                    }
                } catch (InvalidOperationException) { }
                if (results.Count >= maximumMatches) break;
            }
            return results;
        }

        public List<RemoteReference> FindAnyPointerReferences(ulong[] values,
                int maximumMatches) {
            HashSet<ulong> wantedValues = new HashSet<ulong>(values);
            List<RemoteReference> results = new List<RemoteReference>();
            ulong cursor = 0;
            ulong limit = IntPtr.Size == 8 ? 0x00007fffffff0000UL : 0x7fff0000UL;
            int informationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));
            while (cursor < limit && results.Count < maximumMatches) {
                MemoryBasicInformation information;
                IntPtr queried = VirtualQueryEx(handle,
                    new IntPtr(unchecked((long)cursor)), out information,
                    new IntPtr(informationSize));
                if (queried == IntPtr.Zero) break;
                ulong start = ToUInt64(information.BaseAddress);
                ulong size = information.RegionSize.ToUInt64();
                ulong next = start + size;
                if (next <= cursor) break;
                uint baseProtection = information.Protect & 0xff;
                if (information.State == MemCommit && information.Type == MemPrivate &&
                    (information.Protect & PageGuard) == 0 && baseProtection != PageNoAccess) {
                    long offset = 0;
                    while ((ulong)offset < size && results.Count < maximumMatches) {
                        int wanted = (int)Math.Min((ulong)ChunkBytes, size - (ulong)offset);
                        byte[] raw = new byte[wanted];
                        IntPtr bytesRead;
                        bool read = ReadProcessMemory(handle,
                            new IntPtr(unchecked((long)(start + (ulong)offset))), raw,
                            new IntPtr(wanted), out bytesRead);
                        int count = (int)Math.Max(0, bytesRead.ToInt64());
                        if (read && count >= IntPtr.Size) {
                            ulong chunkAddress = start + (ulong)offset;
                            int alignment = (int)((ulong)IntPtr.Size -
                                (chunkAddress % (ulong)IntPtr.Size)) % IntPtr.Size;
                            for (int index = alignment; index <= count - IntPtr.Size;
                                    index += IntPtr.Size) {
                                ulong value = IntPtr.Size == 8 ?
                                    BitConverter.ToUInt64(raw, index) :
                                    BitConverter.ToUInt32(raw, index);
                                if (wantedValues.Contains(value)) {
                                    results.Add(new RemoteReference(
                                        chunkAddress + (ulong)index, value));
                                    if (results.Count >= maximumMatches) break;
                                }
                            }
                        }
                        offset += wanted;
                    }
                }
                cursor = next;
            }
            return results;
        }
    }

    public static class LayoutProbe {
        public static unsafe int[] FindReferenceOffsets(object owner, object target,
                int maximumBytes) {
            TypedReference ownerReference = __makeref(owner);
            TypedReference targetReference = __makeref(target);
            byte* ownerAddress = (byte*)(**(IntPtr**)(&ownerReference));
            IntPtr targetAddress = **(IntPtr**)(&targetReference);
            List<int> offsets = new List<int>();
            for (int offset = 0; offset <= maximumBytes - IntPtr.Size;
                    offset += IntPtr.Size) {
                if (*(IntPtr*)(ownerAddress + offset) == targetAddress) offsets.Add(offset);
            }
            GC.KeepAlive(owner);
            GC.KeepAlive(target);
            return offsets.ToArray();
        }

        public static unsafe int StringDataOffset(string value) {
            TypedReference reference = __makeref(value);
            byte* objectAddress = (byte*)(**(IntPtr**)(&reference));
            fixed (char* characterAddress = value) {
                return (int)((byte*)characterAddress - objectAddress);
            }
        }
    }
}
'@

    $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $parameters.GenerateExecutable = $false
    $parameters.GenerateInMemory = $true
    $parameters.CompilerOptions = '/unsafe /optimize+'
    [void] $parameters.ReferencedAssemblies.Add('System.dll')
    [void] $parameters.ReferencedAssemblies.Add('System.Core.dll')
    try {
        $compiled = $provider.CompileAssemblyFromSource($parameters, $source)
        if ($compiled.Errors.HasErrors) {
            throw "Native read-only memory helper could not be compiled"
        }
        [void] $compiled.CompiledAssembly
    }
    finally {
        $provider.Dispose()
    }
}

function Get-AdGuardService {
    $service = Get-Service -Name 'Adguard Service' -ErrorAction Stop
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "AdGuard service is not running; this CLI will not start or stop it"
    }
    return $service
}

function Get-AdGuardUiProcess {
    [void] (Get-AdGuardService)
    $expectedPaths = @(@(
            (Join-Path $env:ProgramFiles 'AdGuard\Adguard.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'AdGuard\Adguard.exe')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        ForEach-Object { [System.IO.Path]::GetFullPath($_) } | Select-Object -Unique)
    if ($expectedPaths.Count -eq 0) { throw "AdGuard installation was not found" }

    $processes = @(Get-Process -Name Adguard -ErrorAction SilentlyContinue | Where-Object {
            $path = $_.Path
            $path -and ($expectedPaths -icontains [System.IO.Path]::GetFullPath($path))
    })
    if ($processes.Count -eq 0) {
        if ($WhatIfPreference) {
            throw "AdGuard UI is not running; -WhatIf will not start a process"
        }
        $process = Start-Process -FilePath $expectedPaths[0] -WindowStyle Hidden -PassThru
        $script:UiWasStarted = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 250
            $processes = @(Get-Process -Name Adguard -ErrorAction SilentlyContinue | Where-Object {
                    $_.Path -and
                    ($expectedPaths -icontains [System.IO.Path]::GetFullPath($_.Path))
                })
        } while ($processes.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)
    }
    if ($processes.Count -ne 1) { throw "Expected exactly one active AdGuard UI process" }

    $signature = Get-AuthenticodeSignature -LiteralPath $processes[0].Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "AdGuard executable signature is not valid"
    }
    $script:AdGuardProcess = $processes[0]
    $script:AdGuardInstallDirectory = [System.IO.Path]::GetDirectoryName($processes[0].Path)
    return $processes[0]
}

function Get-TypeFromLoadedAssemblies {
    param([Parameter(Mandatory = $true)][string] $FullName)
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $type = $assembly.GetType($FullName, $false, $false)
        if ($type) { return $type }
    }
    throw "Required AdGuard type is unavailable: $FullName"
}

function Initialize-AdGuardAssemblies {
    if ($script:ApiClientType) { return }
    foreach ($name in @('AdGuard.Utils.Base.dll', 'AdGuard.Utils.dll', 'Adguard.Global.dll',
            'Adguard.Ipc.dll')) {
        $path = Join-Path $script:AdGuardInstallDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required AdGuard assembly is missing: $name"
        }
        [void] [System.Reflection.Assembly]::LoadFrom($path)
    }

    $script:ApiClientType = Get-TypeFromLoadedAssemblies -FullName (
        'Adguard.Ipc.Client.UiApplicationApiClient')
    $script:HubType = Get-TypeFromLoadedAssemblies -FullName 'TinyMessenger.TinyMessengerHub'
    $script:FilterSubscriptionType = Get-TypeFromLoadedAssemblies -FullName (
        'Adguard.Global.Model.AdBlocker.FilterSubscriptionType')
    $script:StandardFilterType = [Enum]::Parse($script:FilterSubscriptionType, 'Standard')

    foreach ($methodName in @('Connect', 'Disconnect', 'GetApplicationState',
            'GetProtectionSettings', 'GetInstalledFilterSubscriptions', 'GetAllFilterSubscriptions',
            'GetFilterSubscriptionRules', 'GetUserscripts', 'GetUserscriptCode',
            'GetUserscriptGmProperties', 'GetUserscriptMeta', 'InstallUserscriptFromMeta',
            'UpdateUserscriptCode', 'UpdateUserscriptGmProperties', 'SetUserscriptStatus',
            'RemoveUserscript', 'GetSubscriptionsMetaSet', 'InstallCustomFilter',
            'UpdateFilterSubscriptionState', 'RemoveFilterSubscription',
            'DisableFilterRules', 'EnableFilterRules')) {
        if (-not $script:ApiClientType.GetMethod($methodName)) {
            throw "Installed AdGuard IPC contract is missing method: $methodName"
        }
    }
    Initialize-NativeMemoryType
}

function Get-IpcIdentityFromCurrentLog {
    param([Parameter(Mandatory = $true)] $Process)

    $logDirectory = Join-Path $env:ProgramData 'Adguard\Logs\agent'
    if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
        throw "AdGuard agent log directory was not found"
    }
    $logs = @(Get-ChildItem -LiteralPath $logDirectory -Filter '*.log' -File |
        Sort-Object LastWriteTime -Descending)
    foreach ($log in $logs) {
        if ($log.LastWriteTime -lt $Process.StartTime.AddSeconds(-30)) { continue }
        $matches = @(Select-String -LiteralPath $log.FullName -Pattern (
                'Creating an instance of UiApplicationApiClient\. ' +
                'EndPoint=(?<endpoint>\S+)\. ClientId=(?<id>[A-Za-z0-9_-]{16,128})'))
        if ($matches.Count -eq 0) { continue }
        $match = $matches[-1].Matches[0]
        $endpoint = $match.Groups['endpoint'].Value
        if ($endpoint -cne 'net.pipe://127.0.0.1/AdguardApiEndpoint') {
            throw "AdGuard IPC endpoint in the current log is unexpected"
        }
        return [pscustomobject]@{
            Endpoint = $endpoint
            ClientId = $match.Groups['id'].Value
            LogName = $log.Name
        }
    }
    throw "Current UiApplicationApiClient identity was not found in the latest agent log"
}

function Get-SingleReferenceOffset {
    param(
        [Parameter(Mandatory = $true)] $Owner,
        [Parameter(Mandatory = $true)] $Target,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $offsets = @([HotdealFocus.LayoutProbe]::FindReferenceOffsets($Owner, $Target, 256))
    if ($offsets.Count -ne 1 -or $offsets[0] -lt [IntPtr]::Size -or
        $offsets[0] % [IntPtr]::Size -ne 0) {
        throw "Could not infer the unique $Label field offset from the installed AdGuard client"
    }
    return [int] $offsets[0]
}

function Get-IpcCredentialInMemory {
    param(
        [Parameter(Mandatory = $true)] $Process,
        [Parameter(Mandatory = $true)] $Identity
    )

    $probeHub = [Activator]::CreateInstance($script:HubType)
    $probeEndpoint = 'net.pipe://127.0.0.1/CodexProbe/' + [Guid]::NewGuid().ToString('N')
    $probeKey = 'probe-' + [Guid]::NewGuid().ToString('N')
    $probe = [Activator]::CreateInstance(
        $script:ApiClientType,
        @($probeEndpoint, $probeHub, $probeKey)
    )
    try {
        $endpointOffset = Get-SingleReferenceOffset -Owner $probe -Target $probeEndpoint `
            -Label 'endpoint'
        $keyOffset = Get-SingleReferenceOffset -Owner $probe -Target $probeKey -Label 'key'
        $clientIdOffset = Get-SingleReferenceOffset -Owner $probe -Target $probe.ClientId `
            -Label 'client identity'
        $stringDataOffset = [HotdealFocus.LayoutProbe]::StringDataOffset($probe.ClientId)
        if ($stringDataOffset -lt 8 -or $stringDataOffset -gt 32) {
            throw "Managed string layout failed validation"
        }
    }
    finally {
        try { $probe.Disconnect($false, $true) } catch { }
        $probe = $null
        $probeKey = $null
    }

    $reader = [HotdealFocus.NativeMemory]::new([int] $Process.Id)
    try {
        $identityStrings = @($reader.FindManagedStrings(
                $Identity.ClientId,
                $stringDataOffset,
                16
            ))
        if ($identityStrings.Count -eq 0) {
            throw "Current AdGuard IPC identity was not found in managed memory"
        }
        $remoteValues = New-Object 'System.UInt64[]' $identityStrings.Count
        for ($index = 0; $index -lt $identityStrings.Count; $index++) {
            $remoteValues[$index] = [uint64] $identityStrings[$index]
        }
        $references = @($reader.FindAnyPointerReferences($remoteValues, 256))
        $candidates = New-Object 'System.Collections.Generic.List[object]'
        foreach ($reference in $references) {
            if ($reference.Address -lt [uint64] $clientIdOffset) { continue }
            $objectAddress = $reference.Address - [uint64] $clientIdOffset
            try {
                $clientIdReference = $reader.ReadPointer(
                    $objectAddress + [uint64] $clientIdOffset)
                $endpointReference = $reader.ReadPointer(
                    $objectAddress + [uint64] $endpointOffset)
                $keyReference = $reader.ReadPointer($objectAddress + [uint64] $keyOffset)
                if ($clientIdReference -ne $reference.Value) { continue }
                $remoteEndpoint = $reader.ReadManagedString(
                    $endpointReference,
                    $stringDataOffset,
                    1024
                )
                if ($remoteEndpoint -cne $Identity.Endpoint) { continue }
                $remoteKey = $reader.ReadManagedString($keyReference, $stringDataOffset, 1024)
                if ([string]::IsNullOrWhiteSpace($remoteKey) -or
                    $remoteKey.Length -lt 16 -or $remoteKey.Length -gt 512 -or
                    $remoteKey -match '[\x00-\x1f\x7f]') {
                    continue
                }
                $candidates.Add([pscustomobject]@{
                        Address = $objectAddress
                        Key = $remoteKey
                    })
            }
            catch {
                continue
            }
        }

        $unique = @($candidates | Group-Object Address | ForEach-Object { $_.Group[0] })
        if ($unique.Count -ne 1) {
            throw "Active UiApplicationApiClient credential object was not unique"
        }
        return [pscustomobject]@{
            Endpoint = $Identity.Endpoint
            Key = $unique[0].Key
            IdentityLog = $Identity.LogName
        }
    }
    finally {
        $reader.Dispose()
    }
}

function Connect-AdGuardSession {
    $process = Get-AdGuardUiProcess
    Initialize-AdGuardAssemblies
    $identity = Get-IpcIdentityFromCurrentLog -Process $process
    $credential = Get-IpcCredentialInMemory -Process $process -Identity $identity
    $hub = [Activator]::CreateInstance($script:HubType)
    $client = $null
    try {
        $client = [Activator]::CreateInstance(
            $script:ApiClientType,
            @($credential.Endpoint, $hub, $credential.Key)
        )
        $client.Connect()
        if (-not $client.IsConnected) { throw "AdGuard IPC client did not connect" }
        return [pscustomobject]@{
            Client = $client
            IdentityLog = $credential.IdentityLog
        }
    }
    catch {
        if ($client) {
            try { $client.Disconnect($false, $true) } catch { }
        }
        throw
    }
    finally {
        $credential.Key = $null
        $credential = $null
    }
}

function Close-AdGuardSession {
    param([AllowNull()] $Session)
    if (-not $Session -or -not $Session.Client) { return }
    try {
        $Session.Client.Disconnect($false, $true)
    }
    catch {
        # A cleanup-only disconnect failure must not rewrite an already emitted
        # successful transactional result into an ambiguous process failure.
    }
    finally {
        $Session.Client = $null
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function New-StandardFilterTypeArray {
    $types = [Array]::CreateInstance($script:FilterSubscriptionType, 1)
    $types.SetValue($script:StandardFilterType, 0)
    return $types
}

function Get-InstalledStandardFilters {
    param([Parameter(Mandatory = $true)] $Client)
    return @($Client.GetInstalledFilterSubscriptions(
            $null,
            (New-StandardFilterTypeArray)
        ))
}

function Get-UserFilter {
    param([Parameter(Mandatory = $true)] $Client)
    # AdGuard does not include the editable User filter in every overload of
    # GetInstalledFilterSubscriptions, but it is present in the complete catalog.
    $filters = @($Client.GetAllFilterSubscriptions() | Where-Object {
            $_.FilterId -in @([int]::MinValue, 0) -and
            [string] $_.FilterType -ceq 'Standard' -and $_.IsEditable -and $_.IsCustom
        })
    if ($filters.Count -ne 1) {
        throw "The editable standard AdGuard User filter was not unique"
    }
    return $filters[0]
}

function Get-TargetUserscripts {
    param([Parameter(Mandatory = $true)] $Client)
    return @($Client.GetUserscripts() | Where-Object { $_.Name -ceq $UserscriptName })
}

function Get-TargetFilters {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()][string] $ExactUrl
    )
    $filters = @(Get-InstalledStandardFilters -Client $Client | Where-Object {
            $_.IsCustom -and ($_.Name -ceq $FilterName -or
                ($ExactUrl -and $_.SubscriptionUrl -ceq $ExactUrl))
        })
    return @($filters | Sort-Object FilterId -Unique)
}

function Get-UserscriptSnapshot {
    param([Parameter(Mandatory = $true)] $Client)
    $targets = @(Get-TargetUserscripts -Client $Client)
    if ($targets.Count -gt 1) { throw "Target userscript name is not unique" }
    if ($targets.Count -eq 0) {
        return [pscustomobject]@{
            Exists = $false; Info = $null; Code = $null; GmProperties = $null
        }
    }
    return [pscustomobject]@{
        Exists = $true
        Info = $targets[0]
        Code = $Client.GetUserscriptCode($UserscriptName, $true)
        GmProperties = $Client.GetUserscriptGmProperties($UserscriptName)
    }
}

function Get-FilterSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()][string] $ExactUrl
    )
    $states = @(Get-TargetFilters -Client $Client -ExactUrl $ExactUrl | ForEach-Object {
            $filter = $_
            $rules = $Client.GetFilterSubscriptionRules(
                $filter.FilterId,
                $script:StandardFilterType
            )
            [pscustomobject]@{
                FilterId = [int] $filter.FilterId
                IsEnabled = [bool] $filter.IsEnabled
                IsTrusted = [bool] $filter.IsTrusted
                IsCustom = [bool] $filter.IsCustom
                IsEditable = [bool] $filter.IsEditable
                Name = [string] $filter.Name
                Version = [string] $filter.Version
                SubscriptionUrl = [string] $filter.SubscriptionUrl
                RulesSha256 = Get-RuleListSha256 -Rules $rules.Rules
                DisabledRulesSha256 = Get-RuleMultisetSha256 -Rules $rules.DisabledRules
            }
        })
    return [pscustomobject]@{ States = $states }
}

function Get-CompleteTargetStateSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()][string] $ExactFilterUrl
    )
    $userFilter = Get-UserFilter -Client $Client
    $userRules = $Client.GetFilterSubscriptionRules(
        $userFilter.FilterId,
        $script:StandardFilterType
    )
    $userscript = Get-UserscriptSnapshot -Client $Client
    if ($userscript.Exists) {
        $userscript = [pscustomobject]@{
            Exists = $true
            Info = [pscustomobject]@{
                Name = [string] $userscript.Info.Name
                Version = [string] $userscript.Info.Version
                IsCustom = [bool] $userscript.Info.IsCustom
                IsEnabled = [bool] $userscript.Info.IsEnabled
                IsStyle = [bool] $userscript.Info.IsStyle
                LastUpdateTime = $null
            }
            Code = [string] $userscript.Code
            GmProperties = [string] $userscript.GmProperties
        }
    }
    $filterEntries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($filter in @(Get-TargetFilters -Client $Client -ExactUrl $ExactFilterUrl)) {
        $rules = $Client.GetFilterSubscriptionRules(
            $filter.FilterId,
            $script:StandardFilterType
        )
        $filterEntries.Add([pscustomobject]@{
                Info = [pscustomobject]@{
                    FilterId = [int] $filter.FilterId
                    IsEnabled = [bool] $filter.IsEnabled
                    IsTrusted = [bool] $filter.IsTrusted
                    IsCustom = [bool] $filter.IsCustom
                    IsEditable = [bool] $filter.IsEditable
                    Name = [string] $filter.Name
                    Version = [string] $filter.Version
                    SubscriptionUrl = [string] $filter.SubscriptionUrl
                    LastUpdateTime = $null
                }
                Rules = @($rules.Rules | ForEach-Object { [string] $_ })
                DisabledRules = @($rules.DisabledRules | ForEach-Object { [string] $_ })
            })
    }
    return [pscustomobject]@{
        UserFilter = [pscustomobject]@{
            FilterId = [int] $userFilter.FilterId
            Name = [string] $userFilter.Name
            FilterType = [string] $userFilter.FilterType
            IsEditable = [bool] $userFilter.IsEditable
            IsCustom = [bool] $userFilter.IsCustom
        }
        UserRules = [pscustomobject]@{
            Rules = @($userRules.Rules | ForEach-Object { [string] $_ })
            DisabledRules = @($userRules.DisabledRules | ForEach-Object { [string] $_ })
        }
        UserscriptSnapshot = $userscript
        FilterEntries = @($filterEntries | ForEach-Object { $_ })
    }
}

function Get-CompleteTargetStateSha256 {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $userscript = if ($Snapshot.UserscriptSnapshot.Exists) {
        [ordered]@{
            name = [string] $Snapshot.UserscriptSnapshot.Info.Name
            version = [string] $Snapshot.UserscriptSnapshot.Info.Version
            is_custom = [bool] $Snapshot.UserscriptSnapshot.Info.IsCustom
            is_enabled = [bool] $Snapshot.UserscriptSnapshot.Info.IsEnabled
            is_style = [bool] $Snapshot.UserscriptSnapshot.Info.IsStyle
            code_sha256 = Get-CanonicalTextSha256 -Text $Snapshot.UserscriptSnapshot.Code
            gm_properties_sha256 = Get-CanonicalTextSha256 `
                -Text $Snapshot.UserscriptSnapshot.GmProperties
        }
    } else { $null }
    $filters = @($Snapshot.FilterEntries | Sort-Object { $_.Info.FilterId } | ForEach-Object {
            [ordered]@{
                filter_id = [int] $_.Info.FilterId
                name = [string] $_.Info.Name
                version = [string] $_.Info.Version
                subscription_url = [string] $_.Info.SubscriptionUrl
                is_custom = [bool] $_.Info.IsCustom
                is_editable = [bool] $_.Info.IsEditable
                is_enabled = [bool] $_.Info.IsEnabled
                is_trusted = [bool] $_.Info.IsTrusted
                rule_count = @($_.Rules).Count
                rules_sha256 = Get-RuleListSha256 -Rules $_.Rules
                disabled_rule_count = @($_.DisabledRules).Count
                disabled_rules_sha256 = Get-RuleMultisetSha256 -Rules $_.DisabledRules
            }
        })
    $record = [ordered]@{
        user_filter = [ordered]@{
            filter_id = [int] $Snapshot.UserFilter.FilterId
            name = [string] $Snapshot.UserFilter.Name
            filter_type = [string] $Snapshot.UserFilter.FilterType
            is_editable = [bool] $Snapshot.UserFilter.IsEditable
            is_custom = [bool] $Snapshot.UserFilter.IsCustom
            rule_count = @($Snapshot.UserRules.Rules).Count
            rules_sha256 = Get-RuleListSha256 -Rules $Snapshot.UserRules.Rules
            disabled_rule_count = @($Snapshot.UserRules.DisabledRules).Count
            disabled_rules_sha256 = Get-RuleMultisetSha256 `
                -Rules $Snapshot.UserRules.DisabledRules
        }
        userscript = $userscript
        filters = $filters
    }
    return Get-CanonicalTextSha256 -Text ($record | ConvertTo-Json -Depth 10 -Compress)
}

function Get-StableCompleteTargetStateSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()][string] $ExactFilterUrl,
        [ValidateRange(2, 100)]
        [int] $MaximumObservations = $script:AdGuardStateVisibilityMaxObservations,
        [ValidateRange(0, 5000)]
        [int] $RetryDelayMilliseconds = $script:AdGuardStateVisibilityDelayMilliseconds,
        [ValidateRange(2, 10)]
        [int] $RequiredConsecutiveReads = `
            $script:AdGuardStateVisibilityRequiredConsecutiveReads
    )
    if ($RequiredConsecutiveReads -gt $MaximumObservations) {
        throw "Required consecutive reads exceed the bounded observation count"
    }

    $previousSha = $null
    $consecutiveReads = 0
    for ($observation = 1; $observation -le $MaximumObservations; $observation++) {
        $snapshot = Get-CompleteTargetStateSnapshot -Client $Client `
            -ExactFilterUrl $ExactFilterUrl
        $snapshotSha = Get-CompleteTargetStateSha256 -Snapshot $snapshot
        if ($null -ne $previousSha -and $snapshotSha -ceq $previousSha) {
            $consecutiveReads++
        } else {
            $consecutiveReads = 1
        }
        if ($consecutiveReads -ge $RequiredConsecutiveReads) {
            return [pscustomobject]@{
                Snapshot = $snapshot
                Read1Sha256 = $previousSha
                Read2Sha256 = $snapshotSha
                ObservationCount = $observation
                ConsecutiveReadCount = $consecutiveReads
            }
        }
        $previousSha = $snapshotSha
        if ($observation -lt $MaximumObservations -and $RetryDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RetryDelayMilliseconds
        }
    }
    throw ("Two consecutive complete target-state snapshots were not identical " +
        "within $MaximumObservations bounded observations")
}

function Get-CspProbeInspectionReport {
    param([Parameter(Mandatory = $true)] $Client)
    $stable = Get-StableCompleteTargetStateSnapshot -Client $Client -ExactFilterUrl $null
    $probePresent = [bool] $stable.Snapshot.UserscriptSnapshot.Exists
    return [ordered]@{
        command = 'csp-probe-inspect'
        ok = $true
        state_sha256 = [string] $stable.Read2Sha256
        read_1_sha256 = [string] $stable.Read1Sha256
        read_2_sha256 = [string] $stable.Read2Sha256
        two_read_stable = $true
        stability_observation_count = [int] $stable.ObservationCount
        probe_present = $probePresent
        probe_count = if ($probePresent) { 1 } else { 0 }
        probe_name = $script:CspProbeUserscriptName
        probe_version = $script:CspProbeUserscriptVersion
        probe_source_sha256 = $script:CspProbeSourceSha256
        endpoint = $script:CspProbeEndpoint
        adguard_configuration_changed = $false
    }
}

function Assert-CurrentStateEqualsBackup {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Backup,
        [AllowNull()][string] $ExactFilterUrl
    )
    $current = Get-StableCompleteTargetStateSnapshot -Client $Client `
        -ExactFilterUrl $ExactFilterUrl
    $currentSha = [string] $current.Read2Sha256
    $backupSha = [string] $Backup.Manifest.complete_target_state.read_2_sha256
    if ($currentSha -cne $backupSha) {
        throw "Complete target state changed after backup and before the first write"
    }
    return $currentSha
}

function ConvertTo-FilterMetadataRecord {
    param([Parameter(Mandatory = $true)] $Filter)
    return [ordered]@{
        filter_id = [int] $Filter.FilterId
        name = [string] $Filter.Name
        version = [string] $Filter.Version
        subscription_url = [string] $Filter.SubscriptionUrl
        is_custom = [bool] $Filter.IsCustom
        is_editable = [bool] $Filter.IsEditable
        is_enabled = [bool] $Filter.IsEnabled
        is_trusted = [bool] $Filter.IsTrusted
        last_update_utc = if ($Filter.LastUpdateTime) {
            $Filter.LastUpdateTime.ToUniversalTime().ToString('o')
        } else { $null }
    }
}

function ConvertTo-UserscriptMetadataRecord {
    param([Parameter(Mandatory = $true)] $Info)
    return [ordered]@{
        name = [string] $Info.Name
        version = [string] $Info.Version
        is_custom = [bool] $Info.IsCustom
        is_enabled = [bool] $Info.IsEnabled
        is_style = [bool] $Info.IsStyle
        last_update_utc = if ($Info.LastUpdateTime) {
            $Info.LastUpdateTime.ToUniversalTime().ToString('o')
        } else { $null }
    }
}

function Write-BackupPayload {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Content,
        [Parameter(Mandatory = $true)][string] $Role
    )
    if ([System.IO.Path]::GetFileName($RelativePath) -cne $RelativePath) {
        throw "Backup payload paths must be plain file names"
    }
    $path = Join-Path $Directory $RelativePath
    Write-Utf8FileNew -Path $path -Content $Content
    $bytes = [System.IO.File]::ReadAllBytes($path)
    return [ordered]@{
        path = $RelativePath
        role = $Role
        bytes = $bytes.Length
        raw_sha256 = Get-Sha256Hex -Bytes $bytes
    }
}

function Assert-BackupRuleListCanonical {
    param([AllowNull()] $Rules)
    foreach ($rule in @($Rules | ForEach-Object { [string] $_ })) {
        if (-not $rule -or $rule.Contains("`r") -or $rule.Contains("`n")) {
            throw "AdGuard returned a rule that cannot be represented by the backup schema"
        }
    }
}

function New-StateBackup {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()][string] $ExactFilterUrl
    )

    $root = if ($BackupRoot) {
        [System.IO.Path]::GetFullPath($BackupRoot)
    } else {
        Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) `
            'AdguardHotdealFocus\backups'
    }
    [void] [System.IO.Directory]::CreateDirectory($root)
    $rootItem = Get-Item -LiteralPath $root -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "BackupRoot must be a non-reparse directory"
    }
    $leaf = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss.fffZ') + '-' +
        [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $directory = Join-Path $root ('.pending-' + $leaf)
    [void] [System.IO.Directory]::CreateDirectory($directory)

    try {
        $payloads = New-Object 'System.Collections.Generic.List[object]'
        $stableState = Get-StableCompleteTargetStateSnapshot -Client $Client `
            -ExactFilterUrl $ExactFilterUrl
        $targetState = $stableState.Snapshot
        $userFilter = $targetState.UserFilter
        $userRules = $targetState.UserRules
        $reference = Get-ReferenceUserFilterEvidence
        $conflictReport = Get-LegacyHotdealConflictReport -FilterRules $userRules `
            -HistoricalRules $script:HistoricalSnapshotRules
        $userEvidenceReport = [ordered]@{
            authority = 'complete-target-state-two-read-snapshot'
            authoritative = $true
            filter_id = [int] $userFilter.FilterId
            name = [string] $userFilter.Name
            filter_type = [string] $userFilter.FilterType
            complete_target_read_1_sha256 = $stableState.Read1Sha256
            complete_target_read_2_sha256 = $stableState.Read2Sha256
            two_read_stable = $true
            api_read_1 = [ordered]@{
                rule_count = @($userRules.Rules).Count
                disabled_rule_count = @($userRules.DisabledRules).Count
                canonical_rules_sha256 = Get-RuleListSha256 -Rules $userRules.Rules
                canonical_disabled_rules_sha256 = Get-RuleListSha256 `
                    -Rules $userRules.DisabledRules
            }
            api_read_2 = [ordered]@{
                rule_count = @($userRules.Rules).Count
                disabled_rule_count = @($userRules.DisabledRules).Count
                canonical_rules_sha256 = Get-RuleListSha256 -Rules $userRules.Rules
                canonical_disabled_rules_sha256 = Get-RuleListSha256 `
                    -Rules $userRules.DisabledRules
            }
            legacy_hotdeal_conflicts = $conflictReport
            reference_snapshot = $reference
            historical_snapshot_mismatch_is_blocking = $false
        }
        $script:LastUserFilterEvidence = $userEvidenceReport
        $script:LastConflictReport = $conflictReport
        Assert-BackupRuleListCanonical -Rules $userRules.Rules
        Assert-BackupRuleListCanonical -Rules $userRules.DisabledRules
        $userRuleText = @($userRules.Rules | ForEach-Object { [string] $_ }) -join "`n"
        $userDisabledText = @($userRules.DisabledRules | ForEach-Object { [string] $_ }) -join "`n"
        $userRulesPayload = Write-BackupPayload -Directory $directory `
            -RelativePath 'user-filter.rules.txt' -Content $userRuleText `
            -Role 'user-filter-rules'
        $payloads.Add($userRulesPayload)
        $userDisabledPayload = Write-BackupPayload -Directory $directory `
            -RelativePath 'user-filter.disabled-rules.txt' -Content $userDisabledText `
            -Role 'user-filter-disabled-rules'
        $payloads.Add($userDisabledPayload)

        $userscriptSnapshot = $targetState.UserscriptSnapshot
        $userscriptRecord = $null
        if ($userscriptSnapshot.Exists) {
            $codePayload = Write-BackupPayload -Directory $directory `
                -RelativePath 'target-userscript.code.js' -Content $userscriptSnapshot.Code `
                -Role 'target-userscript-code'
            $payloads.Add($codePayload)
            $gmPropertiesPayload = Write-BackupPayload -Directory $directory `
                -RelativePath 'target-userscript.gm-properties.json' `
                -Content $userscriptSnapshot.GmProperties `
                -Role 'target-userscript-gm-properties'
            $payloads.Add($gmPropertiesPayload)
            $userscriptRecord = ConvertTo-UserscriptMetadataRecord -Info $userscriptSnapshot.Info
            $userscriptRecord.code_sha256 = Get-CanonicalTextSha256 -Text $userscriptSnapshot.Code
            $userscriptRecord.gm_properties_sha256 = Get-CanonicalTextSha256 `
                -Text $userscriptSnapshot.GmProperties
            $userscriptRecord.code_payload = $codePayload.path
            $userscriptRecord.gm_properties_payload = $gmPropertiesPayload.path
        }

        $filterRecords = New-Object 'System.Collections.Generic.List[object]'
        foreach ($entry in @($targetState.FilterEntries)) {
            $filter = $entry.Info
            Assert-BackupRuleListCanonical -Rules $entry.Rules
            Assert-BackupRuleListCanonical -Rules $entry.DisabledRules
            $ruleText = @($entry.Rules | ForEach-Object { [string] $_ }) -join "`n"
            $disabledText = @($entry.DisabledRules | ForEach-Object { [string] $_ }) -join "`n"
            $stem = 'target-filter-' + [int] $filter.FilterId
            $rulesPayload = Write-BackupPayload -Directory $directory `
                -RelativePath "$stem.rules.txt" -Content $ruleText -Role 'target-filter-rules'
            $payloads.Add($rulesPayload)
            $disabledPayload = Write-BackupPayload -Directory $directory `
                -RelativePath "$stem.disabled-rules.txt" -Content $disabledText `
                -Role 'target-filter-disabled-rules'
            $payloads.Add($disabledPayload)
            $record = ConvertTo-FilterMetadataRecord -Filter $filter
            $record.rule_count = @($entry.Rules).Count
            $record.disabled_rule_count = @($entry.DisabledRules).Count
            $record.rules_sha256 = Get-RuleListSha256 -Rules $entry.Rules
            $record.disabled_rules_sha256 = Get-RuleMultisetSha256 -Rules $entry.DisabledRules
            $record.rules_payload = $rulesPayload.path
            $record.disabled_rules_payload = $disabledPayload.path
            $filterRecords.Add($record)
        }

        $service = Get-AdGuardService
        $manifest = [ordered]@{
            schema_version = 2
            backup_id = $leaf
            tool_version = $script:ToolVersion
            created_utc = [DateTime]::UtcNow.ToString('o')
            adguard_version = $script:AdGuardProcess.MainModule.FileVersionInfo.FileVersion
            service_status = [string] $service.Status
            application_state = [string] $Client.GetApplicationState()
            complete_marker = 'backup-complete.json'
            payloads = @($payloads | ForEach-Object { $_ })
            user_filter = [ordered]@{
                filter_id = [int] $userFilter.FilterId
                name = [string] $userFilter.Name
                filter_type = [string] $userFilter.FilterType
                is_editable = [bool] $userFilter.IsEditable
                is_custom = [bool] $userFilter.IsCustom
                rule_count = @($userRules.Rules).Count
                disabled_rule_count = @($userRules.DisabledRules).Count
                rules_sha256 = Get-RuleListSha256 -Rules $userRules.Rules
                disabled_rules_sha256 = Get-RuleMultisetSha256 -Rules $userRules.DisabledRules
                rules_payload = $userRulesPayload.path
                disabled_rules_payload = $userDisabledPayload.path
                evidence = $userEvidenceReport
            }
            target_userscript = $userscriptRecord
            target_filters = @($filterRecords | ForEach-Object { $_ })
            complete_target_state = [ordered]@{
                read_1_sha256 = $stableState.Read1Sha256
                read_2_sha256 = $stableState.Read2Sha256
                identical = $true
            }
        }
        $manifestText = $manifest | ConvertTo-Json -Depth 12
        Write-Utf8FileNew -Path (Join-Path $directory 'backup-manifest.json') `
            -Content $manifestText
        $manifestBytes = [System.IO.File]::ReadAllBytes(
            (Join-Path $directory 'backup-manifest.json'))
        $complete = [ordered]@{
            schema_version = 1
            backup_schema_version = 2
            backup_id = $leaf
            complete = $true
            manifest_path = 'backup-manifest.json'
            manifest_bytes = $manifestBytes.Length
            manifest_raw_sha256 = Get-Sha256Hex -Bytes $manifestBytes
        }
        Write-Utf8FileNew -Path (Join-Path $directory 'backup-complete.json') `
            -Content ($complete | ConvertTo-Json -Depth 4)
        $completedDirectory = Join-Path $root $leaf
        [System.IO.Directory]::Move($directory, $completedDirectory)
        return $completedDirectory
    }
    catch {
        $fullDirectory = [System.IO.Path]::GetFullPath($directory)
        $fullRoot = [System.IO.Path]::GetFullPath($root).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar)
        if ([System.IO.Path]::GetDirectoryName($fullDirectory) -ceq $fullRoot -and
            (Test-Path -LiteralPath $fullDirectory -PathType Container)) {
            [System.IO.Directory]::Delete($fullDirectory, $true)
        }
        throw
    }
}

function Set-RecoveryContext {
    param([Parameter(Mandatory = $true)][string] $Directory)
    $resolved = [System.IO.Path]::GetFullPath($Directory)
    $script:RecoveryBackupPath = $resolved
    $scriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
    $quotedScriptPath = "'" + $scriptPath.Replace("'", "''") + "'"
    $quotedBackupPath = "'" + $resolved.Replace("'", "''") + "'"
    $script:RecoveryCommand = ('powershell.exe -NoProfile -ExecutionPolicy Bypass ' +
        '-File ' + $quotedScriptPath + ' restore-backup -BackupPath ' +
        $quotedBackupPath + ' -Apply')
}

function Set-CspProbeRecoveryContext {
    param([Parameter(Mandatory = $true)][string] $Directory)
    $resolved = [System.IO.Path]::GetFullPath($Directory)
    $script:RecoveryBackupPath = $resolved
    $scriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
    $quotedScriptPath = "'" + $scriptPath.Replace("'", "''") + "'"
    $quotedBackupPath = "'" + $resolved.Replace("'", "''") + "'"
    $script:RecoveryCommand = ('powershell.exe -NoProfile -ExecutionPolicy Bypass ' +
        '-File ' + $quotedScriptPath + ' csp-probe-restore -BackupPath ' +
        $quotedBackupPath + ' -Apply')
}

function Write-TransactionJournalEvent {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][ValidatePattern('\A[a-z0-9-]+\z')]
        [string] $Event,
        [AllowNull()] $Details
    )
    $record = [ordered]@{
        schema_version = 1
        event = $Event
        created_utc = [DateTime]::UtcNow.ToString('o')
        details = $Details
    }
    $name = 'journal-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss.fffffffZ') +
        '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '-' + $Event + '.json'
    Write-Utf8FileNew -Path (Join-Path $Directory $name) `
        -Content ($record | ConvertTo-Json -Depth 10)
}

function Get-ExpectedUserscriptPostState {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired
    )
    $gmProperties = if ($Snapshot.Exists) {
        [string] $Snapshot.GmProperties
    } else {
        [string] $Desired.FreshInstallGmProperties
    }
    return [pscustomobject]@{
        CodeSha256 = Get-CanonicalTextSha256 -Text $Desired.Meta.Content
        GmPropertiesSha256 = Get-CanonicalTextSha256 -Text $gmProperties
        IsCustom = [bool] $Desired.Meta.IsCustom
        IsStyle = [bool] $Desired.Meta.IsStyle
    }
}

function Initialize-TransactionJournal {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $CommandName,
        [AllowNull()] $DesiredUserscript,
        [AllowNull()] $BeforeUserscriptSnapshot,
        [AllowNull()] $DesiredFilter,
        [AllowNull()] $MigrationPlan
    )
    $manifestPath = Join-Path $Directory 'backup-manifest.json'
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $userscriptAfter = $null
    if ($DesiredUserscript) {
        if ($null -eq $BeforeUserscriptSnapshot) {
            throw "Userscript transaction planning requires the validated pre-mutation snapshot"
        }
        $expectedPostState = Get-ExpectedUserscriptPostState `
            -Snapshot $BeforeUserscriptSnapshot -Desired $DesiredUserscript
        $userscriptAfter = [ordered]@{
            exists = $true
            name = $DesiredUserscript.Name
            version = $DesiredUserscript.Version
            code_sha256 = [string] $expectedPostState.CodeSha256
            gm_properties_sha256 = [string] $expectedPostState.GmPropertiesSha256
            fresh_install_gm_properties_sha256 = [string] (
                $DesiredUserscript.FreshInstallGmPropertiesSha256)
            enabled = $true
            is_custom = [bool] $expectedPostState.IsCustom
            is_style = [bool] $expectedPostState.IsStyle
            replacement_required = [bool] (
                $BeforeUserscriptSnapshot.Exists -and
                ([bool] $BeforeUserscriptSnapshot.Info.IsCustom -ne
                    [bool] $expectedPostState.IsCustom -or
                    [bool] $BeforeUserscriptSnapshot.Info.IsStyle -ne
                    [bool] $expectedPostState.IsStyle))
        }
    }
    $filterAfter = $null
    if ($DesiredFilter) {
        $filterAfter = [ordered]@{
            exists = $true
            name = $DesiredFilter.Name
            version = $DesiredFilter.Version
            subscription_url = $DesiredFilter.Url
            raw_sha256 = $DesiredFilter.RawSha256
            installed_rules_sha256 = $ExpectedInstalledFilterRulesSha256.ToLowerInvariant()
            disabled_rules_sha256 = Get-RuleMultisetSha256 -Rules @()
            enabled = $true
            trusted = $true
            is_custom = $true
            is_editable = $false
        }
    }
    $migrationAfter = $null
    if ($MigrationPlan) {
        $migrationAfter = [ordered]@{
            user_filter_id = [int] $MigrationPlan.Filter.FilterId
            changed_rules = @($MigrationPlan.CandidateRecords | Where-Object {
                    -not $_.IsDisabled
                } | ForEach-Object {
                    [ordered]@{
                        zero_based_index = [int] $_.ZeroBasedIndex
                        rule_sha256 = [string] $_.Public.rule_sha256
                    }
                })
        }
    }
    $plan = [ordered]@{
        schema_version = 1
        command = $CommandName
        created_utc = [DateTime]::UtcNow.ToString('o')
        backup_manifest_raw_sha256 = Get-Sha256Hex -Bytes $manifestBytes
        userscript_after = $userscriptAfter
        migration_after = $migrationAfter
        filter_after = $filterAfter
    }
    $planPath = Join-Path $Directory 'transaction-plan.json'
    Write-Utf8FileNew -Path $planPath -Content ($plan | ConvertTo-Json -Depth 12)
    $planBytes = [System.IO.File]::ReadAllBytes($planPath)
    $marker = [ordered]@{
        schema_version = 1
        complete = $true
        plan_path = 'transaction-plan.json'
        plan_bytes = $planBytes.Length
        plan_raw_sha256 = Get-Sha256Hex -Bytes $planBytes
        backup_manifest_raw_sha256 = Get-Sha256Hex -Bytes $manifestBytes
    }
    Write-Utf8FileNew -Path (Join-Path $Directory 'transaction-plan.complete.json') `
        -Content ($marker | ConvertTo-Json -Depth 4)
    Write-TransactionJournalEvent -Directory $Directory -Event 'transaction-started' `
        -Details ([ordered]@{ command = $CommandName })
}

function Read-StrictJsonFile {
    param([Parameter(Mandatory = $true)][string] $Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $script:MaximumSourceBytes -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Backup JSON must be a small regular file"
    }
    $text = ConvertFrom-StrictUtf8 -Bytes ([System.IO.File]::ReadAllBytes($item.FullName))
    try { return $text | ConvertFrom-Json }
    catch { throw "Backup JSON is malformed: $($item.Name)" }
}

function Assert-JsonProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $Names,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $available = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($name in $Names) {
        if ($available -notcontains $name) { throw "$Label is missing property: $name" }
    }
}

function Read-BackupRuleList {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][int] $ExpectedCount
    )
    $text = ConvertFrom-StrictUtf8 -Bytes ([System.IO.File]::ReadAllBytes($Path))
    if ($ExpectedCount -eq 0) {
        if ($text.Length -ne 0) { throw "Zero-count backup rule payload is not empty" }
        return @()
    }
    if ($text.EndsWith("`n") -or $text.Contains("`r")) {
        throw "Backup rule payload is not in canonical LF form"
    }
    $items = @($text.Split([string[]] @("`n"), [StringSplitOptions]::None))
    if ($items.Count -ne $ExpectedCount -or @($items | Where-Object { $_ -eq '' }).Count -gt 0) {
        throw "Backup rule payload count or structure differs from its manifest"
    }
    return $items
}

function Get-ValidatedTransactionPlan {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $ManifestSha256
    )
    $planPath = Join-Path $Directory 'transaction-plan.json'
    $markerPath = Join-Path $Directory 'transaction-plan.complete.json'
    $hasPlan = Test-Path -LiteralPath $planPath -PathType Leaf
    $hasMarker = Test-Path -LiteralPath $markerPath -PathType Leaf
    if (-not $hasPlan -and -not $hasMarker) { return $null }
    if ($hasPlan -and -not $hasMarker) {
        # The plan is written before its complete marker and before every intent.
        # A crash in that narrow setup window cannot have mutated AdGuard. Treat
        # it as no transaction; restore will then require the exact backup state.
        $laterJournal = @(Get-ChildItem -LiteralPath $Directory -File `
                -Filter 'journal-*.json' -ErrorAction Stop)
        if ($laterJournal.Count -eq 0) { return $null }
        throw "Transaction journal is incomplete after journal activity"
    }
    if (-not $hasPlan -or -not $hasMarker) {
        throw "Transaction journal is incomplete"
    }
    $marker = Read-StrictJsonFile -Path $markerPath
    Assert-JsonProperties -Value $marker -Names @('schema_version', 'complete', 'plan_path',
        'plan_bytes', 'plan_raw_sha256', 'backup_manifest_raw_sha256') `
        -Label 'transaction plan complete marker'
    if ([int] $marker.schema_version -ne 1 -or -not [bool] $marker.complete -or
        [string] $marker.plan_path -cne 'transaction-plan.json' -or
        [string] $marker.backup_manifest_raw_sha256 -cne $ManifestSha256) {
        throw "Transaction plan complete marker failed validation"
    }
    $bytes = [System.IO.File]::ReadAllBytes($planPath)
    if ($bytes.Length -ne [int64] $marker.plan_bytes -or
        (Get-Sha256Hex -Bytes $bytes) -cne [string] $marker.plan_raw_sha256) {
        throw "Transaction plan bytes do not match the complete marker"
    }
    $plan = Read-StrictJsonFile -Path $planPath
    Assert-JsonProperties -Value $plan -Names @('schema_version', 'command', 'created_utc',
        'backup_manifest_raw_sha256', 'userscript_after', 'migration_after', 'filter_after') `
        -Label 'transaction plan'
    if ([int] $plan.schema_version -ne 1 -or
        [string] $plan.backup_manifest_raw_sha256 -cne $ManifestSha256) {
        throw "Transaction plan does not belong to this backup"
    }
    return $plan
}

function Get-ValidatedBackup {
    param([Parameter(Mandatory = $true)][string] $Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $directoryItem = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (-not $directoryItem.PSIsContainer -or
        ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        $directoryItem.Name.StartsWith('.pending-', [StringComparison]::Ordinal)) {
        throw "BackupPath must be a completed, non-reparse backup directory"
    }
    $manifestPath = Join-Path $resolved 'backup-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Backup manifest is missing"
    }
    $manifest = Read-StrictJsonFile -Path $manifestPath
    Assert-JsonProperties -Value $manifest -Names @('schema_version') -Label 'backup manifest'
    if ([int] $manifest.schema_version -eq 1) {
        throw ("Legacy schema-v1 backup is preserved but cannot be restored automatically: " +
            "it has no complete marker or per-payload raw hashes. Create a schema-v2 backup")
    }
    if ([int] $manifest.schema_version -ne 2) { throw "Unsupported backup schema version" }
    Assert-JsonProperties -Value $manifest -Names @('backup_id', 'tool_version', 'created_utc',
        'complete_marker', 'payloads', 'user_filter', 'target_userscript', 'target_filters',
        'complete_target_state') `
        -Label 'backup manifest'
    Assert-JsonProperties -Value $manifest.complete_target_state `
        -Names @('read_1_sha256', 'read_2_sha256', 'identical') `
        -Label 'backup complete target state'
    if (-not [bool] $manifest.complete_target_state.identical -or
        [string] $manifest.complete_target_state.read_1_sha256 -cne
            [string] $manifest.complete_target_state.read_2_sha256) {
        throw "Backup was not captured from two identical complete target-state reads"
    }
    if ([string] $manifest.backup_id -cne $directoryItem.Name -or
        [string] $manifest.complete_marker -cne 'backup-complete.json') {
        throw "Backup identity does not match its directory"
    }
    $completePath = Join-Path $resolved 'backup-complete.json'
    $complete = Read-StrictJsonFile -Path $completePath
    Assert-JsonProperties -Value $complete -Names @('schema_version', 'backup_schema_version',
        'backup_id', 'complete', 'manifest_path', 'manifest_bytes', 'manifest_raw_sha256') `
        -Label 'backup complete marker'
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $manifestSha = Get-Sha256Hex -Bytes $manifestBytes
    if ([int] $complete.schema_version -ne 1 -or
        [int] $complete.backup_schema_version -ne 2 -or -not [bool] $complete.complete -or
        [string] $complete.backup_id -cne $directoryItem.Name -or
        [string] $complete.manifest_path -cne 'backup-manifest.json' -or
        [int64] $complete.manifest_bytes -ne $manifestBytes.Length -or
        [string] $complete.manifest_raw_sha256 -cne $manifestSha) {
        throw "Backup complete marker failed validation"
    }

    $payloadByName = @{}
    foreach ($payload in @($manifest.payloads)) {
        Assert-JsonProperties -Value $payload -Names @('path', 'role', 'bytes', 'raw_sha256') `
            -Label 'backup payload record'
        $relative = [string] $payload.path
        if (-not $relative -or [System.IO.Path]::GetFileName($relative) -cne $relative -or
            $payloadByName.ContainsKey($relative)) {
            throw "Backup payload path is unsafe or duplicated"
        }
        $payloadPath = Join-Path $resolved $relative
        $item = Get-Item -LiteralPath $payloadPath -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Backup payload is not a regular file"
        }
        $bytes = [System.IO.File]::ReadAllBytes($item.FullName)
        if ($bytes.Length -ne [int64] $payload.bytes -or
            (Get-Sha256Hex -Bytes $bytes) -cne [string] $payload.raw_sha256) {
            throw "Backup payload failed raw byte validation: $relative"
        }
        $payloadByName[$relative] = $item.FullName
    }

    $user = $manifest.user_filter
    Assert-JsonProperties -Value $user -Names @('filter_id', 'name', 'filter_type',
        'is_editable', 'is_custom', 'rule_count',
        'disabled_rule_count', 'rules_sha256', 'disabled_rules_sha256', 'rules_payload',
        'disabled_rules_payload') -Label 'backup User filter'
    if (-not $payloadByName.ContainsKey([string] $user.rules_payload) -or
        -not $payloadByName.ContainsKey([string] $user.disabled_rules_payload)) {
        throw "Backup User filter payload reference is missing"
    }
    $userRules = @(Read-BackupRuleList -Path $payloadByName[[string] $user.rules_payload] `
        -ExpectedCount ([int] $user.rule_count))
    $userDisabled = @(Read-BackupRuleList `
        -Path $payloadByName[[string] $user.disabled_rules_payload] `
        -ExpectedCount ([int] $user.disabled_rule_count))
    if ((Get-RuleListSha256 -Rules $userRules) -cne [string] $user.rules_sha256 -or
        (Get-RuleMultisetSha256 -Rules $userDisabled) -cne
            [string] $user.disabled_rules_sha256) {
        throw "Backup User filter semantic hashes failed validation"
    }

    $userscriptSnapshot = [pscustomobject]@{
        Exists = $false; Info = $null; Code = $null; GmProperties = $null
    }
    if ($null -ne $manifest.target_userscript) {
        $record = $manifest.target_userscript
        Assert-JsonProperties -Value $record -Names @('name', 'version', 'is_custom',
            'is_enabled', 'is_style', 'code_sha256', 'gm_properties_sha256', 'code_payload',
            'gm_properties_payload') `
            -Label 'backup target userscript'
        if (-not $payloadByName.ContainsKey([string] $record.code_payload) -or
            -not $payloadByName.ContainsKey([string] $record.gm_properties_payload)) {
            throw "Backup userscript payload reference is missing"
        }
        $code = ConvertFrom-StrictUtf8 -Bytes ([System.IO.File]::ReadAllBytes(
                $payloadByName[[string] $record.code_payload]))
        $gmProperties = ConvertFrom-StrictUtf8 -Bytes ([System.IO.File]::ReadAllBytes(
                $payloadByName[[string] $record.gm_properties_payload]))
        if ((Get-CanonicalTextSha256 -Text $code) -cne [string] $record.code_sha256 -or
            (Get-CanonicalTextSha256 -Text $gmProperties) -cne
                [string] $record.gm_properties_sha256) {
            throw "Backup userscript semantic hashes failed validation"
        }
        $userscriptSnapshot = [pscustomobject]@{
            Exists = $true
            Info = [pscustomobject]@{
                Name = [string] $record.name
                Version = [string] $record.version
                IsCustom = [bool] $record.is_custom
                IsEnabled = [bool] $record.is_enabled
                IsStyle = [bool] $record.is_style
            }
            Code = $code
            GmProperties = $gmProperties
        }
    }

    $filterStates = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in @($manifest.target_filters)) {
        Assert-JsonProperties -Value $record -Names @('filter_id', 'name', 'version',
            'subscription_url', 'is_custom', 'is_editable', 'is_enabled', 'is_trusted', 'rule_count',
            'disabled_rule_count', 'rules_sha256', 'disabled_rules_sha256',
            'rules_payload', 'disabled_rules_payload') -Label 'backup target filter'
        if (-not $payloadByName.ContainsKey([string] $record.rules_payload) -or
            -not $payloadByName.ContainsKey([string] $record.disabled_rules_payload)) {
            throw "Backup target filter payload reference is missing"
        }
        $rules = @(Read-BackupRuleList -Path $payloadByName[[string] $record.rules_payload] `
            -ExpectedCount ([int] $record.rule_count))
        $disabled = @(Read-BackupRuleList `
            -Path $payloadByName[[string] $record.disabled_rules_payload] `
            -ExpectedCount ([int] $record.disabled_rule_count))
        if ((Get-RuleListSha256 -Rules $rules) -cne [string] $record.rules_sha256 -or
            (Get-RuleMultisetSha256 -Rules $disabled) -cne
                [string] $record.disabled_rules_sha256) {
            throw "Backup target filter semantic hashes failed validation"
        }
        $filterStates.Add([pscustomobject]@{
                FilterId = [int] $record.filter_id
                IsEnabled = [bool] $record.is_enabled
                IsTrusted = [bool] $record.is_trusted
                Name = [string] $record.name
                Version = [string] $record.version
                SubscriptionUrl = [string] $record.subscription_url
                IsCustom = [bool] $record.is_custom
                IsEditable = [bool] $record.is_editable
                RulesSha256 = [string] $record.rules_sha256
                DisabledRulesSha256 = [string] $record.disabled_rules_sha256
                Rules = $rules
                DisabledRules = $disabled
            })
    }
    $reconstructedState = [pscustomobject]@{
        UserFilter = [pscustomobject]@{
            FilterId = [int] $user.filter_id
            Name = [string] $user.name
            FilterType = [string] $user.filter_type
            IsEditable = [bool] $user.is_editable
            IsCustom = [bool] $user.is_custom
        }
        UserRules = [pscustomobject]@{
            Rules = $userRules
            DisabledRules = $userDisabled
        }
        UserscriptSnapshot = $userscriptSnapshot
        FilterEntries = @($filterStates | ForEach-Object {
                [pscustomobject]@{
                    Info = $_
                    Rules = @($_.Rules)
                    DisabledRules = @($_.DisabledRules)
                }
            })
    }
    $reconstructedSha = Get-CompleteTargetStateSha256 -Snapshot $reconstructedState
    if ($reconstructedSha -cne [string] $manifest.complete_target_state.read_2_sha256) {
        throw "Backup complete target-state SHA-256 does not match its validated payloads"
    }
    $transaction = Get-ValidatedTransactionPlan -Directory $resolved `
        -ManifestSha256 $manifestSha
    return [pscustomobject]@{
        Directory = $resolved
        Manifest = $manifest
        ManifestSha256 = $manifestSha
        UserRules = $userRules
        UserDisabledRules = $userDisabled
        UserscriptSnapshot = $userscriptSnapshot
        FilterSnapshot = [pscustomobject]@{ States = @(
                $filterStates | ForEach-Object { $_ }) }
        TransactionPlan = $transaction
    }
}

function Assert-CspProbeBackupContract {
    param(
        [Parameter(Mandatory = $true)] $Backup,
        [Parameter(Mandatory = $true)] $Desired
    )
    if ($null -ne $Backup.Manifest.target_userscript -or
        $Backup.UserscriptSnapshot.Exists) {
        throw "CSP probe backup must prove that the fixed probe was absent before install"
    }
    if (@($Backup.Manifest.target_filters).Count -ne 0 -or
        @($Backup.FilterSnapshot.States).Count -ne 0) {
        throw "CSP probe backup unexpectedly contains a target filter"
    }
    $plan = $Backup.TransactionPlan
    if (-not $plan -or [string] $plan.command -cne 'csp-probe-install' -or
        $null -ne $plan.migration_after -or $null -ne $plan.filter_after) {
        throw "Backup is not an exact CSP probe installation transaction"
    }
    $after = $plan.userscript_after
    if (-not $after) {
        throw "CSP probe transaction is missing its fixed userscript state"
    }
    Assert-JsonProperties -Value $after -Names @('exists', 'name', 'version',
        'code_sha256', 'gm_properties_sha256', 'fresh_install_gm_properties_sha256',
        'enabled', 'is_custom', 'is_style', 'replacement_required') `
        -Label 'CSP probe transaction userscript plan'
    $expectedPostState = Get-ExpectedUserscriptPostState `
        -Snapshot $Backup.UserscriptSnapshot -Desired $Desired
    if (-not [bool] $after.exists -or
        [string] $after.name -cne $script:CspProbeUserscriptName -or
        [string] $after.version -cne $script:CspProbeUserscriptVersion -or
        [string] $after.code_sha256 -cne [string] $expectedPostState.CodeSha256 -or
        [string] $after.gm_properties_sha256 -cne
            [string] $expectedPostState.GmPropertiesSha256 -or
        [string] $after.fresh_install_gm_properties_sha256 -cne
            [string] $Desired.FreshInstallGmPropertiesSha256 -or
        -not [bool] $after.enabled -or
        [bool] $after.is_custom -ne [bool] $expectedPostState.IsCustom -or
        [bool] $after.is_style -ne [bool] $expectedPostState.IsStyle -or
        [bool] $after.replacement_required) {
        throw "CSP probe transaction userscript state differs from the pinned source"
    }
}

function Test-UserscriptSnapshotExact {
    param(
        [Parameter(Mandatory = $true)] $Left,
        [Parameter(Mandatory = $true)] $Right
    )
    if ([bool] $Left.Exists -ne [bool] $Right.Exists) { return $false }
    if (-not $Left.Exists) { return $true }
    return [string] $Left.Info.Name -ceq [string] $Right.Info.Name -and
        [string] $Left.Info.Version -ceq [string] $Right.Info.Version -and
        [bool] $Left.Info.IsCustom -eq [bool] $Right.Info.IsCustom -and
        [bool] $Left.Info.IsEnabled -eq [bool] $Right.Info.IsEnabled -and
        [bool] $Left.Info.IsStyle -eq [bool] $Right.Info.IsStyle -and
        [string] $Left.Code -ceq [string] $Right.Code -and
        [string] $Left.GmProperties -ceq [string] $Right.GmProperties
}

function Get-AllowedLegacyRestoreDelta {
    param([Parameter(Mandatory = $true)] $Backup)
    if (-not $Backup.TransactionPlan -or
        $null -eq $Backup.TransactionPlan.migration_after) { return @() }
    $migration = $Backup.TransactionPlan.migration_after
    Assert-JsonProperties -Value $migration -Names @('user_filter_id', 'changed_rules') `
        -Label 'transaction migration plan'
    if ([int] $migration.user_filter_id -ne [int] $Backup.Manifest.user_filter.filter_id) {
        throw "Transaction migration plan targets another User filter"
    }
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $rules = New-Object 'System.Collections.Generic.List[string]'
    $lastIndex = -1
    $backupDisabled = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($disabledRule in @($Backup.UserDisabledRules)) {
        [void] $backupDisabled.Add([string] $disabledRule)
    }
    foreach ($record in @($migration.changed_rules)) {
        Assert-JsonProperties -Value $record -Names @('zero_based_index', 'rule_sha256') `
            -Label 'transaction migration rule'
        $index = [int] $record.zero_based_index
        if ($index -lt 0 -or $index -ge @($Backup.UserRules).Count -or
            $index -le $lastIndex -or
            -not $seen.Add($index)) {
            throw "Transaction migration rule indexes are invalid, duplicated, or out of order"
        }
        $rule = [string] $Backup.UserRules[$index]
        if ((Get-CanonicalTextSha256 -Text $rule) -cne [string] $record.rule_sha256) {
            throw "Transaction migration rule SHA-256 differs from the backup"
        }
        $scope = Get-CosmeticRuleScopeAnalysis -Rule $rule
        if (-not $scope.IsCosmetic -or $scope.ScopeKind -cne 'exclusive-target' -or
            $backupDisabled.Contains($rule)) {
            throw "Transaction migration rule is not an enabled exclusive-target backup rule"
        }
        $rules.Add($rule)
        $lastIndex = $index
    }
    return @($rules | ForEach-Object { $_ })
}

function Get-CurrentOnlyRules {
    param(
        [AllowNull()] $Baseline,
        [AllowNull()] $Current
    )
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new(
        [StringComparer]::Ordinal)
    foreach ($rule in @($Baseline | ForEach-Object { [string] $_ })) {
        if ($counts.ContainsKey($rule)) { $counts[$rule]++ } else { $counts[$rule] = 1 }
    }
    $extras = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rule in @($Current | ForEach-Object { [string] $_ })) {
        if ($counts.ContainsKey($rule) -and $counts[$rule] -gt 0) {
            $counts[$rule]--
        } else {
            $extras.Add($rule)
        }
    }
    if (@($counts.Values | Where-Object { $_ -ne 0 }).Count -gt 0) {
        throw "A rule disabled in the backup is currently enabled; refusing ambiguous restore"
    }
    return @($extras | ForEach-Object { [string] $_ })
}

function Assert-UserscriptRestorePreconditions {
    param(
        [Parameter(Mandatory = $true)] $Current,
        [Parameter(Mandatory = $true)] $BackupSnapshot,
        [AllowNull()] $TransactionPlan
    )
    if (Test-UserscriptSnapshotExact -Left $Current -Right $BackupSnapshot) { return $false }
    if (-not $TransactionPlan -or $null -eq $TransactionPlan.userscript_after) {
        throw "Current target userscript differs from backup without an authorized transaction"
    }
    $after = $TransactionPlan.userscript_after
    Assert-JsonProperties -Value $after -Names @('exists', 'name', 'version', 'code_sha256',
        'gm_properties_sha256', 'fresh_install_gm_properties_sha256', 'enabled',
        'is_custom', 'is_style', 'replacement_required') `
        -Label 'transaction userscript plan'
    if (-not [bool] $after.exists) {
        throw "Current userscript existence is not an authorized transaction prefix"
    }

    $replacementRequired = $BackupSnapshot.Exists -and
        ([bool] $BackupSnapshot.Info.IsCustom -ne [bool] $after.is_custom -or
            [bool] $BackupSnapshot.Info.IsStyle -ne [bool] $after.is_style)
    if ([bool] $after.replacement_required -ne [bool] $replacementRequired) {
        throw "Transaction userscript replacement classification is inconsistent"
    }

    # A classification replacement starts with RemoveUserscript. Absence is an
    # authorized durable-intent prefix only when the bound before/after classes
    # prove that the transaction had to replace the existing entry.
    if (-not $Current.Exists) {
        if ($replacementRequired) { return $true }
        throw "Current userscript existence is not an authorized transaction prefix"
    }

    $currentCodeSha = Get-CanonicalTextSha256 -Text ([string] $Current.Code)
    $currentGmSha = Get-CanonicalTextSha256 -Text ([string] $Current.GmProperties)
    $afterCodeSha = [string] $after.code_sha256
    $afterGmSha = [string] $after.gm_properties_sha256
    $afterVersion = [string] $after.version
    $afterEnabled = [bool] $after.enabled
    $freshGmSha = [string] $after.fresh_install_gm_properties_sha256
    $identityMatchesAfter = [string] $Current.Info.Name -ceq [string] $after.name -and
        [bool] $Current.Info.IsCustom -eq [bool] $after.is_custom -and
        [bool] $Current.Info.IsStyle -eq [bool] $after.is_style
    $identityMatchesBefore = $BackupSnapshot.Exists -and
        [string] $Current.Info.Name -ceq [string] $BackupSnapshot.Info.Name -and
        [bool] $Current.Info.IsCustom -eq [bool] $BackupSnapshot.Info.IsCustom -and
        [bool] $Current.Info.IsStyle -eq [bool] $BackupSnapshot.Info.IsStyle
    if ($replacementRequired -and $identityMatchesBefore) {
        # A restore of a classification replacement is itself resumable. After
        # reinstalling the original class, GM values and enabled status may
        # still be at their fresh-install values; the atomic install may expose
        # either enabled value before the explicit snapshot-status write.
        $beforeCodeSha = Get-CanonicalTextSha256 -Text ([string] $BackupSnapshot.Code)
        $beforeGmSha = Get-CanonicalTextSha256 `
            -Text ([string] $BackupSnapshot.GmProperties)
        $isRollbackInstallPrefix = $currentCodeSha -ceq $beforeCodeSha -and
            [string] $Current.Info.Version -ceq [string] $BackupSnapshot.Info.Version -and
            ($currentGmSha -ceq $freshGmSha -or $currentGmSha -ceq $beforeGmSha)
        if ($isRollbackInstallPrefix) { return $true }
        throw "Current userscript is not an enumerated rollback-prefix state"
    }
    if (-not $identityMatchesAfter) {
        throw "Current userscript identity is not an authorized transaction prefix"
    }

    $isAllowedPrefix = $false
    if ($replacementRequired) {
        # InstallUserscriptFromMeta may expose the replacement either disabled
        # or enabled. The next write restores the independent GM value-store,
        # followed by the explicit enabled=true write.
        $isAllowedPrefix = $currentCodeSha -ceq $afterCodeSha -and
            [string] $Current.Info.Version -ceq $afterVersion -and
            ($currentGmSha -ceq $freshGmSha -or $currentGmSha -ceq $afterGmSha) -and
            ([bool] $Current.Info.IsEnabled -eq $false -or
                [bool] $Current.Info.IsEnabled -eq $afterEnabled)
    } elseif ($BackupSnapshot.Exists) {
        $beforeCodeSha = Get-CanonicalTextSha256 -Text ([string] $BackupSnapshot.Code)
        $beforeGmSha = Get-CanonicalTextSha256 `
            -Text ([string] $BackupSnapshot.GmProperties)
        $beforeEnabled = [bool] $BackupSnapshot.Info.IsEnabled
        # Forward API order is UpdateCode -> SetStatus. GM_* persistent values are
        # independent user data and remain byte-exact throughout a normal update.
        $isAfterCodePrefix = $currentCodeSha -ceq $afterCodeSha -and
            $currentGmSha -ceq $beforeGmSha -and
            [string] $Current.Info.Version -ceq $afterVersion -and
            [bool] $Current.Info.IsEnabled -eq $beforeEnabled
        $isAfterEnablePrefix = $currentCodeSha -ceq $afterCodeSha -and
            $currentGmSha -ceq $afterGmSha -and
            [string] $Current.Info.Version -ceq $afterVersion -and
            [bool] $Current.Info.IsEnabled -eq $afterEnabled
        $isAllowedPrefix = $isAfterCodePrefix -or $isAfterEnablePrefix
    } else {
        # InstallUserscriptFromMeta is one atomic IPC substep. AdGuard versions may
        # expose it disabled or already enabled before the explicit SetStatus call.
        $isAllowedPrefix = $currentCodeSha -ceq $afterCodeSha -and
            $currentGmSha -ceq $freshGmSha -and
            [string] $Current.Info.Version -ceq $afterVersion -and
            ([bool] $Current.Info.IsEnabled -eq $false -or
                [bool] $Current.Info.IsEnabled -eq $afterEnabled)
    }
    if (-not $isAllowedPrefix) {
        throw "Current userscript is not an enumerated mutation-prefix state"
    }
    return $true
}

function Test-FilterStateExact {
    param(
        [Parameter(Mandatory = $true)] $Left,
        [Parameter(Mandatory = $true)] $Right
    )
    return [int] $Left.FilterId -eq [int] $Right.FilterId -and
        [string] $Left.Name -ceq [string] $Right.Name -and
        [string] $Left.Version -ceq [string] $Right.Version -and
        [string] $Left.SubscriptionUrl -ceq [string] $Right.SubscriptionUrl -and
        [bool] $Left.IsEnabled -eq [bool] $Right.IsEnabled -and
        [bool] $Left.IsTrusted -eq [bool] $Right.IsTrusted -and
        [bool] $Left.IsCustom -eq [bool] $Right.IsCustom -and
        [bool] $Left.IsEditable -eq [bool] $Right.IsEditable -and
        [string] $Left.RulesSha256 -ceq [string] $Right.RulesSha256 -and
        [string] $Left.DisabledRulesSha256 -ceq [string] $Right.DisabledRulesSha256
}

function Assert-FilterRestorePreconditions {
    param(
        [Parameter(Mandatory = $true)] $CurrentSnapshot,
        [Parameter(Mandatory = $true)] $BackupSnapshot,
        [AllowNull()] $TransactionPlan
    )
    $desired = if ($TransactionPlan) { $TransactionPlan.filter_after } else { $null }
    if ($desired) {
        Assert-JsonProperties -Value $desired -Names @('exists', 'name', 'version',
            'subscription_url', 'raw_sha256', 'installed_rules_sha256',
            'disabled_rules_sha256', 'enabled', 'trusted', 'is_custom', 'is_editable') `
            -Label 'transaction filter plan'
    }
    $current = @($CurrentSnapshot.States)
    $before = @($BackupSnapshot.States)
    $beforeIds = @($before | ForEach-Object { [int] $_.FilterId })
    foreach ($state in $before) {
        $matches = @($current | Where-Object { [int] $_.FilterId -eq [int] $state.FilterId })
        if ($matches.Count -ne 1) { throw "A backed target filter is missing or duplicated" }
        $now = $matches[0]
        if ($now.Name -cne $state.Name -or $now.Version -cne $state.Version -or
            $now.SubscriptionUrl -cne $state.SubscriptionUrl -or
            [bool] $now.IsCustom -ne [bool] $state.IsCustom -or
            [bool] $now.IsEditable -ne [bool] $state.IsEditable -or
            $now.RulesSha256 -cne $state.RulesSha256 -or
            $now.DisabledRulesSha256 -cne $state.DisabledRulesSha256) {
            throw "A backed target filter changed outside the authorized state transition"
        }
    }
    $extras = @($current | Where-Object { $beforeIds -notcontains [int] $_.FilterId })
    if (-not $desired) {
        if ($extras.Count -ne 0) { throw "Unexpected target filter appeared after the backup" }
        foreach ($state in $before) {
            $now = @($current | Where-Object { [int] $_.FilterId -eq [int] $state.FilterId })[0]
            if (-not (Test-FilterStateExact -Left $now -Right $state)) {
                throw "Target filter differs from a backup with no authorized transaction"
            }
        }
        return [pscustomobject]@{ NeedsRestore = $false; ExtraFilterIds = @() }
    }

    $desiredBefore = @($before | Where-Object {
            $_.SubscriptionUrl -ceq [string] $desired.subscription_url
        })
    if ($desiredBefore.Count -gt 1) {
        throw "Backup contains a duplicate desired filter URL"
    }
    if ($desiredBefore.Count -eq 1 -and $extras.Count -ne 0) {
        throw "Unexpected target filter appeared while the desired filter already existed"
    }
    if ($desiredBefore.Count -eq 0 -and $extras.Count -gt 1) {
        throw "More than one target filter appeared after the backup"
    }
    if ($extras.Count -eq 1) {
        $extra = $extras[0]
        if ($extra.Name -cne [string] $desired.name -or
            $extra.Version -cne [string] $desired.version -or
            $extra.SubscriptionUrl -cne [string] $desired.subscription_url -or
            $extra.RulesSha256 -cne [string] $desired.installed_rules_sha256 -or
            $extra.DisabledRulesSha256 -cne [string] $desired.disabled_rules_sha256 -or
            [bool] $extra.IsCustom -ne [bool] $desired.is_custom -or
            [bool] $extra.IsEditable -ne [bool] $desired.is_editable) {
            throw "New target filter is not the exact transaction-created subscription"
        }
    }

    $getSignature = {
        param($States)
        return (@($States | Sort-Object FilterId | ForEach-Object {
                    '{0}:{1}:{2}' -f [int] $_.FilterId,
                    ([int] [bool] $_.IsEnabled), ([int] [bool] $_.IsTrusted)
                }) -join '|')
    }
    $newFlagState = {
        param($Source)
        return @($Source | ForEach-Object {
                [pscustomobject]@{
                    FilterId = [int] $_.FilterId
                    IsEnabled = [bool] $_.IsEnabled
                    IsTrusted = [bool] $_.IsTrusted
                }
            })
    }
    $allowed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $beforeFlags = & $newFlagState $before
    [void] $allowed.Add((& $getSignature $beforeFlags))
    $activeFlags = & $newFlagState $before
    if ($desiredBefore.Count -eq 1) {
        $desiredFlag = @($activeFlags | Where-Object {
                [int] $_.FilterId -eq [int] $desiredBefore[0].FilterId
            })[0]
        $desiredFlag.IsEnabled = [bool] $desired.enabled
        $desiredFlag.IsTrusted = [bool] $desired.trusted
        [void] $allowed.Add((& $getSignature $activeFlags))
    } elseif ($extras.Count -eq 1) {
        # InstallCustomFilter is one IPC substep. Before explicit activation only
        # the two observed untrusted install defaults are accepted.
        foreach ($installEnabled in @($false, $true)) {
            $installedFlags = @(& $newFlagState $before)
            $installedFlags += [pscustomobject]@{
                FilterId = [int] $extras[0].FilterId
                IsEnabled = $installEnabled
                IsTrusted = $false
            }
            [void] $allowed.Add((& $getSignature $installedFlags))
        }
        $activeFlags += [pscustomobject]@{
            FilterId = [int] $extras[0].FilterId
            IsEnabled = [bool] $desired.enabled
            IsTrusted = [bool] $desired.trusted
        }
        [void] $allowed.Add((& $getSignature $activeFlags))
    }
    $priorIds = @($before | Where-Object {
            $_.SubscriptionUrl -cne [string] $desired.subscription_url
        } | Sort-Object FilterId | ForEach-Object { [int] $_.FilterId })
    if ($desiredBefore.Count -eq 1 -or $extras.Count -eq 1) {
        foreach ($priorId in $priorIds) {
            $priorFlag = @($activeFlags | Where-Object { [int] $_.FilterId -eq $priorId })[0]
            $priorFlag.IsEnabled = $false
            [void] $allowed.Add((& $getSignature $activeFlags))
        }
    }
    $currentSignature = & $getSignature $current
    if (-not $allowed.Contains($currentSignature)) {
        throw "Current filter flags are not an enumerated mutation-prefix state"
    }
    $beforeSignature = & $getSignature $before
    return [pscustomobject]@{
        NeedsRestore = $currentSignature -cne $beforeSignature
        ExtraFilterIds = @($extras | ForEach-Object { [int] $_.FilterId })
    }
}

function Get-BackupRestorePlan {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Backup
    )
    $userFilter = Get-UserFilter -Client $Client
    if ([int] $userFilter.FilterId -ne [int] $Backup.Manifest.user_filter.filter_id) {
        throw "Backup belongs to another AdGuard User filter"
    }
    $currentRules = $Client.GetFilterSubscriptionRules(
        $userFilter.FilterId,
        $script:StandardFilterType
    )
    if (-not (Test-ExactStringSequence -Left $Backup.UserRules -Right $currentRules.Rules)) {
        throw "Current User filter Rules digest differs from the backup; unrelated changes are protected"
    }
    $disabledExtras = @(Get-CurrentOnlyRules -Baseline $Backup.UserDisabledRules `
        -Current $currentRules.DisabledRules)
    $allowedDelta = @(Get-AllowedLegacyRestoreDelta -Backup $Backup)
    $isExactPrefix = $false
    $matchedPrefix = [string[]]::new(0)
    for ($prefixLength = 0; $prefixLength -le $allowedDelta.Count; $prefixLength++) {
        $prefix = if ($prefixLength -eq 0) { @() } else {
            @($allowedDelta[0..($prefixLength - 1)])
        }
        if (Test-ExactStringMultiset -Left $prefix -Right $disabledExtras) {
            $isExactPrefix = $true
            $matchedPrefix = [string[]] @($prefix)
            break
        }
    }
    if (-not $isExactPrefix) {
        throw "Current DisabledRules is not an exact ordered migration-prefix delta"
    }

    $currentUserscript = Get-UserscriptSnapshot -Client $Client
    $userscriptNeedsRestore = Assert-UserscriptRestorePreconditions -Current $currentUserscript `
        -BackupSnapshot $Backup.UserscriptSnapshot -TransactionPlan $Backup.TransactionPlan
    $exactUrl = if ($Backup.TransactionPlan -and $Backup.TransactionPlan.filter_after) {
        [string] $Backup.TransactionPlan.filter_after.subscription_url
    } else { $null }
    $currentFilters = Get-FilterSnapshot -Client $Client -ExactUrl $exactUrl
    $filterPlan = Assert-FilterRestorePreconditions -CurrentSnapshot $currentFilters `
        -BackupSnapshot $Backup.FilterSnapshot -TransactionPlan $Backup.TransactionPlan
    return [pscustomobject]@{
        UserFilter = $userFilter
        DisabledRulesToEnable = $matchedPrefix
        UserscriptNeedsRestore = [bool] $userscriptNeedsRestore
        FilterNeedsRestore = [bool] $filterPlan.NeedsRestore
        ExactFilterUrl = $exactUrl
        IsAlreadyRestored = $disabledExtras.Count -eq 0 -and
            -not $userscriptNeedsRestore -and -not $filterPlan.NeedsRestore
    }
}

function Assert-BackupStateRestored {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Backup,
        [AllowNull()][string] $ExactFilterUrl
    )
    $user = Get-UserFilter -Client $Client
    $rules = $Client.GetFilterSubscriptionRules($user.FilterId, $script:StandardFilterType)
    if (-not (Test-ExactStringSequence -Left $Backup.UserRules -Right $rules.Rules) -or
        -not (Test-ExactStringMultiset -Left $Backup.UserDisabledRules `
            -Right $rules.DisabledRules)) {
        throw "Restore postcondition failed for User filter"
    }
    $userscript = Get-UserscriptSnapshot -Client $Client
    if (-not (Test-UserscriptSnapshotExact -Left $userscript `
            -Right $Backup.UserscriptSnapshot)) {
        throw "Restore postcondition failed for target userscript"
    }
    $filters = Get-FilterSnapshot -Client $Client -ExactUrl $ExactFilterUrl
    $filterCheck = Assert-FilterRestorePreconditions -CurrentSnapshot $filters `
        -BackupSnapshot $Backup.FilterSnapshot -TransactionPlan $null
    if ($filterCheck.NeedsRestore) { throw "Restore postcondition failed for target filters" }
}

function Invoke-BackupRestore {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Backup,
        [Parameter(Mandatory = $true)] $Plan
    )
    if ($Plan.FilterNeedsRestore) {
        Restore-FilterSnapshot -Client $Client -Snapshot $Backup.FilterSnapshot `
            -ExactUrl $Plan.ExactFilterUrl -JournalDirectory $Backup.Directory
        Write-TransactionJournalEvent -Directory $Backup.Directory `
            -Event 'restore-filter-verified' -Details $null
    }
    $restoreLegacyRules = @($Plan.DisabledRulesToEnable)
    [array]::Reverse($restoreLegacyRules)
    foreach ($rule in $restoreLegacyRules) {
        Write-TransactionJournalEvent -Directory $Backup.Directory `
            -Event 'intent-restore-legacy-enable' `
            -Details ([ordered]@{
                    rule_sha256 = Get-CanonicalTextSha256 -Text ([string] $rule)
                })
        $Client.EnableFilterRules(
            $Plan.UserFilter.FilterId,
            (New-StringList -Values @([string] $rule)),
            $script:StandardFilterType
        )
    }
    if (@($Plan.DisabledRulesToEnable).Count -gt 0) {
        Write-TransactionJournalEvent -Directory $Backup.Directory `
            -Event 'restore-legacy-rules-applied' `
            -Details ([ordered]@{ count = @($Plan.DisabledRulesToEnable).Count })
    }
    if ($Plan.UserscriptNeedsRestore) {
        Restore-UserscriptSnapshot -Client $Client -Snapshot $Backup.UserscriptSnapshot `
            -JournalDirectory $Backup.Directory
        Write-TransactionJournalEvent -Directory $Backup.Directory `
            -Event 'restore-userscript-verified' -Details $null
    }
    Assert-BackupStateRestored -Client $Client -Backup $Backup `
        -ExactFilterUrl $Plan.ExactFilterUrl
    Write-TransactionJournalEvent -Directory $Backup.Directory `
        -Event 'restore-complete' -Details $null
}

function Prepare-UserscriptMeta {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Source
    )
    $temporary = Join-Path ([System.IO.Path]::GetTempPath()) (
        'hotdeal-focus-' + [Guid]::NewGuid().ToString('N') + '.user.js')
    [System.IO.File]::WriteAllBytes($temporary, $Source.Bytes)
    $script:TemporaryPaths.Add($temporary)
    $Source.TempPath = $temporary
    $Source.Meta = $Client.GetUserscriptMeta($temporary)
    if (-not $Source.Meta -or $Source.Meta.Name -cne $UserscriptName -or
        [string]::IsNullOrWhiteSpace($Source.Meta.Content)) {
        throw "AdGuard did not parse the expected userscript metadata and content"
    }
    $metaProperties = @($Source.Meta.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($requiredProperty in @('IsCustom', 'IsStyle')) {
        if ($metaProperties -notcontains $requiredProperty) {
            throw "AdGuard userscript metadata is missing classification: $requiredProperty"
        }
    }
    if ($Source.Meta.Version -cne $Source.Version) {
        throw "AdGuard parsed a different userscript version"
    }
    if ([bool] $Source.Meta.IsStyle) {
        throw "AdGuard parsed the authenticated userscript as a style extension"
    }
    if ((Get-CanonicalTextSha256 -Text ([string] $Source.Meta.Content)) -cne
            (Get-CanonicalTextSha256 -Text ([string] $Source.Text))) {
        throw "AdGuard parsed userscript content that differs from the authenticated source"
    }
    # GetUserscriptMeta parses a local/manual source with IsCustom=false in
    # AdGuard 7.22. That entry is stored but not selected for execution. Only
    # after the complete authenticated source contract above is proven may the
    # installation request be promoted to an executable manual userscript.
    $Source.Meta.IsCustom = $true
    if (-not [bool] $Source.Meta.IsCustom) {
        throw "AdGuard userscript metadata rejected executable custom classification"
    }
    return $Source
}

function Get-CspProbeParsedMetaEvidence {
    param([Parameter(Mandatory = $true)] $Meta)
    $matches = @($Meta.Match | ForEach-Object { [string] $_ })
    $includes = @($Meta.Include | ForEach-Object { [string] $_ })
    $excludes = @($Meta.Exclude | ForEach-Object { [string] $_ })
    $grants = @($Meta.Grant | ForEach-Object { [string] $_ })
    $connects = @($Meta.Connect | ForEach-Object { [string] $_ })
    $requires = @($Meta.Require)
    $resources = @($Meta.Resource)
    $downloadUri = $null
    $downloadUriValid = [Uri]::TryCreate(
        [string] $Meta.DownloadUrl,
        [UriKind]::Absolute,
        [ref] $downloadUri
    )
    return [ordered]@{
        match_count = $matches.Count
        match_exact = $matches.Count -eq 1 -and
            $matches[0] -ceq $script:CspProbeEndpoint
        include_count = $includes.Count
        exclude_count = $excludes.Count
        grant_count = $grants.Count
        grant_exact = $grants.Count -eq 1 -and $grants[0] -ceq 'GM_addElement'
        connect_count = $connects.Count
        require_count = $requires.Count
        resource_count = $resources.Count
        noframes = [bool] $Meta.IsNoFrames
        run_at_document_start = [string] $Meta.RunAt -ceq 'document-start'
        namespace_exact = [string] $Meta.Namespace -ceq
            'https://github.com/heelee912/adguard-hotdeal-focus/csp-probe'
        download_url_absent = [string]::IsNullOrWhiteSpace([string] $Meta.DownloadUrl)
        download_url_is_file = $downloadUriValid -and [bool] $downloadUri.IsFile
        download_url_is_https = $downloadUriValid -and
            [string] $downloadUri.Scheme -ceq 'https'
        update_url_absent = [string]::IsNullOrWhiteSpace([string] $Meta.UpdateUrl)
        unsafe_csp_required = [bool] $Meta.UnsafeCspRequired
    }
}

function Compare-Version {
    param(
        [AllowNull()][string] $Left,
        [AllowNull()][string] $Right
    )
    $leftVersion = $null
    $rightVersion = $null
    if ([Version]::TryParse($Left, [ref] $leftVersion) -and
        [Version]::TryParse($Right, [ref] $rightVersion)) {
        return $leftVersion.CompareTo($rightVersion)
    }
    return [string]::CompareOrdinal($Left, $Right)
}

function Assert-ReaderGateSnapshotOwnership {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $source = [string] $Snapshot.Code
    $expectedDirectives = [ordered]@{
        name = $UserscriptName
        namespace = 'https://github.com/heelee912/adguard-hotdeal-focus'
        downloadURL = 'https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js'
        updateURL = 'https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js'
    }
    foreach ($entry in $expectedDirectives.GetEnumerator()) {
        $matches = @([regex]::Matches(
                $source,
                ('(?m)^//\s+@' + [regex]::Escape([string] $entry.Key) +
                    '\s+(?<value>.+?)\s*$')
            ))
        if ($matches.Count -ne 1 -or
            $matches[0].Groups['value'].Value -cne [string] $entry.Value) {
            throw "Existing same-name userscript lacks exact Reader Gate ownership metadata"
        }
    }
}

function Assert-UserscriptMutationPreconditions {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired
    )
    if ($Snapshot.Exists -and -not [bool] $Snapshot.Info.IsCustom) {
        # AdGuard 7.22 may store a local/manual source as IsCustom=false, which
        # prevents execution. Exact source coordinates prove that this broken
        # same-name entry is ours and may be transactionally reclassified.
        Assert-ReaderGateSnapshotOwnership -Snapshot $Snapshot
    }
    if ($Snapshot.Exists) {
        $versionOrder = Compare-Version -Left $Desired.Version -Right $Snapshot.Info.Version
        $currentCodeSha = Get-CanonicalTextSha256 -Text $Snapshot.Code
        $desiredCodeSha = Get-CanonicalTextSha256 -Text $Desired.Meta.Content
        if ($versionOrder -lt 0) {
            throw "Userscript version downgrade is forbidden"
        }
        if ($versionOrder -eq 0 -and $currentCodeSha -cne $desiredCodeSha) {
            throw "Userscript bytes changed without a strictly newer version"
        }
    }
}

function Assert-BackupUserscriptMatchesDesired {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired
    )
    if (-not $Snapshot.Exists -or -not [bool] $Snapshot.Info.IsEnabled -or
        [bool] $Snapshot.Info.IsCustom -ne [bool] $Desired.Meta.IsCustom -or
        [bool] $Snapshot.Info.IsStyle -ne [bool] $Desired.Meta.IsStyle -or
        [string] $Snapshot.Info.Name -cne [string] $Desired.Name -or
        [string] $Snapshot.Info.Version -cne [string] $Desired.Version) {
        throw "Completed backup does not contain the exact enabled desired userscript"
    }
    if ((Get-CanonicalTextSha256 -Text ([string] $Snapshot.Code)) -cne
            (Get-CanonicalTextSha256 -Text ([string] $Desired.Meta.Content))) {
        throw "Completed backup userscript code differs from the release contract"
    }
}

function Get-UserscriptMetaForSnapshotRestore {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Snapshot
    )
    if (-not $Snapshot.Exists -or
        [string] $Snapshot.Info.Name -cne [string] $UserscriptName) {
        throw "Userscript snapshot restore metadata identity is invalid"
    }
    $temporary = Join-Path ([System.IO.Path]::GetTempPath()) (
        'hotdeal-focus-restore-' + [Guid]::NewGuid().ToString('N') + '.user.js')
    [System.IO.File]::WriteAllBytes(
        $temporary,
        $script:Utf8NoBom.GetBytes([string] $Snapshot.Code)
    )
    $script:TemporaryPaths.Add($temporary)
    $meta = $Client.GetUserscriptMeta($temporary)
    if (-not $meta -or [string] $meta.Name -cne [string] $Snapshot.Info.Name -or
        [string] $meta.Version -cne [string] $Snapshot.Info.Version -or
        [string]::IsNullOrWhiteSpace([string] $meta.Content)) {
        throw "AdGuard could not parse the exact backup userscript metadata"
    }
    $metaProperties = @($meta.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($requiredProperty in @('IsCustom', 'IsStyle')) {
        if ($metaProperties -notcontains $requiredProperty) {
            throw "Backup userscript metadata is missing classification: $requiredProperty"
        }
    }
    if ((Get-CanonicalTextSha256 -Text ([string] $meta.Content)) -cne
            (Get-CanonicalTextSha256 -Text ([string] $Snapshot.Code))) {
        throw "AdGuard parsed backup userscript content that differs from the snapshot"
    }
    # Classification is restored only after the complete backup identity and
    # content have been authenticated against the validated snapshot.
    $meta.IsCustom = [bool] $Snapshot.Info.IsCustom
    $meta.IsStyle = [bool] $Snapshot.Info.IsStyle
    if ([bool] $meta.IsCustom -ne [bool] $Snapshot.Info.IsCustom -or
        [bool] $meta.IsStyle -ne [bool] $Snapshot.Info.IsStyle) {
        throw "AdGuard rejected the exact backup userscript classification"
    }
    return $meta
}

function Assert-UserscriptInstallReceipt {
    param(
        [Parameter(Mandatory = $true)][AllowNull()] $Receipt,
        [Parameter(Mandatory = $true)] $ExpectedMeta,
        [Parameter(Mandatory = $true)][string] $ExpectedName,
        [Parameter(Mandatory = $true)][string] $ExpectedVersion
    )
    if (-not $Receipt -or -not $Receipt.Meta -or
        [string] $Receipt.Meta.Name -cne $ExpectedName -or
        [string] $Receipt.Meta.Version -cne $ExpectedVersion -or
        [bool] $Receipt.Meta.IsCustom -ne [bool] $ExpectedMeta.IsCustom -or
        [bool] $Receipt.Meta.IsStyle -ne [bool] $ExpectedMeta.IsStyle -or
        (Get-CanonicalTextSha256 -Text ([string] $Receipt.Meta.Content)) -cne
            (Get-CanonicalTextSha256 -Text ([string] $ExpectedMeta.Content))) {
        throw "AdGuard userscript installation receipt differs from the exact source"
    }
}

function Assert-UserscriptAbsent {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [ValidateRange(2, 100)]
        [int] $MaximumObservations = $script:AdGuardStateVisibilityMaxObservations,
        [ValidateRange(0, 5000)]
        [int] $RetryDelayMilliseconds = $script:AdGuardStateVisibilityDelayMilliseconds,
        [ValidateRange(2, 10)]
        [int] $RequiredConsecutiveReads = `
            $script:AdGuardStateVisibilityRequiredConsecutiveReads
    )
    if ($RequiredConsecutiveReads -gt $MaximumObservations) {
        throw "Required consecutive reads exceed the bounded observation count"
    }
    $consecutiveReads = 0
    for ($observation = 1; $observation -le $MaximumObservations; $observation++) {
        $targets = @(Get-TargetUserscripts -Client $Client)
        if ($targets.Count -eq 0) {
            $consecutiveReads++
            if ($consecutiveReads -ge $RequiredConsecutiveReads) { return $observation }
        } else {
            $consecutiveReads = 0
        }
        if ($observation -lt $MaximumObservations -and $RetryDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RetryDelayMilliseconds
        }
    }
    throw ("Target userscript absence did not remain exact for " +
        "$RequiredConsecutiveReads consecutive reads within $MaximumObservations observations")
}

function Assert-UserscriptSnapshotConverged {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $ExpectedSnapshot,
        [ValidateRange(2, 100)]
        [int] $MaximumObservations = $script:AdGuardStateVisibilityMaxObservations,
        [ValidateRange(0, 5000)]
        [int] $RetryDelayMilliseconds = $script:AdGuardStateVisibilityDelayMilliseconds,
        [ValidateRange(2, 10)]
        [int] $RequiredConsecutiveReads = `
            $script:AdGuardStateVisibilityRequiredConsecutiveReads
    )
    if ($RequiredConsecutiveReads -gt $MaximumObservations) {
        throw "Required consecutive reads exceed the bounded observation count"
    }
    $consecutiveReads = 0
    for ($observation = 1; $observation -le $MaximumObservations; $observation++) {
        $current = Get-UserscriptSnapshot -Client $Client
        if (Test-UserscriptSnapshotExact -Left $current -Right $ExpectedSnapshot) {
            $consecutiveReads++
            if ($consecutiveReads -ge $RequiredConsecutiveReads) { return $current }
        } else {
            $consecutiveReads = 0
        }
        if ($observation -lt $MaximumObservations -and $RetryDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RetryDelayMilliseconds
        }
    }
    throw ("Exact userscript snapshot did not converge for " +
        "$RequiredConsecutiveReads consecutive reads within $MaximumObservations observations")
}

function Invoke-UserscriptMutation {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired,
        [AllowNull()][string] $JournalDirectory
    )
    Assert-UserscriptMutationPreconditions -Snapshot $Snapshot -Desired $Desired
    $expectedPostState = Get-ExpectedUserscriptPostState -Snapshot $Snapshot -Desired $Desired
    $replacementRequired = $Snapshot.Exists -and
        ([bool] $Snapshot.Info.IsCustom -ne [bool] $Desired.Meta.IsCustom -or
            [bool] $Snapshot.Info.IsStyle -ne [bool] $Desired.Meta.IsStyle)

    if ($replacementRequired) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-userscript-reclassification-remove' `
                -Details ([ordered]@{
                        before_is_custom = [bool] $Snapshot.Info.IsCustom
                        before_is_style = [bool] $Snapshot.Info.IsStyle
                        after_is_custom = [bool] $Desired.Meta.IsCustom
                        after_is_style = [bool] $Desired.Meta.IsStyle
                        preserved_gm_properties_sha256 = `
                            [string] $expectedPostState.GmPropertiesSha256
                    })
        }
        $Client.RemoveUserscript($UserscriptName)
        $absenceObservationCount = Assert-UserscriptAbsent -Client $Client
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'userscript-reclassification-absence-verified' `
                -Details ([ordered]@{
                        observation_count = [int] $absenceObservationCount
                    })
        }
    }

    if ($Snapshot.Exists -and -not $replacementRequired) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-userscript-update-code' `
                -Details ([ordered]@{
                        code_sha256 = Get-CanonicalTextSha256 -Text $Desired.Meta.Content
                        preserved_gm_properties_sha256 = `
                            [string] $expectedPostState.GmPropertiesSha256
                    })
        }
        [void] $Client.UpdateUserscriptCode($UserscriptName, $Desired.Meta.Content)
    } else {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-userscript-install' `
                -Details ([ordered]@{
                        code_sha256 = Get-CanonicalTextSha256 -Text $Desired.Meta.Content
                        expected_fresh_gm_properties_sha256 = `
                            [string] $Desired.FreshInstallGmPropertiesSha256
                        replacement = [bool] $replacementRequired
                        is_custom = [bool] $Desired.Meta.IsCustom
                        is_style = [bool] $Desired.Meta.IsStyle
                    })
        }
        $installReceipt = $Client.InstallUserscriptFromMeta($Desired.Meta)
        Assert-UserscriptInstallReceipt -Receipt $installReceipt `
            -ExpectedMeta $Desired.Meta -ExpectedName $Desired.Name `
            -ExpectedVersion $Desired.Version
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'userscript-install-accepted' `
                -Details ([ordered]@{
                        version = [string] $installReceipt.Meta.Version
                        initially_enabled = [bool] $installReceipt.IsEnabled
                        is_custom = [bool] $installReceipt.Meta.IsCustom
                        is_style = [bool] $installReceipt.Meta.IsStyle
                        code_sha256 = Get-CanonicalTextSha256 `
                            -Text ([string] $installReceipt.Meta.Content)
                    })
        }
    }
    if ($replacementRequired) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-userscript-reclassification-restore-gm' `
                -Details ([ordered]@{
                        gm_properties_sha256 = `
                            [string] $expectedPostState.GmPropertiesSha256
                    })
        }
        [void] $Client.UpdateUserscriptGmProperties(
            $UserscriptName,
            [string] $Snapshot.GmProperties
        )
    }
    if ($JournalDirectory) {
        Write-TransactionJournalEvent -Directory $JournalDirectory `
            -Event 'intent-userscript-enable' -Details ([ordered]@{ enabled = $true })
    }
    [void] $Client.SetUserscriptStatus($UserscriptName, $true)
    try {
        return Assert-UserscriptInstalled -Client $Client -Desired $Desired `
            -ExpectedPostState $expectedPostState
    }
    catch {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'userscript-convergence-failed' `
                -Details ([ordered]@{ error = [string] $_.Exception.Message })
        }
        throw
    }
}

function Restore-UserscriptSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Snapshot,
        [AllowNull()][string] $JournalDirectory
    )
    $current = @(Get-TargetUserscripts -Client $Client)
    if ($Snapshot.Exists) {
        if ($current.Count -gt 1) {
            throw "Cannot roll back a non-unique userscript"
        }
        $classificationDiffers = $current.Count -eq 0 -or
            [bool] $current[0].IsCustom -ne [bool] $Snapshot.Info.IsCustom -or
            [bool] $current[0].IsStyle -ne [bool] $Snapshot.Info.IsStyle
        if ($classificationDiffers) {
            # Parse and authenticate the backup before removing any current
            # entry. Classification cannot be changed in place by AdGuard.
            $restoreMeta = Get-UserscriptMetaForSnapshotRestore `
                -Client $Client -Snapshot $Snapshot
            if ($current.Count -eq 1) {
                if ($JournalDirectory) {
                    Write-TransactionJournalEvent -Directory $JournalDirectory `
                        -Event 'intent-rollback-userscript-reclassification-remove' `
                        -Details ([ordered]@{
                                current_is_custom = [bool] $current[0].IsCustom
                                restore_is_custom = [bool] $Snapshot.Info.IsCustom
                            })
                }
                $Client.RemoveUserscript($UserscriptName)
                $absenceObservationCount = Assert-UserscriptAbsent -Client $Client
                if ($JournalDirectory) {
                    Write-TransactionJournalEvent -Directory $JournalDirectory `
                        -Event 'rollback-userscript-absence-verified' `
                        -Details ([ordered]@{
                                observation_count = [int] $absenceObservationCount
                            })
                }
            }
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-reclassification-install' `
                    -Details ([ordered]@{
                            version = [string] $Snapshot.Info.Version
                            is_custom = [bool] $Snapshot.Info.IsCustom
                            is_style = [bool] $Snapshot.Info.IsStyle
                            code_sha256 = Get-CanonicalTextSha256 -Text $Snapshot.Code
                        })
            }
            $installReceipt = $Client.InstallUserscriptFromMeta($restoreMeta)
            Assert-UserscriptInstallReceipt -Receipt $installReceipt `
                -ExpectedMeta $restoreMeta -ExpectedName $Snapshot.Info.Name `
                -ExpectedVersion $Snapshot.Info.Version
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'rollback-userscript-install-accepted' `
                    -Details ([ordered]@{
                            initially_enabled = [bool] $installReceipt.IsEnabled
                            is_custom = [bool] $installReceipt.Meta.IsCustom
                            is_style = [bool] $installReceipt.Meta.IsStyle
                        })
            }
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-gm' `
                    -Details ([ordered]@{
                            gm_properties_sha256 = Get-CanonicalTextSha256 `
                                -Text $Snapshot.GmProperties
                        })
            }
            [void] $Client.UpdateUserscriptGmProperties(
                $UserscriptName,
                $Snapshot.GmProperties
            )
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-status' `
                    -Details ([ordered]@{ enabled = [bool] $Snapshot.Info.IsEnabled })
            }
            $Client.SetUserscriptStatus($UserscriptName, [bool] $Snapshot.Info.IsEnabled)
        } else {
            # Reverse the normal UpdateCode -> SetStatus forward order. GM_*
            # values are restored independently before the original code.
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-status' `
                    -Details ([ordered]@{ enabled = [bool] $Snapshot.Info.IsEnabled })
            }
            $Client.SetUserscriptStatus($UserscriptName, [bool] $Snapshot.Info.IsEnabled)
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-gm' `
                    -Details ([ordered]@{
                            gm_properties_sha256 = Get-CanonicalTextSha256 `
                                -Text $Snapshot.GmProperties
                        })
            }
            [void] $Client.UpdateUserscriptGmProperties(
                $UserscriptName,
                $Snapshot.GmProperties
            )
            if ($JournalDirectory) {
                Write-TransactionJournalEvent -Directory $JournalDirectory `
                    -Event 'intent-rollback-userscript-code' `
                    -Details ([ordered]@{
                            code_sha256 = Get-CanonicalTextSha256 -Text $Snapshot.Code
                        })
            }
            $Client.UpdateUserscriptCode($UserscriptName, $Snapshot.Code)
        }
    } elseif ($current.Count -eq 1) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-rollback-userscript-remove' -Details $null
        }
        $Client.RemoveUserscript($UserscriptName)
        [void] (Assert-UserscriptAbsent -Client $Client)
    } elseif ($current.Count -gt 1) {
        throw "Cannot roll back a non-unique newly installed userscript"
    }
    [void] (Assert-UserscriptSnapshotConverged -Client $Client `
            -ExpectedSnapshot $Snapshot)
}

function Assert-UserscriptInstalled {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()] $Desired,
        [AllowNull()] $ExpectedPostState,
        [ValidateRange(2, 100)]
        [int] $MaximumObservations = $script:AdGuardStateVisibilityMaxObservations,
        [ValidateRange(0, 5000)]
        [int] $RetryDelayMilliseconds = $script:AdGuardStateVisibilityDelayMilliseconds,
        [ValidateRange(2, 10)]
        [int] $RequiredConsecutiveReads = `
            $script:AdGuardStateVisibilityRequiredConsecutiveReads
    )
    if ($RequiredConsecutiveReads -gt $MaximumObservations) {
        throw "Required consecutive reads exceed the bounded observation count"
    }

    $previousFingerprint = $null
    $consecutiveReads = 0
    $lastFailure = $null
    for ($observation = 1; $observation -le $MaximumObservations; $observation++) {
        try {
            $targets = @(Get-TargetUserscripts -Client $Client)
            if ($targets.Count -ne 1) {
                throw ("Target userscript is not uniquely installed and enabled " +
                    "(observed_count=$($targets.Count))")
            }
            if (-not $targets[0].IsEnabled) {
                throw ("Target userscript is not uniquely installed and enabled " +
                    "(observed_enabled=false)")
            }
            if (-not [bool] $targets[0].IsCustom) {
                throw ("Target userscript is not selected as an executable custom extension " +
                    "(observed_custom=false)")
            }
            if ($targets[0].IsStyle) {
                throw ("Target userscript is not uniquely installed and enabled " +
                    "(observed_style=true)")
            }
            $installedCode = $Client.GetUserscriptCode($UserscriptName, $true)
            $installedGmProperties = $Client.GetUserscriptGmProperties($UserscriptName)
            $installedCodeHash = Get-CanonicalTextSha256 -Text $installedCode
            $installedGmPropertiesHash = Get-CanonicalTextSha256 `
                -Text $installedGmProperties
            if ($Desired) {
                if ($targets[0].Version -cne $Desired.Version) {
                    throw "Installed userscript version does not match the source"
                }
                $expectedIsCustom = if ($ExpectedPostState) {
                    [bool] $ExpectedPostState.IsCustom
                } else { [bool] $Desired.Meta.IsCustom }
                $expectedIsStyle = if ($ExpectedPostState) {
                    [bool] $ExpectedPostState.IsStyle
                } else { [bool] $Desired.Meta.IsStyle }
                if ([bool] $targets[0].IsCustom -ne $expectedIsCustom -or
                    [bool] $targets[0].IsStyle -ne $expectedIsStyle) {
                    throw ("Installed userscript metadata classification does not match " +
                        "the planned post-state " +
                        "(observed IsCustom=$([bool] $targets[0].IsCustom), " +
                        "IsStyle=$([bool] $targets[0].IsStyle); " +
                        "expected IsCustom=$expectedIsCustom, " +
                        "IsStyle=$expectedIsStyle)")
                }
                $desiredHash = Get-CanonicalTextSha256 -Text $Desired.Meta.Content
                if ($installedCodeHash -cne $desiredHash) {
                    throw "Installed userscript code SHA-256 does not match the source"
                }
                if ($ExpectedPostState -and $installedGmPropertiesHash -cne
                    [string] $ExpectedPostState.GmPropertiesSha256) {
                    throw ("Installed userscript GM value-store SHA-256 does not match " +
                        "the planned post-state " +
                        "(observed=$installedGmPropertiesHash, " +
                        "expected=$($ExpectedPostState.GmPropertiesSha256), " +
                        "observed_length=$(([string] $installedGmProperties).Length), " +
                        "fresh_contract_length=$(([string] $Desired.FreshInstallGmProperties).Length))")
                }
            }
            $fingerprintRecord = [ordered]@{
                name = [string] $targets[0].Name
                version = [string] $targets[0].Version
                enabled = [bool] $targets[0].IsEnabled
                custom = [bool] $targets[0].IsCustom
                style = [bool] $targets[0].IsStyle
                code_sha256 = $installedCodeHash
                gm_properties_sha256 = $installedGmPropertiesHash
            }
            $fingerprint = Get-CanonicalTextSha256 -Text (
                $fingerprintRecord | ConvertTo-Json -Compress)
            if ($null -ne $previousFingerprint -and
                $fingerprint -ceq $previousFingerprint) {
                $consecutiveReads++
            } else {
                $consecutiveReads = 1
            }
            $previousFingerprint = $fingerprint
            $lastFailure = $null
            if ($consecutiveReads -ge $RequiredConsecutiveReads) {
                Add-Member -InputObject $targets[0] -NotePropertyName InstalledCodeSha256 `
                    -NotePropertyValue $installedCodeHash -Force
                Add-Member -InputObject $targets[0] `
                    -NotePropertyName InstalledGmPropertiesSha256 `
                    -NotePropertyValue $installedGmPropertiesHash -Force
                Add-Member -InputObject $targets[0] -NotePropertyName VisibilityObservationCount `
                    -NotePropertyValue $observation -Force
                return $targets[0]
            }
        }
        catch {
            $lastFailure = [string] $_.Exception.Message
            $previousFingerprint = $null
            $consecutiveReads = 0
        }
        if ($observation -lt $MaximumObservations -and $RetryDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RetryDelayMilliseconds
        }
    }
    if ($lastFailure) {
        throw ("$lastFailure; exact userscript state did not converge within " +
            "$MaximumObservations bounded observations")
    }
    throw ("Exact installed userscript state did not remain identical for " +
        "$RequiredConsecutiveReads consecutive reads within $MaximumObservations observations")
}

function Prepare-FilterMetaSet {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Source
    )
    $metaSet = $Client.GetSubscriptionsMetaSet($Source.Url)
    if (-not $metaSet -or -not $metaSet.Main) {
        throw "AdGuard could not parse the custom filter subscription metadata"
    }
    if ($metaSet.Required) {
        throw "Filter unexpectedly requires an additional subscription"
    }
    if ($metaSet.Main.Name -cne $FilterName -or
        $metaSet.Main.SubscriptionUrl -cne $Source.Url -or
        $metaSet.Main.Version -cne $Source.Version) {
        throw "AdGuard parsed custom-filter metadata that differs from the verified source"
    }
    $Source.MetaSet = $metaSet
    return $Source
}

function Assert-FilterMutationPreconditions {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Source
    )
    [void] (Assert-UserscriptInstalled -Client $Client -Desired $null)
    [void] (Assert-NoLegacyHotdealConflict -Client $Client)
    $snapshot = Get-FilterSnapshot -Client $Client -ExactUrl $Source.Url
    Assert-FilterSnapshotMutationPreconditions -Snapshot $snapshot -Desired $Source
}

function Assert-FilterSnapshotMutationPreconditions {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired
    )
    $states = @($Snapshot.States)
    $exact = @($states | Where-Object { $_.SubscriptionUrl -ceq $Desired.Url })
    if ($exact.Count -gt 1) { throw "Exact custom filter URL is installed more than once" }
    if ($exact.Count -eq 1) {
        $state = $exact[0]
        if (-not [bool] $state.IsCustom -or [bool] $state.IsEditable) {
            throw "Exact filter URL belongs to a non-custom filter"
        }
        if ($state.Name -cne $FilterName -or $state.Version -cne $Desired.Version -or
            $state.RulesSha256 -cne $ExpectedInstalledFilterRulesSha256.ToLowerInvariant() -or
            $state.DisabledRulesSha256 -cne (Get-RuleMultisetSha256 -Rules @())) {
            throw "Installed exact filter is not the immutable verified release state"
        }
    }
    foreach ($old in @($states | Where-Object { $_.SubscriptionUrl -cne $Desired.Url })) {
        $versionOrder = Compare-Version -Left $Desired.Version -Right $old.Version
        if ($versionOrder -lt 0) {
            throw "New filter URL carries a lower gate artifact version"
        }
        if ($versionOrder -eq 0 -and (
                -not [bool] $old.IsCustom -or [bool] $old.IsEditable -or
                $old.Name -cne $FilterName -or
                $old.RulesSha256 -cne $ExpectedInstalledFilterRulesSha256.ToLowerInvariant() -or
                $old.DisabledRulesSha256 -cne (Get-RuleMultisetSha256 -Rules @()))) {
            throw "Same-version prior filter URL is not the exact equivalent gate artifact"
        }
    }
}

function Invoke-FilterMutation {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Desired,
        [AllowNull()][string] $JournalDirectory
    )
    Assert-FilterSnapshotMutationPreconditions -Snapshot $Snapshot -Desired $Desired
    $exact = @($Snapshot.States | Where-Object {
            $_.SubscriptionUrl -ceq $Desired.Url
        })
    if ($exact.Count -eq 0) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-filter-install' `
                -Details ([ordered]@{
                        subscription_url_sha256 = Get-CanonicalTextSha256 -Text $Desired.Url
                        installed_rules_sha256 = $ExpectedInstalledFilterRulesSha256.ToLowerInvariant()
                    })
        }
        $Client.InstallCustomFilter($Desired.MetaSet, $script:StandardFilterType)
        $exact = @(Get-InstalledStandardFilters -Client $Client | Where-Object {
                $_.IsCustom -and $_.SubscriptionUrl -ceq $Desired.Url
            })
    }
    if ($exact.Count -ne 1 -or $exact[0].Name -cne $FilterName) {
        throw "New custom filter subscription was not installed uniquely"
    }
    if ($JournalDirectory) {
        Write-TransactionJournalEvent -Directory $JournalDirectory `
            -Event 'intent-filter-activate' `
            -Details ([ordered]@{ filter_id = [int] $exact[0].FilterId
                    enabled = $true; trusted = $true })
    }
    $Client.UpdateFilterSubscriptionState(
        $exact[0].FilterId,
        $true,
        $true,
        $script:StandardFilterType
    )
    [void] (Assert-FilterInstalled -Client $Client -Desired $Desired)

    foreach ($state in @($Snapshot.States | Where-Object {
                $_.SubscriptionUrl -cne $Desired.Url
            } | Sort-Object FilterId)) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-filter-disable-prior' `
                -Details ([ordered]@{ filter_id = [int] $state.FilterId
                        trusted = [bool] $state.IsTrusted })
        }
        $Client.UpdateFilterSubscriptionState(
            $state.FilterId,
            $false,
            $state.IsTrusted,
            $script:StandardFilterType
        )
    }
}

function Restore-FilterSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [Parameter(Mandatory = $true)] $Snapshot,
        [AllowNull()][string] $ExactUrl,
        [AllowNull()][string] $JournalDirectory
    )
    $beforeIds = @($Snapshot.States | ForEach-Object { [int] $_.FilterId })
    $current = @(Get-TargetFilters -Client $Client -ExactUrl $ExactUrl)
    # Reverse the forward order: prior filters were disabled in ascending id
    # order, then the desired subscription had been activated/created.
    $restoreStates = @(
        @($Snapshot.States | Where-Object {
                -not $ExactUrl -or $_.SubscriptionUrl -cne $ExactUrl
            } | Sort-Object FilterId -Descending)
        @($Snapshot.States | Where-Object {
                $ExactUrl -and $_.SubscriptionUrl -ceq $ExactUrl
            })
    )
    foreach ($state in $restoreStates) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-rollback-filter-state' `
                -Details ([ordered]@{ filter_id = [int] $state.FilterId
                        enabled = [bool] $state.IsEnabled
                        trusted = [bool] $state.IsTrusted })
        }
        $Client.UpdateFilterSubscriptionState(
            $state.FilterId,
            $state.IsEnabled,
            $state.IsTrusted,
            $script:StandardFilterType
        )
    }
    foreach ($filter in @($current | Where-Object {
                $beforeIds -notcontains [int] $_.FilterId
            } | Sort-Object FilterId -Descending)) {
        if ($JournalDirectory) {
            Write-TransactionJournalEvent -Directory $JournalDirectory `
                -Event 'intent-rollback-filter-remove' `
                -Details ([ordered]@{ filter_id = [int] $filter.FilterId })
        }
        $Client.RemoveFilterSubscription($filter.FilterId, $script:StandardFilterType)
    }

    $restoredSnapshot = Get-FilterSnapshot -Client $Client -ExactUrl $ExactUrl
    $restored = @($restoredSnapshot.States)
    if ($restored.Count -ne @($Snapshot.States).Count) {
        throw "Filter rollback postcondition failed: target filter count differs"
    }
    foreach ($before in @($Snapshot.States)) {
        $matches = @($restored | Where-Object { $_.FilterId -eq $before.FilterId })
        if ($matches.Count -ne 1) {
            throw "Filter rollback postcondition failed: prior filter id is not unique"
        }
        $after = $matches[0]
        if ($after.Name -cne $before.Name -or
            $after.Version -cne $before.Version -or
            $after.SubscriptionUrl -cne $before.SubscriptionUrl -or
            [bool] $after.IsEnabled -ne [bool] $before.IsEnabled -or
            [bool] $after.IsTrusted -ne [bool] $before.IsTrusted -or
            $after.RulesSha256 -cne $before.RulesSha256 -or
            $after.DisabledRulesSha256 -cne $before.DisabledRulesSha256) {
            throw "Filter rollback postcondition failed: prior filter state differs"
        }
    }
}

function Assert-FilterInstalled {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()] $Desired
    )
    $exactUrl = if ($Desired) { $Desired.Url } elseif ($FilterUrl) {
        ([Uri] $FilterUrl).AbsoluteUri
    } else { $null }
    $targets = @(Get-TargetFilters -Client $Client -ExactUrl $exactUrl | Where-Object {
            $_.Name -ceq $FilterName -and $_.IsEnabled -and $_.IsTrusted -and
            (-not $exactUrl -or $_.SubscriptionUrl -ceq $exactUrl)
        })
    if ($targets.Count -ne 1) {
        throw "Target custom filter is not uniquely installed, enabled, and trusted"
    }
    if ($Desired -and $targets[0].Version -cne $Desired.Version) {
        throw "Installed custom filter version does not match the verified source"
    }
    $rules = $Client.GetFilterSubscriptionRules(
        $targets[0].FilterId,
        $script:StandardFilterType
    )
    if (@($rules.Rules).Count -lt 2) { throw "Installed custom filter has too few rules" }
    $disabledRuleCount = @($rules.DisabledRules).Count
    $disabledRulesHash = Get-RuleMultisetSha256 -Rules $rules.DisabledRules
    if ($disabledRuleCount -ne 0) {
        throw "Installed custom filter contains disabled rules"
    }
    $rulesHash = Get-RuleListSha256 -Rules $rules.Rules
    if ($ExpectedInstalledFilterRulesSha256 -and
        $rulesHash -cne $ExpectedInstalledFilterRulesSha256.ToLowerInvariant()) {
        throw "Installed custom-filter rules SHA-256 does not match the expected value"
    }
    return [pscustomobject]@{
        Filter = $targets[0]
        RulesSha256 = $rulesHash
        RuleCount = @($rules.Rules).Count
        DisabledRulesSha256 = $disabledRulesHash
        DisabledRuleCount = $disabledRuleCount
    }
}

function Assert-GlobalProtection {
    param([Parameter(Mandatory = $true)] $Client)
    $service = Get-AdGuardService
    $state = [string] $Client.GetApplicationState()
    $protection = $Client.GetProtectionSettings()
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running -or
        $state -cne 'Enabled' -or -not $protection.IsAdBlockerEnabled -or
        -not $protection.IsExtensionsEnabled) {
        throw "AdGuard service, protection, ad blocker, and extensions must all be enabled"
    }
    return $protection
}

function Get-InspectionReport {
    param([Parameter(Mandatory = $true)] $Session)
    $client = $Session.Client
    $service = Get-AdGuardService
    $protection = $client.GetProtectionSettings()
    $userEvidence = Get-UserFilterEvidence -Client $client
    $userFilter = $userEvidence.Filter
    $userRules = $userEvidence.Rules

    $userscripts = @(Get-TargetUserscripts -Client $client)
    $userscriptRecords = @($userscripts | ForEach-Object {
            $record = ConvertTo-UserscriptMetadataRecord -Info $_
            $code = $client.GetUserscriptCode($_.Name, $true)
            $gmProperties = $client.GetUserscriptGmProperties($_.Name)
            $record.code_sha256 = Get-CanonicalTextSha256 -Text $code
            $record.gm_properties_sha256 = Get-CanonicalTextSha256 -Text $gmProperties
            $record
        })

    $filterRecords = @(
        Get-TargetFilters -Client $client -ExactUrl $(if ($FilterUrl) {
                ([Uri] $FilterUrl).AbsoluteUri
            } else { $null }) | ForEach-Object {
            $record = ConvertTo-FilterMetadataRecord -Filter $_
            $rules = $client.GetFilterSubscriptionRules(
                $_.FilterId,
                $script:StandardFilterType
            )
            $record.rule_count = @($rules.Rules).Count
            $record.rules_sha256 = Get-RuleListSha256 -Rules $rules.Rules
            $record
        })

    return [ordered]@{
        command = 'inspect'
        tool_version = $script:ToolVersion
        adguard_version = $script:AdGuardProcess.MainModule.FileVersionInfo.FileVersion
        ui_started_by_cli = $script:UiWasStarted
        ipc_connected = [bool] $client.IsConnected
        ipc_identity_source = $Session.IdentityLog
        service = [ordered]@{
            status = [string] $service.Status
            start_type = [string] $service.StartType
        }
        protection = [ordered]@{
            application_state = [string] $client.GetApplicationState()
            ad_blocker_enabled = [bool] $protection.IsAdBlockerEnabled
            extensions_enabled = [bool] $protection.IsExtensionsEnabled
        }
        user_filter = [ordered]@{
            preserved = $true
            filter_id = [int] $userFilter.FilterId
            name = [string] $userFilter.Name
            filter_type = [string] $userFilter.FilterType
            rule_count = @($userRules.Rules).Count
            disabled_rule_count = @($userRules.DisabledRules).Count
            rules_sha256 = Get-RuleListSha256 -Rules $userRules.Rules
            evidence = $userEvidence.Report
        }
        target_userscripts = $userscriptRecords
        target_filters = $filterRecords
    }
}

function Assert-DeploymentVerified {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()] $DesiredUserscript,
        [AllowNull()] $DesiredFilter
    )
    [void] (Assert-GlobalProtection -Client $Client)
    [void] (Assert-NoLegacyHotdealConflict -Client $Client)
    $userscript = Assert-UserscriptInstalled -Client $Client -Desired $DesiredUserscript
    $filter = Assert-FilterInstalled -Client $Client -Desired $DesiredFilter
    return [ordered]@{
        verified = $true
        service_running = $true
        protection_enabled = $true
        userscript = ConvertTo-UserscriptMetadataRecord -Info $userscript
        installed_userscript_code_sha256 = $userscript.InstalledCodeSha256
        installed_userscript_gm_properties_sha256 = `
            $userscript.InstalledGmPropertiesSha256
        filter = ConvertTo-FilterMetadataRecord -Filter $filter.Filter
        installed_filter_rule_count = $filter.RuleCount
        installed_filter_rules_sha256 = $filter.RulesSha256
        installed_filter_disabled_rule_count = $filter.DisabledRuleCount
        installed_filter_disabled_rules_sha256 = $filter.DisabledRulesSha256
    }
}

function Invoke-Rollback {
    param(
        [Parameter(Mandatory = $true)] $Client,
        [AllowNull()] $UserscriptSnapshot,
        [AllowNull()] $FilterSnapshot,
        [AllowNull()] $MigrationTransaction,
        [AllowNull()][string] $ExactFilterUrl,
        [AllowNull()][string] $JournalDirectory
    )
    $errors = New-Object 'System.Collections.Generic.List[string]'
    if ($FilterSnapshot) {
        try {
            Restore-FilterSnapshot -Client $Client -Snapshot $FilterSnapshot `
                -ExactUrl $ExactFilterUrl -JournalDirectory $JournalDirectory
        }
        catch { $errors.Add('filter rollback failed') }
    }
    if ($MigrationTransaction) {
        try {
            Restore-LegacyMigration -Client $Client -Transaction $MigrationTransaction `
                -JournalDirectory $JournalDirectory
        }
        catch { $errors.Add('legacy-rule rollback failed') }
    }
    if ($UserscriptSnapshot) {
        try {
            Restore-UserscriptSnapshot -Client $Client -Snapshot $UserscriptSnapshot `
                -JournalDirectory $JournalDirectory
        }
        catch { $errors.Add('userscript rollback failed') }
    }
    if ($errors.Count -gt 0) {
        throw ($errors -join '; ')
    }
}

function Assert-MutationAuthorized {
    if (-not $Apply -and -not $WhatIfPreference) {
        throw "Mutating commands require the explicit -Apply switch"
    }
}

function Assert-ExclusiveTargetMigrationAuthorized {
    param([Parameter(Mandatory = $true)] $Plan)
    $enabledCount = @($Plan.EnabledCandidateRules).Count
    if ($enabledCount -gt 0 -and -not $ApproveExclusiveTargetMigration) {
        throw ("Disabling the current snapshot's $enabledCount exclusive-target User-filter " +
            "rule(s) requires -ApproveExclusiveTargetMigration. Run migrate-legacy -WhatIf " +
            "first; scope alone does not prove that a rule came from an earlier Hotdeal " +
            "Focus release")
    }
}

$isCspProbeCommand = $Command -in @(
    'csp-probe-inspect', 'csp-probe-install', 'csp-probe-restore')
$cspProbeForbiddenParameters = @(
    'UserscriptSource', 'FilterUrl', 'ReleaseManifestSource',
    'UserscriptName', 'FilterName', 'ExpectedUserscriptSha256',
    'ExpectedFilterSha256', 'ExpectedInstalledFilterRulesSha256',
    'ReferenceUserFilterSnapshot', 'ApproveExclusiveTargetMigration'
)
if ($isCspProbeCommand) {
    $UserscriptName = $script:CspProbeUserscriptName
    $FilterName = $script:CspProbeFilterName
}

Assert-Sha256Value -Value $ExpectedUserscriptSha256 -Name 'ExpectedUserscriptSha256'
Assert-Sha256Value -Value $ExpectedFilterSha256 -Name 'ExpectedFilterSha256'
Assert-Sha256Value -Value $ExpectedInstalledFilterRulesSha256 `
    -Name 'ExpectedInstalledFilterRulesSha256'

$session = $null
$desiredUserscript = $null
$desiredFilter = $null
$validatedBackup = $null
$releaseManifestContract = $null
try {
    if ($isCspProbeCommand) {
        foreach ($forbiddenParameter in $cspProbeForbiddenParameters) {
            if ($PSBoundParameters.ContainsKey($forbiddenParameter)) {
                throw "CSP probe commands reject parameter: -$forbiddenParameter"
            }
        }
        if ($Command -eq 'csp-probe-inspect' -and
            ($Apply -or $PSBoundParameters.ContainsKey('WhatIf') -or
                $PSBoundParameters.ContainsKey('BackupRoot') -or
                $PSBoundParameters.ContainsKey('BackupPath'))) {
            throw "csp-probe-inspect is read-only and accepts no mutation or backup switch"
        }
        if ($Command -eq 'csp-probe-install' -and
            $PSBoundParameters.ContainsKey('BackupPath')) {
            throw "csp-probe-install does not accept -BackupPath"
        }
        if ($Command -eq 'csp-probe-restore' -and
            $PSBoundParameters.ContainsKey('BackupRoot')) {
            throw "csp-probe-restore does not accept -BackupRoot"
        }
    }
    if ($Command -in @('install-userscript', 'install-filter', 'deploy', 'verify') -and
        -not $UserscriptSource) {
        throw "$Command requires -UserscriptSource"
    }
    if ($Command -in @('install-filter', 'deploy', 'verify') -and -not $FilterUrl) {
        throw "$Command requires -FilterUrl"
    }
    if ($Command -in @('install-userscript', 'install-filter', 'deploy', 'verify') -and
        -not $ExpectedUserscriptSha256) {
        throw "$Command requires -ExpectedUserscriptSha256, including with -WhatIf"
    }
    if ($Command -in @('install-filter', 'deploy', 'verify') -and
        -not $ExpectedFilterSha256) {
        throw "$Command requires -ExpectedFilterSha256, including with -WhatIf"
    }
    if ($Command -in @('install-filter', 'deploy', 'verify') -and
        -not $ExpectedInstalledFilterRulesSha256) {
        throw "$Command requires -ExpectedInstalledFilterRulesSha256, including with -WhatIf"
    }
    if ($Command -eq 'restore-backup' -and -not $BackupPath) {
        throw "restore-backup requires -BackupPath"
    }
    if ($Command -eq 'csp-probe-restore' -and -not $BackupPath) {
        throw "csp-probe-restore requires -BackupPath"
    }

    if ($isCspProbeCommand) {
        $desiredUserscript = Get-CspProbeUserscriptSource
    }
    if ($UserscriptSource) {
        $desiredUserscript = Get-UserscriptSource -Source $UserscriptSource
    }
    if ($FilterUrl) {
        $desiredFilter = Get-FilterSource -Url $FilterUrl
    }
    if ($Command -in @('install-userscript', 'install-filter', 'deploy', 'verify')) {
        $manifestSource = Get-DefaultReleaseManifestSource
        $releaseManifestContract = Get-ReleaseManifestContract -Source $manifestSource
        Assert-ReleaseInputsMatchManifest -ManifestContract $releaseManifestContract `
            -DesiredUserscript $desiredUserscript -DesiredFilter $desiredFilter
    }
    if ($Command -eq 'restore-backup') {
        $validatedBackup = Get-ValidatedBackup -Path $BackupPath
        Set-RecoveryContext -Directory $validatedBackup.Directory
    }
    if ($Command -eq 'csp-probe-restore') {
        $validatedBackup = Get-ValidatedBackup -Path $BackupPath
        Set-CspProbeRecoveryContext -Directory $validatedBackup.Directory
    }

    $session = Connect-AdGuardSession
    $client = $session.Client
    if ($desiredUserscript -and $Command -ne 'csp-probe-inspect') {
        $desiredUserscript = Prepare-UserscriptMeta -Client $client -Source $desiredUserscript
    }
    if ($desiredFilter) {
        $desiredFilter = Prepare-FilterMetaSet -Client $client -Source $desiredFilter
    }
    if ($Command -eq 'csp-probe-restore') {
        Assert-CspProbeBackupContract -Backup $validatedBackup -Desired $desiredUserscript
    }

    switch ($Command) {
        'inspect' {
            Write-JsonResult -Value (Get-InspectionReport -Session $session)
        }
        'csp-probe-inspect' {
            Write-JsonResult -Value (Get-CspProbeInspectionReport -Client $client)
        }
        'backup' {
            if (-not $WhatIfPreference -and
                $PSCmdlet.ShouldProcess('AdGuard state', 'Write a recovery backup')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $(if ($FilterUrl) {
                        ([Uri] $FilterUrl).AbsoluteUri
                    } else { $null })
                Write-JsonResult -Value ([ordered]@{
                        command = 'backup'
                        backup = $backup
                        adguard_configuration_changed = $false
                    })
            } else {
                Write-JsonResult -Value ([ordered]@{
                        command = 'backup'
                        what_if = $true
                        adguard_configuration_changed = $false
                    })
            }
        }
        'restore-backup' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            $restorePlan = Get-BackupRestorePlan -Client $client -Backup $validatedBackup
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess(
                    $validatedBackup.Directory,
                    'Restore exact target state from validated backup')) {
                Write-TransactionJournalEvent -Directory $validatedBackup.Directory `
                    -Event 'restore-started' `
                    -Details ([ordered]@{ already_restored = $restorePlan.IsAlreadyRestored })
                Invoke-BackupRestore -Client $client -Backup $validatedBackup -Plan $restorePlan
                Write-JsonResult -Value ([ordered]@{
                        command = 'restore-backup'
                        changed = -not $restorePlan.IsAlreadyRestored
                        verified = $true
                        backup = $validatedBackup.Directory
                        idempotent = $true
                    })
            } else {
                Write-JsonResult -Value ([ordered]@{
                        command = 'restore-backup'
                        what_if = $true
                        backup = $validatedBackup.Directory
                        already_restored = $restorePlan.IsAlreadyRestored
                        filter_restore_required = $restorePlan.FilterNeedsRestore
                        legacy_rule_enable_count = @($restorePlan.DisabledRulesToEnable).Count
                        userscript_restore_required = $restorePlan.UserscriptNeedsRestore
                        restore_order = @('target-filter', 'legacy-rule-delta', 'target-userscript',
                            'exact-postcondition-verification')
                        adguard_configuration_changed = $false
                })
            }
        }
        'csp-probe-restore' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            $restorePlan = Get-BackupRestorePlan -Client $client -Backup $validatedBackup
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess(
                    $validatedBackup.Directory,
                    'Restore and remove the fixed CSP probe from its validated backup')) {
                Write-TransactionJournalEvent -Directory $validatedBackup.Directory `
                    -Event 'restore-started' `
                    -Details ([ordered]@{ already_restored = $restorePlan.IsAlreadyRestored })
                Invoke-BackupRestore -Client $client -Backup $validatedBackup -Plan $restorePlan
                $post = Get-CspProbeInspectionReport -Client $client
                if ($post.probe_present -or
                    [string] $post.state_sha256 -cne
                        [string] $validatedBackup.Manifest.complete_target_state.read_2_sha256) {
                    throw "CSP probe restore did not reproduce the exact pre-install state"
                }
                Write-JsonResult -Value ([ordered]@{
                        command = 'csp-probe-restore'
                        ok = $true
                        changed = -not $restorePlan.IsAlreadyRestored
                        verified = $true
                        backup = $validatedBackup.Directory
                        state_sha256 = $post.state_sha256
                        probe_present = $false
                        probe_source_sha256 = $script:CspProbeSourceSha256
                        idempotent = $true
                    })
            } else {
                Write-JsonResult -Value ([ordered]@{
                        command = 'csp-probe-restore'
                        ok = $true
                        what_if = $true
                        backup = $validatedBackup.Directory
                        already_restored = $restorePlan.IsAlreadyRestored
                        userscript_restore_required = $restorePlan.UserscriptNeedsRestore
                        restore_order = @('fixed-probe-userscript',
                            'two-read-exact-postcondition-verification')
                        probe_source_sha256 = $script:CspProbeSourceSha256
                        adguard_configuration_changed = $false
                    })
            }
        }
        'verify' {
            $verified = Assert-DeploymentVerified -Client $client `
                -DesiredUserscript $desiredUserscript -DesiredFilter $desiredFilter
            $verified.command = 'verify'
            Write-JsonResult -Value $verified
        }
        'install-userscript' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess(
                    $UserscriptName, 'Install or update and enable userscript')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $null
                Set-RecoveryContext -Directory $backup
                $mutationBackup = Get-ValidatedBackup -Path $backup
                $snapshot = $mutationBackup.UserscriptSnapshot
                Initialize-TransactionJournal -Directory $backup `
                    -CommandName 'install-userscript' -DesiredUserscript $desiredUserscript `
                    -BeforeUserscriptSnapshot $snapshot -DesiredFilter $null -MigrationPlan $null
                try {
                    [void] (Assert-CurrentStateEqualsBackup -Client $client `
                            -Backup $mutationBackup -ExactFilterUrl $null)
                    $installed = Invoke-UserscriptMutation -Client $client -Snapshot $snapshot `
                        -Desired $desiredUserscript -JournalDirectory $backup
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'userscript-applied' `
                        -Details ([ordered]@{
                                code_sha256 = $installed.InstalledCodeSha256
                                gm_properties_sha256 = `
                                    $installed.InstalledGmPropertiesSha256
                            })
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'transaction-complete' -Details $null
                    Write-JsonResult -Value ([ordered]@{
                            command = 'install-userscript'
                            changed = $true
                            backup = $backup
                            userscript = ConvertTo-UserscriptMetadataRecord -Info $installed
                            code_sha256 = $installed.InstalledCodeSha256
                            gm_properties_sha256 = $installed.InstalledGmPropertiesSha256
                        })
                }
                catch {
                    try {
                        Invoke-Rollback -Client $client -UserscriptSnapshot $snapshot `
                            -FilterSnapshot $null -ExactFilterUrl $null `
                            -JournalDirectory $backup
                        try { Write-TransactionJournalEvent -Directory $backup `
                                -Event 'rollback-complete' -Details $null } catch { }
                    }
                    catch { throw "Userscript deployment failed and rollback was incomplete" }
                    throw
                }
            } else {
                Write-JsonResult -Value ([ordered]@{
                        command = 'install-userscript'
                        what_if = $true
                        userscript_name = $desiredUserscript.Name
                        userscript_version = $desiredUserscript.Version
                        userscript_sha256 = $desiredUserscript.Sha256
                        adguard_configuration_changed = $false
                })
            }
        }
        'csp-probe-install' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            $pre = Get-CspProbeInspectionReport -Client $client
            if ($pre.probe_present -or [int] $pre.probe_count -ne 0) {
                throw "Fixed CSP probe already exists; refusing to overwrite or adopt it"
            }
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess(
                    $script:CspProbeUserscriptName,
                    'Install the fixed hash-pinned CSP probe temporarily')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $null
                $mutationBackup = Get-ValidatedBackup -Path $backup
                if ($mutationBackup.UserscriptSnapshot.Exists -or
                    @($mutationBackup.FilterSnapshot.States).Count -ne 0) {
                    throw "Completed CSP probe backup does not prove an absent probe target"
                }
                Initialize-TransactionJournal -Directory $backup `
                    -CommandName 'csp-probe-install' -DesiredUserscript $desiredUserscript `
                    -BeforeUserscriptSnapshot $mutationBackup.UserscriptSnapshot `
                    -DesiredFilter $null -MigrationPlan $null
                $mutationBackup = Get-ValidatedBackup -Path $backup
                Assert-CspProbeBackupContract -Backup $mutationBackup `
                    -Desired $desiredUserscript
                Set-CspProbeRecoveryContext -Directory $backup
                try {
                    [void] (Assert-CurrentStateEqualsBackup -Client $client `
                            -Backup $mutationBackup -ExactFilterUrl $null)
                    $installed = Invoke-UserscriptMutation -Client $client `
                        -Snapshot $mutationBackup.UserscriptSnapshot `
                        -Desired $desiredUserscript -JournalDirectory $backup
                    $installedState = Get-CspProbeInspectionReport -Client $client
                    if (-not $installedState.probe_present -or
                        [int] $installedState.probe_count -ne 1) {
                        throw "Fixed CSP probe was not uniquely visible after installation"
                    }
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'userscript-applied' `
                        -Details ([ordered]@{
                                code_sha256 = $installed.InstalledCodeSha256
                                gm_properties_sha256 = `
                                    $installed.InstalledGmPropertiesSha256
                            })
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'transaction-complete' -Details $null
                    Write-JsonResult -Value ([ordered]@{
                            command = 'csp-probe-install'
                            ok = $true
                            changed = $true
                            backup = $backup
                            pre_state_sha256 = [string] (
                                $mutationBackup.Manifest.complete_target_state.read_2_sha256)
                            installed_state_sha256 = $installedState.state_sha256
                            probe_present = $true
                            probe_name = $script:CspProbeUserscriptName
                            probe_version = $script:CspProbeUserscriptVersion
                            probe_source_sha256 = $script:CspProbeSourceSha256
                            endpoint = $script:CspProbeEndpoint
                            is_custom = [bool] $installed.IsCustom
                            is_style = [bool] $installed.IsStyle
                            code_sha256 = $installed.InstalledCodeSha256
                            gm_properties_sha256 = $installed.InstalledGmPropertiesSha256
                        })
                }
                catch {
                    $original = $_
                    try {
                        Invoke-Rollback -Client $client `
                            -UserscriptSnapshot $mutationBackup.UserscriptSnapshot `
                            -FilterSnapshot $null -ExactFilterUrl $null `
                            -JournalDirectory $backup
                        try { Write-TransactionJournalEvent -Directory $backup `
                                -Event 'rollback-complete' -Details $null } catch { }
                    }
                    catch { throw "CSP probe installation failed and rollback was incomplete" }
                    throw $original
                }
            } else {
                Write-JsonResult -Value ([ordered]@{
                        command = 'csp-probe-install'
                        ok = $true
                        what_if = $true
                        order = @('two-read-stable-pre-inspection',
                            'complete-schema-v2-backup', 'fixed-hash-pinned-probe-install',
                            'strict-CSP-browser-proof', 'validated-backup-restore',
                            'two-independent-stable-post-inspections')
                        pre_state_sha256 = $pre.state_sha256
                        probe_present = $false
                        probe_name = $script:CspProbeUserscriptName
                        probe_version = $script:CspProbeUserscriptVersion
                        probe_source_sha256 = $script:CspProbeSourceSha256
                        endpoint = $script:CspProbeEndpoint
                        is_custom = [bool] $desiredUserscript.Meta.IsCustom
                        is_style = [bool] $desiredUserscript.Meta.IsStyle
                        parsed_meta = Get-CspProbeParsedMetaEvidence `
                            -Meta $desiredUserscript.Meta
                        adguard_configuration_changed = $false
                    })
            }
        }
        'migrate-legacy' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess(
                    'AdGuard User filter exclusive-target rules',
                    'Disable the explicitly approved backup-derived rule delta')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $null
                Set-RecoveryContext -Directory $backup
                $mutationBackup = Get-ValidatedBackup -Path $backup
                $migrationPlan = Get-LegacyMigrationPlanFromBackup -Backup $mutationBackup
                if (-not $migrationPlan.CanMigrate) {
                    throw ("Legacy migration exact precondition failed: " +
                        (@($migrationPlan.PublicReport.block_reasons) -join ', '))
                }
                Assert-ExclusiveTargetMigrationAuthorized -Plan $migrationPlan
                Initialize-TransactionJournal -Directory $backup `
                    -CommandName 'migrate-legacy' -DesiredUserscript $null `
                    -BeforeUserscriptSnapshot $null -DesiredFilter $null `
                    -MigrationPlan $migrationPlan
                $migration = $null
                try {
                    [void] (Assert-CurrentStateEqualsBackup -Client $client `
                            -Backup $mutationBackup -ExactFilterUrl $null)
                    $migration = Invoke-LegacyMigration -Client $client -Plan $migrationPlan `
                        -JournalDirectory $backup -CurrentMatchesBackup
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'legacy-migration-applied' `
                        -Details ([ordered]@{ changed = [bool] $migration.PublicReport.changed })
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'transaction-complete' -Details $null
                    Write-JsonResult -Value ([ordered]@{
                            command = 'migrate-legacy'
                            changed = [bool] $migration.PublicReport.changed
                            backup = $backup
                            migration = $migration.PublicReport
                        })
                }
                catch {
                    $original = $_
                    if ($migration) {
                        try {
                            Restore-LegacyMigration -Client $client -Transaction $migration `
                                -JournalDirectory $backup
                            try { Write-TransactionJournalEvent -Directory $backup `
                                    -Event 'rollback-complete' -Details $null } catch { }
                        }
                        catch { throw "Legacy migration output failed and rollback was incomplete" }
                    }
                    throw $original
                }
            } else {
                $migrationPlan = Get-LegacyMigrationPlan -Client $client
                if (-not $migrationPlan.CanMigrate) {
                    throw ("Legacy migration exact precondition failed: " +
                        (@($migrationPlan.PublicReport.block_reasons) -join ', '))
                }
                Write-JsonResult -Value ([ordered]@{
                        command = 'migrate-legacy'
                        what_if = $true
                        plan = $migrationPlan.PublicReport
                        mutation_order = @('full-authoritative-backup',
                            'DisableFilterRules(exact candidate delta)', 'postcondition-verification')
                        rollback = 'EnableFilterRules(exact transaction delta)'
                        approval_required = @($migrationPlan.EnabledCandidateRules).Count -gt 0
                        approval_switch = '-ApproveExclusiveTargetMigration'
                        approval_supplied = [bool] $ApproveExclusiveTargetMigration
                        adguard_configuration_changed = $false
                    })
            }
        }
        'install-filter' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess($desiredFilter.Url,
                    'Install or activate trusted custom marker filter')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $desiredFilter.Url
                Set-RecoveryContext -Directory $backup
                $mutationBackup = Get-ValidatedBackup -Path $backup
                $snapshot = $mutationBackup.FilterSnapshot
                Assert-BackupUserscriptMatchesDesired `
                    -Snapshot $mutationBackup.UserscriptSnapshot -Desired $desiredUserscript
                $backupMigrationPlan = Get-LegacyMigrationPlanFromBackup -Backup $mutationBackup
                if (-not $backupMigrationPlan.CanMigrate -or
                    @($backupMigrationPlan.EnabledCandidateRules).Count -ne 0 -or
                    [int] $backupMigrationPlan.PublicReport.protected.enabled_mixed_target_rule_count -ne 0) {
                    throw "Completed backup contains enabled legacy or mixed-target Hotdeal rules"
                }
                Assert-FilterSnapshotMutationPreconditions -Snapshot $snapshot `
                    -Desired $desiredFilter
                Initialize-TransactionJournal -Directory $backup `
                    -CommandName 'install-filter' -DesiredUserscript $null `
                    -BeforeUserscriptSnapshot $null -DesiredFilter $desiredFilter `
                    -MigrationPlan $null
                try {
                    [void] (Assert-CurrentStateEqualsBackup -Client $client `
                            -Backup $mutationBackup -ExactFilterUrl $desiredFilter.Url)
                    Invoke-FilterMutation -Client $client -Snapshot $snapshot `
                        -Desired $desiredFilter -JournalDirectory $backup
                    $installed = Assert-FilterInstalled -Client $client -Desired $desiredFilter
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'filter-applied' `
                        -Details ([ordered]@{ filter_id = [int] $installed.Filter.FilterId
                                rules_sha256 = $installed.RulesSha256
                                disabled_rule_count = $installed.DisabledRuleCount
                                disabled_rules_sha256 = $installed.DisabledRulesSha256 })
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'transaction-complete' -Details $null
                    Write-JsonResult -Value ([ordered]@{
                            command = 'install-filter'
                            changed = $true
                            backup = $backup
                            filter = ConvertTo-FilterMetadataRecord -Filter $installed.Filter
                            installed_rules_sha256 = $installed.RulesSha256
                            disabled_rule_count = $installed.DisabledRuleCount
                            disabled_rules_sha256 = $installed.DisabledRulesSha256
                        })
                }
                catch {
                    try {
                        Invoke-Rollback -Client $client -UserscriptSnapshot $null `
                            -FilterSnapshot $snapshot -ExactFilterUrl $desiredFilter.Url `
                            -JournalDirectory $backup
                        try { Write-TransactionJournalEvent -Directory $backup `
                                -Event 'rollback-complete' -Details $null } catch { }
                    }
                    catch { throw "Filter deployment failed and rollback was incomplete" }
                    throw
                }
            } else {
                [void] (Assert-UserscriptInstalled -Client $client -Desired $desiredUserscript)
                [void] (Assert-NoLegacyHotdealConflict -Client $client)
                $snapshot = Get-FilterSnapshot -Client $client -ExactUrl $desiredFilter.Url
                Assert-FilterSnapshotMutationPreconditions -Snapshot $snapshot `
                    -Desired $desiredFilter
                Write-JsonResult -Value ([ordered]@{
                        command = 'install-filter'
                        what_if = $true
                        filter_name = $desiredFilter.Name
                        filter_version = $desiredFilter.Version
                        filter_url = $desiredFilter.Url
                        filter_raw_sha256 = $desiredFilter.RawSha256
                        filter_source_rules_sha256 = $desiredFilter.SourceRulesSha256
                        adguard_configuration_changed = $false
                    })
            }
        }
        'deploy' {
            Assert-MutationAuthorized
            [void] (Assert-GlobalProtection -Client $client)
            if (-not $WhatIfPreference -and $PSCmdlet.ShouldProcess('AdGuard Hotdeal Focus',
                    'Deploy userscript, disable approved exclusive-target rules, then trusted marker filter')) {
                $backup = New-StateBackup -Client $client -ExactFilterUrl $desiredFilter.Url
                Set-RecoveryContext -Directory $backup
                $mutationBackup = Get-ValidatedBackup -Path $backup
                $userscriptSnapshot = $mutationBackup.UserscriptSnapshot
                $filterSnapshot = $mutationBackup.FilterSnapshot
                $migrationPlan = Get-LegacyMigrationPlanFromBackup -Backup $mutationBackup
                if (-not $migrationPlan.CanMigrate) {
                    throw ("Legacy migration exact precondition failed: " +
                        (@($migrationPlan.PublicReport.block_reasons) -join ', '))
                }
                if ([int] $migrationPlan.PublicReport.protected.enabled_mixed_target_rule_count -gt 0) {
                    throw "Enabled mixed-target User filter rules are preserved and block deployment"
                }
                Assert-ExclusiveTargetMigrationAuthorized -Plan $migrationPlan
                Assert-FilterSnapshotMutationPreconditions -Snapshot $filterSnapshot `
                    -Desired $desiredFilter
                Initialize-TransactionJournal -Directory $backup -CommandName 'deploy' `
                    -DesiredUserscript $desiredUserscript `
                    -BeforeUserscriptSnapshot $userscriptSnapshot -DesiredFilter $desiredFilter `
                    -MigrationPlan $migrationPlan
                $migrationTransaction = $null
                try {
                    [void] (Assert-CurrentStateEqualsBackup -Client $client `
                            -Backup $mutationBackup -ExactFilterUrl $desiredFilter.Url)
                    $appliedUserscript = Invoke-UserscriptMutation -Client $client `
                        -Snapshot $userscriptSnapshot `
                        -Desired $desiredUserscript -JournalDirectory $backup
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'userscript-applied' `
                        -Details ([ordered]@{
                                code_sha256 = $appliedUserscript.InstalledCodeSha256
                                gm_properties_sha256 = `
                                    $appliedUserscript.InstalledGmPropertiesSha256
                            })
                    $migrationTransaction = Invoke-LegacyMigration -Client $client `
                        -Plan $migrationPlan -JournalDirectory $backup
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'legacy-migration-applied' `
                        -Details ([ordered]@{ changed = [bool] $migrationTransaction.PublicReport.changed })
                    Invoke-FilterMutation -Client $client -Snapshot $filterSnapshot `
                        -Desired $desiredFilter -JournalDirectory $backup
                    $appliedFilter = Assert-FilterInstalled -Client $client `
                        -Desired $desiredFilter
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'filter-applied' `
                        -Details ([ordered]@{ filter_id = [int] $appliedFilter.Filter.FilterId
                                rules_sha256 = $appliedFilter.RulesSha256
                                disabled_rule_count = $appliedFilter.DisabledRuleCount
                                disabled_rules_sha256 = $appliedFilter.DisabledRulesSha256 })
                    $verified = Assert-DeploymentVerified -Client $client `
                        -DesiredUserscript $desiredUserscript -DesiredFilter $desiredFilter
                    Write-TransactionJournalEvent -Directory $backup `
                        -Event 'transaction-complete' -Details $null
                    $verified.command = 'deploy'
                    $verified.backup = $backup
                    $verified.legacy_migration = $migrationTransaction.PublicReport
                    Write-JsonResult -Value $verified
                }
                catch {
                    try {
                        Invoke-Rollback -Client $client `
                            -UserscriptSnapshot $userscriptSnapshot `
                            -FilterSnapshot $filterSnapshot `
                            -MigrationTransaction $migrationTransaction `
                            -ExactFilterUrl $desiredFilter.Url -JournalDirectory $backup
                        try { Write-TransactionJournalEvent -Directory $backup `
                                -Event 'rollback-complete' -Details $null } catch { }
                    }
                    catch { throw "Deployment failed and transactional rollback was incomplete" }
                    throw
                }
            } else {
                $migrationPlan = Get-LegacyMigrationPlan -Client $client
                if (-not $migrationPlan.CanMigrate) {
                    throw ("Legacy migration exact precondition failed: " +
                        (@($migrationPlan.PublicReport.block_reasons) -join ', '))
                }
                if ([int] $migrationPlan.PublicReport.protected.enabled_mixed_target_rule_count -gt 0) {
                    throw "Enabled mixed-target User filter rules are preserved and block deployment"
                }
                Write-JsonResult -Value ([ordered]@{
                        command = 'deploy'
                        what_if = $true
                        order = @('full-authoritative-backup', 'userscript',
                            'approved-exclusive-target-rule-disable', 'custom-marker-filter',
                            'verification')
                        migration_plan = $migrationPlan.PublicReport
                        migration_approval_required = @(
                            $migrationPlan.EnabledCandidateRules).Count -gt 0
                        migration_approval_switch = '-ApproveExclusiveTargetMigration'
                        migration_approval_supplied = [bool] $ApproveExclusiveTargetMigration
                        userscript_version = $desiredUserscript.Version
                        userscript_sha256 = $desiredUserscript.Sha256
                        filter_version = $desiredFilter.Version
                        filter_url = $desiredFilter.Url
                        filter_raw_sha256 = $desiredFilter.RawSha256
                        filter_source_rules_sha256 = $desiredFilter.SourceRulesSha256
                        adguard_configuration_changed = $false
                    })
            }
        }
    }
}
catch {
    $message = [string] $_.Exception.Message
    $message = [regex]::Replace(
        $message,
        '(?i)(clientid|key|token|secret)\s*[:=]\s*\S+',
        '$1=<redacted>'
    )
    $failure = [ordered]@{
        command = $Command
        ok = $false
        error = $message
        error_line = [int] $_.InvocationInfo.ScriptLineNumber
    }
    if ($script:LastConflictReport) {
        $failure.legacy_hotdeal_conflicts = $script:LastConflictReport
    }
    if ($script:LastUserFilterEvidence) {
        $failure.user_filter_evidence = $script:LastUserFilterEvidence
    }
    if ($script:RecoveryBackupPath) {
        $failure.backup_path = $script:RecoveryBackupPath
        $failure.recovery_command = $script:RecoveryCommand
        $failure.recovery_command_contains_credentials = $false
    }
    Write-JsonResult -Value $failure
    exit 1
}
finally {
    Close-AdGuardSession -Session $session
    foreach ($temporaryPath in $script:TemporaryPaths) {
        if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath -PathType Leaf)) {
            try { [System.IO.File]::Delete($temporaryPath) } catch { }
        }
    }
}
