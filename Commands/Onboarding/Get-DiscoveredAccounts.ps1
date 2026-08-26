[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$query = @{};
if ($Arguments['Search']) { $query.search = [string]$Arguments['Search'] };
if ($Arguments['PlatformType']) { $query.filter = "platformType eq $([string]$Arguments['PlatformType'])" }
$warnings = [Collections.Generic.List[string]]::new();
$discovered = @(Get-FastPASOptionalItems -Context $Context -Paths @('DiscoveredAccounts') -Query $query -CollectionNames @('value', 'DiscoveredAccounts', 'PendingAccounts') -Warnings $warnings)
$rules = @(Get-FastPASOptionalItems -Context $Context -Paths @('AutomaticOnboardingRules') -CollectionNames @('value', 'AutomaticOnboardingRules', 'Rules') -Warnings $warnings)
$accounts = @(Get-FastPASPagedItems -Context $Context -Path 'Accounts' -CollectionNames @('value', 'Accounts'));
$existing = @{}
foreach ($account in $accounts) {
    $key = "$(Get-FastPASObjectString $account @('userName','UserName'))|$(Get-FastPASObjectString $account @('address','Address'))".ToLowerInvariant();
    $existing[$key] = $account
}
$rows = foreach ($item in $discovered) {
    $id = Get-FastPASObjectString $item @('id', 'ID', 'accountId');
    $user = Get-FastPASObjectString $item @('userName', 'UserName', 'username');
    $address = Get-FastPASObjectString $item @('address', 'Address', 'machine');
    $platformType = Get-FastPASObjectString $item @('platformType', 'PlatformType');
    $key = "$user|$address".ToLowerInvariant();
    $dependencies = @(Get-FastPASPropertyValue $item @('dependencies', 'Dependencies'))
    $matching = @($rules | Where-Object { $ruleType = Get-FastPASObjectString $_ @('platformType', 'PlatformType', 'machineType', 'MachineType');
            -not $ruleType -or $ruleType -eq $platformType });
    $match = $matching | Select-Object -First 1
    [pscustomobject][ordered]@{Action = 'Review';
        DiscoveredAccountId = $id;
        Name = Get-FastPASObjectString $item @('name', 'Name') $user;
        Address = $address;
        UserName = $user;
        PlatformType = $platformType;
        Privileged = Get-FastPASPropertyValue $item @('privileged', 'Privileged');
        Enabled = Get-FastPASPropertyValue $item @('accountEnabled', 'enabled', 'Enabled');
        RulesEvaluated = $rules.Count;
        MatchingRule = Get-FastPASObjectString $match @('ruleName', 'RuleName', 'name', 'Name', 'id', 'ID');
        RecommendedPlatformId = $(if ($match) { Get-FastPASObjectString $match @('targetPlatformId', 'TargetPlatformId', 'platformId', 'PlatformId') }else { Get-FastPASObjectString $item @('platformId', 'PlatformId') });
        RecommendedSafeName = $(if ($match) { Get-FastPASObjectString $match @('targetSafeName', 'TargetSafeName', 'safeName', 'SafeName') }else { '' });
        DependencyCount = $dependencies.Count;
        DuplicateAccountId = if ($existing.ContainsKey($key)) { Get-FastPASObjectString $existing[$key] @('id', 'ID') }else { '' };
        Recommendation = if ($existing.ContainsKey($key)) {
            'Review duplicate; do not onboard automatically.'
        }
        elseif ($match) {
            'Review the matching automatic-onboarding rule recommendation.'
        }
        elseif ($dependencies.Count) {
            'Onboard parent and review dependencies together.'
        }
        else {
            'Select a safe and platform, then onboard.'
        }
    }
}
$data = @($rows | Sort-Object @{Expression = { if ($_.DuplicateAccountId) { 0 }else { 1 } } }, Address, UserName);
$csv = Export-FastPASCsv $data $OutputPath 'discovered_onboarding_workbench';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'discovered_onboarding_workbench' 'FastPAS Discovery-to-Onboarding Workbench' @{Discovered = $data.Count;
    Rules = $rules.Count;
    RuleMatches = @($data | Where-Object MatchingRule).Count;
    Duplicates = @($data | Where-Object DuplicateAccountId).Count;
    WithDependencies = @($data | Where-Object DependencyCount -GT 0).Count;
    Ready = @($data | Where-Object { -not $_.DuplicateAccountId }).Count
}
$summary = "Exported $($data.Count) discovered account(s). Edit Action to Onboard or Ignore, add the safe and platform, then run onboarding.discovered.apply."
New-FastPASResult -Success $true -Summary $summary -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
