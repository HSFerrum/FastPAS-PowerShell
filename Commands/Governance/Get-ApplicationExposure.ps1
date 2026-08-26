[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$filter = [string]$Arguments['ApplicationId'];
$warnings = [Collections.Generic.List[string]]::new();
$rows = [Collections.Generic.List[object]]::new()
$aamBase = $Context.Profile.VaultApiBaseUrl -replace '(?i)/API/?$', '/WebServices/PIMServices.svc';
$apps = @(Get-FastPASOptionalItems -Context $Context -Paths @("$aamBase/Applications") -CollectionNames @('value', 'Applications', 'application') -Warnings $warnings)
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -CollectionNames @('value', 'Safes'))
$safeAccess = @{}
foreach ($safe in $safes) {
    $name = Get-FastPASObjectString $safe @('safeName', 'SafeName');
    $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
    if (-not $id) { continue };
    try {
        foreach ($m in @(Get-FastPASPagedItems -Context $Context -Path "Safes/$([uri]::EscapeDataString($id))/Members" -CollectionNames @('value', 'Members'))) {
            $mn = Get-FastPASObjectString $m @('memberName', 'MemberName');
            if (-not $safeAccess.ContainsKey($mn)) { $safeAccess[$mn] = [Collections.Generic.List[string]]::new() };
            $safeAccess[$mn].Add($name)
        }
    }
    catch { $warnings.Add("Application-safe membership could not be checked for '$name': $($_.Exception.Message)") }
}
foreach ($app in $apps) {
    $id = Get-FastPASObjectString $app @('AppID', 'appId', 'applicationId', 'id');
    if ($filter -and $id -ne $filter) { continue }
    $auth = @();
    try {
        $authenticationPath = "$aamBase/Applications/$([uri]::EscapeDataString($id))/Authentications"
        $auth = @(Get-FastPASPagedItems -Context $Context -Path $authenticationPath -CollectionNames @('value', 'Authentications', 'authentication'))
    }
    catch {
        $warnings.Add("Authentication rules for application '$id' were unavailable: $($_.Exception.Message)")
    }
    $safeNames = if ($safeAccess.ContainsKey($id)) { @($safeAccess[$id]) }else { @() };
    $weak = @($auth | Where-Object { (Get-FastPASObjectString $_ @('AuthType', 'authType', 'type')) -match '(?i)path|osuser' -and -not (Get-FastPASPropertyValue $_ @('IsFolder', 'isFolder', 'Hash', 'hash', 'Address', 'address')) })
    if (-not $auth.Count) {
        $rows.Add([pscustomobject]@{ApplicationId = $id;
                Description = Get-FastPASObjectString $app @('Description', 'description');
                AuthenticationType = 'None returned';
                AuthenticationDetail = '';
                Safes = ($safeNames -join ';');
                SafeCount = $safeNames.Count;
                Risk = 'High';
                Finding = 'No authentication rule was returned.'
            });
        continue
    }
    foreach ($rule in $auth) {
        $type = Get-FastPASObjectString $rule @('AuthType', 'authType', 'type');
        $rows.Add([pscustomobject]@{ApplicationId = $id;
                Description = Get-FastPASObjectString $app @('Description', 'description');
                AuthenticationType = $type;
                AuthenticationDetail = ($rule | ConvertTo-Json -Compress -Depth 20);
                Safes = ($safeNames -join ';');
                SafeCount = $safeNames.Count;
                Risk = if ($weak -contains $rule -or $safeNames.Count -gt 20) { 'High' }elseif ($safeNames.Count -gt 5) { 'Medium' }else { 'Low' };
                Finding = if ($weak -contains $rule) { 'Rule appears to rely on a broad single factor.' }elseif ($safeNames.Count -gt 20) { 'Application can reach many safes.' }else { 'Review against the approved application baseline.' }
            })
    }
}
$data = @($rows | Sort-Object Risk, ApplicationId, AuthenticationType);
$applicationCount = @($data | ForEach-Object ApplicationId | Where-Object { $_ } | Sort-Object -Unique).Count;
$csv = Export-FastPASCsv $data $OutputPath 'application_exposure';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'application_exposure' 'FastPAS Application ID and Credential Provider Exposure' @{Applications = $applicationCount;
    Rules = $data.Count;
    HighRisk = @($data | Where-Object Risk -EQ High).Count;
    Safes = $safes.Count
}
New-FastPASResult -Success $true -Summary "Assessed $applicationCount application ID(s). Unsupported Privilege Cloud application endpoints are reported as warnings, not hidden." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
