[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$token = if ($Context.PSObject.Properties['IdentityToken'] -and $Context.IdentityToken) { $Context.IdentityToken }else { $Context.PlatformToken }
if (-not $token) { throw 'The selected authentication flow did not return a token usable for Identity telemetry.' }
$now = [DateTimeOffset]::UtcNow;
$rows = [Collections.Generic.List[object]]::new();
$start = 1;
$count = 200
for ($page = 0;
    $page -lt 50;
    $page++) {
    $uri = "https://$($Context.Profile.IdentityHost)/scim/Users?startIndex=$start&count=$count"
    $response = Invoke-FastPASRawRequest -Method GET -Uri $uri -Headers @{Authorization = "Bearer $token";
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
    Assert-FastPASSuccessResponse $response 'Identity active-user scan'
    $resources = @(Get-FastPASPropertyValue $response.Data @('Resources', 'resources'))
    if (-not $resources.Count) { break }
    foreach ($user in $resources) {
        $username = Get-FastPASObjectString $user @('userName', 'username', 'UserName') 'Unknown user'
        $displayName = Get-FastPASObjectString $user @('displayName', 'DisplayName') $username
        $lastSeen = Get-FastPASObjectString $user @('lastLogin', 'lastLoginDate', 'lastSuccessfulLogin', 'lastLoginTime', 'LastLogin', 'LastLoginDate', 'LastSuccessfulLogin', 'LastLoginTime')
        if (-not $lastSeen) {
            foreach ($property in $user.PSObject.Properties) {
                if ($property.Value -and $property.Value.PSObject) {
                    $lastSeen = Get-FastPASObjectString $property.Value @('lastLogin', 'lastLoginDate', 'lastSuccessfulLogin', 'lastLoginTime');
                    if ($lastSeen) { break }
                }
            }
        }
        $timestamp = $null;
        if ($lastSeen) {
            $parsed = [DateTimeOffset]::MinValue;
            if ([DateTimeOffset]::TryParse($lastSeen, [ref]$parsed)) { $timestamp = $parsed }
        }
        $group = if ($timestamp -and $timestamp -ge $now.AddDays(-7)) { 'Active This Week' }elseif ($timestamp -and $timestamp -ge $now.AddDays(-28)) { 'Inactive 1-4 Weeks' }else { 'Inactive 1+ Month' }
        $active = Get-FastPASPropertyValue $user @('active', 'Active')
        $rows.Add([pscustomobject]@{ActivityGroup = $group;
                Username = $username;
                DisplayName = $displayName;
                Source = 'Identity';
                LastSeen = if ($lastSeen) { $lastSeen }else { 'Never logged in' };
                Enabled = ($active -ne $false);
                Detail = if ($active -eq $false) { 'Identity user is disabled.' }else { 'Identity user activity.' }
            })
    }
    $total = Get-FastPASPropertyValue $response.Data @('totalResults', 'TotalResults');
    $start += $count
    if ($resources.Count -lt $count -or ($total -and $start -gt [int]$total)) { break }
}
$data = @($rows | Sort-Object ActivityGroup, Username)
$activeCount = @($data | Where-Object ActivityGroup -EQ 'Active This Week').Count
$recentCount = @($data | Where-Object ActivityGroup -EQ 'Inactive 1-4 Weeks').Count
$longCount = @($data | Where-Object ActivityGroup -EQ 'Inactive 1+ Month').Count
$csv = Export-FastPASCsv $data $OutputPath 'identity_user_activity'
$html = Export-FastPASHtmlDashboard $data $OutputPath 'identity_user_activity' 'FastPAS Identity User Activity' @{'Active This Week' = $activeCount;
    'Inactive 1-4 Weeks' = $recentCount;
    'Inactive 1+ Month' = $longCount;
    Source = 'Identity SCIM'
}
New-FastPASResult -Success $true -Summary "Classified $($data.Count) Identity user(s): $activeCount active, $recentCount recently inactive, $longCount inactive at least one month." -Data $data -Artifacts @($csv, $html)
