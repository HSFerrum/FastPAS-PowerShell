[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an application-authentication-changes CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no changes.' };
$results = [Collections.Generic.List[object]]::new();
$aamBase = $Context.Profile.VaultApiBaseUrl -replace '(?i)/API/?$', '/WebServices/PIMServices.svc'
foreach ($item in $items) {
    $action = Get-FastPASRowString $item @('Action');
    $app = Get-FastPASRowString $item @('ApplicationId');
    $authId = Get-FastPASRowString $item @('AuthenticationId');
    $status = 'Completed';
    $detail = '';
    try {
        if ($action -notin @('Add', 'Delete')) { throw 'Action must be Add or Delete.' };
        if (-not $app) { throw 'ApplicationId is required.' };
        if ($action -eq 'Delete' -and -not $authId) { throw 'AuthenticationId is required for Delete.' };
        $authType = Get-FastPASRowString $item @('AuthType')
        $authValue = Get-FastPASRowString $item @('AuthValue')
        $authentication = $null
        if ($action -eq 'Add') {
            if (-not $authType -or -not $authValue) { throw 'AuthType and AuthValue are required for Add.' };
            $authentication = [ordered]@{AuthType = $authType; AuthValue = $authValue}
            $isFolder = Get-FastPASRowString $item @('IsFolder')
            $allowInternalScripts = Get-FastPASRowString $item @('AllowInternalScripts')
            if ($isFolder) { $authentication.IsFolder = ConvertTo-FastPASStrictBoolean $isFolder 'IsFolder' }
            if ($allowInternalScripts) { $authentication.AllowInternalScripts = ConvertTo-FastPASStrictBoolean $allowInternalScripts 'AllowInternalScripts' }
        }
        $target = if ($authId) { "$app/$authId" }else { "$app/$authType" };
        if (-not $PSCmdlet.ShouldProcess($target, "$action application authentication rule")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Delete') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "$aamBase/Applications/$([uri]::EscapeDataString($app))/Authentications/$([uri]::EscapeDataString($authId))";
            $detail = 'Authentication rule deleted.'
        }
        else {
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "$aamBase/Applications/$([uri]::EscapeDataString($app))/Authentications" -Body @{authentication = $authentication };
            $detail = 'Authentication rule added.'
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{Action = $action;
            ApplicationId = $app;
            AuthenticationId = $authId;
            AuthType = Get-FastPASRowString $item @('AuthType');
            AuthValue = Get-FastPASRowString $item @('AuthValue');
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'application_authentication_change_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) application authentication change(s): $failed failed. Endpoint availability depends on deployment type." -Data $data -Artifacts @($csv) -AuditEvents @($data)
