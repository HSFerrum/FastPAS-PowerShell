[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing bulk-safe-members CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 2000) { throw 'Bulk safe-member operations are limited to 2000 rows.' }
foreach ($required in 'Action', 'SafeName', 'MemberName') { if ($items[0].PSObject.Properties.Name -notcontains $required) { throw "The CSV requires a '$required' column." } }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = [string]$item.Action;
    $safeName = [string]$item.SafeName;
    $member = [string]$item.MemberName;
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Add', 'Update', 'Delete')) { throw "Unsupported Action '$action'. Use Add, Update, or Delete." };
        if (-not $safeName -or -not $member) { throw 'SafeName and MemberName are required.' }
        $safe = Resolve-FastPASSafe -Context $Context -SafeName $safeName;
        $safeId = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
        $base = "Safes/$([uri]::EscapeDataString($safeId))/Members"
        if (-not $PSCmdlet.ShouldProcess("$member on $safeName", "$action safe member")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Delete') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "$base/$([uri]::EscapeDataString($member))";
            $detail = 'Member removed.'
        }
        else {
            $role = if ($item.Role) { [string]$item.Role }else { 'Viewer' };
            if ($role -notin @('Viewer', 'Operator', 'Manager')) { throw 'Role must be Viewer, Operator, or Manager.' }
            $body = [ordered]@{memberName = $member;
                searchIn = if ($item.SearchIn) { [string]$item.SearchIn }else { 'Vault' };
                memberType = if ($item.MemberType) { [string]$item.MemberType }else { 'user' };
                permissions = (Get-FastPASSafePermissions $role)
            }
            if ($action -eq 'Add') {
                $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path $base -Body $body
            }
            else {
                $memberPath = "$base/$([uri]::EscapeDataString($member))"
                $null = Invoke-FastPASApiRequest -Context $Context -Method PUT -Path $memberPath -Body $body
            }
            $detail = "Member $($action.ToLowerInvariant()) completed with $role permissions."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{Action = $action;
            SafeName = $safeName;
            MemberName = $member;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'bulk_safe_members_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Bulk safe-member operation complete: $($data.Count-$failed) succeeded/previewed, $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
