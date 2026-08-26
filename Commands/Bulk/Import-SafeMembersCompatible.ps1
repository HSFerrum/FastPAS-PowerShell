[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing safe-member CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 5000) { throw 'Safe-member imports are limited to 5000 rows.' }
$safes = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -CollectionNames @('value', 'Safes'));
$lookup = @{};
foreach ($safe in $safes) {
    $name = Get-FastPASObjectString $safe @('safeName', 'SafeName');
    $id = Get-FastPASObjectString $safe @('safeUrlId', 'SafeUrlId');
    if ($name -and $id) {
        $lookup[$name] = [pscustomobject]@{Name = $name;
            Id = $id
        }
    }
}
$results = [Collections.Generic.List[object]]::new();
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($item in $items) {
    $safeName = Get-FastPASRowString $item @('SafeName', 'Safename');
    $member = Get-FastPASRowString $item @('UserName', 'Member', 'MemberName');
    $status = 'Added';
    $detail = ''
    try {
        if (-not $safeName -or -not $member) { throw 'SafeName/Safename and UserName/Member are required.' };
        $key = "$safeName`n$member";
        if (-not $seen.Add($key)) { throw 'Duplicate safe/member row in CSV.' };
        if (-not $lookup.ContainsKey($safeName)) { throw "Safe '$safeName' was not found or did not return a safeUrlId." }
        $safeId = $lookup[$safeName].Id;
        $base = "Safes/$([uri]::EscapeDataString($safeId))/Members";
        $exists = $false
        try {
            $null = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "$base/$([uri]::EscapeDataString($member))" -NoRetry;
            $exists = $true
        }
        catch { if ($_.Exception.Message -notmatch 'HTTP 404') { throw } }
        if ($exists) {
            $status = 'Skipped';
            $detail = 'Member already exists; permissions were not overwritten.'
        }
        else {
            $permissions = New-FastPASPermissionsFromCsvRow $item;
            $memberType = Get-FastPASRowString $item @('MemberType');
            if (-not $memberType) {
                $isGroup = Get-FastPASRowString $item @('IsGroup');
                $identityType = Get-FastPASRowString $item @('IdentityType');
                $memberType = if ($isGroup -match '^(?i:true|yes|1)$' -or $identityType -match '^(?i:group)$') { 'group' }else { 'user' }
            }
            if ($memberType -notmatch '^(?i:user|group)$') { throw "MemberType '$memberType' must be user or group." };
            $location = Get-FastPASRowString $item @('MemberLocation', 'UserLocation', 'SearchIn')
            $body = [ordered]@{memberName = $member;
                memberType = $memberType.ToLowerInvariant();
                permissions = $permissions
            };
            if ($location -and $location -notmatch '^(?i:vault)$') { $body.searchIn = $location }
            if (-not $PSCmdlet.ShouldProcess("$member on $safeName", 'Add missing safe member with CSV permissions')) {
                $status = 'WhatIf';
                $detail = 'No mutation was sent.'
            }
            else {
                $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path $base -Body $body;
                $detail = 'Member added with explicit CSV permissions.'
            }
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{SafeName = $safeName;
            MemberName = $member;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'safe_member_import_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
$addedCount = @($data | Where-Object Status -EQ 'Added').Count
$skippedCount = @($data | Where-Object Status -EQ 'Skipped').Count
$summary = "Safe-member import: $addedCount added, $skippedCount skipped, $failed failed."
New-FastPASResult -Success ($failed -eq 0) -Summary $summary -Data $data -Artifacts @($csv) -AuditEvents @($data)
