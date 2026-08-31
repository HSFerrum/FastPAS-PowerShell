[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)

function ConvertTo-LicenseCount {
    param($Value, [string]$FieldName, [string]$LicenseName)

    $number = 0
    if ($null -eq $Value -or -not [int]::TryParse([string]$Value, [ref]$number) -or $number -lt 0) {
        throw "License '$LicenseName' returned an invalid $FieldName value."
    }
    return $number
}

try {
    # Privilege Cloud's documented path is lower-case and case sensitive.
    $response = Invoke-FastPASApiRequest -Context $Context -Method GET -Path 'licenses/pcloud/'
}
catch {
    throw "The Privilege Cloud license report could not be retrieved. It requires a supported Privilege Cloud tenant and a Privilege Cloud Administrator, Basic Administrator, or Lite Administrator role. $($_.Exception.Message)"
}

$componentName = Get-FastPASObjectString $response @('componentName', 'ComponentName') 'Privilege Cloud'
$summary = Get-FastPASPropertyValue $response @('optionalSummary', 'OptionalSummary')
$licenseGroups = @(Get-FastPASPropertyValue $response @('licensesData', 'LicensesData'))
$rows = [Collections.Generic.List[object]]::new()

foreach ($group in $licenseGroups) {
    $category = Get-FastPASObjectString $group @('licenseSubCategory', 'LicenseSubCategory') 'User Types'
    $elements = @(Get-FastPASPropertyValue $group @('licencesElements', 'licenseElements', 'licensesElements', 'LicencesElements', 'LicenseElements'))
    foreach ($element in $elements) {
        $name = Get-FastPASObjectString $element @('name', 'Name')
        if (-not $name) { throw 'The Privilege Cloud license report returned an entry without a license name.' }

        $used = ConvertTo-LicenseCount (Get-FastPASPropertyValue $element @('used', 'Used')) 'used' $name
        $total = ConvertTo-LicenseCount (Get-FastPASPropertyValue $element @('total', 'Total')) 'total' $name
        $available = $total - $used
        $percent = if ($total -gt 0) { [Math]::Round(($used / $total) * 100, 2) } else { 0 }
        $status = if ($total -eq 0 -and $used -eq 0) { 'Not Licensed' }
        elseif ($used -gt $total) { 'Over Capacity' }
        elseif ($used -eq $total) { 'At Capacity' }
        elseif ($percent -ge 90) { 'Critical' }
        elseif ($percent -ge 80) { 'Warning' }
        else { 'Healthy' }

        $rows.Add([pscustomobject][ordered]@{
                Component = $componentName
                Category = $category
                LicenseType = $name
                Used = $used
                Total = $total
                Available = $available
                UtilizationPercent = $percent
                Status = $status
            })
    }
}

if ($rows.Count -eq 0) {
    throw 'The Privilege Cloud license report returned no license records.'
}

$overallName = Get-FastPASObjectString $summary @('name', 'Name') 'License consumption'
$overallUsed = if ($null -ne $summary) { ConvertTo-LicenseCount (Get-FastPASPropertyValue $summary @('used', 'Used')) 'used' $overallName } else { 0 }
$overallTotal = if ($null -ne $summary) { ConvertTo-LicenseCount (Get-FastPASPropertyValue $summary @('total', 'Total')) 'total' $overallName } else { 0 }
$overallAvailable = $overallTotal - $overallUsed
$overallPercent = if ($overallTotal -gt 0) { [Math]::Round(($overallUsed / $overallTotal) * 100, 2) } else { 0 }

$data = @($rows | Sort-Object Category, LicenseType)
$csv = Export-FastPASCsv $data $OutputPath 'license_capacity'
$json = Export-FastPASJson $response $OutputPath 'license_capacity_raw'
$html = Export-FastPASHtmlDashboard $data $OutputPath 'license_capacity' 'FastPAS Privilege Cloud License Capacity' @{
    'Overall used' = $overallUsed
    'Overall capacity' = $overallTotal
    'Overall available' = $overallAvailable
    'Overall utilization' = "$overallPercent%"
    'License types' = $data.Count
    'At or above 80%' = @($data | Where-Object { $_.Total -gt 0 -and $_.UtilizationPercent -ge 80 }).Count
}

$summaryText = "License capacity: $overallUsed of $overallTotal in use ($overallPercent%); $overallAvailable available across the Privilege Cloud summary."
New-FastPASResult -Success $true -Summary $summaryText -Data $data -Artifacts @($csv, $html, $json)
