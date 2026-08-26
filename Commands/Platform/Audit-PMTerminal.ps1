[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$platforms = @(Get-FastPASPagedItems -Context $Context -Path 'Platforms/Targets' -CollectionNames @('Platforms', 'platforms', 'value') -Limit 100);
$rows = [Collections.Generic.List[object]]::new();
$warnings = [Collections.Generic.List[string]]::new()
foreach ($platform in $platforms) {
    $id = Get-FastPASObjectString $platform @('PlatformID', 'platformID', 'id');
    if (-not $id) {
        $general = Get-FastPASPropertyValue $platform @('general', 'General');
        $id = Get-FastPASObjectString $general @('id', 'ID')
    };
    if (-not $id) {
        $warnings.Add('Skipped a platform whose ID could not be determined.');
        continue
    }
    try {
        $details = Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Platforms/$([uri]::EscapeDataString($id))";
        $name = Get-FastPASObjectString (Get-FastPASPropertyValue $details @('Details', 'details')) @('PolicyName', 'policyName');
        if (-not $name) { $name = Get-FastPASObjectString (Get-FastPASPropertyValue $details @('general', 'General')) @('name', 'Name') };
        if (-not $name) { $name = Get-FastPASObjectString $platform @('Name', 'name') $id };
        foreach ($match in @(Find-FastPASStringMatch $details '(?i)pmterminal(?:\.exe)?')) {
            $rows.Add([pscustomobject]@{PlatformId = $id;
                    PlatformName = $name;
                    PropertyPath = $match.PropertyPath;
                    CurrentValue = $match.CurrentValue;
                    ProposedValue = 'CyberArk.TPC.exe'
                })
        }
    }
    catch { $warnings.Add("${id}: $($_.Exception.Message)") }
}
$data = @($rows | Sort-Object PlatformId, PropertyPath);
$csv = Export-FastPASCsv $data $OutputPath 'pmterminal_platform_audit';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'pmterminal_platform_audit' 'FastPAS PMTerminal Platform Audit' @{PlatformsScanned = $platforms.Count;
    Matches = $data.Count;
    Mode = 'Read only'
}
New-FastPASResult -Success $true -Summary "Read-only audit found $($data.Count) PMTerminal setting(s) across $($platforms.Count) platform(s); no platform changes were attempted." -Data $data -Warnings @($warnings) -Artifacts @($csv, $html)
