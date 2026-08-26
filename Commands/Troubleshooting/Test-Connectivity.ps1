[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$vaultHost = ([uri]$Context.Profile.VaultApiBaseUrl).Host
$targets = @(
    [pscustomobject]@{Service = 'CyberArk Identity';
        Host = $Context.Profile.IdentityHost;
        Source = 'Profile'
    }
    [pscustomobject]@{Service = 'Privilege Cloud / Vault API';
        Host = $vaultHost;
        Source = 'Profile'
    }
    [pscustomobject]@{Service = 'Shared Services';
        Host = "$($Context.Profile.Subdomain).cyberark.cloud";
        Source = 'Tenant-derived'
    }
)
$endpointCsvPath = [string]$Arguments['EndpointCsvPath']
if ($endpointCsvPath) {
    if (-not(Test-Path -LiteralPath $endpointCsvPath -PathType Leaf)) { throw 'EndpointCsvPath must identify an existing outbound-endpoints CSV file.' }
    foreach ($custom in @(Import-Csv -LiteralPath $endpointCsvPath)) {
        $parsed = $null;
        $validEndpoint = [uri]::TryCreate([string]$custom.Endpoint, [UriKind]::Absolute, [ref]$parsed)
        if (-not $validEndpoint -or $parsed.Scheme -ne 'https' -or $parsed.IsLoopback) {
            throw "Custom endpoint '$($custom.Endpoint)' must be an absolute, non-local HTTPS URL."
        }
        $targets += [pscustomobject]@{Service = if ($custom.Service) { [string]$custom.Service }else { 'Custom CyberArk endpoint' };
            Host = $parsed.Host;
            Source = 'Custom CSV'
        }
    }
}
$rows = [Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    $status = 'Failed';
    $stage = 'DNS';
    $detail = '';
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try {
        $addresses = @([Net.Dns]::GetHostAddresses($target.Host));
        if (-not $addresses.Count) { throw 'DNS returned no addresses.' };
        $stage = 'TCP/443'
        $client = [Net.Sockets.TcpClient]::new();
        try {
            $task = $client.ConnectAsync($target.Host, 443);
            if (-not $task.Wait(5000)) { throw 'TCP/443 connection timed out after five seconds.' };
            $status = 'Passed';
            $detail = "Resolved to $($addresses[0]) and connected to TCP/443."
        }
        finally { $client.Dispose() }
    }
    catch { $detail = $_.Exception.Message }
    $elapsed.Stop();
    $rows.Add([pscustomobject]@{Service = $target.Service;
            Endpoint = "https://$($target.Host):443";
            Source = $target.Source;
            Status = $status;
            Stage = $stage;
            ElapsedMs = $elapsed.ElapsedMilliseconds;
            Detail = $detail
        })
}
if (-not @($targets | Where-Object Service -Match 'SIA|Secure Infrastructure').Count) {
    $rows.Add([pscustomobject]@{Service = 'Secure Infrastructure Access';
            Endpoint = 'Tenant-specific';
            Source = 'Not configured in profile';
            Status = 'Unknown';
            Stage = 'Configuration';
            ElapsedMs = 0;
            Detail = 'Supply the documented SIA URL in outbound-endpoints.csv; FastPAS will not guess product-region hosts.'
        })
}
$data = @($rows);
$csv = Export-FastPASCsv $data $OutputPath 'connectivity_diagnostic';
$html = Export-FastPASHtmlDashboard $data $OutputPath 'connectivity_diagnostic' 'FastPAS Connectivity Diagnostic' @{Passed = @($data | Where-Object Status -EQ 'Passed').Count;
    Failed = @($data | Where-Object Status -EQ 'Failed').Count;
    Unknown = @($data | Where-Object Status -EQ 'Unknown').Count
}
$passedCount = @($data | Where-Object Status -EQ 'Passed').Count
$failedCount = @($data | Where-Object Status -EQ 'Failed').Count
$unknownCount = @($data | Where-Object Status -EQ 'Unknown').Count
$summary = "Connectivity diagnostic: $passedCount passed, $failedCount failed, $unknownCount unknown."
New-FastPASResult -Success ($failedCount -eq 0) -Summary $summary -Data $data -Artifacts @($csv, $html)
