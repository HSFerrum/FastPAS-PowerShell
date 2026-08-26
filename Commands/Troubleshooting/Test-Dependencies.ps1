[CmdletBinding(SupportsShouldProcess = $true)]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$checks = @(
    [pscustomobject]@{Check = 'PowerShell version';
        Status = if ($PSVersionTable.PSVersion.Major -ge 7) { 'Passed' }else { 'Failed' };
        Detected = $PSVersionTable.PSVersion.ToString();
        Required = '7.0 or newer'
    }
    [pscustomobject]@{Check = 'TLS 1.2 support';
        Status = if ([Net.SecurityProtocolType]::Tls12) { 'Passed' }else { 'Failed' };
        Detected = [Net.ServicePointManager]::SecurityProtocol;
        Required = 'TLS 1.2'
    }
    [pscustomobject]@{Check = 'Invoke-WebRequest';
        Status = if (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) { 'Passed' }else { 'Failed' };
        Detected = 'PowerShell cmdlet';
        Required = 'Available'
    }
    [pscustomobject]@{Check = 'Profile configuration';
        Status = if ($Context.Profile) { 'Passed' }else { 'Failed' };
        Detected = $Context.Profile.Name;
        Required = 'Selected profile'
    }
    [pscustomobject]@{Check = 'Identity host';
        Status = if (Test-FastPASIdentityHost $Context.Profile.IdentityHost) { 'Passed' }else { 'Warning' };
        Detected = $Context.Profile.IdentityHost;
        Required = 'CyberArk Identity hostname'
    }
    [pscustomobject]@{Check = 'Platform token';
        Status = if ($Context.PlatformToken) { 'Passed' }else { 'Failed' };
        Detected = if ($Context.PlatformToken) { 'Present in memory' }else { 'Missing' };
        Required = 'Runtime only'
    }
)
$csv = Export-FastPASCsv $checks $OutputPath 'dependency_check';
$failed = @($checks | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Dependency check completed with $failed failure(s)." -Data $checks -Artifacts @($csv)
