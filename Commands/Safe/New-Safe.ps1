[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$name = [string]$Arguments['SafeName']
if ([string]::IsNullOrWhiteSpace($name)) { throw 'SafeName is required.' }
if ($name.Length -gt 28) { throw 'SafeName cannot exceed 28 characters.' }
$body = [ordered]@{safeName = $name;
    description = [string]$Arguments['Description'];
    olacEnabled = $false
}
if ($Arguments['ManagingCPM']) { $body.managingCPM = [string]$Arguments['ManagingCPM'] }
if ($Arguments['NumberOfDaysRetention']) { $body.numberOfDaysRetention = [int]$Arguments['NumberOfDaysRetention'] } else { $body.numberOfVersionsRetention = 5 }
if (-not $PSCmdlet.ShouldProcess($name, 'Create CyberArk safe')) {
    return New-FastPASResult -Success $true -Summary "WhatIf: would create safe '$name'." -Data @([pscustomobject]$body)
}
$created = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'Safes' -Body $body
New-FastPASResult -Success $true -Summary "Created safe '$name'." -Data @($created) -AuditEvents @([pscustomobject]@{Action = 'CreateSafe';
        Target = $name
    })
