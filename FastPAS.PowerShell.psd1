@{
    RootModule        = 'FastPAS.PowerShell.psm1'
    ModuleVersion     = '0.4.0'
    GUID              = 'd98e87b0-6945-4cec-b66d-b34eeceafc2c'
    Author            = 'FastPAS'
    CompanyName       = 'FastPAS'
    Copyright         = '(c) FastPAS. All rights reserved.'
    Description       = 'PowerShell 7 orchestration toolkit for Idira/CyberArk ISPSS, on-premises PAM, and standalone Privilege Cloud.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Connect-FastPAS',
        'Disconnect-FastPAS',
        'Get-FastPASCommand',
        'Get-FastPASMenuSection',
        'Get-FastPASProfile',
        'Invoke-FastPASApiRequest',
        'Invoke-FastPASCommand',
        'New-FastPASProfile',
        'Remove-FastPASProfile',
        'Resolve-FastPASTenant',
        'Set-FastPASActiveProfile'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('CyberArk', 'Idira', 'PAM', 'Security', 'PowerShell')
            ProjectUri = 'https://github.com/HSFerrum/FastPAS-PowerShell'
        }
    }
}
