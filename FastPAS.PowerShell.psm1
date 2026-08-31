#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleRoot = $PSScriptRoot
$script:ConfigSchemaVersion = 3
$script:SecretTargetPrefix = 'FastPAS.PowerShell/profile/'
$script:SensitiveNames = @('Authorization', 'client_secret', 'password', 'secret', 'token', 'answer')

function Get-FastPASDataRoot {
    if ($env:FASTPAS_DATA_ROOT) { return [IO.Path]::GetFullPath($env:FASTPAS_DATA_ROOT) }
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FastPAS.PowerShell'
}

function Get-FastPASConfigPath { Join-Path (Get-FastPASDataRoot) 'profiles.json' }
function Get-FastPASAuditPath { Join-Path (Join-Path (Get-FastPASDataRoot) 'logs') 'operations.jsonl' }

function Test-FastPASIdentityHost {
    param([string]$HostName)
    $clean = $HostName.Trim().Trim('/').ToLowerInvariant()
    return $clean.EndsWith('.id.cyberark.cloud') -or $clean.EndsWith('.my.idaptive.app')
}

<#
.SYNOPSIS
Discovers the CyberArk Identity host and Vault API URL for a tenant subdomain.
#>
function Resolve-FastPASTenant {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]+$')][string]$Subdomain)
    $clean = $Subdomain.Trim().ToLowerInvariant()
    $candidates = @(
        "https://$clean.cyberark.cloud",
        "https://$clean-userportal.cyberark.cloud",
        "https://$clean.privilegecloud.cyberark.cloud"
    )
    $identityHost = $null
    foreach ($candidate in $candidates) {
        try {
            $response = Invoke-WebRequest -Uri $candidate -Method GET -MaximumRedirection 10 -TimeoutSec 6 -UserAgent 'FastPAS.PowerShell/0.1.0' -SkipHttpErrorCheck -ErrorAction Stop
            $finalHost = $response.BaseResponse.RequestMessage.RequestUri.Host
            if (Test-FastPASIdentityHost $finalHost) {
                $identityHost = $finalHost.ToLowerInvariant();
                break
            }
            $hostMatches = [regex]::Matches([string]$response.Content, '(?i)([a-z0-9][a-z0-9.-]*\.(?:id\.cyberark\.cloud|my\.idaptive\.app))')
            foreach ($match in $hostMatches) {
                if (Test-FastPASIdentityHost $match.Groups[1].Value) {
                    $identityHost = $match.Groups[1].Value.ToLowerInvariant();
                    break
                }
            }
            if ($identityHost) { break }
        }
        catch { continue }
    }
    if (-not $identityHost) { throw "Could not discover the Identity host for tenant '$clean' from its shared-services, user-portal, or Privilege Cloud endpoints." }
    [pscustomobject]@{
        Subdomain = $clean;
        IdentityHost = $identityHost;
        IdentityHostDiscovered = $true
        SharedServicesUrl = "https://$clean.cyberark.cloud"
        VaultApiBaseUrl = "https://$clean.privilegecloud.cyberark.cloud/PasswordVault/API"
        IdentityTokenUrlPrefix = "https://$identityHost/oauth2/token"
        PlatformTokenUrl = "https://$identityHost/oauth2/platformtoken"
    }
}

function Initialize-FastPASLegacyCredentialCleanupApi {
    if ('FastPAS.Native.LegacyCredentialCleanup' -as [type]) { return }
    if (-not $IsWindows) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FastPAS.Native {
    public static class LegacyCredentialCleanup {
        [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool CredDelete(string target, UInt32 type, UInt32 flags);

        public static void Delete(string target) {
            if (!CredDelete(target, 1, 0)) {
                int error = Marshal.GetLastWin32Error();
                if (error != 1168) throw new Win32Exception(error);
            }
        }
    }
}
'@
}

function ConvertFrom-FastPASSecureString {
    param([Parameter(Mandatory)][Security.SecureString]$SecureString)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Remove-FastPASLegacyCredential {
    param([Parameter(Mandatory)][string]$ProfileId)
    if (-not $IsWindows) { return }
    Initialize-FastPASLegacyCredentialCleanupApi
    [FastPAS.Native.LegacyCredentialCleanup]::Delete("$script:SecretTargetPrefix$ProfileId")
}

function New-FastPASDefaultConfig {
    [ordered]@{ schemaVersion = $script:ConfigSchemaVersion;
        activeProfileId = $null;
        profiles = @()
    }
}

function Resolve-FastPASPVWAUrl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Url)
    $candidate = $Url.Trim().TrimEnd('/')
    if ($candidate -notmatch '^https://') { throw 'PVWA and Privilege Cloud URLs must be absolute HTTPS URLs.' }
    $parsed = $null
    if (-not [uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$parsed) -or -not $parsed.Host -or $parsed.UserInfo) {
        throw "PVWA URL '$Url' is invalid."
    }
    if ($parsed.Query -or $parsed.Fragment) { throw 'PVWA URL cannot contain a query string or fragment.' }
    $path = $parsed.AbsolutePath.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($path) -or $path -eq '/') { $path = '/PasswordVault' }
    elseif ($path -notmatch '(?i)/PasswordVault$') {
        if ($path -match '(?i)/PasswordVault/API$') { $path = $path.Substring(0, $path.Length - 4) }
        else { throw 'PVWA URL must be the server root or end with /PasswordVault (not an arbitrary application path).' }
    }
    return "$($parsed.Scheme)://$($parsed.Authority)$path"
}

function Get-FastPASDeploymentCapabilities {
    param([Parameter(Mandatory)][ValidateSet('ispss', 'onprem', 'standalone')][string]$DeploymentType)
    [pscustomobject]@{
        DeploymentType = $DeploymentType
        VaultApi = $true
        IdentityApi = ($DeploymentType -eq 'ispss')
        DirectPVWALogon = ($DeploymentType -ne 'ispss')
        SelfHosted = ($DeploymentType -eq 'onprem')
        PrivilegeCloud = ($DeploymentType -in @('ispss', 'standalone'))
    }
}

function Read-FastPASConfig {
    $path = Get-FastPASConfigPath
    if (-not (Test-Path -LiteralPath $path)) { return New-FastPASDefaultConfig }
    try { $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -Depth 20 }
    catch { throw "FastPAS profile configuration is invalid: $($_.Exception.Message)" }
    if ($config.schemaVersion -eq 1) {
        foreach ($storedProfile in @($config.profiles)) {
            try { Remove-FastPASLegacyCredential -ProfileId $storedProfile.id } catch { Write-Warning "Could not remove the legacy saved credential for profile '$($storedProfile.name)': $($_.Exception.Message)" }
            $storedProfile.Remove('secretStored')
        }
        $config.schemaVersion = 2
    }
    if ($config.schemaVersion -eq 2) {
        foreach ($storedProfile in @($config.profiles)) {
            if (-not $storedProfile.ContainsKey('deploymentType')) { $storedProfile.deploymentType = 'ispss' }
            if (-not $storedProfile.ContainsKey('skipCertificateCheck')) { $storedProfile.skipCertificateCheck = $false }
        }
        $config.schemaVersion = $script:ConfigSchemaVersion
        Write-FastPASConfig $config
    }
    if ($config.schemaVersion -ne $script:ConfigSchemaVersion) { throw "Unsupported FastPAS profile schema version '$($config.schemaVersion)'." }
    if (-not $config.ContainsKey('profiles')) { $config.profiles = @() }
    return $config
}

function Write-FastPASConfig {
    param([Parameter(Mandatory)][hashtable]$Config)
    $path = Get-FastPASConfigPath
    $directory = Split-Path -Parent $path
    $null = New-Item -ItemType Directory -Path $directory -Force
    $temporary = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
        Move-Item -LiteralPath $temporary -Destination $path -Force
    }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

<#
.SYNOPSIS
Lists saved FastPAS connection profiles or returns one selected profile.
#>
function Get-FastPASProfile {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'ById')][string]$Id,
        [Parameter(ParameterSetName = 'ByName')][string]$Name,
        [switch]$Active
    )
    $config = Read-FastPASConfig
    $profiles = @($config.profiles | ForEach-Object { [pscustomobject]$_ })
    if ($Active) { return $profiles | Where-Object Id -EQ $config.activeProfileId | Select-Object -First 1 }
    if ($Id) { return $profiles | Where-Object Id -EQ $Id | Select-Object -First 1 }
    if ($Name) { return $profiles | Where-Object Name -EQ $Name | Select-Object -First 1 }
    return $profiles
}

<#
.SYNOPSIS
Saves a metadata-only tenant profile without storing a password or client secret.
#>
function New-FastPASProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [ValidateSet('ispss', 'onprem', 'standalone')][string]$DeploymentType = 'ispss',
        [AllowEmptyString()][ValidatePattern('^$|^[a-zA-Z0-9-]+$')][string]$Subdomain,
        [string]$IdentityHost,
        [Parameter(Mandatory)][ValidateSet('oauth', 'interactive', 'federated', 'eidp', 'cyberark', 'ldap', 'radius', 'windows')][string]$AuthType,
        [string]$ApplicationId, [string]$ClientId, [string]$Username,
        [string]$VaultApiBaseUrl, [string]$PVWAUrl,
        [string]$RadiusOtpDelimiter = ',', [switch]$SkipCertificateCheck,
        [switch]$SetActive
    )
    $config = Read-FastPASConfig
    if (@($config.profiles | Where-Object { $_.name -eq $Name }).Count) { throw "A profile named '$Name' already exists." }
    if ($AuthType -eq 'eidp') { $AuthType = 'federated' }
    if ($SkipCertificateCheck -and $DeploymentType -ne 'onprem') { throw 'SkipCertificateCheck is permitted only for explicitly approved on-premises profiles.' }
    if ($DeploymentType -eq 'ispss') {
        if ([string]::IsNullOrWhiteSpace($Subdomain)) { throw 'ISPSS profiles require the tenant subdomain.' }
        if ($AuthType -notin @('oauth', 'interactive', 'federated')) { throw "ISPSS profiles do not support '$AuthType' authentication. Choose oauth, interactive, or federated." }
        if ($AuthType -eq 'oauth' -and ([string]::IsNullOrWhiteSpace($ApplicationId) -or [string]::IsNullOrWhiteSpace($ClientId))) { throw 'ISPSS OAuth profiles require ApplicationId and ClientId.' }
        if ($AuthType -in @('interactive', 'federated') -and [string]::IsNullOrWhiteSpace($Username)) { throw 'ISPSS interactive and federated profiles require Username.' }
        if ([string]::IsNullOrWhiteSpace($IdentityHost)) { $IdentityHost = (Resolve-FastPASTenant -Subdomain $Subdomain).IdentityHost }
        $IdentityHost = $IdentityHost.Trim() -replace '^https?://', '' -replace '/.*$', ''
        if (-not (Test-FastPASIdentityHost $IdentityHost)) { throw "Identity host '$IdentityHost' is not a supported CyberArk Identity hostname." }
        if (-not $VaultApiBaseUrl) { $VaultApiBaseUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault/API" }
        $PVWAUrl = Resolve-FastPASPVWAUrl $VaultApiBaseUrl
        $VaultApiBaseUrl = "$PVWAUrl/API"
    }
    else {
        if ($AuthType -notin @('cyberark', 'ldap', 'radius', 'windows')) { throw "$DeploymentType profiles require cyberark, ldap, radius, or windows authentication." }
        if ([string]::IsNullOrWhiteSpace($PVWAUrl)) {
            if ($VaultApiBaseUrl) { $PVWAUrl = $VaultApiBaseUrl -replace '(?i)/API/?$', '' }
            else { throw "$DeploymentType profiles require the PVWA URL. Use the address that opens Password Vault Web Access, for example https://pvwa.example.com/PasswordVault." }
        }
        $PVWAUrl = Resolve-FastPASPVWAUrl $PVWAUrl
        $VaultApiBaseUrl = "$PVWAUrl/API"
        if ([string]::IsNullOrWhiteSpace($Username)) { throw "$DeploymentType profiles require the Vault username." }
        $IdentityHost = $null
        $ApplicationId = $null
        $ClientId = $null
        $Subdomain = $null
    }
    $id = [guid]::NewGuid().ToString()
    $now = [DateTimeOffset]::UtcNow.ToString('o')
    $profileRecord = [ordered]@{
        id = $id;
        name = $Name.Trim();
        deploymentType = $DeploymentType;
        authType = $AuthType;
        subdomain = $(if ($Subdomain) { $Subdomain.ToLowerInvariant() }else { $null });
        identityHost = $IdentityHost
        pvwaUrl = $PVWAUrl;
        vaultApiBaseUrl = $VaultApiBaseUrl.TrimEnd('/');
        applicationId = $ApplicationId;
        clientId = $ClientId;
        username = $Username
        radiusOtpDelimiter = $RadiusOtpDelimiter;
        skipCertificateCheck = [bool]$SkipCertificateCheck
        createdAt = $now;
        updatedAt = $now
    }
    $config.profiles = @($config.profiles) + $profileRecord
    if ($SetActive -or -not $config.activeProfileId) { $config.activeProfileId = $id }
    Write-FastPASConfig $config
    return [pscustomobject]$profileRecord
}

<#
.SYNOPSIS
Selects the saved profile used when no profile ID is supplied at connection time.
#>
function Set-FastPASActiveProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProfileId)
    $config = Read-FastPASConfig
    if (-not @($config.profiles | Where-Object id -EQ $ProfileId).Count) { throw "Profile '$ProfileId' was not found." }
    $config.activeProfileId = $ProfileId
    Write-FastPASConfig $config
    Get-FastPASProfile -Id $ProfileId
}

<#
.SYNOPSIS
Deletes one saved profile after PowerShell confirmation.
#>
function Remove-FastPASProfile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$ProfileId)
    $config = Read-FastPASConfig
    $profileRecord = @($config.profiles | Where-Object id -EQ $ProfileId) | Select-Object -First 1
    if (-not $profileRecord) { return }
    if ($PSCmdlet.ShouldProcess($profileRecord.name, 'Delete FastPAS profile')) {
        $config.profiles = @($config.profiles | Where-Object id -NE $ProfileId)
        if ($config.activeProfileId -eq $ProfileId) {
            $nextProfile = @($config.profiles | Select-Object -First 1)
            $config.activeProfileId = if ($nextProfile.Count) { $nextProfile[0].id }else { $null }
        }
        Write-FastPASConfig $config
        # Remove credentials written by FastPAS versions prior to schema v2.
        Remove-FastPASLegacyCredential $ProfileId
    }
}

function Get-FastPASPropertyValue {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string[]]$Name)
    if ($null -eq $InputObject) { return $null }
    foreach ($candidate in $Name) {
        if ($InputObject -is [Collections.IDictionary]) {
            $matchingKey = $InputObject.Keys | Where-Object { [string]$_ -ieq $candidate } | Select-Object -First 1
            if ($null -ne $matchingKey) { return $InputObject[$matchingKey] }
        }
        $property = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $candidate } | Select-Object -First 1
        if ($property) { return $property.Value }
    }
    return $null
}

function ConvertFrom-FastPASResponseContent {
    param([AllowEmptyString()][string]$Content)
    if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
    try { return $Content | ConvertFrom-Json -Depth 100 }
    catch { return $Content }
}

function Invoke-FastPASRawRequest {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        $Body,
        [string]$ContentType = 'application/json',
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [switch]$SkipCertificateCheck
    )
    $parameters = @{ Method = $Method;
        Uri = $Uri;
        Headers = $Headers;
        SkipHttpErrorCheck = $true;
        ErrorAction = 'Stop'
    }
    if ($WebSession) { $parameters.WebSession = $WebSession }
    if ($SkipCertificateCheck) { $parameters.SkipCertificateCheck = $true }
    if ($null -ne $Body) {
        $parameters.ContentType = $ContentType
        $parameters.Body = if ($ContentType -eq 'application/json' -and $Body -isnot [string]) { $Body | ConvertTo-Json -Depth 30 -Compress } else { $Body }
    }
    try { $response = Invoke-WebRequest @parameters }
    catch { throw "Request to $Uri failed before receiving an HTTP response: $($_.Exception.Message)" }
    [pscustomobject]@{ StatusCode = [int]$response.StatusCode;
        Uri = $Uri;
        Headers = $response.Headers;
        Data = (ConvertFrom-FastPASResponseContent $response.Content);
        Raw = $response.Content
    }
}

function Invoke-FastPASPVWAAuthentication {
    param(
        [Parameter(Mandatory)]$ProfileRecord,
        [Parameter(Mandatory)][Security.SecureString]$Secret,
        [Security.SecureString]$OneTimePassword,
        [switch]$NonInteractive
    )
    $provider = switch ([string]$ProfileRecord.AuthType) {
        'cyberark' { 'CyberArk' }
        'ldap' { 'LDAP' }
        'radius' { 'RADIUS' }
        'windows' { 'Windows' }
        default { throw "Unsupported PVWA authentication type '$($ProfileRecord.AuthType)'." }
    }
    $plain = ConvertFrom-FastPASSecureString $Secret
    $otpPlain = $null
    $ownsOneTimePassword = $false
    try {
        if ($provider -eq 'RADIUS') {
            if ($null -eq $OneTimePassword) {
                if ($NonInteractive) { throw 'RADIUS authentication requires a fresh runtime -OneTimePassword when -NonInteractive is used.' }
                $OneTimePassword = Read-Host 'RADIUS one-time password / push keyword' -AsSecureString
                $ownsOneTimePassword = $true
            }
            $otpPlain = ConvertFrom-FastPASSecureString $OneTimePassword
            if (-not [string]::IsNullOrWhiteSpace($otpPlain)) {
                $delimiter = [string]$ProfileRecord.RadiusOtpDelimiter
                $plain = "$plain$delimiter$otpPlain"
            }
        }
        $response = Invoke-FastPASRawRequest -Method POST -Uri "$($ProfileRecord.VaultApiBaseUrl)/Auth/$provider/Logon" -Body @{
            username = $ProfileRecord.Username
            password = $plain
            concurrentSession = $true
        } -SkipCertificateCheck:([bool]$ProfileRecord.SkipCertificateCheck)
        Assert-FastPASSuccessResponse $response "$provider PVWA authentication"
        $token = if ($response.Data -is [string]) { [string]$response.Data }else { Get-FastPASTokenFromResponse $response.Data }
        if ([string]::IsNullOrWhiteSpace($token)) { throw "$provider PVWA authentication succeeded without returning a session token." }
        return $token.Trim()
    }
    finally {
        $plain = $null
        $otpPlain = $null
        if ($ownsOneTimePassword -and $OneTimePassword) { $OneTimePassword.Dispose() }
    }
}

function Get-FastPASTokenFromResponse {
    param($Response)
    foreach ($name in 'access_token', 'token', 'Token', 'CyberArkLogonResult') {
        $value = Get-FastPASPropertyValue $Response @($name)
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return [string]$value }
    }
    foreach ($name in 'Result', 'result') {
        $nested = Get-FastPASPropertyValue $Response @($name)
        if ($nested) {
            $token = Get-FastPASTokenFromResponse $nested
            if ($token) { return $token }
        }
    }
    return $null
}

function Assert-FastPASSuccessResponse {
    param($Response, [string]$Operation)
    if ($Response.StatusCode -lt 200 -or $Response.StatusCode -ge 300) {
        $detail = if ($Response.Raw) { $Response.Raw.Substring(0, [Math]::Min(2000, $Response.Raw.Length)) } else { 'No response body.' }
        throw "$Operation failed with HTTP $($Response.StatusCode). $detail"
    }
}

function Assert-FastPASInteractivePayload {
    param($Data, [string]$Operation = 'Interactive authentication')
    $success = Get-FastPASPropertyValue $Data @('success', 'Success')
    if ($null -ne $success -and -not [bool]$success) {
        $message = Get-FastPASObjectString -InputObject $Data -Name @('Message', 'message') -Default 'CyberArk rejected the authentication step.'
        $errorId = Get-FastPASObjectString -InputObject $Data -Name @('ErrorID', 'errorId')
        $summary = Get-FastPASObjectString -InputObject (Get-FastPASPropertyValue $Data @('Result', 'result')) -Name @('Summary', 'summary')
        $detail = "$Operation failed: $message"
        if ($summary) { $detail += " (Summary: $summary)" };
        if ($errorId) { $detail += " [ErrorID: $errorId]" }
        throw $detail
    }
}

function Read-FastPASChallengeAnswer {
    param([string]$Prompt = 'MFA answer/code')
    $secureAnswer = Read-Host $Prompt -AsSecureString
    if ($secureAnswer -is [Security.SecureString]) {
        try { return ConvertFrom-FastPASSecureString $secureAnswer }finally { $secureAnswer.Dispose() }
    }
    return [string]$secureAnswer
}

function Get-FastPASChallengeMechanisms {
    param($InputObject)
    $found = [Collections.Generic.List[object]]::new()
    function Visit($value) {
        if ($null -eq $value) { return }
        if ($value -is [string] -or $value -is [ValueType]) { return }
        $id = Get-FastPASPropertyValue $value @('MechanismId', 'mechanismId')
        if ($id) {
            $found.Add($value);
            return
        }
        if ($value -is [Collections.IEnumerable]) {
            foreach ($item in $value) { Visit $item };
            return
        }
        foreach ($property in $value.PSObject.Properties) { Visit $property.Value }
    }
    Visit $InputObject
    return @($found)
}

function Get-FastPASChallengeSets {
    param($InputObject)
    $result = Get-FastPASPropertyValue $InputObject @('Result', 'result')
    $challenges = @(Get-FastPASPropertyValue $result @('Challenges', 'challenges'))
    $sets = [Collections.Generic.List[object]]::new()
    foreach ($challenge in $challenges) {
        $mechanisms = @(Get-FastPASPropertyValue $challenge @('Mechanisms', 'mechanisms'))
        if ($mechanisms.Count) { $sets.Add($mechanisms) }
    }
    return @($sets)
}

function Get-FastPASMechanismActions {
    param($Mechanism)
    $actions = [Collections.Generic.List[string]]::new()
    foreach ($rawAction in @(Get-FastPASPropertyValue $Mechanism @('Actions', 'actions'))) {
        $name = if ($rawAction -is [string]) { [string]$rawAction }else { Get-FastPASObjectString $rawAction @('Name', 'name') }
        if ($name -and -not $actions.Contains($name)) { $actions.Add($name) }
    }
    $name = Get-FastPASObjectString $Mechanism @('Name', 'name')
    $prompt = Get-FastPASObjectString $Mechanism @('PromptSelectMech', 'PromptMechChosen', 'Prompt', 'prompt')
    $answerType = Get-FastPASObjectString $Mechanism @('AnswerType', 'answerType')
    $hint = "$name $prompt $answerType".ToLowerInvariant()
    if (($answerType -ieq 'StartTextOob' -or $hint -match 'sms|email|message') -and -not $actions.Contains('StartTextOob')) { $actions.Add('StartTextOob') }
    if (($answerType -ieq 'StartOOB' -or $hint -match 'mobile|push|\boob\b|\bapp\b') -and -not $actions.Contains('StartOOB')) { $actions.Add('StartOOB') }
    if (($answerType -in @('Text', 'Numeric') -or $hint -match 'otp|code|answer|password') -and -not $actions.Contains('Answer')) { $actions.Add('Answer') }
    if (-not $actions.Count) {
        $actions.Add('Answer');
        $actions.Add('Poll')
    }
    return @($actions)
}

function Test-FastPASFederatedRedirectUrl {
    param([string]$Url)
    $parsed = $null
    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed)) { return $false }
    return $parsed.Scheme -eq 'https' -and -not $parsed.IsLoopback -and [string]::IsNullOrWhiteSpace($parsed.UserInfo) -and -not [string]::IsNullOrWhiteSpace($parsed.Host)
}

function Start-FastPASIdentityAuthentication {
    param([Parameter(Mandatory)]$ProfileRecord, [Parameter(Mandatory)][hashtable]$Headers)

    $baseUrl = "https://$($ProfileRecord.IdentityHost)"
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $start = Invoke-FastPASRawRequest -Method POST -Uri "$baseUrl/Security/StartAuthentication" -Headers $Headers -Body @{
            User = $ProfileRecord.Username
            Version = '1.0'
            TenantId = $ProfileRecord.Subdomain
        } -WebSession $webSession
        Assert-FastPASSuccessResponse $start 'StartAuthentication'
        Assert-FastPASInteractivePayload $start.Data 'StartAuthentication'

        $result = Get-FastPASPropertyValue $start.Data @('Result', 'result')
        $podFqdn = Get-FastPASObjectString $result @('PodFqdn', 'podFqdn')
        if (-not $podFqdn) {
            return [pscustomobject]@{BaseUrl = $baseUrl; WebSession = $webSession; Response = $start }
        }
        if ($attempt -gt 0) { throw 'CyberArk returned more than one Identity pod redirect during authentication.' }

        $podUrl = if ($podFqdn -match '^https://') { $podFqdn } else { "https://$podFqdn" }
        if (-not (Test-FastPASFederatedRedirectUrl $podUrl)) {
            throw 'CyberArk returned an unsafe or invalid Identity pod redirect.'
        }
        $baseUrl = ([uri]$podUrl).GetLeftPart([UriPartial]::Authority).TrimEnd('/')
    }
    throw 'CyberArk Identity authentication could not establish a tenant pod session.'
}

function Complete-FastPASFederatedAuthentication {
    param(
        [Parameter(Mandatory)]$StartResponse,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter(Mandatory)][string]$BaseUrl, [hashtable]$Headers, [switch]$NonInteractive
    )
    if ($NonInteractive) { throw 'Federated eIDP authentication requires an interactive system browser and cannot run with -NonInteractive.' }
    $result = Get-FastPASPropertyValue $StartResponse.Data @('Result', 'result')
    $redirectUrl = Get-FastPASObjectString $result @('IdpRedirectShortUrl', 'idpRedirectShortUrl')
    $idpLoginSessionId = Get-FastPASObjectString $result @('IdpLoginSessionId', 'idpLoginSessionId')
    if (-not $redirectUrl -or -not $idpLoginSessionId) { throw 'CyberArk did not return the eIDP redirect URL and login session required for federated authentication.' }
    if (-not (Test-FastPASFederatedRedirectUrl $redirectUrl)) { throw 'CyberArk returned an unsafe or invalid eIDP redirect URL; only absolute, non-local HTTPS URLs are allowed.' }

    Write-Host ''
    Write-Host 'External identity-provider authentication is required.' -ForegroundColor Cyan
    Write-Host "Opening the system browser: $redirectUrl"
    try { Start-Process -FilePath $redirectUrl -ErrorAction Stop }
    catch { Write-Warning "The browser could not be opened automatically. Open this URL manually: $redirectUrl" }
    $pinRequiredValue = Get-FastPASPropertyValue $result @('IdpOobAuthPinRequired', 'idpOobAuthPinRequired')
    $pinRequired = $pinRequiredValue -is [bool] -and $pinRequiredValue
    if (-not ($pinRequiredValue -is [bool])) { $pinRequired = [string]$pinRequiredValue -match '^(?i:true|1)$' }

    if ($pinRequired) {
        Write-Host 'Complete authentication in the browser, then enter the CyberArk PIN displayed by the flow.' -ForegroundColor Cyan
        do {
            $pin = Read-FastPASChallengeAnswer 'Federated authentication PIN'
            if ($pin -notmatch '^\d+$') { Write-Warning 'The federated PIN must contain numbers only.' }
        }until($pin -match '^\d+$')
        try {
            $pinResponse = Invoke-FastPASRawRequest -Method POST -Uri "$BaseUrl/Security/AdvanceAuthentication" -Headers $Headers -Body @{
                SessionId = $idpLoginSessionId
                MechanismId = 'OOBAUTHPIN'
                Action = 'Answer'
                Answer = $pin
            } -WebSession $WebSession
        }
        finally { $pin = $null }
        Assert-FastPASSuccessResponse $pinResponse 'Federated PIN submission'
        Assert-FastPASInteractivePayload $pinResponse.Data 'Federated PIN submission'
        $token = Get-FastPASTokenFromResponse $pinResponse.Data
        if (-not $token) {
            $additional = @(Get-FastPASChallengeMechanisms $pinResponse.Data)
            if ($additional.Count) { throw 'Federated authentication accepted the PIN but returned additional challenges that are not supported yet.' }
            throw 'Federated authentication completed without returning a CyberArk platform token.'
        }
    }
    else {
        Write-Host 'Complete authentication and MFA approval in the browser. FastPAS is monitoring the CyberArk login session.' -ForegroundColor Cyan
        $token = $null
        try {
            for ($approvalAttempt = 1; $approvalAttempt -le 120 -and -not $token; $approvalAttempt++) {
                $statusResponse = Invoke-FastPASRawRequest -Method POST -Uri "$BaseUrl/Security/OobAuthStatus" -Headers $Headers -Body @{
                    SessionId = $idpLoginSessionId
                } -WebSession $WebSession
                Assert-FastPASSuccessResponse $statusResponse 'Federated authentication status'
                Assert-FastPASInteractivePayload $statusResponse.Data 'Federated authentication status'
                $token = Get-FastPASTokenFromResponse $statusResponse.Data
                $statusResult = Get-FastPASPropertyValue $statusResponse.Data @('Result', 'result')
                if ($null -eq $statusResult) { $statusResult = $statusResponse.Data }
                $state = Get-FastPASObjectString $statusResult @('State', 'state', 'Summary', 'summary')
                if ($token) { break }
                if ($state -match '^(?i:failed|failure|denied|rejected|cancelled|canceled|expired|error)$') {
                    throw "External identity-provider authentication ended with state '$state'."
                }
                if ($state -match '^(?i:success|loginsuccess)$') {
                    throw 'CyberArk marked the external identity-provider login successful but did not return a platform token.'
                }
                Write-Progress -Activity 'Waiting for external identity-provider authentication' -Status "$($approvalAttempt * 2) seconds elapsed" -PercentComplete ([Math]::Min(99, [int](($approvalAttempt / 120) * 100)))
                if ($approvalAttempt -lt 120) { Start-Sleep -Seconds 2 }
            }
        }
        finally { Write-Progress -Activity 'Waiting for external identity-provider authentication' -Completed }
        if (-not $token) { throw 'Timed out after four minutes waiting for the external identity-provider login. Start a new session and approve only its newest request.' }
    }
    Write-Host 'Federated authentication succeeded.' -ForegroundColor Green
    return $token
}

function Invoke-FastPASFederatedAuthentication {
    param([Parameter(Mandatory)][Alias('Profile')]$ProfileRecord, [switch]$NonInteractive)
    $headers = @{'X-IDAP-NATIVE-CLIENT' = 'true';
        'OobIdPAuth' = 'true'
    }
    $started = Start-FastPASIdentityAuthentication -ProfileRecord $ProfileRecord -Headers $headers
    return Complete-FastPASFederatedAuthentication -StartResponse $started.Response -WebSession $started.WebSession -BaseUrl $started.BaseUrl -Headers $headers -NonInteractive:$NonInteractive
}

function Invoke-FastPASInteractiveAuthentication {
    param([Parameter(Mandatory)][Alias('Profile')]$ProfileRecord, [Parameter(Mandatory)][Security.SecureString]$Secret, [switch]$NonInteractive)
    if ($NonInteractive) { throw 'Interactive MFA profiles cannot connect with -NonInteractive.' }
    $headers = @{ 'X-IDAP-NATIVE-CLIENT' = 'true';
        'OobIdPAuth' = 'true'
    }
    $started = Start-FastPASIdentityAuthentication -ProfileRecord $ProfileRecord -Headers $headers
    $base = $started.BaseUrl
    $webSession = $started.WebSession
    $start = $started.Response
    $startResult = Get-FastPASPropertyValue $start.Data @('Result', 'result')
    if (Get-FastPASObjectString $startResult @('IdpRedirectShortUrl', 'idpRedirectShortUrl')) {
        return Complete-FastPASFederatedAuthentication -StartResponse $start -WebSession $webSession -BaseUrl $base -Headers $headers -NonInteractive:$NonInteractive
    }
    $sessionId = Get-FastPASPropertyValue $startResult @('SessionId', 'sessionId')
    $tenantId = Get-FastPASObjectString $startResult @('TenantId', 'tenantId') $ProfileRecord.Subdomain
    if (-not $sessionId) { throw 'StartAuthentication did not return a session ID.' }
    $challengeSets = @(Get-FastPASChallengeSets $start.Data)
    $nextChallengeIndex = 1
    $mechanisms = if ($challengeSets.Count) { @($challengeSets[0]) }else { @(Get-FastPASChallengeMechanisms $start.Data) }
    $passwordMechanism = $mechanisms | Where-Object {
        (Get-FastPASObjectString $_ @('Name', 'name')) -ieq 'UP'
    } | Select-Object -First 1
    if (-not $passwordMechanism) { $passwordMechanism = $mechanisms | Where-Object { (Get-FastPASObjectString $_ @('PromptSelectMech', 'PromptMechChosen', 'Prompt')) -match '(?i)password' } | Select-Object -First 1 }
    if (-not $passwordMechanism) { $passwordMechanism = $mechanisms | Where-Object { (Get-FastPASObjectString $_ @('AnswerType', 'answerType')) -ieq 'Text' } | Select-Object -First 1 }
    if (-not $passwordMechanism) { throw 'Interactive authentication did not offer a password mechanism.' }
    $plain = ConvertFrom-FastPASSecureString $Secret
    try {
        $current = Invoke-FastPASRawRequest -Method POST -Uri "$base/Security/AdvanceAuthentication" -Headers $headers -Body @{
            TenantId = $tenantId;
            SessionId = $sessionId;
            MechanismId = (Get-FastPASPropertyValue $passwordMechanism @('MechanismId', 'mechanismId'));
            Action = 'Answer';
            Answer = $plain
        } -WebSession $webSession
    }
    finally { $plain = $null }
    Assert-FastPASSuccessResponse $current 'AdvanceAuthentication'
    Assert-FastPASInteractivePayload $current.Data 'Password authentication'
    $token = Get-FastPASTokenFromResponse $current.Data
    $polls = 0
    while (-not $token -and $polls -lt 120) {
        $mechanisms = @(Get-FastPASChallengeMechanisms $current.Data)
        $result = Get-FastPASPropertyValue $current.Data @('Result', 'result')
        $summary = Get-FastPASObjectString $result @('Summary', 'summary')
        if ($mechanisms.Count -eq 0 -and $summary -ieq 'StartNextChallenge' -and $nextChallengeIndex -lt $challengeSets.Count) {
            $mechanisms = @($challengeSets[$nextChallengeIndex]);
            $nextChallengeIndex++
        }
        if ($mechanisms.Count -eq 0) { throw "Interactive authentication returned neither a token nor a usable challenge. Summary: $summary" }
        for ($i = 0;
            $i -lt $mechanisms.Count;
            $i++) {
            $description = Get-FastPASPropertyValue $mechanisms[$i] @('PromptSelectMech', 'Name', 'PromptMechChosen', 'AnswerType')
            Write-Host "[$($i+1)] $description"
        }
        $selected = if ($mechanisms.Count -eq 1) { $mechanisms[0] } else {
            $choice = Read-Host 'Choose MFA mechanism'
            if ($choice -notmatch '^\d+$' -or [int]$choice -lt 1 -or [int]$choice -gt $mechanisms.Count) { throw 'Invalid MFA mechanism selection.' }
            $mechanisms[[int]$choice - 1]
        }
        $actions = @(Get-FastPASMechanismActions $selected)
        $answerType = Get-FastPASObjectString $selected @('AnswerType', 'answerType')
        # CyberArk labels Email/SMS mechanisms as StartTextOob, but the
        # AdvanceAuthentication action for these mechanisms is StartOOB. The
        # response becomes OobPending and must be polled for approval.
        $action = if ($answerType -ieq 'StartTextOob') { 'StartOOB' }elseif ($answerType -ieq 'StartOOB') { 'StartOOB' }elseif ($answerType -in @('Text', 'Numeric')) { 'Answer' }elseif ($actions -contains 'StartOOB') { 'StartOOB' } elseif ($actions -contains 'StartTextOob') { 'StartOOB' } elseif ($actions -contains 'Answer') { 'Answer' } elseif ($actions -contains 'Poll') { 'Poll' }else { 'Answer' }
        $advanceBody = @{
            TenantId = $tenantId;
            SessionId = $sessionId;
            MechanismId = (Get-FastPASPropertyValue $selected @('MechanismId', 'mechanismId'));
            Action = $action
        }
        if ($action -eq 'Answer') { $advanceBody.Answer = Read-FastPASChallengeAnswer 'MFA answer/code' }
        try {
            $current = Invoke-FastPASRawRequest -Method POST -Uri "$base/Security/AdvanceAuthentication" -Headers $headers -Body $advanceBody -WebSession $webSession
        }
        finally {
            if ($advanceBody.ContainsKey('Answer')) { $advanceBody.Answer = $null }
        }
        Assert-FastPASSuccessResponse $current 'AdvanceAuthentication'
        Assert-FastPASInteractivePayload $current.Data 'Interactive challenge'
        $token = Get-FastPASTokenFromResponse $current.Data
        if (-not $token -and $action -eq 'StartOOB') {
            $startOobSummary = Get-FastPASObjectString (Get-FastPASPropertyValue $current.Data @('Result', 'result')) @('Summary', 'summary')
            if ($startOobSummary -and $startOobSummary -notmatch '^(?i:OobPending)$') { continue }
            Write-Host 'Approval request sent. Waiting for Email/SMS/mobile approval...' -ForegroundColor Cyan
            $pollMechanisms = @()
            $pollFinished = $false
            try {
                for ($approvalAttempt = 1;
                    $approvalAttempt -le 120 -and -not $token;
                    $approvalAttempt++) {
                    Start-Sleep -Seconds 2
                    $polls = $approvalAttempt
                    Write-Progress -Activity 'Waiting for CyberArk approval' -Status "$($approvalAttempt * 2) seconds elapsed" -PercentComplete ([Math]::Min(99, [int](($approvalAttempt / 120) * 100)))
                    $current = Invoke-FastPASRawRequest -Method POST -Uri "$base/Security/AdvanceAuthentication" -Headers $headers -Body @{
                        TenantId = $tenantId;
                        SessionId = $sessionId;
                        MechanismId = (Get-FastPASPropertyValue $selected @('MechanismId', 'mechanismId'));
                        Action = 'Poll'
                    } -WebSession $webSession
                    Assert-FastPASSuccessResponse $current 'AdvanceAuthentication poll'
                    Assert-FastPASInteractivePayload $current.Data 'Approval polling'
                    $token = Get-FastPASTokenFromResponse $current.Data
                    if ($token) {
                        Write-Host 'CyberArk approval received.' -ForegroundColor Green;
                        break
                    }
                    $pollMechanisms = @(Get-FastPASChallengeMechanisms $current.Data)
                    if ($pollMechanisms.Count) { break }
                    $pollResult = Get-FastPASPropertyValue $current.Data @('Result', 'result')
                    $pollSummary = Get-FastPASObjectString $pollResult @('Summary', 'summary')
                    $pollState = Get-FastPASObjectString $pollResult @('State', 'state')
                    if ($pollState -match '^(?i:failed|failure|denied|rejected|cancelled|canceled|expired|error)$') {
                        throw "CyberArk MFA approval ended with state '$pollState'."
                    }
                    if ($pollSummary -and $pollSummary -notmatch '^(?i:OobPending)$') {
                        $pollFinished = $true
                        break
                    }
                    if ($approvalAttempt % 5 -eq 0) {
                        Write-Host "Still waiting for approval... $($approvalAttempt * 2)s (CyberArk: $(if($pollSummary){$pollSummary}else{'no status'}))" -ForegroundColor DarkGray
                    }
                }
            }
            finally {
                Write-Progress -Activity 'Waiting for CyberArk approval' -Completed
            }
            if (-not $token -and -not $pollMechanisms.Count -and -not $pollFinished) { throw 'Timed out after four minutes waiting for CyberArk approval. Start a new authentication session and approve only its newest request.' }
        }
    }
    if (-not $token) { throw 'Interactive authentication timed out before a platform token was returned.' }
    return $token
}

<#
.SYNOPSIS
Authenticates a saved profile and returns an in-memory FastPAS session context.
.DESCRIPTION
Secrets are accepted only for the current connection and are never added to the
saved profile. Federated profiles open the system browser when CyberArk returns
an external identity-provider challenge.
#>
function Connect-FastPAS {
    [CmdletBinding()]
    param([string]$ProfileId, [Security.SecureString]$Secret, [Security.SecureString]$OneTimePassword, [switch]$NonInteractive)
    $profileRecord = if ($ProfileId) { Get-FastPASProfile -Id $ProfileId } else { Get-FastPASProfile -Active }
    if (-not $profileRecord) { throw 'No FastPAS profile is selected.' }
    $deploymentType = if ($profileRecord.PSObject.Properties['DeploymentType']) { [string]$profileRecord.DeploymentType }else { 'ispss' }
    $naiveIdentityHost = "$($profileRecord.Subdomain).id.cyberark.cloud"
    if ($deploymentType -eq 'ispss' -and ([string]::IsNullOrWhiteSpace($profileRecord.IdentityHost) -or $profileRecord.IdentityHost -ieq $naiveIdentityHost)) {
        try {
            $discovered = (Resolve-FastPASTenant -Subdomain $profileRecord.Subdomain).IdentityHost
            if ($discovered -and $discovered -ine $profileRecord.IdentityHost) {
                $profileRecord.IdentityHost = $discovered
                $config = Read-FastPASConfig
                foreach ($storedProfile in $config.profiles) {
                    if ($storedProfile.id -eq $profileRecord.Id) {
                        $storedProfile.identityHost = $discovered;
                        $storedProfile.updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
                    }
                }
                Write-FastPASConfig $config
            }
        }
        catch {
            if ([string]::IsNullOrWhiteSpace($profileRecord.IdentityHost)) { throw }
        }
    }
    $platformToken = $null
    $identityToken = $null
    $ownsSecret = $false
    $runtimeSecret = $null
    try {
        if ($deploymentType -ne 'ispss') {
            if ($null -eq $Secret) {
                if ($NonInteractive) { throw "$deploymentType authentication requires a runtime -Secret. FastPAS never stores passwords." }
                $Secret = Read-Host "Password for $($profileRecord.Username)" -AsSecureString
                $ownsSecret = $true
            }
            $platformToken = Invoke-FastPASPVWAAuthentication -ProfileRecord $profileRecord -Secret $Secret -OneTimePassword $OneTimePassword -NonInteractive:$NonInteractive
            $expiresIn = 900
        }
        elseif ($profileRecord.AuthType -eq 'oauth') {
            if ($null -eq $Secret) {
                if ($NonInteractive) { throw 'OAuth authentication requires a runtime -Secret when -NonInteractive is used. FastPAS never stores secrets.' }
                $Secret = Read-Host 'OAuth client secret / password' -AsSecureString
                $ownsSecret = $true
            }
            $plain = ConvertFrom-FastPASSecureString $Secret
            try {
                $form = @{grant_type = 'client_credentials';
                    client_id = $profileRecord.ClientId;
                    client_secret = $plain
                }
                $identity = Invoke-FastPASRawRequest -Method POST -Uri "https://$($profileRecord.IdentityHost)/oauth2/token/$($profileRecord.ApplicationId)" -Body $form -ContentType 'application/x-www-form-urlencoded'
                Assert-FastPASSuccessResponse $identity 'Identity OAuth token request'
                $identityToken = Get-FastPASTokenFromResponse $identity.Data
                $platform = Invoke-FastPASRawRequest -Method POST -Uri "https://$($profileRecord.IdentityHost)/oauth2/platformtoken" -Body $form -ContentType 'application/x-www-form-urlencoded'
                Assert-FastPASSuccessResponse $platform 'Platform token request'
                $platformToken = Get-FastPASTokenFromResponse $platform.Data
                $expiresIn = Get-FastPASPropertyValue $platform.Data @('expires_in', 'expiresIn')
            }
            finally {
                $plain = $null;
                $form = $null
            }
        }
        elseif ($profileRecord.AuthType -eq 'interactive') {
            if ($null -eq $Secret) {
                if ($NonInteractive) { throw 'Interactive authentication requires a runtime -Secret when -NonInteractive is used. FastPAS never stores passwords.' }
                $Secret = Read-Host "Password for $($profileRecord.Username)" -AsSecureString
                $ownsSecret = $true
            }
            $platformToken = Invoke-FastPASInteractiveAuthentication -Profile $profileRecord -Secret $Secret -NonInteractive:$NonInteractive
            $expiresIn = 900
        }
        elseif ($profileRecord.AuthType -in @('federated', 'eidp')) {
            $platformToken = Invoke-FastPASFederatedAuthentication -Profile $profileRecord -NonInteractive:$NonInteractive
            $expiresIn = 900
        }
        else {
            throw "Unsupported profile authentication type '$($profileRecord.AuthType)'."
        }
    }
    finally {
        try {
            if ($platformToken -and $Secret) {
                $runtimeSecret = $Secret.Copy()
                $runtimeSecret.MakeReadOnly()
            }
        }
        finally { if ($ownsSecret -and $Secret) { $Secret.Dispose() } }
    }
    if (-not $platformToken) { throw 'Authentication succeeded but no platform token was returned.' }
    if (-not $expiresIn) { $expiresIn = 900 }
    [pscustomobject]@{
        PSTypeName = 'FastPAS.SessionContext';
        Profile = $profileRecord;
        PlatformToken = $platformToken;
        AuthorizationHeader = $(if ($deploymentType -eq 'ispss') { "Bearer $platformToken" }else { $platformToken });
        IdentityToken = $identityToken
        RuntimeSecret = $runtimeSecret
        DeploymentType = $deploymentType;
        Capabilities = (Get-FastPASDeploymentCapabilities $deploymentType)
        ExpiresAt = [DateTimeOffset]::UtcNow.AddSeconds([double]$expiresIn);
        CorrelationId = [guid]::NewGuid().ToString()
        ConnectedAt = [DateTimeOffset]::UtcNow;
        NonInteractive = [bool]$NonInteractive;
        Disconnected = $false
    }
}

<#
.SYNOPSIS
Clears tokens from an in-memory FastPAS session context.
#>
function Disconnect-FastPAS {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $Context.PlatformToken = $null
    $Context.IdentityToken = $null
    if ($Context.PSObject.Properties['RuntimeSecret'] -and $Context.RuntimeSecret) {
        $Context.RuntimeSecret.Dispose()
        $Context.RuntimeSecret = $null
    }
    $Context.Disconnected = $true
}

function Update-FastPASContextToken {
    param([Parameter(Mandatory)]$Context)
    $runtimeSecret = if ($Context.PSObject.Properties['RuntimeSecret']) { $Context.RuntimeSecret }else { $null }
    $replacement = Connect-FastPAS -ProfileId $Context.Profile.Id -Secret $runtimeSecret -NonInteractive:$Context.NonInteractive
    if ($Context.PSObject.Properties['RuntimeSecret'] -and $Context.RuntimeSecret) { $Context.RuntimeSecret.Dispose() }
    $Context.PlatformToken = $replacement.PlatformToken
    if ($Context.PSObject.Properties['AuthorizationHeader']) { $Context.AuthorizationHeader = $replacement.AuthorizationHeader }
    $Context.IdentityToken = $replacement.IdentityToken
    if ($Context.PSObject.Properties['RuntimeSecret']) { $Context.RuntimeSecret = $replacement.RuntimeSecret }
    $Context.ExpiresAt = $replacement.ExpiresAt
}

function Join-FastPASApiUri {
    param([string]$BaseUrl, [string]$Path, [hashtable]$Query)
    $trimmedBase = $BaseUrl.TrimEnd('/')
    $trimmedPath = $Path.Trim()
    $uri = if ($trimmedPath -match '^https://') {
        $trimmedPath
    }
    elseif ($trimmedPath.StartsWith('/')) {
        $baseUri = [uri]$trimmedBase
        "$($baseUri.Scheme)://$($baseUri.Authority)$trimmedPath"
    }
    else {
        # CyberArk pagination links can be returned as API/Safes?... even when
        # the configured base URL already ends in /API. Avoid /API/API here.
        if ($trimmedBase -match '(?i)/API$' -and $trimmedPath -match '(?i)^API(?:/|$)') {
            $trimmedPath = $trimmedPath.Substring(3).TrimStart('/')
        }
        "$trimmedBase/$trimmedPath"
    }
    if ($Query -and $Query.Count) {
        $pairs = foreach ($item in $Query.GetEnumerator()) {
            if ($null -ne $item.Value -and "$($item.Value)" -ne '') { '{0}={1}' -f [uri]::EscapeDataString([string]$item.Key), [uri]::EscapeDataString([string]$item.Value) }
        }
        if ($pairs) { $uri += $(if ($uri.Contains('?')) { '&' } else { '?' }) + ($pairs -join '&') }
    }
    return $uri
}

<#
.SYNOPSIS
Calls a CyberArk Vault API path through an authenticated FastPAS session.
.DESCRIPTION
Builds the tenant URL, adds the platform token, parses the response, and retries
once after an authorization failure by renewing the current session.
#>
function Invoke-FastPASApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query,
        $Body,
        [switch]$NoRetry
    )
    if ($Context.Disconnected -or -not $Context.PlatformToken) { throw 'The FastPAS session is disconnected.' }
    if ($Context.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2)) { Update-FastPASContextToken -Context $Context }
    $uri = Join-FastPASApiUri -BaseUrl $Context.Profile.VaultApiBaseUrl -Path $Path -Query $Query
    $authorization = if ($Context.PSObject.Properties['AuthorizationHeader'] -and $Context.AuthorizationHeader) { [string]$Context.AuthorizationHeader }else { "Bearer $($Context.PlatformToken)" }
    $skipCertificateCheck = [bool](Get-FastPASPropertyValue $Context.Profile @('skipCertificateCheck', 'SkipCertificateCheck'))
    $response = Invoke-FastPASRawRequest -Method $Method -Uri $uri -Headers @{Authorization = $authorization } -Body $Body -SkipCertificateCheck:$skipCertificateCheck
    if ($response.StatusCode -in 401, 403 -and -not $NoRetry) {
        Update-FastPASContextToken $Context
        $authorization = if ($Context.PSObject.Properties['AuthorizationHeader'] -and $Context.AuthorizationHeader) { [string]$Context.AuthorizationHeader }else { "Bearer $($Context.PlatformToken)" }
        $response = Invoke-FastPASRawRequest -Method $Method -Uri $uri -Headers @{Authorization = $authorization } -Body $Body -SkipCertificateCheck:$skipCertificateCheck
    }
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $detail = if ($response.Raw) { $response.Raw.Substring(0, [Math]::Min(2000, $response.Raw.Length)) } else { 'No response body.' }
        if ($response.StatusCode -eq 404 -and $Path -match '(?i)^Safes(?:/|$)') {
            $detail += " Verify that profile '$($Context.Profile.Name)' uses the correct Vault API base URL (normally ending in /PasswordVault/API). For a per-safe request, confirm that the safe still exists and is visible to the signed-in user."
        }
        throw "$Method $uri failed with HTTP $($response.StatusCode). $detail"
    }
    return $response.Data
}

function Get-FastPASPagedItems {
    param(
        [Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query = @{}, [string[]]$CollectionNames = @('value', 'Value', 'Accounts', 'Safes', 'Recordings'),
        [int]$Limit = 500, [int]$MaximumPages = 100
    )
    $all = [Collections.Generic.List[object]]::new()
    $offset = 0
    $followingNextLink = $false
    for ($page = 0;
        $page -lt $MaximumPages;
        $page++) {
        $pageQuery = if ($followingNextLink) { @{} }else { @{} + $Query }
        if (-not $followingNextLink) {
            $pageQuery.limit = $Limit
            $pageQuery.offset = $offset
        }
        $response = Invoke-FastPASApiRequest -Context $Context -Method GET -Path $Path -Query $pageQuery
        $items = $null
        foreach ($name in $CollectionNames) {
            $items = Get-FastPASPropertyValue $response @($name);
            if ($null -ne $items) { break }
        }
        if ($null -eq $items -and $response -is [array]) { $items = $response }
        $batch = @($items)
        foreach ($item in $batch) { $all.Add($item) }
        $nextLink = Get-FastPASPropertyValue $response @('nextLink', 'NextLink')
        $count = Get-FastPASPropertyValue $response @('count', 'Count', 'Total')
        if ($nextLink) {
            $Path = [string]$nextLink;
            $Query = @{}
            $followingNextLink = $true
        }
        elseif ($batch.Count -lt $Limit -or ($count -and $all.Count -ge [int]$count)) { break }
        else {
            $offset += $Limit
            $followingNextLink = $false
        }
    }
    return @($all)
}

function Get-FastPASObjectString {
    param($InputObject, [string[]]$Name, [string]$Default = '')
    $value = Get-FastPASPropertyValue $InputObject $Name
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Resolve-FastPASSafe {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$SafeName)
    $safeCandidates = @(Get-FastPASPagedItems -Context $Context -Path 'Safes' -Query @{search = $SafeName } -CollectionNames @('value', 'Safes') -Limit 100)
    $exact = @($safeCandidates | Where-Object { (Get-FastPASObjectString $_ @('safeName', 'SafeName')) -eq $SafeName })
    if ($exact.Count -eq 0) { throw "Safe '$SafeName' was not found." }
    if ($exact.Count -gt 1) { throw "More than one exact safe named '$SafeName' was returned." }
    return $exact[0]
}

function Resolve-FastPASAccount {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$AccountId)
    if ($AccountId -match '[/\\?#]') { throw 'AccountId contains unsupported path characters.' }
    Invoke-FastPASApiRequest -Context $Context -Method GET -Path "Accounts/$([uri]::EscapeDataString($AccountId))"
}

function ConvertTo-FastPASAccountRow {
    param($Account)
    $management = Get-FastPASPropertyValue $Account @('secretManagement', 'SecretManagement')
    [pscustomobject]@{
        AccountId = Get-FastPASObjectString $Account @('id', 'ID', 'accountId')
        Name = Get-FastPASObjectString $Account @('name', 'Name')
        SafeName = Get-FastPASObjectString $Account @('safeName', 'SafeName')
        UserName = Get-FastPASObjectString $Account @('userName', 'UserName', 'username')
        Address = Get-FastPASObjectString $Account @('address', 'Address')
        PlatformId = Get-FastPASObjectString $Account @('platformId', 'PlatformID')
        Locked = [bool](Get-FastPASPropertyValue $Account @('locked', 'Locked'))
        AutomaticManagementEnabled = Get-FastPASPropertyValue $management @('automaticManagementEnabled', 'AutomaticManagementEnabled')
        ManagementStatus = Get-FastPASObjectString $management @('status', 'Status')
        FailureReason = Get-FastPASObjectString $management @('manualManagementReason', 'failureReason', 'lastTaskFailureReason')
    }
}

function Get-FastPASSafePermissions {
    param([ValidateSet('Viewer', 'Operator', 'Manager')][string]$Role = 'Viewer')
    $permissions = [ordered]@{
        useAccounts = $false;
        retrieveAccounts = $false;
        listAccounts = $true;
        addAccounts = $false;
        updateAccountContent = $false
        updateAccountProperties = $false;
        initiateCPMAccountManagementOperations = $false;
        specifyNextAccountContent = $false
        renameAccounts = $false;
        deleteAccounts = $false;
        unlockAccounts = $false;
        manageSafe = $false;
        manageSafeMembers = $false
        backupSafe = $false;
        viewAuditLog = $true;
        viewSafeMembers = $true;
        accessWithoutConfirmation = $false
        createFolders = $false;
        deleteFolders = $false;
        moveAccountsAndFolders = $false;
        requestsAuthorizationLevel1 = $false
        requestsAuthorizationLevel2 = $false
    }
    if ($Role -in @('Operator', 'Manager')) {
        foreach ($name in 'useAccounts', 'retrieveAccounts', 'initiateCPMAccountManagementOperations', 'accessWithoutConfirmation') { $permissions[$name] = $true }
    }
    if ($Role -eq 'Manager') {
        foreach ($name in 'addAccounts', 'updateAccountContent', 'updateAccountProperties', 'specifyNextAccountContent', 'renameAccounts', 'deleteAccounts', 'unlockAccounts', 'manageSafeMembers', 'moveAccountsAndFolders') { $permissions[$name] = $true }
    }
    return $permissions
}

function Get-FastPASPermissionColumnMap {
    [ordered]@{
        UseAccounts = 'useAccounts';
        RetrieveAccounts = 'retrieveAccounts';
        ListAccounts = 'listAccounts';
        AddAccounts = 'addAccounts'
        UpdateAccountContent = 'updateAccountContent';
        UpdateAccountProperties = 'updateAccountProperties'
        InitiateCPMAccountManagementOperations = 'initiateCPMAccountManagementOperations';
        SpecifyNextAccountContent = 'specifyNextAccountContent'
        RenameAccounts = 'renameAccounts';
        DeleteAccounts = 'deleteAccounts';
        UnlockAccounts = 'unlockAccounts';
        ManageSafe = 'manageSafe'
        ManageSafeMembers = 'manageSafeMembers';
        BackupSafe = 'backupSafe';
        ViewAuditLog = 'viewAuditLog';
        ViewSafeMembers = 'viewSafeMembers'
        AccessWithoutConfirmation = 'accessWithoutConfirmation';
        CreateFolders = 'createFolders';
        DeleteFolders = 'deleteFolders'
        MoveAccountsAndFolders = 'moveAccountsAndFolders';
        RequestsAuthorizationLevel1 = 'requestsAuthorizationLevel1'
        RequestsAuthorizationLevel2 = 'requestsAuthorizationLevel2'
    }
}

function Get-FastPASRowString {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string[]]$Names)
    foreach ($name in $Names) {
        $property = $Row.PSObject.Properties | Where-Object Name -ieq $name | Select-Object -First 1;
        if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { return ([string]$property.Value).Trim() }
    }
    return ''
}

function ConvertTo-FastPASStrictBoolean {
    param([AllowNull()]$Value, [Parameter(Mandatory)][string]$Column)
    if ($Value -is [bool]) { return $Value };
    $text = ([string]$Value).Trim()
    if ($text -match '^(?i:true|yes|y|1)$') { return $true };
    if ($text -match '^(?i:false|no|n|0)$') { return $false }
    throw "Column '$Column' must be TRUE or FALSE; received '$text'."
}

function New-FastPASPermissionsFromCsvRow {
    param([Parameter(Mandatory)]$Row)
    $permissions = [ordered]@{};
    $map = Get-FastPASPermissionColumnMap
    foreach ($column in $map.Keys) {
        $property = $Row.PSObject.Properties | Where-Object Name -ieq $column | Select-Object -First 1
        if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { $permissions[$map[$column]] = ConvertTo-FastPASStrictBoolean $property.Value $column }
    }
    $legacyLevel = $Row.PSObject.Properties | Where-Object Name -ieq 'RequestsAuthorizationLevel' | Select-Object -First 1
    if ($legacyLevel -and -not [string]::IsNullOrWhiteSpace([string]$legacyLevel.Value)) {
        $level = 0;
        if (-not [int]::TryParse(([string]$legacyLevel.Value).Trim(), [ref]$level) -or $level -lt 0 -or $level -gt 2) { throw "Column 'RequestsAuthorizationLevel' must be 0, 1, or 2." }
        if (-not $permissions.Contains('requestsAuthorizationLevel1')) { $permissions.requestsAuthorizationLevel1 = ($level -ge 1) }
        if (-not $permissions.Contains('requestsAuthorizationLevel2')) { $permissions.requestsAuthorizationLevel2 = ($level -ge 2) }
    }
    if (-not $permissions.Count) { throw 'The row contains no recognized permission values. Export current safe membership to obtain the supported columns.' }
    return $permissions
}

function Get-FastPASSafeSnapshotHash {
    param([Parameter(Mandatory)]$Safe)
    $snapshot = [ordered]@{
        SafeName = Get-FastPASObjectString $Safe @('safeName', 'SafeName');
        SafeUrlId = Get-FastPASObjectString $Safe @('safeUrlId', 'SafeUrlId')
        ManagingCPM = Get-FastPASObjectString $Safe @('managingCPM', 'ManagingCPM');
        Description = Get-FastPASObjectString $Safe @('description', 'Description')
        OLACEnabled = [bool](Get-FastPASPropertyValue $Safe @('olacEnabled', 'OLACEnabled'))
        NumberOfVersionsRetention = Get-FastPASPropertyValue $Safe @('numberOfVersionsRetention', 'NumberOfVersionsRetention')
        NumberOfDaysRetention = Get-FastPASPropertyValue $Safe @('numberOfDaysRetention', 'NumberOfDaysRetention')
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($snapshot | ConvertTo-Json -Compress -Depth 5));
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function New-FastPASSafeUpdateBody {
    param([Parameter(Mandatory)]$Safe, [Parameter(Mandatory)][AllowEmptyString()][string]$ManagingCPM)
    $name = Get-FastPASObjectString $Safe @('safeName', 'SafeName');
    if (-not $name) { throw 'Safe details did not contain a safe name.' }
    $body = [ordered]@{safeName = $name;
        description = Get-FastPASObjectString $Safe @('description', 'Description');
        olacEnabled = [bool](Get-FastPASPropertyValue $Safe @('olacEnabled', 'OLACEnabled'));
        managingCPM = $ManagingCPM
    }
    $versions = Get-FastPASPropertyValue $Safe @('numberOfVersionsRetention', 'NumberOfVersionsRetention');
    $days = Get-FastPASPropertyValue $Safe @('numberOfDaysRetention', 'NumberOfDaysRetention')
    if ($null -ne $versions -and "$versions" -ne '') { $body.numberOfVersionsRetention = [int]$versions }elseif ($null -ne $days -and "$days" -ne '') { $body.numberOfDaysRetention = [int]$days }else { throw "Safe '$name' did not contain a retention setting." }
    return $body
}

function Find-FastPASStringMatch {
    param([AllowNull()]$Value, [string]$Pattern, [string]$Path = '')
    $results = [Collections.Generic.List[object]]::new()
    function Visit($item, $itemPath) {
        if ($null -eq $item) { return };
        if ($item -is [string]) {
            if ($item -match $Pattern) {
                $results.Add([pscustomobject]@{PropertyPath = $itemPath;
                        CurrentValue = $item
                    })
            };
            return
        }
        if ($item -is [ValueType]) { return };
        if ($item -is [Collections.IDictionary]) {
            foreach ($key in $item.Keys) { Visit $item[$key] $(if ($itemPath) { "$itemPath.$key" }else { "$key" }) };
            return
        }
        if ($item -is [Collections.IEnumerable]) {
            $index = 0;
            foreach ($child in $item) {
                Visit $child "$itemPath[$index]";
                $index++
            };
            return
        }
        foreach ($property in $item.PSObject.Properties) { Visit $property.Value $(if ($itemPath) { "$itemPath.$($property.Name)" }else { $property.Name }) }
    }
    Visit $Value $Path;
    return @($results)
}

function Get-FastPASObjectHash {
    param([Parameter(Mandatory)]$InputObject)
    $json = $InputObject | ConvertTo-Json -Compress -Depth 100
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function New-FastPASAccountTransferBody {
    param(
        [Parameter(Mandatory)]$Account,
        [Parameter(Mandatory)][string]$DestinationSafe,
        [Parameter(Mandatory)][string]$Secret
    )
    $body = [ordered]@{
        name = Get-FastPASObjectString $Account @('name', 'Name')
        address = Get-FastPASObjectString $Account @('address', 'Address')
        userName = Get-FastPASObjectString $Account @('userName', 'UserName', 'username')
        platformId = Get-FastPASObjectString $Account @('platformId', 'PlatformID')
        safeName = $DestinationSafe
        secretType = $(if (Get-FastPASObjectString $Account @('secretType', 'SecretType')) {
                Get-FastPASObjectString $Account @('secretType', 'SecretType')
            } else { 'password' })
        secret = $Secret
    }
    $platformProperties = Get-FastPASPropertyValue $Account @('platformAccountProperties', 'PlatformAccountProperties')
    if ($null -ne $platformProperties) { $body.platformAccountProperties = $platformProperties }
    $sourceManagement = Get-FastPASPropertyValue $Account @('secretManagement', 'SecretManagement')
    if ($null -ne $sourceManagement) {
        $management = [ordered]@{}
        $automatic = Get-FastPASPropertyValue $sourceManagement @('automaticManagementEnabled', 'AutomaticManagementEnabled')
        $reason = Get-FastPASObjectString $sourceManagement @('manualManagementReason', 'ManualManagementReason')
        if ($null -ne $automatic) { $management.automaticManagementEnabled = [bool]$automatic }
        if ($reason) { $management.manualManagementReason = $reason }
        if ($management.Count) { $body.secretManagement = $management }
    }
    $remoteAccess = Get-FastPASPropertyValue $Account @('remoteMachinesAccess', 'RemoteMachinesAccess')
    if ($null -ne $remoteAccess) { $body.remoteMachinesAccess = $remoteAccess }
    return $body
}

function Invoke-FastPASWorkerApiRequest {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query,
        $Body,
        [int]$MaxGetRetries = 5
    )
    $attempt = 0
    while ($true) {
        try {
            $parameters = @{Context = $Context; Method = $Method; Path = $Path }
            if ($Query -and $Query.Count) { $parameters.Query = $Query }
            if ($null -ne $Body) { $parameters.Body = $Body }
            if ($Method -ne 'GET') { $parameters.NoRetry = $true }
            return Invoke-FastPASApiRequest @parameters
        }
        catch {
            $attempt++
            $isTransient = $_.Exception.Message -match '(?i)HTTP\s+(429|502|503|504)|timed?\s*out|temporarily unavailable'
            if ($Method -ne 'GET' -or -not $isTransient -or $attempt -gt $MaxGetRetries) { throw }
            $delayMilliseconds = [Math]::Min(30000, (500 * [Math]::Pow(2, $attempt - 1)) + (Get-Random -Minimum 50 -Maximum 750))
            Start-Sleep -Milliseconds $delayMilliseconds
        }
    }
}

function Test-FastPASSecretMatch {
    param([AllowEmptyString()][string]$First, [AllowEmptyString()][string]$Second)
    $firstBytes = [Text.Encoding]::UTF8.GetBytes($First)
    $secondBytes = [Text.Encoding]::UTF8.GetBytes($Second)
    $firstHash = $null
    $secondHash = $null
    try {
        $firstHash = [Security.Cryptography.SHA256]::HashData($firstBytes)
        $secondHash = [Security.Cryptography.SHA256]::HashData($secondBytes)
        return [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($firstHash, $secondHash)
    }
    finally {
        [Array]::Clear($firstBytes, 0, $firstBytes.Length)
        [Array]::Clear($secondBytes, 0, $secondBytes.Length)
        if ($firstHash) { [Array]::Clear($firstHash, 0, $firstHash.Length) }
        if ($secondHash) { [Array]::Clear($secondHash, 0, $secondHash.Length) }
    }
}

function Get-FastPASAccountSecretVersionMarker {
    param([Parameter(Mandatory)]$Account)
    $management = Get-FastPASPropertyValue $Account @('secretManagement', 'SecretManagement')
    foreach ($candidate in @(
            @(Get-FastPASPropertyValue $management @('lastModifiedTime', 'LastModifiedTime', 'lastPasswordChange', 'LastPasswordChange')),
            @(Get-FastPASPropertyValue $Account @('lastModifiedTime', 'LastModifiedTime', 'lastPasswordChange', 'LastPasswordChange'))
        )) {
        if ($null -ne $candidate -and -not [string]::IsNullOrWhiteSpace([string]$candidate)) { return [string]$candidate }
    }
    return ''
}

function ConvertTo-FastPASCanonicalValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [Collections.IDictionary]) {
        $normalized = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $normalized[$key] = ConvertTo-FastPASCanonicalValue $Value[$key]
        }
        return $normalized
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = @($Value | ForEach-Object { ConvertTo-FastPASCanonicalValue $_ })
        return ,$items
    }
    $properties = @($Value.PSObject.Properties | Where-Object MemberType -In @('NoteProperty', 'Property') | Sort-Object Name)
    if ($properties.Count) {
        $normalized = [ordered]@{}
        foreach ($property in $properties) { $normalized[$property.Name] = ConvertTo-FastPASCanonicalValue $property.Value }
        return $normalized
    }
    return [string]$Value
}

function Get-FastPASCanonicalHash {
    param([AllowNull()]$Value)
    $normalized = ConvertTo-FastPASCanonicalValue $Value
    $json = $normalized | ConvertTo-Json -Compress -Depth 100
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function ConvertTo-FastPASAccountTransferLink {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Link,
        [int]$MaxGetRetries = 5
    )
    $indexText = Get-FastPASObjectString $Link @('extraPasswordIndex', 'ExtraPasswordIndex', 'index', 'Index')
    if (-not $indexText) {
        $type = Get-FastPASObjectString $Link @('type', 'Type', 'relationshipType', 'RelationshipType')
        $indexText = if ($type -match '(?i)logon') { '1' } elseif ($type -match '(?i)reconcile') { '3' } else { '' }
    }
    if ($indexText -notin @('1', '2', '3')) { throw "Unrecognized linked-account index '$indexText'." }
    $targetId = Get-FastPASObjectString $Link @('accountId', 'AccountID', 'linkedAccountId', 'LinkedAccountId', 'id', 'ID')
    $targetSafe = Get-FastPASObjectString $Link @('safe', 'Safe', 'safeName', 'SafeName')
    $targetName = Get-FastPASObjectString $Link @('name', 'Name', 'accountName', 'AccountName')
    $targetFolder = Get-FastPASObjectString $Link @('folder', 'Folder') 'Root'
    if ((!$targetSafe -or !$targetName) -and $targetId) {
        $target = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET `
            -Path "Accounts/$([uri]::EscapeDataString($targetId))" -MaxGetRetries $MaxGetRetries
        $targetSafe = Get-FastPASObjectString $target @('safeName', 'SafeName')
        $targetName = Get-FastPASObjectString $target @('name', 'Name')
    }
    if (-not $targetId -and $targetSafe -and $targetName) {
        $response = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET -Path 'Accounts' `
            -Query @{filter = "safeName eq $targetSafe"; search = $targetName; limit = 100; offset = 0 } -MaxGetRetries $MaxGetRetries
        $candidates = @(Get-FastPASPropertyValue $response @('value', 'Value', 'Accounts'))
        $exact = @($candidates | Where-Object {
                (Get-FastPASObjectString $_ @('safeName', 'SafeName')) -eq $targetSafe -and
                (Get-FastPASObjectString $_ @('name', 'Name')) -eq $targetName
            })
        if ($exact.Count -eq 1) { $targetId = Get-FastPASObjectString $exact[0] @('id', 'ID', 'accountId') }
    }
    if (-not $targetSafe -or -not $targetName -or -not $targetId) {
        throw "Could not resolve linked account '$indexText' to one exact account ID, safe, and name."
    }
    return [pscustomobject]@{
        Key = ("{0}`0{1}`0{2}" -f $indexText, $targetSafe, $targetName).ToLowerInvariant()
        ExtraPasswordIndex = [int]$indexText; TargetAccountId = $targetId
        TargetSafe = $targetSafe; TargetName = $targetName; TargetFolder = $targetFolder
    }
}

function New-FastPASDependentTransferBody {
    param([Parameter(Mandatory)]$Dependent)
    $body = [ordered]@{
        platformId = Get-FastPASObjectString $Dependent @('platformId', 'PlatformID')
        platformAccountProperties = Get-FastPASPropertyValue $Dependent @('platformAccountProperties', 'PlatformAccountProperties')
    }
    $name = Get-FastPASObjectString $Dependent @('name', 'Name')
    if ($name) { $body.name = $name }
    $management = Get-FastPASPropertyValue $Dependent @('secretManagement', 'SecretManagement')
    if ($null -ne $management) {
        $managementBody = [ordered]@{}
        $automatic = Get-FastPASPropertyValue $management @('automaticManagementEnabled', 'AutomaticManagementEnabled')
        $manualReason = Get-FastPASPropertyValue $management @('manualManagementReason', 'ManualManagementReason')
        if ($null -ne $automatic) { $managementBody.automaticManagementEnabled = [bool]$automatic }
        if ($null -ne $manualReason) { $managementBody.manualManagementReason = [string]$manualReason }
        if ($managementBody.Count) { $body.secretManagement = $managementBody }
    }
    return $body
}

function Test-FastPASDependentTransferBody {
    param([Parameter(Mandatory)]$ExpectedBody, [Parameter(Mandatory)]$Actual)
    $actualBody = New-FastPASDependentTransferBody -Dependent $Actual
    $differences = [Collections.Generic.List[string]]::new()
    foreach ($field in @('name', 'platformId')) {
        $expectedValue = Get-FastPASPropertyValue $ExpectedBody @($field)
        $actualValue = Get-FastPASPropertyValue $actualBody @($field)
        if ([string]$expectedValue -ne [string]$actualValue) { $differences.Add($field) }
    }
    $expectedProperties = Get-FastPASPropertyValue $ExpectedBody @('platformAccountProperties')
    $actualProperties = Get-FastPASPropertyValue $actualBody @('platformAccountProperties')
    if ((Get-FastPASCanonicalHash $expectedProperties) -ne
        (Get-FastPASCanonicalHash $actualProperties)) { $differences.Add('platformAccountProperties') }
    $expectedManagement = Get-FastPASPropertyValue $ExpectedBody @('secretManagement')
    $actualManagement = Get-FastPASPropertyValue $actualBody @('secretManagement')
    if ((Get-FastPASCanonicalHash $expectedManagement) -ne
        (Get-FastPASCanonicalHash $actualManagement)) { $differences.Add('secretManagement') }
    return [pscustomobject]@{Success = ($differences.Count -eq 0); Differences = @($differences) }
}

function Get-FastPASAccountTransferRelationshipState {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Account,
        [Parameter(Mandatory)][string]$AccountId,
        [Parameter(Mandatory)][string]$DeploymentType,
        [int]$MaxGetRetries = 5
    )
    $links = [Collections.Generic.List[object]]::new()
    $preservedDependents = [Collections.Generic.List[object]]::new()
    $unsupported = [Collections.Generic.List[string]]::new()
    $groupId = Get-FastPASObjectString $Account @('accountGroupId', 'AccountGroupId', 'groupId', 'GroupId')
    if ($groupId) { $unsupported.Add("AccountGroup:$groupId") }

    $embeddedDependents = @()
    foreach ($name in @(@('dependencies', 'Dependencies'), @('usages', 'Usages'))) {
        $value = Get-FastPASPropertyValue $Account $name
        if ($null -ne $value) { $embeddedDependents += @($value) }
    }

    $linkedResponse = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET `
        -Path "ExtendedAccounts/$([uri]::EscapeDataString($AccountId))/LinkedAccounts" -MaxGetRetries $MaxGetRetries
    $rawLinks = @(Get-FastPASPropertyValue $linkedResponse @('linkedAccounts', 'LinkedAccounts', 'value', 'Value'))
    if (-not $rawLinks.Count -and $linkedResponse -is [array]) { $rawLinks = @($linkedResponse) }
    foreach ($property in @(@('linkedAccounts', 'LinkedAccounts'), @('logonAccount', 'LogonAccount'), @('reconcileAccount', 'ReconcileAccount'))) {
        $embedded = Get-FastPASPropertyValue $Account $property
        if ($null -ne $embedded) { $rawLinks += @($embedded) }
    }
    foreach ($link in $rawLinks) {
        if ($null -eq $link) { continue }
        try {
            $normalizedLink = ConvertTo-FastPASAccountTransferLink -Context $Context -Link $link -MaxGetRetries $MaxGetRetries
            if (-not @($links | Where-Object Key -EQ $normalizedLink.Key).Count) { $links.Add($normalizedLink) }
        }
        catch {
            $unsupported.Add("UnresolvedLink:$($_.Exception.Message)")
        }
    }

    $dependentPath = if ($DeploymentType -eq 'ispss') {
        "Accounts/$([uri]::EscapeDataString($AccountId))/account-dependents"
    } else {
        "Accounts/$([uri]::EscapeDataString($AccountId))/dependentAccounts"
    }
    $dependentResponse = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET -Path $dependentPath -MaxGetRetries $MaxGetRetries
    $dependents = @(Get-FastPASPropertyValue $dependentResponse @('accountDependents', 'AccountDependents', 'dependentAccounts', 'DependentAccounts', 'value', 'Value'))
    if (-not $dependents.Count -and $dependentResponse -is [array]) { $dependents = @($dependentResponse) }
    if ($embeddedDependents.Count -and -not $dependents.Count) {
        $unsupported.Add("DependentDiscoveryMismatch:$($embeddedDependents.Count) embedded usage(s) were not returned by the dependent API")
    }
    foreach ($dependentSummary in $dependents) {
        $dependentId = Get-FastPASObjectString $dependentSummary @(
            'id', 'ID', 'dependentAccountId', 'DependentAccountId', 'accountId', 'AccountID'
        )
        if (-not $dependentId) {
            $unsupported.Add('UnresolvedDependent:the dependent API omitted its ID')
            continue
        }
        try {
            $dependentDetail = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET `
                -Path "$dependentPath/$([uri]::EscapeDataString($dependentId))" -Query @{extendedDetails = 'true' } -MaxGetRetries $MaxGetRetries
            $wrappedDetail = Get-FastPASPropertyValue $dependentDetail @('dependentAccount', 'DependentAccount')
            if ($null -ne $wrappedDetail) { $dependentDetail = $wrappedDetail }
            $dependentPlatform = Get-FastPASObjectString $dependentDetail @('platformId', 'PlatformID')
            $dependentProperties = Get-FastPASPropertyValue $dependentDetail @('platformAccountProperties', 'PlatformAccountProperties')
            if (-not $dependentPlatform -or $null -eq $dependentProperties) {
                throw 'extended details omitted platformId or platformAccountProperties'
            }
            $dependentLinks = [Collections.Generic.List[object]]::new()
            $rawDependentLinks = @()
            foreach ($property in @(@('linkedAccounts', 'LinkedAccounts'), @('logonAccount', 'LogonAccount'), @('reconcileAccount', 'ReconcileAccount'))) {
                $embeddedLink = Get-FastPASPropertyValue $dependentDetail $property
                if ($null -ne $embeddedLink) { $rawDependentLinks += @($embeddedLink) }
            }
            foreach ($dependentLink in $rawDependentLinks) {
                $normalizedLink = ConvertTo-FastPASAccountTransferLink -Context $Context -Link $dependentLink -MaxGetRetries $MaxGetRetries
                if (-not @($dependentLinks | Where-Object Key -EQ $normalizedLink.Key).Count) { $dependentLinks.Add($normalizedLink) }
            }
            $preservedDependents.Add([pscustomobject]@{
                    SourceDependentId = $dependentId
                    Name = Get-FastPASObjectString $dependentDetail @('name', 'Name')
                    PlatformId = $dependentPlatform
                    Body = New-FastPASDependentTransferBody -Dependent $dependentDetail
                    Links = @($dependentLinks)
                })
        }
        catch {
            $unsupported.Add("UnresolvedDependent:$dependentId $($_.Exception.Message)")
        }
    }
    return [pscustomobject]@{Links = @($links); Dependents = @($preservedDependents); Unsupported = @($unsupported) }
}

function Test-FastPASAccountTransferLinkSet {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$AccountId,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExpectedLinks,
        [int]$MaxGetRetries = 5
    )
    if (-not $ExpectedLinks.Count) { return [pscustomobject]@{Success = $true; Missing = @(); Actual = @() } }
    $response = Invoke-FastPASWorkerApiRequest -Context $Context -Method GET `
        -Path "ExtendedAccounts/$([uri]::EscapeDataString($AccountId))/LinkedAccounts" -MaxGetRetries $MaxGetRetries
    $actual = @(Get-FastPASPropertyValue $response @('linkedAccounts', 'LinkedAccounts', 'value', 'Value'))
    if (-not $actual.Count -and $response -is [array]) { $actual = @($response) }
    $missing = [Collections.Generic.List[string]]::new()
    foreach ($expected in $ExpectedLinks) {
        $found = @($actual | Where-Object {
                $index = Get-FastPASObjectString $_ @('extraPasswordIndex', 'ExtraPasswordIndex', 'index', 'Index')
                $safe = Get-FastPASObjectString $_ @('safe', 'Safe', 'safeName', 'SafeName')
                $name = Get-FastPASObjectString $_ @('name', 'Name', 'accountName', 'AccountName')
                $index -eq [string]($expected.ExtraPasswordIndex) -and $safe -eq [string]($expected.TargetSafe) -and $name -eq [string]($expected.TargetName)
            })
        if (-not $found.Count) { $missing.Add("$($expected.ExtraPasswordIndex):$($expected.TargetSafe)/$($expected.TargetName)") }
    }
    $actualDescriptions = @($actual | ForEach-Object {
            '{0}:{1}/{2}' -f (Get-FastPASObjectString $_ @('extraPasswordIndex', 'ExtraPasswordIndex', 'index', 'Index')),
            (Get-FastPASObjectString $_ @('safe', 'Safe', 'safeName', 'SafeName')),
            (Get-FastPASObjectString $_ @('name', 'Name', 'accountName', 'AccountName'))
        })
    return [pscustomobject]@{Success = ($missing.Count -eq 0); Missing = @($missing); Actual = $actualDescriptions }
}

function Get-FastPASAccountTransferFailure {
    param([string]$Stage, [string]$Message)
    $uncertain = $Message -match '(?i)failed before receiving|did not return a destination account ID|HTTP\s+(408|429|500|502|503|504)|timed?\s*out|connection.*closed'
    switch ($Stage) {
        'Retrieve' {
            return [pscustomobject]@{Status = 'RetrieveFailed'; Retryable = $true; Action = 'Confirm Retrieve permission and retry this account.' }
        }
        'Create' {
            if ($uncertain) {
                return [pscustomobject]@{Status = 'CreateUncertain'; Retryable = $false; Action = 'Search the destination safe before retrying; never assume the create failed.' }
            }
            return [pscustomobject]@{Status = 'CreateRejected'; Retryable = $true; Action = 'Correct the reported destination/platform problem, then retry.' }
        }
        'Verify' {
            return [pscustomobject]@{Status = 'DestinationCreatedSourceRetained'; Retryable = $false; Action = 'Inspect the destination account and source account before cleanup.' }
        }
        'VerifySecret' {
            $status = if ($Message -match '(?i)did not match') { 'DestinationSecretMismatch' } else { 'DestinationSecretVerificationFailed' }
            return [pscustomobject]@{Status = $status; Retryable = $false; Action = 'The source was retained. Inspect and correct the destination before cleanup.' }
        }
        'PreserveRelationships' {
            return [pscustomobject]@{Status = 'RelationshipPreservationFailed'; Retryable = $false; Action = 'The source was retained. Inspect or remove the incomplete destination before resuming.' }
        }
        'PreserveDependents' {
            return [pscustomobject]@{Status = 'DependentPreservationFailed'; Retryable = $false; Action = 'The source was retained. Inspect the destination master and any partially recreated dependents before resuming.' }
        }
        'StabilityCheck' {
            return [pscustomobject]@{Status = 'SourceChangedDuringTransfer'; Retryable = $false; Action = 'The source was retained. Pause CPM and other writers, inspect the destination, and retry only after cleanup.' }
        }
        'Delete' {
            return [pscustomobject]@{Status = 'DuplicateNeedsCleanup'; Retryable = $false; Action = 'The verified destination exists. Review both accounts and remove the source manually when safe.' }
        }
        default {
            return [pscustomobject]@{Status = 'Failed'; Retryable = $true; Action = 'Review the issue, correct it, and resume the run.' }
        }
    }
}

function Invoke-FastPASAccountTransferWorker {
    param([Parameter(Mandatory)]$WorkerSpec)
    $context = $WorkerSpec.ExistingContext
    $ownsContext = $false
    $results = [Collections.Generic.List[object]]::new()
    $checkpointPath = [string]$WorkerSpec.CheckpointPath
    $relationshipMode = Get-FastPASObjectString $WorkerSpec @('RelationshipMode') 'Block'
    $deploymentType = Get-FastPASObjectString $WorkerSpec @('DeploymentType') 'ispss'
    $movingAccountLookup = Get-FastPASPropertyValue $WorkerSpec @('MovingAccountLookup')
    if ($null -eq $movingAccountLookup) { $movingAccountLookup = @{} }

    function Save-WorkerRow($Row) {
        $append = Test-Path -LiteralPath $checkpointPath
        $Row | Export-Csv -LiteralPath $checkpointPath -NoTypeInformation -Encoding utf8BOM -Append:$append -WhatIf:$false
    }

    try {
        if (-not $context) {
            $startupDelay = Get-FastPASPropertyValue $WorkerSpec @('StartupDelayMilliseconds')
            if ($startupDelay -and [int]$startupDelay -gt 0) { Start-Sleep -Milliseconds ([int]$startupDelay) }
            $context = Connect-FastPAS -ProfileId $WorkerSpec.ProfileId -Secret $WorkerSpec.RuntimeSecret -NonInteractive
            $ownsContext = $true
        }
    }
    catch {
        foreach ($planned in @($WorkerSpec.Accounts)) {
            $row = [pscustomobject][ordered]@{
                Timestamp = [DateTimeOffset]::UtcNow.ToString('o'); RunId = $WorkerSpec.RunId; Attempt = $WorkerSpec.Attempt
                WorkerId = $WorkerSpec.WorkerId; OldSafe = $planned.OldSafe; NewSafe = $planned.NewSafe
                SourceAccountId = $planned.SourceAccountId; DestinationAccountId = ''; AccountName = $planned.AccountName
                PlatformId = $planned.PlatformId; PreservedDirectLinks = 0; PreservedDependents = 0; PreservedDependentLinks = 0
                Stage = 'Authentication'; Status = 'WorkerAuthenticationFailed'
                Retryable = $true; DurationMs = 0; Issue = $_.Exception.Message
                RecommendedAction = 'Correct worker authentication and resume the run.'
            }
            Save-WorkerRow $row
            $results.Add($row)
        }
        return @($results)
    }

    try {
        foreach ($planned in @($WorkerSpec.Accounts)) {
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            $sourceId = [string]$planned.SourceAccountId
            $destinationId = ''
            $stage = 'Prepare'
            $status = 'Completed'
            $issue = ''
            $recommendedAction = ''
            $retryable = $false
            $retrievedSecret = $null
            $destinationSecret = $null
            $finalSourceSecret = $null
            $creationBody = $null
            $relationships = [pscustomobject]@{Links = @(); Dependents = @(); Unsupported = @() }
            $sourceVersionMarker = ''
            $preservedDirectLinks = 0
            $preservedDependents = 0
            $preservedDependentLinks = 0
            try {
                $account = $planned.Account
                if ($WorkerSpec.DetailMode -eq 'Always') {
                    $stage = 'ReadDetails'
                    $readParameters = @{
                        Context = $context
                        Method = 'GET'
                        Path = "Accounts/$([uri]::EscapeDataString($sourceId))"
                        MaxGetRetries = $WorkerSpec.MaxGetRetries
                    }
                    $account = Invoke-FastPASWorkerApiRequest @readParameters
                }
                $stage = 'Prepare'
                if ($relationshipMode -eq 'FullFidelity') {
                    $relationships = Get-FastPASAccountTransferRelationshipState -Context $context -Account $account `
                        -AccountId $sourceId -DeploymentType $deploymentType -MaxGetRetries $WorkerSpec.MaxGetRetries
                    if ($relationships.Unsupported.Count) {
                        throw "Full-fidelity transfer cannot safely recreate: $($relationships.Unsupported -join ', ')."
                    }
                    $allPreservedLinks = @($relationships.Links) + @($relationships.Dependents | ForEach-Object { @($_.Links) })
                    foreach ($link in $allPreservedLinks) {
                        $movingById = $link.TargetAccountId -and $movingAccountLookup.ContainsKey("id:$($link.TargetAccountId)")
                        $movingByName = $movingAccountLookup.ContainsKey(("name:{0}`0{1}" -f $link.TargetSafe, $link.TargetName).ToLowerInvariant())
                        if ($movingById -or $movingByName) {
                            throw "Full-fidelity transfer cannot preserve a link to another account in this run ($($link.TargetSafe)/$($link.TargetName)). Move linked targets in a separate completed run."
                        }
                    }
                    $sourceVersionMarker = Get-FastPASAccountSecretVersionMarker -Account $account
                    if (-not $sourceVersionMarker) { throw 'Full-fidelity transfer requires a source password-version marker, but this PVWA response did not provide one.' }
                }
                else {
                    $group = Get-FastPASPropertyValue $account @('accountGroupId', 'AccountGroupId', 'groupId', 'GroupId')
                    $relationshipNames = @(
                        @('linkedAccounts', 'LinkedAccounts'), @('logonAccount', 'LogonAccount'),
                        @('reconcileAccount', 'ReconcileAccount'), @('dependencies', 'Dependencies'), @('usages', 'Usages')
                    )
                    foreach ($relationshipName in $relationshipNames) {
                        $relationship = Get-FastPASPropertyValue $account $relationshipName
                        if ($null -ne $relationship -and @($relationship).Count -gt 0) {
                            throw "The account has relationship metadata ($($relationshipName[0])). FastPAS will not silently discard it."
                        }
                    }
                    if ($group) { throw 'The account belongs to an account group. FastPAS will not silently discard group membership.' }
                }

                $stage = 'Retrieve'
                $retrieveBody = @{reason = [string]$WorkerSpec.Reason }
                $retrieveParameters = @{
                    Context = $context
                    Method = 'POST'
                    Path = "Accounts/$([uri]::EscapeDataString($sourceId))/Password/Retrieve"
                    Body = $retrieveBody
                }
                $retrievedSecret = Invoke-FastPASWorkerApiRequest @retrieveParameters
                if ($retrievedSecret -isnot [string]) {
                    $retrievedSecret = Get-FastPASObjectString $retrievedSecret @('password', 'Password', 'content', 'Content', 'secret', 'Secret')
                }
                if ([string]::IsNullOrEmpty([string]$retrievedSecret)) { throw 'CyberArk returned an empty current secret.' }

                $stage = 'Create'
                $creationBody = New-FastPASAccountTransferBody -Account $account -DestinationSafe $planned.NewSafe -Secret ([string]$retrievedSecret)
                $created = Invoke-FastPASWorkerApiRequest -Context $context -Method POST -Path 'Accounts' -Body $creationBody
                $destinationId = Get-FastPASObjectString $created @('id', 'ID', 'accountId')
                if (-not $destinationId) { throw 'CyberArk did not return a destination account ID after the create request.' }

                $stage = 'Verify'
                $verifyParameters = @{
                    Context = $context
                    Method = 'GET'
                    Path = "Accounts/$([uri]::EscapeDataString($destinationId))"
                    MaxGetRetries = $WorkerSpec.MaxGetRetries
                }
                $verified = Invoke-FastPASWorkerApiRequest @verifyParameters
                if ((Get-FastPASObjectString $verified @('safeName', 'SafeName')) -ne $planned.NewSafe -or
                    (Get-FastPASObjectString $verified @('platformId', 'PlatformID')) -ne $planned.PlatformId -or
                    (Get-FastPASObjectString $verified @('name', 'Name')) -ne $planned.AccountName) {
                    throw 'Destination verification did not match safe, platform, and account name.'
                }

                $stage = 'VerifySecret'
                $destinationRetrieveParameters = @{
                    Context = $context
                    Method = 'POST'
                    Path = "Accounts/$([uri]::EscapeDataString($destinationId))/Password/Retrieve"
                    Body = @{reason = "$($WorkerSpec.Reason) (destination verification)" }
                }
                $destinationSecret = Invoke-FastPASWorkerApiRequest @destinationRetrieveParameters
                if ($destinationSecret -isnot [string]) {
                    $destinationSecret = Get-FastPASObjectString $destinationSecret @('password', 'Password', 'content', 'Content', 'secret', 'Secret')
                }
                if ([string]::IsNullOrEmpty([string]$destinationSecret)) {
                    throw 'CyberArk returned an empty destination secret during verification.'
                }
                if (-not (Test-FastPASSecretMatch -First ([string]$retrievedSecret) -Second ([string]$destinationSecret))) {
                    throw 'The destination current secret did not match the retrieved source secret.'
                }

                if ($relationshipMode -eq 'FullFidelity') {
                    $stage = 'PreserveRelationships'
                    foreach ($link in @($relationships.Links)) {
                        $linkBody = @{
                            safe = [string]$link.TargetSafe; extraPasswordIndex = [int]$link.ExtraPasswordIndex
                            name = [string]$link.TargetName; folder = [string]$link.TargetFolder
                        }
                        $null = Invoke-FastPASWorkerApiRequest -Context $context -Method POST `
                            -Path "Accounts/$([uri]::EscapeDataString($destinationId))/LinkAccount" -Body $linkBody
                    }
                    $linkVerification = Test-FastPASAccountTransferLinkSet -Context $context -AccountId $destinationId `
                        -ExpectedLinks @($relationships.Links) -MaxGetRetries $WorkerSpec.MaxGetRetries
                    if (-not $linkVerification.Success) {
                        throw "Destination link verification did not return: $($linkVerification.Missing -join ', '). API returned: $($linkVerification.Actual -join ', ')."
                    }
                    $preservedDirectLinks = @($relationships.Links).Count

                    $stage = 'PreserveDependents'
                    $destinationDependentPath = if ($deploymentType -eq 'ispss') {
                        "Accounts/$([uri]::EscapeDataString($destinationId))/account-dependents"
                    } else {
                        "Accounts/$([uri]::EscapeDataString($destinationId))/dependentAccounts"
                    }
                    foreach ($dependent in @($relationships.Dependents)) {
                        $createdDependent = Invoke-FastPASWorkerApiRequest -Context $context -Method POST `
                            -Path $destinationDependentPath -Body $dependent.Body
                        $destinationDependentId = Get-FastPASObjectString $createdDependent @('id', 'ID', 'dependentAccountId', 'DependentAccountId')
                        if (-not $destinationDependentId) {
                            throw "CyberArk did not return an ID after creating dependent '$($dependent.Name)' ($($dependent.PlatformId))."
                        }
                        foreach ($dependentLink in @($dependent.Links)) {
                            if ($deploymentType -eq 'ispss') {
                                $dependentLinkPath = "$destinationDependentPath/$([uri]::EscapeDataString($destinationDependentId))/link-accounts"
                                $dependentLinkBody = @{
                                    accountID = [string]$dependentLink.TargetAccountId
                                    extraPasswordIndex = [int]$dependentLink.ExtraPasswordIndex
                                }
                            }
                            else {
                                $dependentLinkPath = "$destinationDependentPath/$([uri]::EscapeDataString($destinationDependentId))/Link"
                                $dependentLinkBody = @{
                                    safe = [string]$dependentLink.TargetSafe
                                    extraPasswordIndex = [int]$dependentLink.ExtraPasswordIndex
                                    name = [string]$dependentLink.TargetName
                                    folder = [string]$dependentLink.TargetFolder
                                }
                            }
                            $null = Invoke-FastPASWorkerApiRequest -Context $context -Method POST `
                                -Path $dependentLinkPath -Body $dependentLinkBody
                        }
                        $verifiedDependent = Invoke-FastPASWorkerApiRequest -Context $context -Method GET `
                            -Path "$destinationDependentPath/$([uri]::EscapeDataString($destinationDependentId))" `
                            -Query @{extendedDetails = 'true' } -MaxGetRetries $WorkerSpec.MaxGetRetries
                        $wrappedDependent = Get-FastPASPropertyValue $verifiedDependent @('dependentAccount', 'DependentAccount')
                        if ($null -ne $wrappedDependent) { $verifiedDependent = $wrappedDependent }
                        $dependentVerification = Test-FastPASDependentTransferBody -ExpectedBody $dependent.Body -Actual $verifiedDependent
                        if (-not $dependentVerification.Success) {
                            throw "Dependent '$($dependent.Name)' verification differed in: $($dependentVerification.Differences -join ', ')."
                        }
                        $actualDependentLinks = [Collections.Generic.List[object]]::new()
                        foreach ($property in @(@('linkedAccounts', 'LinkedAccounts'), @('logonAccount', 'LogonAccount'), @('reconcileAccount', 'ReconcileAccount'))) {
                            $rawActualLinks = @(Get-FastPASPropertyValue $verifiedDependent $property)
                            foreach ($rawActualLink in $rawActualLinks) {
                                if ($null -eq $rawActualLink) { continue }
                                $normalizedActualLink = ConvertTo-FastPASAccountTransferLink -Context $context -Link $rawActualLink `
                                    -MaxGetRetries $WorkerSpec.MaxGetRetries
                                if (-not @($actualDependentLinks | Where-Object Key -EQ $normalizedActualLink.Key).Count) {
                                    $actualDependentLinks.Add($normalizedActualLink)
                                }
                            }
                        }
                        $actualDependentLinkKeys = @($actualDependentLinks | ForEach-Object { $_.Key })
                        $missingDependentLinks = @($dependent.Links | Where-Object Key -NotIn $actualDependentLinkKeys)
                        if ($missingDependentLinks.Count) {
                            throw "Dependent '$($dependent.Name)' did not return recreated link(s): $(@($missingDependentLinks.Key) -join ', ')."
                        }
                        $preservedDependents++
                        $preservedDependentLinks += @($dependent.Links).Count
                    }

                    $stage = 'StabilityCheck'
                    $currentSource = Invoke-FastPASWorkerApiRequest -Context $context -Method GET `
                        -Path "Accounts/$([uri]::EscapeDataString($sourceId))" -MaxGetRetries $WorkerSpec.MaxGetRetries
                    $currentMarker = Get-FastPASAccountSecretVersionMarker -Account $currentSource
                    if (-not $currentMarker -or $currentMarker -ne $sourceVersionMarker) {
                        throw "The source password-version marker changed or disappeared during transfer (before='$sourceVersionMarker', after='$currentMarker')."
                    }
                    $finalSourceSecret = Invoke-FastPASWorkerApiRequest -Context $context -Method POST `
                        -Path "Accounts/$([uri]::EscapeDataString($sourceId))/Password/Retrieve" `
                        -Body @{reason = "$($WorkerSpec.Reason) (pre-delete stability verification)" }
                    if ($finalSourceSecret -isnot [string]) {
                        $finalSourceSecret = Get-FastPASObjectString $finalSourceSecret @('password', 'Password', 'content', 'Content', 'secret', 'Secret')
                    }
                    if ([string]::IsNullOrEmpty([string]$finalSourceSecret) -or
                        -not (Test-FastPASSecretMatch -First ([string]$retrievedSecret) -Second ([string]$finalSourceSecret))) {
                        throw 'The source current secret changed during transfer.'
                    }
                }

                $stage = 'Delete'
                $deleteParameters = @{
                    Context = $context
                    Method = 'DELETE'
                    Path = "Accounts/$([uri]::EscapeDataString($sourceId))"
                }
                $null = Invoke-FastPASWorkerApiRequest @deleteParameters
                $stage = 'Completed'
                $recommendedAction = 'No action required; final reconciliation will confirm both safes.'
            }
            catch {
                if ($stage -eq 'Prepare' -and $_.Exception.Message -match 'Full-fidelity transfer cannot safely recreate') {
                    $failure = [pscustomobject]@{Status = 'UnsupportedRelationshipBlocked'; Retryable = $false; Action = 'The source was retained. Resolve the reported account group, API limitation, or unresolvable relationship before retrying.' }
                }
                elseif ($stage -eq 'Prepare' -and $_.Exception.Message -match 'another account in this run') {
                    $failure = [pscustomobject]@{Status = 'LinkedTargetInRunBlocked'; Retryable = $false; Action = 'Move the linked target first in a separate run, then retry this account.' }
                }
                elseif ($stage -eq 'Prepare' -and $_.Exception.Message -match 'password-version marker') {
                    $failure = [pscustomobject]@{Status = 'SecretVersionUnavailable'; Retryable = $false; Action = 'The source was retained. Confirm PVWA/API support before using full-fidelity mode.' }
                }
                elseif ($stage -eq 'Prepare' -and $_.Exception.Message -match 'relationship metadata') {
                    $failure = [pscustomobject]@{Status = 'LinkedAccountBlocked'; Retryable = $false; Action = 'Migrate or remove account relationships explicitly before retrying.' }
                }
                elseif ($stage -eq 'Prepare' -and $_.Exception.Message -match 'account group') {
                    $failure = [pscustomobject]@{Status = 'AccountGroupBlocked'; Retryable = $false; Action = 'Plan account-group membership migration before retrying.' }
                }
                else { $failure = Get-FastPASAccountTransferFailure -Stage $stage -Message $_.Exception.Message }
                $status = $failure.Status
                $retryable = $failure.Retryable
                $recommendedAction = $failure.Action
                $issue = $_.Exception.Message
            }
            finally {
                if ($creationBody -is [Collections.IDictionary] -and $creationBody.Contains('secret')) { $creationBody.secret = $null }
                $retrievedSecret = $null
                $destinationSecret = $null
                $finalSourceSecret = $null
                $stopwatch.Stop()
            }
            $row = [pscustomobject][ordered]@{
                Timestamp = [DateTimeOffset]::UtcNow.ToString('o'); RunId = $WorkerSpec.RunId; Attempt = $WorkerSpec.Attempt
                WorkerId = $WorkerSpec.WorkerId; OldSafe = $planned.OldSafe; NewSafe = $planned.NewSafe
                SourceAccountId = $sourceId; DestinationAccountId = $destinationId; AccountName = $planned.AccountName
                PlatformId = $planned.PlatformId; Stage = $stage; Status = $status; Retryable = $retryable
                PreservedDirectLinks = $preservedDirectLinks; PreservedDependents = $preservedDependents
                PreservedDependentLinks = $preservedDependentLinks
                DurationMs = $stopwatch.ElapsedMilliseconds; Issue = $issue; RecommendedAction = $recommendedAction
            }
            Save-WorkerRow $row
            $results.Add($row)
        }
    }
    finally {
        if ($ownsContext -and $context) { Disconnect-FastPAS -Context $context }
    }
    return @($results)
}

function ConvertFrom-FastPASEpoch {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try {
        $number = [double]$Value
        if ($number -gt 100000000000) { return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$number) }
        if ($number -gt 1000000000) { return [DateTimeOffset]::FromUnixTimeSeconds([long]$number) }
    }
    catch {
        # The value may be a normal date string rather than an epoch value.
        Write-Debug "Value '$Value' is not a numeric epoch; trying date parsing instead."
    }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-FastPASOptionalItems {
    param(
        [Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string[]]$Paths,
        [hashtable]$Query = @{}, [string[]]$CollectionNames = @('value', 'Value'),
        [Collections.Generic.List[string]]$Warnings
    )
    foreach ($path in $Paths) {
        try {
            $paged = @(Get-FastPASPagedItems -Context $Context -Path $path -Query $Query -CollectionNames $CollectionNames)
            if ($paged.Count) { return $paged }
            # Some monitoring, license, and application endpoints return one
            # object rather than a standard offset/limit collection.
            $direct = Invoke-FastPASApiRequest -Context $Context -Method GET -Path $path -Query $Query
            foreach ($name in $CollectionNames) {
                $collection = Get-FastPASPropertyValue $direct @($name);
                if ($null -ne $collection) { return @($collection) }
            }
            if ($null -ne $direct) { return @($direct) }
            return @()
        }
        catch { $Warnings.Add("Endpoint '$path' is unavailable for this tenant or role: $($_.Exception.Message)") }
    }
    return @()
}

function Protect-FastPASAuditValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $redacted = $Value -replace '(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+', '$1[REDACTED]'
        $redacted = $redacted -replace '(?i)("?(?:access_token|client_secret|password|token)"?\s*[:=]\s*"?)[^",\s}]+', '$1[REDACTED]'
        return $redacted
    }
    if ($Value -is [Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) { $copy[$key] = if ($script:SensitiveNames -contains $key) { '[REDACTED]' } else { Protect-FastPASAuditValue $Value[$key] } }
        return $copy
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value | ForEach-Object { Protect-FastPASAuditValue $_ }) }
    return $Value
}

function Write-FastPASAuditEvent {
    param([Parameter(Mandatory)]$Context, [string]$CommandId, [string]$Outcome, [hashtable]$Detail = @{})
    $path = Get-FastPASAuditPath;
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force -WhatIf:$false
    $auditEvent = [ordered]@{
        timestamp = [DateTimeOffset]::UtcNow.ToString('o');
        correlationId = $Context.CorrelationId;
        profileId = $Context.Profile.Id
        profileName = $Context.Profile.Name;
        tenant = $Context.Profile.Subdomain;
        command = $CommandId;
        outcome = $Outcome
        detail = (Protect-FastPASAuditValue $Detail)
    }
    Add-Content -LiteralPath $path -Value ($auditEvent | ConvertTo-Json -Compress -Depth 20) -Encoding utf8NoBOM -WhatIf:$false
}

function New-FastPASResult {
    param([bool]$Success, [string]$Summary, $Data = @(), [string[]]$Warnings = @(), [string[]]$Artifacts = @(), [object[]]$AuditEvents = @())
    [pscustomobject]@{ PSTypeName = 'FastPAS.CommandResult';
        Success = $Success;
        Summary = $Summary;
        Data = @($Data);
        Warnings = @($Warnings);
        Artifacts = @($Artifacts);
        AuditEvents = @($AuditEvents)
    }
}

function Get-FastPASOutputDirectory {
    param([string]$OutputPath)
    if (-not $OutputPath) { $OutputPath = Join-Path $PWD 'output' }
    $full = [IO.Path]::GetFullPath($OutputPath);
    $null = New-Item -ItemType Directory -Path $full -Force -WhatIf:$false;
    return $full
}

function Export-FastPASCsv {
    param([object[]]$Data, [string]$OutputPath, [string]$Prefix)
    $dir = Get-FastPASOutputDirectory $OutputPath;
    $path = Join-Path $dir ("{0}_{1}.csv" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
    @($Data) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8BOM -WhatIf:$false
    return $path
}

function Export-FastPASJson {
    param($Data, [string]$OutputPath, [string]$Prefix)
    $dir = Get-FastPASOutputDirectory $OutputPath;
    $path = Join-Path $dir ("{0}_{1}.json" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
    $Data | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8NoBOM -WhatIf:$false
    return $path
}

function Export-FastPASHtmlDashboard {
    param([object[]]$Data, [string]$OutputPath, [string]$Prefix, [string]$Title, [hashtable]$Metrics = @{})
    $dir = Get-FastPASOutputDirectory $OutputPath;
    $path = Join-Path $dir ("{0}_{1}.html" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
    $encode = { param($v) [Net.WebUtility]::HtmlEncode([string]$v) }
    $metricHtml = ($Metrics.GetEnumerator() | ForEach-Object { "<div class='metric'><strong>$(& $encode $_.Value)</strong><span>$(& $encode $_.Key)</span></div>" }) -join "`n"
    $rows = @($Data);
    $table = ''
    if ($rows.Count) {
        $columns = @($rows[0].PSObject.Properties.Name)
        $head = ($columns | ForEach-Object { "<th>$(& $encode $_)</th>" }) -join ''
        $body = foreach ($row in $rows) {
            $cells = foreach ($column in $columns) {
                $value = $row.$column
                if ($column -in @('PercentOfTotal', 'UtilizationPercent')) {
                    $width = [Math]::Max(0, [Math]::Min(100, [double]$value));
                    "<td><div class='bar'><span style='width:$width%'></span><b>$(& $encode $value)%</b></div></td>"
                }
                elseif ($column -in @('ActivityGroup', 'Status', 'Service', 'ManagementStatus')) {
                    $class = ([string]$value -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant();
                    "<td><span class='badge $class'>$(& $encode $value)</span></td>"
                }
                else { "<td>$(& $encode $value)</td>" }
            }
            '<tr>' + ($cells -join '') + '</tr>'
        }
        $table = "<table><thead><tr>$head</tr></thead><tbody>$($body -join "`n")</tbody></table>"
    }
    else { $table = '<p>No rows returned.</p>' }
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>$(& $encode $Title)</title>
<style>:root{color-scheme:light}*{box-sizing:border-box}body{font:14px Segoe UI,Arial;margin:0;padding:2rem;color:#172033;background:linear-gradient(135deg,#eef3f8,#f8fafc)}h1{color:#123b65;margin-top:0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem}.metric{background:white;border-top:4px solid #f04d1e;border-radius:8px;padding:1rem;box-shadow:0 3px 12px #123b6518}.metric strong,.metric span{display:block}.metric strong{font-size:1.6rem;color:#123b65}.metric span{color:#52606d;margin-top:.25rem}table{border-collapse:separate;border-spacing:0;width:100%;background:white;margin-top:1.5rem;border-radius:8px;overflow:hidden;box-shadow:0 3px 12px #123b6518}th,td{text-align:left;border-bottom:1px solid #dce3ec;padding:.65rem;vertical-align:top}th{background:#123b65;color:white;position:sticky;top:0}tr:nth-child(even){background:#f5f8fc}.meta{color:#52606d}.badge{display:inline-block;padding:.2rem .55rem;border-radius:99px;background:#e7eef6;color:#123b65;font-weight:600}.badge.passed,.badge.completed,.badge.active-this-week,.badge.success{background:#d9f2e6;color:#176943}.badge.failed,.badge.failure,.badge.inactive-1-month{background:#fde2dc;color:#9c2f1b}.badge.cpm{background:#e4efff;color:#245fa8}.badge.psm{background:#f5e4ef;color:#84335d}.bar{position:relative;min-width:130px;height:1.35rem;background:#e7edf4;border-radius:99px;overflow:hidden}.bar span{position:absolute;inset:0 auto 0 0;background:linear-gradient(90deg,#f04d1e,#ff8b4c)}.bar b{position:relative;display:block;text-align:center;line-height:1.35rem;color:#172033}@media(max-width:700px){body{padding:1rem;overflow-x:auto}}</style></head><body>
<h1>$(& $encode $Title)</h1><p class="meta">Generated $([DateTimeOffset]::Now.ToString('u')) by FastPAS PowerShell.</p><div class="metrics">$metricHtml</div>$table</body></html>
"@
    Set-Content -LiteralPath $path -Value $html -Encoding utf8NoBOM -WhatIf:$false;
    return $path
}

<#
.SYNOPSIS
Lists FastPAS command descriptors or returns one descriptor by command ID.
#>
function Get-FastPASCommand {
    [CmdletBinding()]
    param([string]$Id)
    $catalog = Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'config/commands.psd1')
    $operatorHelp = Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'config/operator-help.psd1')
    $commands = @($catalog.Commands | ForEach-Object {
            $copy = [ordered]@{} + $_
            if (-not $copy.Contains('Sections')) { $copy.Sections = @($copy.Category) }
            if (-not $copy.Contains('Parameters')) { $copy.Parameters = @() }
            if (-not $copy.Contains('Deployments')) { $copy.Deployments = @('ispss', 'onprem', 'standalone') }
            $metadata = $operatorHelp.Commands[$copy.Id]
            if ($null -eq $metadata) { $metadata = @{} }
            $copy.Description = if ($metadata.ContainsKey('Description')) { $metadata.Description } else { $copy.DisplayName }
            $copy.RequiredParameters = if ($metadata.ContainsKey('Required')) { @($metadata.Required) } else { @() }
            $copy.Defaults = if ($metadata.ContainsKey('Defaults')) { $metadata.Defaults } else { @{} }
            $copy.Template = if ($metadata.ContainsKey('Template')) { [string]$metadata.Template } else { '' }
            $copy.ParameterHelp = $operatorHelp.ParameterHelp
            $copy.MenuGroup = if ($copy.RiskLevel -eq 'Write') { 'Changes and repair actions' } else { 'Read-only reports and inspection' }
            [pscustomobject]$copy
        })
    if ($Id) { return $commands | Where-Object Id -EQ $Id | Select-Object -First 1 }
    return $commands
}

<#
.SYNOPSIS
Returns the ordered list of FastPAS main-menu sections.
#>
function Get-FastPASMenuSection {
    [CmdletBinding()]
    param()
    $catalog = Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'config/commands.psd1')
    return @($catalog.MenuSections)
}

function Confirm-FastPASMutation {
    param([Parameter(Mandatory)]$Descriptor, [Parameter(Mandatory)][hashtable]$Arguments)
    Write-Warning "This command will modify CyberArk: $($Descriptor.DisplayName)"
    $Arguments.GetEnumerator() | Sort-Object Key | Format-Table Key, Value -AutoSize | Out-Host
    return (Read-Host "Type APPLY to continue") -ceq 'APPLY'
}

<#
.SYNOPSIS
Runs one cataloged FastPAS command through the shared orchestration contract.
.DESCRIPTION
Validates unattended use, confirms changes, invokes the command script, verifies
its result contract, and writes redacted start and completion audit events.
#>
function Invoke-FastPASCommand {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Context, [hashtable]$Arguments = @{},
        [string]$OutputPath = (Join-Path $PWD 'output'), [switch]$NonInteractive, [switch]$Force
    )
    $descriptor = Get-FastPASCommand -Id $Id
    if (-not $descriptor) { throw "Unknown FastPAS command '$Id'." }
    $deploymentType = if ($Context.PSObject.Properties['DeploymentType'] -and $Context.DeploymentType) {
        [string]$Context.DeploymentType
    }
    elseif ($Context.Profile.PSObject.Properties['DeploymentType'] -and $Context.Profile.DeploymentType) {
        [string]$Context.Profile.DeploymentType
    }
    else { 'ispss' }
    if ($deploymentType -notin @($descriptor.Deployments)) {
        throw "Command '$Id' is not available for the '$deploymentType' deployment type. Supported deployment(s): $($descriptor.Deployments -join ', ')."
    }
    if ($NonInteractive -and -not $descriptor.SupportsUnattended) { throw "Command '$Id' does not support unattended execution." }
    if ($descriptor.RiskLevel -eq 'Write') {
        if ($NonInteractive -and -not $WhatIfPreference) {
            if (-not $Force -or $ConfirmPreference -ne 'None') { throw 'Unattended writes require both -Force and -Confirm:$false.' }
        }
        elseif (-not $WhatIfPreference -and -not (Confirm-FastPASMutation $descriptor $Arguments)) {
            return New-FastPASResult -Success $false -Summary 'Operation cancelled; APPLY was not entered.'
        }
    }
    $path = Join-Path $script:ModuleRoot $descriptor.Script
    if (-not (Test-Path -LiteralPath $path)) { throw "Command script is missing: $path" }
    Write-FastPASAuditEvent -Context $Context -CommandId $Id -Outcome 'started' -Detail @{arguments = $Arguments;
        risk = $descriptor.RiskLevel
    }
    try {
        $result = & $path -Context $Context -Arguments $Arguments -OutputPath $OutputPath -NonInteractive:$NonInteractive -Force:$Force -WhatIf:$WhatIfPreference -Confirm:$false
        if ($null -eq $result -or $result.PSTypeNames -notcontains 'FastPAS.CommandResult') { throw "Command '$Id' did not return a FastPAS.CommandResult." }
        Write-FastPASAuditEvent -Context $Context -CommandId $Id -Outcome $(if ($result.Success) { 'succeeded' }else { 'failed' }) -Detail @{summary = $result.Summary;
            artifacts = $result.Artifacts
        }
        return $result
    }
    catch {
        Write-FastPASAuditEvent -Context $Context -CommandId $Id -Outcome 'failed' -Detail @{error = $_.Exception.Message }
        throw
    }
}

Export-ModuleMember -Function Connect-FastPAS, Disconnect-FastPAS, Get-FastPASCommand, Get-FastPASMenuSection, Get-FastPASProfile, Invoke-FastPASApiRequest, Invoke-FastPASCommand, New-FastPASProfile, Remove-FastPASProfile, Resolve-FastPASTenant, Set-FastPASActiveProfile
