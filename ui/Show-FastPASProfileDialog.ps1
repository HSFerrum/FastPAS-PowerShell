function Show-FastPASProfileDialog {
    [CmdletBinding()]
    param()
    if (-not $IsWindows) { throw 'The profile GUI is available on Windows only. Use the text profile wizard on this platform.' }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = [Windows.Forms.Form]@{Text = 'FastPAS Profile Builder'; Width = 700; Height = 690; StartPosition = 'CenterScreen'; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false }
    $form.Font = [Drawing.Font]::new('Segoe UI', 10)
    $controls = @{}
    $layout = [pscustomobject]@{ Y = 22 }
    $dialogState = [pscustomobject]@{ CreatedProfile = $null }
    function Add-ProfileField([string]$Key, [string]$Label, [string]$Type = 'Text') {
        $caption = [Windows.Forms.Label]@{Text = $Label; Left = 24; Top = $layout.Y; Width = 240; Height = 25 }
        $form.Controls.Add($caption)
        if ($Type -eq 'Combo') {
            $input = [Windows.Forms.ComboBox]@{Left = 275; Top = $layout.Y - 3; Width = 380; DropDownStyle = 'DropDownList' }
        }
        elseif ($Type -eq 'Check') {
            $input = [Windows.Forms.CheckBox]@{Left = 275; Top = $layout.Y - 2; Width = 380; Text = 'Enabled' }
        }
        else { $input = [Windows.Forms.TextBox]@{Left = 275; Top = $layout.Y - 3; Width = 380 } }
        $form.Controls.Add($input)
        $controls[$Key] = [pscustomobject]@{Label = $caption; Input = $input }
        $layout.Y += 42
    }

    Add-ProfileField Name 'Profile name'
    Add-ProfileField DeploymentType 'Deployment type' Combo
    Add-ProfileField AuthType 'Authentication type' Combo
    Add-ProfileField Subdomain 'ISPSS tenant subdomain'
    Add-ProfileField IdentityHost 'Identity host override (optional)'
    Add-ProfileField EndpointUrl 'PVWA / Privilege Cloud API URL'
    Add-ProfileField Username 'Username'
    Add-ProfileField ApplicationId 'OAuth application ID'
    Add-ProfileField ClientId 'OAuth client ID / service-user login'
    Add-ProfileField RadiusOtpDelimiter 'RADIUS password/OTP delimiter'
    Add-ProfileField SkipCertificateCheck 'Skip TLS certificate validation' Check

    $controls.DeploymentType.Input.Items.AddRange(@('ISPSS / Shared Services', 'On-premises PAM', 'Standalone / legacy Privilege Cloud'))
    $controls.DeploymentType.Input.SelectedIndex = 0
    $controls.RadiusOtpDelimiter.Input.Text = ','
    $notice = [Windows.Forms.Label]@{Left = 24; Top = 495; Width = 630; Height = 55; ForeColor = [Drawing.Color]::DarkGreen; Text = 'Profiles contain connection metadata only. This dialog never asks for or stores a password, client secret, OTP, or session token.' }
    $form.Controls.Add($notice)
    $status = [Windows.Forms.Label]@{Left = 24; Top = 548; Width = 630; Height = 38; ForeColor = [Drawing.Color]::DarkRed }
    $form.Controls.Add($status)
    $create = [Windows.Forms.Button]@{Text = 'Create profile'; Left = 423; Top = 590; Width = 112; Height = 34; DialogResult = [Windows.Forms.DialogResult]::None }
    $cancel = [Windows.Forms.Button]@{Text = 'Cancel'; Left = 543; Top = 590; Width = 112; Height = 34; DialogResult = [Windows.Forms.DialogResult]::Cancel }
    $form.Controls.AddRange(@($create, $cancel)); $form.CancelButton = $cancel

    $updateFields = {
        $deployment = $controls.DeploymentType.Input.SelectedIndex
        $previousAuth = [string]$controls.AuthType.Input.SelectedItem
        $controls.AuthType.Input.Items.Clear()
        if ($deployment -eq 0) { $controls.AuthType.Input.Items.AddRange(@('OAuth service user', 'Identity user with MFA', 'External IdP')) }
        else { $controls.AuthType.Input.Items.AddRange(@('CyberArk', 'LDAP', 'RADIUS', 'Windows')) }
        $controls.AuthType.Input.SelectedIndex = 0
        $isISPSS = $deployment -eq 0
        foreach ($key in 'Subdomain', 'IdentityHost', 'ApplicationId', 'ClientId') {
            $controls[$key].Label.Visible = $isISPSS
            $controls[$key].Input.Visible = $isISPSS
        }
        $controls.EndpointUrl.Label.Text = if ($deployment -eq 0) { 'Privilege Cloud API URL (optional)' }elseif ($deployment -eq 1) { 'PVWA URL' }else { 'Privilege Cloud PVWA URL' }
        $controls.SkipCertificateCheck.Label.Visible = $deployment -eq 1
        $controls.SkipCertificateCheck.Input.Visible = $deployment -eq 1
        & $updateAuthFields
    }
    $updateAuthFields = {
        $isISPSS = $controls.DeploymentType.Input.SelectedIndex -eq 0
        $authIndex = $controls.AuthType.Input.SelectedIndex
        $isOAuth = $isISPSS -and $authIndex -eq 0
        $isRadius = -not $isISPSS -and $authIndex -eq 2
        $controls.Username.Label.Visible = -not $isOAuth
        $controls.Username.Input.Visible = -not $isOAuth
        foreach ($key in 'ApplicationId', 'ClientId') {
            $controls[$key].Label.Visible = $isOAuth
            $controls[$key].Input.Visible = $isOAuth
        }
        $controls.RadiusOtpDelimiter.Label.Visible = $isRadius
        $controls.RadiusOtpDelimiter.Input.Visible = $isRadius
    }
    $controls.DeploymentType.Input.Add_SelectedIndexChanged($updateFields)
    $controls.AuthType.Input.Add_SelectedIndexChanged($updateAuthFields)
    & $updateFields

    $create.Add_Click({
            try {
                $deployment = @('ispss', 'onprem', 'standalone')[$controls.DeploymentType.Input.SelectedIndex]
                $auth = if ($deployment -eq 'ispss') { @('oauth', 'interactive', 'federated')[$controls.AuthType.Input.SelectedIndex] }else { @('cyberark', 'ldap', 'radius', 'windows')[$controls.AuthType.Input.SelectedIndex] }
                $parameters = @{Name = $controls.Name.Input.Text; DeploymentType = $deployment; AuthType = $auth; SetActive = $true }
                if ($deployment -eq 'ispss') {
                    $parameters.Subdomain = $controls.Subdomain.Input.Text
                    if ($controls.IdentityHost.Input.Text) { $parameters.IdentityHost = $controls.IdentityHost.Input.Text }
                    if ($controls.EndpointUrl.Input.Text) { $parameters.VaultApiBaseUrl = $controls.EndpointUrl.Input.Text }
                    if ($auth -eq 'oauth') { $parameters.ApplicationId = $controls.ApplicationId.Input.Text; $parameters.ClientId = $controls.ClientId.Input.Text }
                    else { $parameters.Username = $controls.Username.Input.Text }
                }
                else {
                    $parameters.PVWAUrl = $controls.EndpointUrl.Input.Text
                    $parameters.Username = $controls.Username.Input.Text
                    if ($auth -eq 'radius') { $parameters.RadiusOtpDelimiter = $controls.RadiusOtpDelimiter.Input.Text }
                    if ($deployment -eq 'onprem' -and $controls.SkipCertificateCheck.Input.Checked) { $parameters.SkipCertificateCheck = $true }
                }
                $dialogState.CreatedProfile = New-FastPASProfile @parameters
                $form.DialogResult = [Windows.Forms.DialogResult]::OK
                $form.Close()
            }
            catch { $status.Text = $_.Exception.Message }
        })
    try {
        if ($form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) { return $dialogState.CreatedProfile }
        return $null
    }
    finally { $form.Dispose() }
}
