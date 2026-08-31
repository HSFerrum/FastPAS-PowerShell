# Support

FastPAS is an independent community project, not an official CyberArk support
channel. For product defects, outages, licensing, or tenant configuration that
requires vendor access, use your normal CyberArk support process.

For a FastPAS problem, open a GitHub issue and include:

- FastPAS version or commit
- PowerShell version from `$PSVersionTable.PSVersion`
- command ID and whether it was interactive or command mode
- sanitized error text and HTTP status, if present
- whether `-WhatIf` was used
- expected and actual behavior

Never post passwords, client secrets, platform tokens, profile files, raw
authentication challenges, tenant exports, or unredacted account/user/safe
data. Replace tenant hostnames, usernames, account IDs, and correlation IDs with
synthetic values unless they are essential and approved for disclosure.

Before opening an issue, run:

```powershell
$PSVersionTable | Format-List PSVersion, PSEdition, OS
./FastPAS.ps1 -Command troubleshooting.dependencies -Profile <profile-name>
```

The supported runtimes are Windows PowerShell 5.1 and PowerShell 7+. Include
the complete version and edition from `$PSVersionTable` when reporting a startup
or authentication problem.

For connectivity problems, run the read-only
`troubleshooting.connectivity` command and sanitize its report before sharing.
