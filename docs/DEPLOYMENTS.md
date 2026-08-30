# Deployment and profile guide

[Home](../README.md) · [CLI reference](CLI-REFERENCE.md) · [Security](../SECURITY.md)

FastPAS chooses authentication and URL construction from the profile's
deployment type. This choice is required before any login fields are shown.

## ISPSS

Use ISPSS for Privilege Cloud Shared Services where CyberArk Identity brokers
the login and issues a platform token.

The profile builder asks for:

- profile name and tenant subdomain;
- OAuth service user, native Identity/MFA, or external IdP authentication;
- OAuth application/client IDs, or the human username;
- Identity host and Privilege Cloud API URL only when discovery needs an override.

External IdP profiles open the CyberArk-provided HTTPS URL in the system browser,
so Entra, Okta, Ping, or another configured provider owns its password, MFA, and
conditional-access flow. FastPAS receives only the CyberArk continuation data.

## On-premises PAM

Use on-premises for a self-hosted PVWA/Vault environment. A Vault address alone
is not enough for this REST client: FastPAS needs the HTTPS **PVWA URL** because
authentication and every command use PVWA web services.

The profile builder asks for:

- profile name;
- PVWA URL (server root, `/PasswordVault`, or `/PasswordVault/API`);
- CyberArk, LDAP, RADIUS, or Windows PVWA authentication;
- Vault/directory username;
- RADIUS separator when applicable;
- optional certificate-validation bypass only for an explicitly approved
  internal/self-signed deployment.

The password and RADIUS OTP are runtime inputs, not profile fields. FastPAS
normalizes the URL to `/PasswordVault/API`, logs on through
`Auth/<provider>/Logon`, and sends the returned raw PVWA session token in the
Authorization header.

## Standalone

FastPAS uses **standalone** to mean legacy/standard Privilege Cloud reached
directly through its PVWA rather than the ISPSS Identity platform-token flow.
It asks for the Privilege Cloud PVWA URL, direct PVWA authentication type, and
username. It does not ask for an ISPSS subdomain or Identity host.

If an environment called “standalone” in local documentation is actually a
self-hosted PVWA, choose **On-premises** so diagnostics and product capability
labels remain accurate.

## Command compatibility

Core account, safe, platform, recording, request, PSM, reporting, and bulk
commands use relative PVWA API paths and therefore inherit the active profile's
URL and token format. Identity user telemetry is ISPSS-only. Legacy Application
ID WebServices are on-premises-only. The menu marks these commands unavailable
on other deployment types, and the orchestrator blocks them before a request.

Optional endpoints can still depend on the installed PAM version, licensed
components, enabled features, and the signed-in user's authorizations.

## Implementation references

- [psPAS authentication guide](https://pspas.pspete.dev/docs/authentication/)
- [psPAS `New-PASSession` parameter sets](https://pspas.pspete.dev/commands/New-PASSession)
- [CyberArk EPV API scripts](https://github.com/cyberark/epv-api-scripts)
- [CyberArk Ark SDK](https://github.com/cyberark/ark-sdk-golang)
