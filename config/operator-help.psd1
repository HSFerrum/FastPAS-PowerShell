@{
    ParameterHelp = @{
        AccountId = 'CyberArk account ID. Obtain it from Search accounts or an account inventory export.'
        AccountIds = 'One or more CyberArk account IDs separated by commas.'
        ApplicationId = 'Application ID to filter. Leave blank to include every application.'
        BaselinePath = 'Existing platform_baseline JSON file to compare. Leave blank to create a new baseline.'
        CsvPath = 'Full path to the CSV you reviewed and intend to process. Drag-and-drop or paste the file path.'
        Concurrency = 'Number of parallel authenticated workers. Use 12 initially; allowed range is 1 through 32.'
        RelationshipMode = "Block rejects every detected relationship. FullFidelity recreates and verifies direct links plus dependent accounts and their platform-specific fields; unsupported relationships remain blocked."
        CpmOperationalState = "Operator attestation for CPM/reconcile activity: Unknown, Paused, or Active. FullFidelity requires Paused."
        Description = 'Short purpose or ownership description. This is optional.'
        DetailMode = 'Always retrieves authoritative account details before moving. Inventory is faster but trusts list metadata.'
        EndpointCsvPath = 'Optional outbound-endpoints CSV. Leave blank to test the tenant-derived endpoints only.'
        InactiveDays = 'Flag users with no successful login for this many days.'
        LookbackDays = 'Number of previous days to include in the report.'
        ManagingCPM = 'Managing CPM name. Leave blank when the safe should use no explicit CPM assignment.'
        MaxAccounts = 'Safety limit for account-detail API calls in this report.'
        MaxGetRetries = 'Transient retry limit for read-only GET requests. Create and delete requests are never automatically retried.'
        MemberName = 'Exact Vault or directory user/group name to add.'
        MemberType = 'Principal type: user or group.'
        OnlyWaiting = 'Enter true to return only requests waiting for action; false returns all current requests.'
        PasswordAgeDays = 'Flag managed passwords older than this many days.'
        PlatformId = 'Exact target platform ID. Leave blank when the command supports all platforms.'
        PlatformType = 'Optional discovery platform type, such as Windows Domain or Unix.'
        Principal = 'Optional user or group name filter.'
        Role = 'Safe role preset: Viewer, Operator, or Manager.'
        Reason = 'Auditable reason included with every current-secret retrieval.'
        ResumePath = 'Existing account_safe_transfer run directory to reconcile and safely continue.'
        SafeName = 'Exact safe name, unless the prompt says it is an optional filter.'
        Search = 'Optional text search. Leave blank to return all items you are authorized to see.'
        Status = 'Optional status text filter.'
        UserName = 'Optional Vault username filter.'
    }
    Commands = @{
        'telemetry.components' = @{ Description = 'Ranks PSM connection components by use during the selected period.'; Defaults = @{ LookbackDays = 7 } }
        'telemetry.active-users' = @{ Description = 'Shows Identity users grouped by recent activity and inactivity.' }
        'telemetry.account-failures' = @{ Description = 'Combines CPM account-management failures with failed PSM session evidence.'; Defaults = @{ LookbackDays = 7 } }
        'telemetry.psm-users' = @{ Description = 'Summarizes who used PSM, which protocols they used, and when.'; Defaults = @{ LookbackDays = 90 } }
        'telemetry.license-capacity' = @{ Description = 'Reports Privilege Cloud licensed, used, and available user/application capacity with utilization warnings. Requires a Privilege Cloud administrator role.' }
        'account.inventory' = @{ Description = 'Exports account metadata to CSV and HTML; it never exports passwords.' }
        'safe.members.report' = @{ Description = 'Exports safe members and their exact permissions for one or all visible safes.' }
        'safe.inventory' = @{ Description = 'Exports safe names, retention, CPM assignment, and other safe metadata.' }
        'bulk.safes.apply' = @{ Description = 'Creates, updates, or deletes safes from a reviewed CSV.'; Required = @('CsvPath'); Template = 'bulk-safes.csv' }
        'bulk.safe-members.apply' = @{ Description = 'Adds, updates, or removes safe members using role-based permissions.'; Required = @('CsvPath'); Template = 'bulk-safe-members.csv' }
        'bulk.safe-members.import-compatible' = @{ Description = 'Adds missing safe members using explicit permission columns from an export.'; Required = @('CsvPath'); Template = 'safe-member-permissions.csv' }
        'bulk.accounts.apply' = @{ Description = 'Creates or changes account metadata, or deletes accounts, without accepting passwords in CSV.'; Required = @('CsvPath'); Template = 'bulk-accounts.csv' }
        'platform.accounts.move' = @{ Description = 'Changes target-platform assignments for accounts listed in a reviewed CSV.'; Required = @('CsvPath'); Template = 'platform-account-moves.csv' }
        'resolution.account-failures' = @{ Description = 'Unlocks eligible accounts, re-enables management, starts reconciliation, and verifies the result.'; Required = @('AccountIds') }
        'safe.list' = @{ Description = 'Lists or searches safes visible to the signed-in operator.' }
        'safe.detail' = @{ Description = 'Returns complete metadata for one exact safe name.'; Required = @('SafeName') }
        'safe.create' = @{ Description = 'Creates one safe with conservative retention defaults.'; Required = @('SafeName') }
        'safe.members.list' = @{ Description = 'Lists every member and permission set for one safe.'; Required = @('SafeName') }
        'safe.members.add' = @{ Description = 'Adds one user or group to a safe using a standard role preset.'; Required = @('SafeName','MemberName'); Defaults = @{ MemberType = 'user'; Role = 'Viewer' } }
        'safe.cpm.export' = @{ Description = 'Creates a verified safe-to-CPM snapshot for review or later modification.' }
        'safe.cpm.apply' = @{ Description = 'Applies only CPM changes whose safe snapshot still matches the export.'; Required = @('CsvPath'); Template = 'safe-cpm-assignments.csv' }
        'account.search' = @{ Description = 'Searches account metadata by text and optional safe name.' }
        'account.detail' = @{ Description = 'Returns complete metadata for one CyberArk account ID.'; Required = @('AccountId') }
        'platform.list' = @{ Description = 'Lists and exports target platforms, status, type, and description.' }
        'platform.accounts.report' = @{ Description = 'Exports accounts grouped or filtered by target platform.' }
        'platform.pmterminal.audit' = @{ Description = 'Finds obsolete PMTerminal executable references without changing platforms.' }
        'troubleshooting.dependencies' = @{ Description = 'Checks PowerShell, profile, module, and local FastPAS requirements.' }
        'troubleshooting.connectivity' = @{ Description = 'Checks DNS and TCP 443 connectivity to CyberArk, Identity, and optional SIA endpoints.'; Template = 'outbound-endpoints.csv' }
        'troubleshooting.local-to-domain' = @{ Description = 'Converts selected local-account metadata to domain values from a reviewed CSV.'; Required = @('CsvPath'); Template = 'local-to-domain-accounts.csv' }
        'compliance.posture' = @{ Description = 'Finds high-value account, safe, permission, password-age, and inactive-user hygiene issues.'; Defaults = @{ PasswordAgeDays = 90; InactiveDays = 90 } }
        'onboarding.discovered' = @{ Description = 'Exports pending discovered accounts with duplicate, dependency, and onboarding-rule recommendations.' }
        'onboarding.discovered.apply' = @{ Description = 'Onboards or ignores only the explicit decisions in a reviewed workbench CSV.'; Required = @('CsvPath'); Template = 'discovered-account-decisions.csv' }
        'relationships.report' = @{ Description = 'Maps logon, reconcile, linked, and dependent-account relationships.'; Defaults = @{ MaxAccounts = 500 } }
        'relationships.apply' = @{ Description = 'Creates or removes documented Logon and Reconcile links from CSV.'; Required = @('CsvPath'); Template = 'account-links.csv' }
        'governance.entitlements' = @{ Description = 'Reports direct, group, and expanded effective safe access plus license information when available.' }
        'telemetry.system-health' = @{ Description = 'Combines CyberArk component health with CPM workload and active PSM capacity.' }
        'platform.drift' = @{ Description = 'Captures platform settings or compares them with a previous JSON baseline.' }
        'platform.drift.apply' = @{ Description = 'Applies hash-verified platform setting changes where the deployment exposes that API.'; Required = @('CsvPath'); Template = 'platform-changes.csv' }
        'psm.sessions' = @{ Description = 'Exports active and historical PSM session metadata for operations or incident review.'; Defaults = @{ LookbackDays = 7 } }
        'psm.sessions.action' = @{ Description = 'Suspends, resumes, or terminates active PSM sessions with a mandatory reason.'; Required = @('CsvPath'); Template = 'psm-session-actions.csv' }
        'aam.exposure' = @{ Description = 'Audits Application IDs, authentication methods, and reachable safes where AAM APIs are available.' }
        'aam.exposure.apply' = @{ Description = 'Adds or removes Application ID authentication methods from a reviewed CSV.'; Required = @('CsvPath'); Template = 'application-authentication-changes.csv' }
        'request.queue' = @{ Description = 'Shows personal and incoming dual-control access requests.'; Defaults = @{ OnlyWaiting = 'true' } }
        'request.action' = @{ Description = 'Creates, approves, or rejects dual-control requests from CSV with an audit reason.'; Required = @('CsvPath'); Template = 'access-request-actions.csv' }
        'safe.migration.plan' = @{ Description = 'Validates destination safes, duplicates, account hashes, and relationships before a move.'; Required = @('CsvPath'); Template = 'safe-account-migrations.csv' }
        'safe.migration.apply' = @{ Description = 'Applies only a current verified migration plan and writes a metadata checkpoint.'; Required = @('CsvPath') }
        'account.safe-transfer' = @{ Description = 'DESTRUCTIVE: high-volume, checkpointed transfer that retrieves only each current secret, recreates and verifies the destination, deletes the source, and reconciles both safes. FullFidelity preserves direct links and dependent-account platform fields, management settings, and links; unsupported relationships are blocked.'; Required = @('CsvPath'); Defaults = @{ Concurrency = 12; DetailMode = 'Always'; MaxGetRetries = 5; Reason = 'FastPAS high-volume current-secret-only safe transfer'; RelationshipMode = 'Block'; CpmOperationalState = 'Unknown' }; Template = 'account-safe-transfers.csv' }
    }
}
