## Operator outcome

Describe the operator problem and the behavior this change provides.

## Safety

- [ ] Read/write risk is correctly cataloged.
- [ ] Every mutation uses `ShouldProcess` and was tested with `-WhatIf`.
- [ ] No password, token, client secret, profile, or tenant data is included.
- [ ] New inputs have plain-language help, validation, and safe defaults.
- [ ] Results contain useful summary, data, warnings, artifacts, and audit details.

## Validation

- [ ] `pwsh ./tools/Format-Project.ps1`
- [ ] `pwsh ./tools/Test-Project.ps1`
- [ ] Relevant mocked success, failure, empty-result, and `-WhatIf` tests
- [ ] Documentation and CSV template updated where applicable

