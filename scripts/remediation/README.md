# Remediation scripts

Only scripts in this folder can be run on a VM by `azure_run_remediation_script`, and only after the user approves the preview. Each script must:

- Have a header comment saying what it changes and how to roll it back.
- Be idempotent (safe to run twice).
- Be reviewed in a pull request before use.

Scripts are added in Phase 3 and Phase 7.
