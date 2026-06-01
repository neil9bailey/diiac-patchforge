# PatchForge Production Purge Status

Date: 2026-06-01

Status: pending exact confirmation

Requested action: purge PatchForge production data to start fresh on the new build.

Result: not executed.

Reason: destructive purge is intentionally gated by the exact typed confirmation phrase `FACTORY_RESET_PATCHFORGE`. The phrase has not been provided, and protected API dry-run access could not be completed from Azure CLI because Entra consent for the Azure CLI application is not granted for the PatchForge API audience.

Required next step: sign in as `PatchForge.Admin` in the live UI and use Admin -> System & Data Health -> Factory Reset, or provide the exact phrase `FACTORY_RESET_PATCHFORGE` in this thread so the destructive purge can be run through the guarded deployed API path.
