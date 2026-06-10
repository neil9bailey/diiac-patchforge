# PatchForge Backup & Recovery Runbook

Date: 2026-06-10

## Current Posture (stated honestly)

- PostgreSQL Flexible Server `psql-diiac-patchforge-prod`: **7-day local point-in-time restore window**, geo-redundant backup **Disabled**, high availability **Disabled** (Burstable B1ms SKU does not support HA).
- Blob storage `stdiiacpatchforgeprod01`: default redundancy; signed packs and evidence are not currently replicated cross-region.
- There is **no automated cross-region DR**. A regional outage of uksouth implies recovery from local backups only.

RTO/RPO statement (current): RPO up to a few minutes within the 7-day PITR window for the database; RTO is hours (manual restore + revalidation). This must be communicated honestly in any customer SLA discussion until geo-redundancy is implemented.

## Point-in-Time Restore (PostgreSQL)

```bash
az postgres flexible-server restore \
  --resource-group rg-diiac-patchforge-prod \
  --name psql-diiac-patchforge-restored \
  --source-server psql-diiac-patchforge-prod \
  --restore-time "2026-06-10T08:00:00Z"
```

Then: validate row counts in `patchforge_records` per tenant/collection, repoint the bridge/worker/scheduler connection settings to the restored server (or rename), verify `/readiness`, and verify one signed pack end-to-end (`POST /api/runtime/decision-packs/verify`).

## Enabling Geo-Redundant Backup (migration required)

`geoRedundantBackup` can only be chosen at server creation. To move to geo-redundant backups:

1. Deploy a new server with `postgresGeoRedundantBackup='Enabled'` (parameter added in `infra/bicep/main.bicep`).
2. Migrate data (`pg_dump`/`pg_restore` during a maintenance window, or logical replication for minimal downtime).
3. Cut over connection settings, verify, then decommission the old server after a soak period.

High availability additionally requires moving off the Burstable SKU to General Purpose (`postgresHighAvailabilityMode='ZoneRedundant'`).

## Blob Storage

Upgrade `stdiiacpatchforgeprod01` to RA-GRS (or add a lifecycle copy of `decision-packs` and `signed-exports` containers to a paired-region account). Signed packs are self-verifying (embedded public key material), so replicated copies remain independently verifiable.

## Quarterly Restore Test Checklist

- [ ] Restore database to a scratch server from a point in the last 24h
- [ ] Verify per-tenant record counts vs production
- [ ] Verify one decision pack signature via the runtime verify endpoint
- [ ] Verify one DOCX/PDF report export from the restored data
- [ ] Record evidence under `docs/release/evidence/<date>-restore-test/`
- [ ] Delete scratch resources

## Key Vault

Key Vault is geo-resilient by platform. Do not delete old versions of `pf-pack-signing-prod`; soft-delete and purge protection must remain enabled.
