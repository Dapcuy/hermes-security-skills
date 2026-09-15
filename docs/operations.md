# Operations runbook

## Scheduled maintenance

Run `scripts/maintenance.sh` from a dedicated service account after setting the
state roots and backup destination. The script uses an atomic lock, creates and
verifies a backup before retention, skips young cases, and fails closed for
unknown/corrupt case contents.

Example cron entry (adjust the absolute path and environment file):

```cron
17 2 * * * . /etc/hermes/maintenance.env; /opt/hermes/scripts/maintenance.sh >>/var/log/hermes-maintenance.log 2>&1
```

On Windows Task Scheduler, run Git Bash's `bash.exe` with the absolute script
path and provide the same variables through the service account environment.
Do not put credentials in the script, repository, or command-line arguments.

## Log rotation

The production and monitoring Compose profiles use Docker `json-file`
rotation (`10m`, five files). Hosts must also enforce a disk quota and alert on
low free space; container log rotation is not a substitute for host capacity
monitoring.

## Monitoring and alerting

Start production first, then the monitoring profile as documented in
`deploy/monitoring/README.md`. The Prometheus rules alert on scrape failure,
execution errors, and p95 latency. Alertmanager configuration is required from
an operator-managed path; the checked-in example intentionally has no sink.
Configure and test the approved notification destination before production use.

## Controlled rollback

Use `scripts/rollback-compose.sh <image@sha256:digest>` only after selecting a
previous release from a verified release bundle. The script requires:

- a fully-qualified immutable image digest;
- `HERMES_BUNDLE_SHA256`;
- `HERMES_POLICY_DIR`;
- an explicit Cosign public key reference;
- successful signature verification;
- successful Compose config validation and local container health.

It does not contact an external target and does not implement unattended
rollback. Unattended rollback requires an approved orchestrator policy,
change-management integration, and a separately reviewed control plane.
