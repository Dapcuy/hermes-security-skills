# Internal monitoring profile

The monitoring profile is intentionally separate from `production.yaml`.
Start the production profile first so it creates the shared `hermes-control`
network, then start monitoring with operator-provided config paths:

```bash
export HERMES_PROMETHEUS_CONFIG="$PWD/deploy/monitoring/prometheus.yml"
export HERMES_ALERT_RULES="$PWD/deploy/monitoring/hermes-alerts.yml"
export HERMES_ALERTMANAGER_CONFIG="/secure/path/alertmanager.yml"
docker compose -f deploy/compose/monitoring.yaml config
docker compose -f deploy/compose/monitoring.yaml up -d
```

The example Alertmanager file is structurally valid but has no notification
sink. Replace it with an approved secret-managed configuration before relying
on notifications. No monitoring service publishes a host port by default.
Both images are digest-pinned, run read-only, drop all capabilities, use
no-new-privileges, and have bounded resources and Docker log rotation.
