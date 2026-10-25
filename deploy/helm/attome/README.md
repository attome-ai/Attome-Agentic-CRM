# Attome Helm chart (optional)

A single server with PostgreSQL is the normal Attome install; this chart is for
deployments that run on Kubernetes. It runs `attome serve` (readiness, liveness
and startup probes on `/health/ready`, `/health` and `/health/startup`),
`attome worker`, the audit chainer (`attome audit-chainer`) and, before each
install and upgrade, `attome migrate`.

The configuration file comes from a Secret (`config.secretName`, key
`config.key`) mounted at `/etc/attome` and named by `CONFIG_FILE`; the secrets it
refers to as `${VAR}` come from `envFromSecret`. Set `server.port` to the
configuration's `app.port`.

The audit chainer may run several replicas: they share one `process_lease` row
(`attome_jobs::lease`), so one polls while the others wait, and another takes
over within the lease time when the holder stops. Server autoscaling is off by
default (`server.autoscaling.enabled`).

```
kubectl create secret generic attome-config --from-file=config.json
helm install crm deploy/helm/attome --set image.tag=<version>
```
