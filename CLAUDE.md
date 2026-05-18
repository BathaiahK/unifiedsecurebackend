# Unified Secure Platform — Backend

REST API service that aggregates security scanner findings from BlackDuck, Sysdig, 42Crunch, and Sonatype into a unified MongoDB store. Consumed exclusively by the `unifiedsecureplatform` frontend via HTTP.

## Repo layout

```
apps/api/                   — Fastify REST API (port 4000)
packages/schema/            — Zod schemas + TypeScript types (shared within this repo)
packages/config/            — Zod-validated env config (DB, scanner URLs, remediation)
packages/adapters/blackduck — BlackDuck SCA scanner adapter
packages/remediation/       — NVD + OSV.dev enrichment engine
```

## Quick start

```bash
pnpm install
pnpm db:generate        # generate Prisma client
pnpm db:push            # push schema to MongoDB (creates collections + indexes)
pnpm dev                # start API on :4000
```

## Environment — apps/api/.env

```
DATABASE_URL=mongodb://localhost:27017/uspservice
PORT=4000
CORS_ORIGIN=http://localhost:3000   # frontend origin

# Scanner credentials (leave blank to disable that adapter)
BLACKDUCK_URL=
BLACKDUCK_API_TOKEN=
SYSDIG_URL=
SYSDIG_API_TOKEN=
CRUNCH42_API_KEY=
SONATYPE_URL=
SONATYPE_USERNAME=
SONATYPE_PASSWORD=

# Remediation enrichment
NVD_API_KEY=
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
OSV_API_URL=https://api.osv.dev/v1
```

## API surface

| Method | Path                | Description                                                     |
| ------ | ------------------- | --------------------------------------------------------------- |
| GET    | /health             | Liveness + configured adapters                                  |
| GET    | /api/findings       | Paginated findings (filter: tool, severity, status, asset, cve) |
| GET    | /api/findings/:id   | Single finding with full evidence                               |
| POST   | /api/scans          | Trigger a scan                                                  |
| GET    | /api/scans          | Recent scan history                                             |
| GET    | /api/scans/:id      | Scan status                                                     |
| GET    | /api/scans/:id/diff | Diff vs previous scan for same asset                            |
| GET    | /api/stats          | Aggregate counts by severity/tool/status                        |
| GET    | /api/assets         | All known asset names                                           |

## Scanner adapter interface

Every adapter implements: `trigger()` → `poll()` → `normalize()` → `store()`.  
Adapters are registered at startup only if their credentials are present in `.env`.

## Build order (dependency graph)

```
packages/schema → packages/config → packages/adapters/* → packages/remediation → apps/api
```

Run `pnpm -r build` to build everything in order.
