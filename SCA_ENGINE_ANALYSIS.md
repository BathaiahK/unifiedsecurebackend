# SCA Engine - Comprehensive Analysis & Implementation Plan

## Current Architecture Analysis

### What Exists Today

```
┌─────────────────────────────────────────────────────────────────┐
│                         SCA Pipeline                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Manifest Parsing (via repo-fetcher + purl-extractor)        │
│     ↓                                                             │
│     Reads: package.json, requirements.txt, pom.xml, go.mod       │
│     Output: List of dependencies with versions                  │
│                                                                   │
│  2. PURL Generation (via purl-extractor)                         │
│     ↓                                                             │
│     Format: pkg:npm/express@4.18.0                               │
│     Supports: npm, PyPI, Maven, Go, cargo, gem, nuget           │
│                                                                   │
│  3. Vulnerability Lookup (via @usp/vuln-db)                     │
│     ↓                                                             │
│     OSV Database (offline, synced from google/osv-data)         │
│     Lookup: name + ecosystem → list of advisories               │
│                                                                   │
│  4. Version Matching (semver-match.ts)                           │
│     ↓                                                             │
│     Check if installed version falls in [introduced, fixed)     │
│     Fallback to exact version lists                              │
│                                                                   │
│  5. Severity Scoring (normalize.ts)                              │
│     ↓                                                             │
│     CVSS 9.0+ → critical                                         │
│     CVSS 7.0-8.9 → high                                          │
│     CVSS 4.0-6.9 → medium                                        │
│     CVSS 1-3.9 → low                                             │
│                                                                   │
│  6. Remediation Generation (normalize.ts)                        │
│     ↓                                                             │
│     Find fixVersion from OSV                                      │
│     Generate ecosystem-specific commands                         │
│     npm: npm install pkg@version                                 │
│     pip: pip install pkg==version                                │
│     go: go get pkg@version                                       │
│                                                                   │
│  7. Finding Normalization → UnifiedFinding                       │
│     ↓                                                             │
│     Standard schema with tool=sca                                │
│     Evidence: full OSV advisory data                             │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Current Strengths

✅ Offline-first: No external API calls (OSV data is pre-synced)  
✅ Multi-ecosystem support: npm, PyPI, Maven, Go, cargo, gem, nuget  
✅ Semver-aware: Understands version ranges, not just exact matches  
✅ Real-time: Local MongoDB, immediate results  
✅ Rich evidence: Full OSV advisory data preserved  
✅ Ecosystem-specific fixes: Commands tailored to package manager

### Current Gaps / Enhancement Opportunities

❌ No license risk analysis (only vulnerability)  
❌ No transitive dependency tracking (only direct deps)  
❌ No dependency tree analysis  
❌ No supply chain attack detection (typosquatting, maintainer changes)  
❌ No deprecated package detection  
❌ No SBOM generation  
❌ No real-time status updates (completes instantly)  
❌ Limited remediation guidance (just version bumps)

---

## Enhanced SCA Engine - Implementation Plan

### Phase 1: Real-Time Streaming & Enhanced Detection (Immediate)

**Goal**: Add real-time progress reporting + license analysis + transitive deps

#### 1.1 Real-Time Scan Progress

- Convert instant completion → simulated scan stages
- Emit progress events: "parsing manifests" → "looking up advisories" → "generating fixes"
- Benefits: Better UX, matches other scanners' workflow

```
trigger() {
  scanId = generate()
  emit(scanId, "initializing", progress: 0%)

  // Stage 1: Parse manifests
  emit(scanId, "running", progress: 25%, stage: "parsing")
  manifests = extractManifests(repo)
  purls = generatePurls(manifests)

  // Stage 2: Lookup vulnerabilities
  emit(scanId, "running", progress: 50%, stage: "vulnerability-lookup")
  matches = queryVulnDb(purls)

  // Stage 3: License analysis
  emit(scanId, "running", progress: 75%, stage: "license-analysis")
  licenses = extractLicenses(manifests)
  risks = analyzeLicenseRisks(licenses)

  // Stage 4: Remediation generation
  emit(scanId, "running", progress: 90%, stage: "remediation")
  fixes = generateRemediationPlan(matches)

  // Complete
  emit(scanId, "complete", progress: 100%)
}
```

#### 1.2 Transitive Dependency Tracking

```
Instead of just:
  express 4.18.0 → vulnerability

Track:
  express@4.18.0
    ├── body-parser@1.20.0 (has vuln)
    ├── cookie@0.5.0
    └── ... (100+ transitive)

Report as:
  - Direct: express itself (0 vulns)
  - Transitive: body-parser (1 critical)
  - Risk level: Medium (fixable via express upgrade)
```

#### 1.3 License Risk Analysis

```
Per dependency:
  lodash@4.17.21 → MIT (safe)
  some-proprietary@1.0.0 → Commercial (risk: GPL copyleft)

Aggregate:
  Permissive licenses: 89
  Copyleft (GPL, AGPL): 3 ⚠️
  Proprietary: 1 ⚠️
  Unknown: 2 ⚠️

Recommendation: License violations if using in proprietary product
```

#### 1.4 Enhanced Version Recommendations

```
Current:
  express@4.18.0 → "upgrade to 4.18.2"

Enhanced:
  express@4.18.0
    ├─ Critical vuln in body-parser@1.20.0
    │  Fix: upgrade to body-parser@1.20.2
    │  OR: upgrade express (which bumps body-parser)
    │
    └─ Recommendation: upgrade express@4.18.0 → 4.20.0
       - Fixes all critical transitive vulns
       - Breaking changes: requires Node 18+
       - Migration guide: https://...
```

---

### Phase 2: Supply Chain Security (Week 2)

**Goal**: Detect typosquatting, suspicious packages, unmaintained deps

#### 2.1 Package Metadata Inspection

```
For each package, collect:
  - Published date range (old = potentially unmaintained)
  - Recent version history (check for gaps/inactivity)
  - Author/maintainer info (compare to npm registry)
  - Repository health: stars, open issues, last commit date
  - License: verify it matches declared

Flags:
  ⚠️ UNMAINTAINED: No release in >2 years
  🚩 TYPOSQUATTING: Similar name to popular pkg
  🚩 SUSPICIOUS: New package, few downloads, high similar name score
  🚩 AUTHOR_CHANGE: Maintainer changed in last 6 months
```

#### 2.2 Dependency Tree Visualization

```
Export dependency graph:
  {
    "express": {
      "version": "4.18.0",
      "vulnerabilities": 1,
      "dependencies": {
        "body-parser": { "version": "1.20.0", "vulnerabilities": 2 },
        "cookie": { "version": "0.5.0", "vulnerabilities": 0 }
      }
    }
  }

UI Benefit: Visual dep graph, click to see vuln context
```

---

### Phase 3: SBOM Generation (Week 3)

**Goal**: Generate CycloneDX / SPDX BOMs for compliance

#### 3.1 SBOM Output

```
Format: CycloneDX 1.4 / SPDX 2.3

Includes:
  - All direct + transitive dependencies
  - Version hashes (integrity)
  - License info per component
  - Known vulnerabilities at scan time
  - Component metadata (purl, homepage, etc)

Use cases:
  - Legal compliance (vendor assessment)
  - Incident response (quick lookup of affected versions)
  - Supply chain risk management
```

---

## Implementation Timeline & Files

### Immediate (Phase 1) — Real-Time + License

```
packages/adapters/sca/src/
├── adapter.ts                      (✏️ add progress events)
├── manifest-parser.ts              (✏️ new: parse manifests in-stream)
├── license-analyzer.ts             (✨ new: license risk scoring)
├── transitive-resolver.ts          (✨ new: dep tree analysis)
├── enhanced-normalize.ts           (✏️ update: add license + transitive data)
└── streaming-queue.ts              (✨ new: event emitter for real-time updates)

packages/vuln-db/src/
├── query.ts                        (✏️ add transitive lookup)
└── license-db.ts                   (✨ new: SPDX license risk mapping)

Test:
  packages/adapters/sca/src/__tests__/
  ├── adapter.test.ts               (✏️ update: streaming tests)
  ├── license-analyzer.test.ts      (✨ new)
  └── transitive-resolver.test.ts   (✨ new)
```

### Week 2 (Phase 2) — Supply Chain

```
packages/adapters/sca/src/
├── package-metadata-inspector.ts   (✨ new: fetch pkg registry metadata)
├── supply-chain-detector.ts        (✨ new: typosquatting, unmaintained)
└── dependency-graph.ts             (✨ new: visualizable graph structure)
```

### Week 3 (Phase 3) — SBOM

```
packages/adapters/sca/src/
├── sbom-generator.ts               (✨ new: CycloneDX/SPDX output)
└── sbom-serializers/
    ├── cyclonedx.ts
    └── spdx.ts
```

---

## Data Flow Diagram (Enhanced)

```
Repo (package.json, etc)
         ↓
  ┌──────────────────────────────────────┐
  │     Manifest Parser (real-time)      │
  │  → emit("parsing", 25%)              │
  └─────────────┬────────────────────────┘
                ↓
        List of deps + versions
                ↓
        PURL Generator
        (pkg:npm/express@4.18.0)
                ↓
  ┌──────────────────────────────────────┐
  │  Vuln Lookup (local MongoDB)         │
  │  → emit("vulnerability-lookup", 50%)  │
  ├──────────────────────────────────────┤
  │  Transitive Resolver                  │
  │  (dep tree analysis)                  │
  └─────────────┬────────────────────────┘
                ↓
        Vuln Matches + Dependencies
                ↓
  ┌──────────────────────────────────────┐
  │  License Analyzer                    │
  │  → emit("license-analysis", 75%)      │
  ├──────────────────────────────────────┤
  │  Remediation Generator               │
  │  (version bumps + migration guides)  │
  ├──────────────────────────────────────┤
  │  SBOM Generator                      │
  │  (CycloneDX/SPDX)                     │
  └─────────────┬────────────────────────┘
                ↓
        ┌─────────────────────────────┐
        │  Findings + Findings Array   │
        │  License Risks              │
        │  Dependency Tree            │
        │  SBOM                       │
        │  → emit("complete", 100%)    │
        └─────────────────────────────┘
                ↓
        Normalized UnifiedFinding[]
        + Enhanced Evidence
                ↓
        Storage → MongoDB
                ↓
        Dashboard Display
```

---

## Real-Time Event Schema

```typescript
// New event type for streaming progress
interface ScanProgressEvent {
  scanId: string;
  status: 'initializing' | 'running' | 'complete' | 'failed';
  progress: number; // 0-100
  stage?: 'parsing' | 'vulnerability-lookup' | 'license-analysis' | 'remediation' | 'sbom';
  message?: string;

  // Intermediate results (sent as we go)
  manifestCount?: number;
  dependencyCount?: number;
  findingCount?: number;
  licenseRisks?: { critical: number; high: number; medium: number };

  error?: string;
}
```

---

## Success Metrics

✅ **Real-time feedback**: User sees progress 0% → 100%  
✅ **Transitive tracking**: Can identify deep-nested vulns  
✅ **License visibility**: Orgs can assess compliance risk  
✅ **Smart remediation**: Not just "bump version" but "understand impact"  
✅ **SBOM compliance**: Can pass vendor security assessments  
✅ **Supply chain awareness**: Flag suspicious/unmaintained pkgs

---

## Key Decisions

1. **Keep OSV as primary source** — Free, comprehensive, maintained by Google
2. **Add streaming progress** — Match user experience of other scanners
3. **Transitive-aware fixes** — Reduce false positives from indirect deps
4. **License DB approach** — Use SPDX license list + custom risk mapping
5. **SBOM format** — CycloneDX (de facto standard) + SPDX (compliance)
