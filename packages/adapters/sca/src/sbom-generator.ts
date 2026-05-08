import { randomUUID } from 'node:crypto';
import { extractName, extractVersion } from './supply-chain-detector.js';

// ─── CycloneDX 1.4 SBOM Generator ─────────────────────────────────────────

export function generateCycloneDxSbom(
  scanId: string,
  asset: string,
  purls: string[],
): Record<string, unknown> {
  const components = purls.map((purl) => {
    const name = extractName(purl);
    const version = extractVersion(purl);
    return {
      type: 'library',
      name,
      version,
      purl,
      licenses: [],
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'Unified Secure Platform',
          name: 'usp-sca',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        name: asset,
        version: 'unknown',
      },
    },
    components,
  };
}

// ─── SPDX 2.3 SBOM Generator ──────────────────────────────────────────────

export function generateSpdxSbom(
  scanId: string,
  asset: string,
  purls: string[],
): Record<string, unknown> {
  const packages = purls.map((purl, index) => {
    const name = extractName(purl);
    const version = extractVersion(purl);
    const spdxId = `SPDXRef-Package-${index}`;

    return {
      SPDXID: spdxId,
      name,
      versionInfo: version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: purl,
        },
      ],
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
    };
  });

  // Build relationships: DOCUMENT DESCRIBES each package
  const relationships = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-Package-0',
    },
  ];
  for (let i = 1; i < purls.length; i++) {
    relationships.push({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: `SPDXRef-Package-${i}`,
    });
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${asset}-sbom`,
    documentNamespace: `https://usp.dev/sbom/${scanId}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: usp-sca-1.0.0'],
    },
    packages,
    relationships,
  };
}
