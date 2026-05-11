import { execFile } from 'child_process';
import { promisify } from 'util';
import type { TrivyReport } from './types.js';

const execFileAsync = promisify(execFile);

export interface TrivyClientConfig {
  trivyPath: string;
  registryUsername?: string;
  registryPassword?: string;
  registryToken?: string;
}

export class TrivyClient {
  constructor(private config: TrivyClientConfig) {}

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.trivyPath, ['--version']);
      return true;
    } catch {
      return false;
    }
  }

  private buildAuthArgs(): string[] {
    const args: string[] = [];
    if (this.config.registryUsername) {
      args.push('--username', this.config.registryUsername);
    }
    if (this.config.registryPassword) {
      args.push('--password', this.config.registryPassword);
    }
    if (this.config.registryToken) {
      args.push('--registry-token', this.config.registryToken);
    }
    return args;
  }

  async scan(image: string): Promise<TrivyReport> {
    const [vulnReport, miscReport] = await Promise.all([
      this.scanVulnerabilities(image),
      this.scanMisconfigAndSecrets(image),
    ]);

    const results = [...(vulnReport.results || []), ...(miscReport.results || [])];

    return {
      ...vulnReport,
      results,
    };
  }

  async scanWithLicenses(image: string): Promise<TrivyReport> {
    try {
      const authArgs = this.buildAuthArgs();
      const { stdout } = await execFileAsync(this.config.trivyPath, [
        'image',
        '--format', 'json',
        '--quiet',
        '--no-progress',
        '--scanners', 'vuln,license',
        ...authArgs,
        image,
      ]);

      return JSON.parse(stdout) as TrivyReport;
    } catch (error) {
      console.error(`Trivy license scan failed for ${image}:`, error);
      return { schemaVersion: 2, artifactType: 'image', artifactName: image, results: [] };
    }
  }

  async generateSbom(image: string): Promise<Record<string, unknown>> {
    try {
      const authArgs = this.buildAuthArgs();
      const { stdout } = await execFileAsync(this.config.trivyPath, [
        'image',
        '--format', 'cyclonedx',
        '--quiet',
        '--no-progress',
        ...authArgs,
        image,
      ]);

      return JSON.parse(stdout) as Record<string, unknown>;
    } catch (error) {
      console.error(`Trivy SBOM generation failed for ${image}:`, error);
      return {};
    }
  }

  async scanCisBenchmark(image: string): Promise<TrivyReport> {
    try {
      const authArgs = this.buildAuthArgs();
      const { stdout } = await execFileAsync(this.config.trivyPath, [
        'image',
        '--format', 'json',
        '--quiet',
        '--no-progress',
        '--compliance', 'docker-cis',
        ...authArgs,
        image,
      ]);

      return JSON.parse(stdout) as TrivyReport;
    } catch (error) {
      console.warn(`Trivy CIS benchmark scan failed for ${image} (may not be supported):`, error);
      return { schemaVersion: 2, artifactType: 'image', artifactName: image, results: [] };
    }
  }

  private async scanVulnerabilities(image: string): Promise<TrivyReport> {
    try {
      const authArgs = this.buildAuthArgs();
      const { stdout } = await execFileAsync(this.config.trivyPath, [
        'image',
        '--format', 'json',
        '--quiet',
        '--no-progress',
        '--scanners', 'vuln',
        ...authArgs,
        image,
      ]);

      return JSON.parse(stdout) as TrivyReport;
    } catch (error) {
      console.error(`Trivy vulnerability scan failed for ${image}:`, error);
      throw error;
    }
  }

  private async scanMisconfigAndSecrets(image: string): Promise<TrivyReport> {
    try {
      const authArgs = this.buildAuthArgs();
      const { stdout } = await execFileAsync(this.config.trivyPath, [
        'image',
        '--format', 'json',
        '--quiet',
        '--no-progress',
        '--scanners', 'misconfig,secret',
        ...authArgs,
        image,
      ]);

      return JSON.parse(stdout) as TrivyReport;
    } catch (error) {
      console.error(`Trivy misconfig/secret scan failed for ${image}:`, error);
      return { schemaVersion: 2, artifactType: 'image', artifactName: image, results: [] };
    }
  }
}
