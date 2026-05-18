import type { ScannerAdapter } from '@usp/schema';

const registry = new Map<string, ScannerAdapter>();

export function registerAdapter(adapter: ScannerAdapter): void {
  registry.set(adapter.tool, adapter);
}

export function getAdapter(tool: string): ScannerAdapter {
  const adapter = registry.get(tool);
  if (!adapter) {
    throw new Error(
      `No adapter registered for tool: ${tool}. Registered: ${[...registry.keys()].join(', ')}`,
    );
  }
  return adapter;
}

export function listAdapters(): string[] {
  return [...registry.keys()];
}
