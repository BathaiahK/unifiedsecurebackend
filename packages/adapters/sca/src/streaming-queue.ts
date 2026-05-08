import type { ScanProgressEvent } from './types.js';

type EventListener = (event: ScanProgressEvent) => void;

export class StreamingQueue {
  private events = new Map<string, ScanProgressEvent[]>();
  private listeners = new Map<string, Set<EventListener>>();

  /**
   * Emit a progress event for a scan
   */
  emit(event: ScanProgressEvent): void {
    // Store event in history
    if (!this.events.has(event.scanId)) {
      this.events.set(event.scanId, []);
    }
    this.events.get(event.scanId)!.push(event);

    // Notify listeners
    const listeners = this.listeners.get(event.scanId);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(event);
        } catch (err) {
          console.error('[SCA] Event listener error:', err);
        }
      }
    }
  }

  /**
   * Subscribe to events for a specific scan
   * Returns unsubscribe function
   */
  subscribe(scanId: string, listener: EventListener): () => void {
    if (!this.listeners.has(scanId)) {
      this.listeners.set(scanId, new Set());
    }
    this.listeners.get(scanId)!.add(listener);

    // Return unsubscribe function
    return () => {
      this.listeners.get(scanId)?.delete(listener);
    };
  }

  /**
   * Get all events for a scan
   */
  getEvents(scanId: string): ScanProgressEvent[] {
    return this.events.get(scanId) ?? [];
  }

  /**
   * Get the latest event for a scan
   */
  getLatestEvent(scanId: string): ScanProgressEvent | undefined {
    const events = this.events.get(scanId);
    return events ? events[events.length - 1] : undefined;
  }

  /**
   * Clear events (for testing or cleanup)
   */
  clear(scanId?: string): void {
    if (scanId) {
      this.events.delete(scanId);
      this.listeners.delete(scanId);
    } else {
      this.events.clear();
      this.listeners.clear();
    }
  }

  /**
   * Helper to emit progress with consistent timestamp
   */
  progress(
    scanId: string,
    status: ScanProgressEvent['status'],
    progress: number,
    stage?: ScanProgressEvent['stage'],
    message?: string,
    data?: Partial<ScanProgressEvent>,
  ): void {
    this.emit({
      scanId,
      status,
      progress: Math.min(100, Math.max(0, progress)),
      ...(stage !== undefined && { stage }),
      ...(message !== undefined && { message }),
      timestamp: new Date().toISOString(),
      ...data,
    });
  }
}

// Global instance
export const scaStreamingQueue = new StreamingQueue();
