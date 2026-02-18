import fs from "node:fs/promises";
import path from "node:path";

/**
 * Audit log entry for Gateway write operations (VD-2).
 * Provides forensic trail for config.set, exec.approvals.set, sessions.delete.
 */
export interface AuditEntry {
  /** ISO 8601 timestamp of the operation */
  timestamp: string;
  /** Gateway API method name (e.g., "config.set") */
  method: string;
  /** Device ID that performed the operation */
  deviceId?: string;
  /** Device name if available */
  deviceName?: string;
  /** User ID if available */
  userId?: string;
  /** Client IP address */
  clientIp?: string;
  /** Method parameters (sanitized) */
  params: unknown;
  /** Previous value for the operation (if applicable) */
  previous?: unknown;
  /** Whether the operation succeeded */
  success: boolean;
  /** Error message if operation failed */
  error?: string;
}

/**
 * Filter options for querying audit log entries.
 */
export interface AuditFilter {
  /** Start time (ISO 8601) */
  since?: string;
  /** End time (ISO 8601) */
  until?: string;
  /** Filter by method name */
  method?: string;
  /** Filter by device ID */
  deviceId?: string;
  /** Filter by user ID */
  userId?: string;
  /** Only show successful operations */
  successOnly?: boolean;
  /** Only show failed operations */
  failuresOnly?: boolean;
  /** Maximum number of entries to return */
  limit?: number;
}

/**
 * Append-only audit logger for Gateway write operations (VD-2).
 *
 * Security properties:
 * - JSONL format (one entry per line) for easy parsing and streaming
 * - Append-only mode prevents modification of historical entries
 * - File permissions set to 0600 (owner read/write only)
 * - No delete or edit functionality
 *
 * Usage:
 *   const logger = new AuditLogger('/var/log/openclaw/audit.jsonl');
 *   await logger.log({
 *     timestamp: new Date().toISOString(),
 *     method: 'config.set',
 *     deviceId: 'abc123',
 *     params: { key: 'model', value: 'opus-4-6' },
 *     previous: 'sonnet-4-5',
 *     success: true
 *   });
 */
export class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  /**
   * Append an audit entry to the log file.
   * Automatically creates the log file with secure permissions if it doesn't exist.
   */
  async log(entry: AuditEntry): Promise<void> {
    // Ensure parent directory exists
    const dir = path.dirname(this.logPath);
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    } catch (err) {
      // Ignore if directory already exists
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
        throw err;
      }
    }

    // Serialize entry as JSONL (one line per entry)
    const line = JSON.stringify(entry) + "\n";

    // Append with secure permissions
    // Mode 0o600 = owner read/write only
    await fs.appendFile(this.logPath, line, { flag: "a", mode: 0o600 });
  }

  /**
   * Query audit log entries with optional filtering.
   * Returns entries in chronological order (oldest first).
   */
  async query(filter: AuditFilter = {}): Promise<AuditEntry[]> {
    // Check if log file exists
    try {
      await fs.access(this.logPath);
    } catch {
      return []; // Log file doesn't exist yet
    }

    // Read entire log file
    const content = await fs.readFile(this.logPath, "utf-8");
    const lines = content.split("\n").filter((line) => line.trim());

    // Parse JSONL entries
    const entries: AuditEntry[] = [];
    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        entries.push(entry);
      } catch {
        // Skip invalid lines (corrupted or incomplete)
        continue;
      }
    }

    // Apply filters
    let filtered = entries;

    if (filter.since) {
      const sinceTime = new Date(filter.since).getTime();
      filtered = filtered.filter((e) => new Date(e.timestamp).getTime() >= sinceTime);
    }

    if (filter.until) {
      const untilTime = new Date(filter.until).getTime();
      filtered = filtered.filter((e) => new Date(e.timestamp).getTime() <= untilTime);
    }

    if (filter.method) {
      filtered = filtered.filter((e) => e.method === filter.method);
    }

    if (filter.deviceId) {
      filtered = filtered.filter((e) => e.deviceId === filter.deviceId);
    }

    if (filter.userId) {
      filtered = filtered.filter((e) => e.userId === filter.userId);
    }

    if (filter.successOnly) {
      filtered = filtered.filter((e) => e.success === true);
    }

    if (filter.failuresOnly) {
      filtered = filtered.filter((e) => e.success === false);
    }

    // Apply limit
    if (filter.limit && filter.limit > 0) {
      filtered = filtered.slice(-filter.limit); // Return last N entries
    }

    return filtered;
  }

  /**
   * Get the audit log file path.
   */
  getLogPath(): string {
    return this.logPath;
  }
}

/**
 * Initialize audit log with secure permissions.
 * Creates the log file and parent directory if they don't exist.
 */
export async function initializeAuditLog(logPath: string): Promise<void> {
  const dir = path.dirname(logPath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });

  // Create empty file with secure permissions if it doesn't exist
  try {
    await fs.appendFile(logPath, "", { flag: "a", mode: 0o600 });
  } catch (err) {
    // Ignore if file already exists
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
      throw err;
    }
  }
}
