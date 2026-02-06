/**
 * Koba Governance Plugin for ClawdBot
 *
 * This plugin integrates ClawdBot with Koba (VACP) to provide:
 * - Policy enforcement on all AI tool calls
 * - Cryptographically signed action receipts
 * - Audit logging to Koba's transparency log
 *
 * Installation:
 * 1. Copy this file to your ClawdBot workspace plugins directory
 * 2. Configure KOBA_API_URL in your environment or clawdbot config
 * 3. Restart ClawdBot gateway
 *
 * @module koba-governance
 */

import type { PluginApi, BeforeToolCallEvent, AfterToolCallEvent, HookContext } from "clawdbot/plugin-sdk";

interface KobaConfig {
  /** Koba API URL (default: http://localhost:8000) */
  apiUrl?: string;
  /** API key for authentication (optional) */
  apiKey?: string;
  /** Tenant ID (default: default) */
  tenantId?: string;
  /** Whether to block on evaluation failures (default: false) */
  blockOnError?: boolean;
  /** Tools to skip governance for (e.g., ["read_file"]) */
  skipTools?: string[];
  /** Enable verbose logging (default: false) */
  verbose?: boolean;
}

interface EvaluationResult {
  request_id: string;
  tool_id: string;
  decision: "allow" | "deny" | "require_approval";
  pre_auth_token?: string;
  approval_id?: string;
  denial_reason?: string;
  constraints?: Record<string, unknown>;
  redacted_params?: Record<string, unknown>;
  expires_at?: string;
}

interface RecordResult {
  receipt_id: string;
  agent_id: string;
  tool_id: string | null;
  decision: string | null;
  timestamp: string;
  signature: string;
}

// Parameter names that contain resource identifiers
const RESOURCE_PARAM_NAMES = [
  "file_path", "filepath", "file_name", "filename",
  "path", "file", "target_path", "source_path", "dest_path",
  "destination", "source",
  "folder_path", "folder", "directory", "dir", "dirpath",
  "working_directory", "cwd",
  "url", "uri", "endpoint", "href", "link",
  "base_url", "api_url", "target_url",
  "database", "db", "db_name", "database_name",
  "table", "table_name", "collection", "collection_name",
  "schema", "connection_string", "dsn",
  "to", "recipient", "recipients", "email", "email_address",
  "bucket", "bucket_name", "key", "object_key",
  "command", "cmd", "script", "query", "sql",
  "repo", "repository", "branch", "remote",
  "resource", "name", "id", "target",
];

// Tool name normalization map (mirrors the Python normalize.py exactly)
const TOOL_NORMALIZATION_MAP: Record<string, [string, string]> = {
  // File operations
  read_file: ["file", "read"],
  write_file: ["file", "write"],
  edit_file: ["file", "write"],
  create_file: ["file", "write"],
  delete_file: ["file", "delete"],
  rename_file: ["file", "write"],
  move_file: ["file", "write"],
  copy_file: ["file", "write"],
  cat: ["file", "read"],
  head: ["file", "read"],
  tail: ["file", "read"],
  str_replace_editor: ["file", "write"],
  file_editor: ["file", "write"],
  open_file: ["file", "read"],
  save_file: ["file", "write"],
  patch_file: ["file", "write"],

  // Folder operations
  list_files: ["folder", "list"],
  list_directory: ["folder", "list"],
  search_files: ["folder", "read"],
  find_files: ["folder", "read"],
  create_directory: ["folder", "write"],
  delete_directory: ["folder", "delete"],
  mkdir: ["folder", "write"],
  rmdir: ["folder", "delete"],
  ls: ["folder", "list"],
  tree: ["folder", "list"],
  glob: ["folder", "list"],
  find: ["folder", "read"],

  // System / shell
  bash: ["system", "execute"],
  shell: ["system", "execute"],
  terminal: ["system", "execute"],
  exec: ["system", "execute"],
  execute: ["system", "execute"],
  run: ["system", "execute"],
  run_command: ["system", "execute"],
  computer_tool: ["system", "execute"],
  computer: ["system", "execute"],
  code_interpreter: ["system", "execute"],
  python: ["system", "execute"],
  python_tool: ["system", "execute"],
  subprocess: ["system", "execute"],
  process: ["system", "execute"],
  powershell: ["system", "execute"],
  cmd: ["system", "execute"],

  // HTTP / web
  http_request: ["http", "request"],
  fetch: ["http", "request"],
  curl: ["http", "request"],
  wget: ["http", "request"],
  http_get: ["http", "get"],
  http_post: ["http", "post"],
  http_put: ["http", "put"],
  http_delete: ["http", "delete"],
  api_call: ["api", "request"],
  rest_call: ["api", "request"],
  graphql_query: ["api", "request"],
  request: ["http", "request"],
  web_fetch: ["http", "request"],

  // Website / browsing
  web_search: ["website", "search"],
  browse: ["website", "read"],
  scrape: ["website", "scrape"],
  open_url: ["website", "read"],
  browser: ["website", "read"],
  search: ["website", "search"],
  google_search: ["website", "search"],
  bing_search: ["website", "search"],
  tavily_search: ["website", "search"],
  duckduckgo_search: ["website", "search"],
  web_browse: ["website", "read"],

  // Email
  send_email: ["email", "send"],
  read_email: ["email", "read"],
  list_emails: ["email", "list"],
  delete_email: ["email", "delete"],
  gmail_send: ["email", "send"],
  gmail_read: ["email", "read"],
  gmail_search: ["email", "read"],
  gmail_draft: ["email", "write"],
  outlook_send: ["email", "send"],
  outlook_read: ["email", "read"],
  compose_email: ["email", "send"],
  reply_email: ["email", "send"],
  forward_email: ["email", "send"],
  email_send: ["email", "send"],
  email_read: ["email", "read"],

  // Database
  sql_query: ["database", "read"],
  sql_execute: ["database", "write"],
  db_query: ["database", "read"],
  db_read: ["database", "read"],
  db_insert: ["database", "write"],
  db_update: ["database", "write"],
  db_delete: ["database", "delete"],
  query_database: ["database", "read"],
  execute_sql: ["database", "write"],
  postgres_query: ["database", "read"],
  mysql_query: ["database", "read"],
  mongo_find: ["database", "read"],
  mongo_insert: ["database", "write"],
  redis_get: ["database", "read"],
  redis_set: ["database", "write"],
  sqlite_query: ["database", "read"],

  // Calendar
  create_event: ["calendar", "write"],
  read_calendar: ["calendar", "read"],
  delete_event: ["calendar", "delete"],
  list_events: ["calendar", "list"],
  update_event: ["calendar", "write"],
  google_calendar: ["calendar", "read"],
  outlook_calendar: ["calendar", "read"],
  calendar_create: ["calendar", "write"],
  calendar_read: ["calendar", "read"],

  // Messaging
  send_message: ["messaging", "send"],
  slack_send: ["messaging", "send"],
  slack_post: ["messaging", "send"],
  slack_read: ["messaging", "read"],
  discord_send: ["messaging", "send"],
  teams_send: ["messaging", "send"],
  sms_send: ["messaging", "send"],
  chat_send: ["messaging", "send"],
  read_messages: ["messaging", "read"],
  telegram_send: ["messaging", "send"],

  // Cloud storage
  s3_get: ["cloud_storage", "read"],
  s3_put: ["cloud_storage", "write"],
  s3_delete: ["cloud_storage", "delete"],
  s3_list: ["cloud_storage", "list"],
  gcs_get: ["cloud_storage", "read"],
  gcs_put: ["cloud_storage", "write"],
  gcs_delete: ["cloud_storage", "delete"],
  azure_blob_get: ["cloud_storage", "read"],
  azure_blob_put: ["cloud_storage", "write"],
  upload_file: ["cloud_storage", "write"],
  download_file: ["cloud_storage", "read"],

  // Git
  git_clone: ["git", "read"],
  git_commit: ["git", "write"],
  git_push: ["git", "write"],
  git_pull: ["git", "read"],
  git_diff: ["git", "read"],
  git_log: ["git", "read"],
  git_status: ["git", "read"],
  git_checkout: ["git", "write"],

  // Contacts
  read_contacts: ["contacts", "read"],
  create_contact: ["contacts", "write"],
  delete_contact: ["contacts", "delete"],
  search_contacts: ["contacts", "read"],

  // Photos / images
  read_image: ["photos", "read"],
  create_image: ["photos", "write"],
  delete_image: ["photos", "delete"],
  generate_image: ["photos", "write"],
  dalle: ["photos", "write"],
  edit_image: ["photos", "write"],
  screenshot: ["screenshot", "capture"],
  take_screenshot: ["screenshot", "capture"],

  // Documents
  read_pdf: ["documents", "read"],
  create_pdf: ["documents", "write"],
  read_document: ["documents", "read"],
  write_document: ["documents", "write"],
  read_spreadsheet: ["documents", "read"],
  write_spreadsheet: ["documents", "write"],

  // Clipboard
  clipboard_read: ["clipboard", "read"],
  clipboard_write: ["clipboard", "write"],
  copy_to_clipboard: ["clipboard", "write"],
  paste_from_clipboard: ["clipboard", "read"],

  // Notifications
  send_notification: ["notifications", "send"],
  push_notification: ["notifications", "send"],

  // Payments
  create_payment: ["payments", "write"],
  send_payment: ["payments", "transfer"],
  read_transactions: ["payments", "read"],
  stripe_charge: ["payments", "write"],

  // Secrets
  get_secret: ["secrets", "read"],
  set_secret: ["secrets", "write"],
  read_env: ["secrets", "read"],
  vault_read: ["secrets", "read"],
  vault_write: ["secrets", "write"],
};

/**
 * Extract the resource identifier from tool parameters.
 * Looks for known parameter names like path, file, url, database, etc.
 */
function extractResource(params: Record<string, unknown>): string | undefined {
  if (!params) return undefined;

  for (const name of RESOURCE_PARAM_NAMES) {
    const value = params[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  // Check nested "input" object (some tools wrap params)
  const input = params.input;
  if (input && typeof input === "object" && !Array.isArray(input)) {
    for (const name of RESOURCE_PARAM_NAMES) {
      const value = (input as Record<string, unknown>)[name];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
  }

  return undefined;
}

/**
 * Normalize a tool name to (category, method) for policy matching.
 */
function normalizeToolName(rawName: string | undefined | null): { category: string; method: string | undefined } {
  if (!rawName || typeof rawName !== "string") {
    return { category: "unknown", method: undefined };
  }
  const normalized = rawName.trim().toLowerCase().replace(/-/g, "_");

  const mapping = TOOL_NORMALIZATION_MAP[normalized];
  if (mapping) {
    return { category: mapping[0], method: mapping[1] };
  }

  // Fall back: the server-side normalization will also handle this,
  // but we still send what we can for logging/debugging.
  return { category: normalized, method: undefined };
}


// Store pre-auth tokens for recording results
const preAuthStore = new Map<string, { token: string; toolCallId: string; startTime: number }>();

/**
 * Main plugin registration function
 */
export function activate(api: PluginApi<KobaConfig>) {
  const config: KobaConfig = {
    apiUrl: process.env.KOBA_API_URL || api.pluginConfig?.apiUrl || "http://localhost:8000",
    apiKey: process.env.KOBA_API_KEY || api.pluginConfig?.apiKey,
    tenantId: process.env.KOBA_TENANT_ID || api.pluginConfig?.tenantId || "default",
    blockOnError: api.pluginConfig?.blockOnError ?? false,
    skipTools: api.pluginConfig?.skipTools ?? [],
    verbose: api.pluginConfig?.verbose ?? false,
  };

  const log = config.verbose ? api.logger.info : () => {};

  log(`Koba governance plugin initialized - API: ${config.apiUrl}`);

  /**
   * Before tool call hook - evaluates policy with Koba
   */
  api.on("before_tool_call", async (event: BeforeToolCallEvent, ctx: HookContext) => {
    const toolName = event.toolName;

    // Skip governance for excluded tools
    if (config.skipTools?.includes(toolName)) {
      log(`Skipping governance for tool: ${toolName}`);
      return undefined;
    }

    log(`Evaluating tool call: ${toolName}`);

    try {
      // Extract resource and method from the tool call
      const resource = extractResource(event.params || {});
      const { method } = normalizeToolName(toolName);

      log(`Normalized: tool=${toolName}, method=${method}, resource=${resource}`);

      const response = await fetch(`${config.apiUrl}/v1/tools/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        },
        body: JSON.stringify({
          tool_id: toolName,
          parameters: event.params,
          agent_id: ctx.sessionKey || "clawdbot-agent",
          tenant_id: config.tenantId,
          session_id: ctx.sessionKey || "default",
          // These are the critical fields that were missing:
          method: method,
          resource: resource,
          context: {
            source: "clawdbot",
            channel: ctx.channel,
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        api.logger.error(`Koba API error: ${response.status} - ${errorText}`);

        if (config.blockOnError) {
          return {
            block: true,
            blockReason: `Koba governance unavailable: ${response.status}`,
          };
        }
        return undefined;
      }

      let result: EvaluationResult;
      try {
        result = await response.json();
      } catch (parseError) {
        api.logger.error(`Koba response parse error: ${parseError}`);
        if (config.blockOnError) {
          return { block: true, blockReason: "Koba returned invalid response" };
        }
        return undefined;
      }

      log(`Evaluation result: ${result.decision} for ${toolName}`);

      // Handle denial
      if (result.decision === "deny") {
        api.logger.warn(`Tool call denied by Koba policy: ${result.denial_reason}`);
        return {
          block: true,
          blockReason: result.denial_reason || "Denied by Koba governance policy",
        };
      }

      // Handle pending approval
      if (result.decision === "require_approval") {
        api.logger.info(`Tool call requires approval: ${result.approval_id}`);
        return {
          block: true,
          blockReason: `Requires approval (ID: ${result.approval_id}). Approve via Koba dashboard.`,
        };
      }

      // Store pre-auth token for recording result later
      if (result.pre_auth_token && event.toolCallId) {
        preAuthStore.set(event.toolCallId, {
          token: result.pre_auth_token,
          toolCallId: event.toolCallId,
          startTime: Date.now(),
        });
      }

      // Apply redacted parameters if provided
      if (result.redacted_params) {
        return {
          params: result.redacted_params,
        };
      }

      // Allow the tool call
      return undefined;

    } catch (error) {
      api.logger.error(`Koba evaluation failed: ${error}`);

      if (config.blockOnError) {
        return {
          block: true,
          blockReason: `Koba governance error: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
      return undefined;
    }
  }, { priority: 100 }); // High priority to run before other hooks

  /**
   * After tool call hook - records execution result with Koba
   */
  api.on("after_tool_call", async (event: AfterToolCallEvent, ctx: HookContext) => {
    const preAuth = event.toolCallId ? preAuthStore.get(event.toolCallId) : undefined;

    if (!preAuth) {
      // Tool was either skipped or evaluation failed - nothing to record
      return;
    }

    // Clean up
    preAuthStore.delete(event.toolCallId!);

    const executionTimeMs = Date.now() - preAuth.startTime;

    log(`Recording execution result for ${event.toolName} (${executionTimeMs}ms)`);

    try {
      const response = await fetch(`${config.apiUrl}/v1/audit/record`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        },
        body: JSON.stringify({
          pre_auth_token: preAuth.token,
          success: !event.isError,
          result: event.isError ? undefined : event.result,
          error: event.isError ? String(event.result) : undefined,
          execution_time_ms: executionTimeMs,
          source: "clawdbot",
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        api.logger.error(`Koba record failed: ${response.status} - ${errorText}`);
        return;
      }

      let result: RecordResult;
      try {
        result = await response.json();
      } catch {
        api.logger.error("Koba record response parse error");
        return;
      }
      log(`Receipt issued: ${result.receipt_id}`);

    } catch (error) {
      api.logger.error(`Koba record failed: ${error}`);
    }
  }, { priority: 100 });

  api.logger.info("Koba governance plugin activated");
}

/**
 * Plugin definition for ClawdBot
 */
export default {
  id: "koba-governance",
  name: "Koba Governance",
  version: "1.1.0",
  description: "AI governance and audit logging via Koba (VACP)",
  activate,
};
