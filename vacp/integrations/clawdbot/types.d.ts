/**
 * Type definitions for ClawdBot plugin SDK
 * These are simplified types for the Koba governance plugin
 */

declare module "clawdbot/plugin-sdk" {
  export interface Logger {
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
    debug: (message: string) => void;
  }

  export interface PluginApi<TConfig = unknown> {
    id: string;
    name: string;
    version: string;
    description?: string;
    source: string;
    config: unknown;
    pluginConfig?: TConfig;
    runtime: unknown;
    logger: Logger;

    /**
     * Register a typed hook handler
     */
    on<T extends HookEvent>(
      hookName: HookName,
      handler: (event: T, ctx: HookContext) => Promise<HookResult | undefined> | HookResult | undefined,
      opts?: HookOptions
    ): void;

    /**
     * Register a tool
     */
    registerTool(tool: unknown, opts?: unknown): void;
  }

  export type HookName =
    | "before_agent_start"
    | "agent_end"
    | "before_compaction"
    | "after_compaction"
    | "message_received"
    | "message_sending"
    | "message_sent"
    | "before_tool_call"
    | "after_tool_call"
    | "tool_result_persist"
    | "session_start"
    | "session_end"
    | "gateway_start"
    | "gateway_stop";

  export interface HookOptions {
    priority?: number;
  }

  export interface HookContext {
    sessionKey?: string;
    channel?: string;
    [key: string]: unknown;
  }

  export interface HookEvent {
    [key: string]: unknown;
  }

  export interface BeforeToolCallEvent extends HookEvent {
    toolName: string;
    toolCallId?: string;
    params: Record<string, unknown>;
  }

  export interface AfterToolCallEvent extends HookEvent {
    toolName: string;
    toolCallId?: string;
    params: Record<string, unknown>;
    result: unknown;
    isError: boolean;
  }

  export interface BeforeToolCallResult {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
  }

  export type HookResult = BeforeToolCallResult | void;

  export interface PluginDefinition<TConfig = unknown> {
    id: string;
    name: string;
    version: string;
    description?: string;
    activate: (api: PluginApi<TConfig>) => void;
  }
}
