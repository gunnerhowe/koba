"""
ClawdBot Koba Governance Plugin Auto-Installer

Detects the ClawdBot installation, locates the plugins directory,
and installs the koba-governance plugin with all necessary files.

Usage:
    from integrations.clawdbot.install import auto_install_clawdbot_plugin
    result = auto_install_clawdbot_plugin(koba_api_url="http://localhost:8000")
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class InstallResult:
    """Result of the auto-install operation."""
    success: bool
    message: str
    installed_to: Optional[str] = None
    clawdbot_version: Optional[str] = None
    files_installed: List[str] = field(default_factory=list)
    error: Optional[str] = None
    instructions: Optional[List[str]] = None

    def to_dict(self) -> Dict:
        result = {
            "success": self.success,
            "message": self.message,
        }
        if self.installed_to:
            result["installed_to"] = self.installed_to
        if self.clawdbot_version:
            result["clawdbot_version"] = self.clawdbot_version
        if self.files_installed:
            result["files_installed"] = self.files_installed
        if self.error:
            result["error"] = self.error
        if self.instructions:
            result["instructions"] = self.instructions
        return result


# Directory containing this file (where source plugin files live)
PLUGIN_SOURCE_DIR = Path(__file__).parent

# Files to copy from source to the plugin install directory
PLUGIN_FILES = [
    "index.ts",
    "package.json",
    "types.d.ts",
    "tsconfig.json",
]

PLUGIN_NAME = "koba-governance"


def detect_clawdbot_version() -> Optional[str]:
    """
    Check if ClawdBot is installed by running `clawdbot --version`.
    Returns the version string if found, None otherwise.
    """
    try:
        result = subprocess.run(
            ["clawdbot", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=(platform.system() == "Windows"),
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            # Handle output like "clawdbot v2024.1.0" or just "2024.1.0"
            if version.lower().startswith("clawdbot"):
                version = version.split(None, 1)[-1] if " " in version else version
            return version.lstrip("v").strip()
        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def detect_clawdbot_plugins_dir() -> Optional[Path]:
    """
    Detect where ClawdBot looks for plugins.

    ClawdBot discovers plugins from multiple locations (based on its
    discovery.js module). The priority order is:

    1. Workspace-level: .clawdbot/plugins/ in the current workspace
    2. User-level (XDG/platform-specific):
       - Linux:   ~/.config/clawdbot/plugins/
       - macOS:   ~/Library/Application Support/clawdbot/plugins/
       - Windows: %APPDATA%/clawdbot/plugins/
    3. Legacy user-level: ~/.clawdbot/plugins/

    We install to the user-level directory so the plugin is available
    across all workspaces.
    """
    home = Path.home()
    system = platform.system()

    # Check platform-specific config directories
    candidate_dirs: List[Path] = []

    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidate_dirs.append(Path(appdata) / "clawdbot" / "plugins")
        candidate_dirs.append(home / "AppData" / "Roaming" / "clawdbot" / "plugins")
    elif system == "Darwin":
        candidate_dirs.append(home / "Library" / "Application Support" / "clawdbot" / "plugins")
    else:
        # Linux / other Unix
        xdg_config = os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))
        candidate_dirs.append(Path(xdg_config) / "clawdbot" / "plugins")

    # Legacy path (all platforms)
    candidate_dirs.append(home / ".clawdbot" / "plugins")

    # Also check CLAWDBOT_PLUGINS_DIR environment variable
    env_plugins_dir = os.environ.get("CLAWDBOT_PLUGINS_DIR")
    if env_plugins_dir:
        candidate_dirs.insert(0, Path(env_plugins_dir))

    # Return the first directory that already exists, or the first candidate
    # (which we will create)
    for d in candidate_dirs:
        if d.exists():
            return d

    # None exist yet; return the first candidate (platform-specific preferred path)
    if candidate_dirs:
        return candidate_dirs[0]

    return None


def generate_index_js(koba_api_url: str, api_key: Optional[str] = None, tenant_id: str = "default") -> str:
    """
    Generate a plain JavaScript version of the plugin that ClawdBot can load
    directly without TypeScript compilation.
    """
    api_key_line = f'"{api_key}"' if api_key else "undefined"

    return f'''\
/**
 * Koba Governance Plugin for ClawdBot (auto-generated JS build)
 *
 * Provides policy enforcement and audit logging via Koba (VACP).
 * Generated by Koba auto-installer. Do not edit manually.
 *
 * @module koba-governance
 */

const preAuthStore = new Map();

function activate(api) {{
  const config = {{
    apiUrl: process.env.KOBA_API_URL || (api.pluginConfig && api.pluginConfig.apiUrl) || "{koba_api_url}",
    apiKey: process.env.KOBA_API_KEY || (api.pluginConfig && api.pluginConfig.apiKey) || {api_key_line},
    tenantId: process.env.KOBA_TENANT_ID || (api.pluginConfig && api.pluginConfig.tenantId) || "{tenant_id}",
    blockOnError: (api.pluginConfig && api.pluginConfig.blockOnError) || false,
    skipTools: (api.pluginConfig && api.pluginConfig.skipTools) || [],
    verbose: (api.pluginConfig && api.pluginConfig.verbose) || false,
  }};

  const log = config.verbose ? api.logger.info.bind(api.logger) : () => {{}};

  log("Koba governance plugin initialized - API: " + config.apiUrl);

  /**
   * Before tool call hook - evaluates policy with Koba
   */
  api.on("before_tool_call", async (event, ctx) => {{
    const toolName = event.toolName;

    // Skip governance for excluded tools
    if (config.skipTools.includes(toolName)) {{
      log("Skipping governance for tool: " + toolName);
      return undefined;
    }}

    log("Evaluating tool call: " + toolName);

    try {{
      const headers = {{ "Content-Type": "application/json" }};
      if (config.apiKey) {{
        headers["Authorization"] = "Bearer " + config.apiKey;
      }}

      const response = await fetch(config.apiUrl + "/v1/tools/evaluate", {{
        method: "POST",
        headers: headers,
        body: JSON.stringify({{
          tool_id: toolName,
          parameters: event.params,
          agent_id: (ctx && ctx.sessionKey) || "clawdbot-agent",
          tenant_id: config.tenantId,
          session_id: (ctx && ctx.sessionKey) || "default",
          context: {{
            source: "clawdbot",
            channel: ctx && ctx.channel,
          }},
        }}),
      }});

      if (!response.ok) {{
        const errorText = await response.text();
        api.logger.error("Koba API error: " + response.status + " - " + errorText);

        if (config.blockOnError) {{
          return {{
            block: true,
            blockReason: "Koba governance unavailable: " + response.status,
          }};
        }}
        return undefined;
      }}

      const result = await response.json();

      log("Evaluation result: " + result.decision + " for " + toolName);

      // Handle denial
      if (result.decision === "deny") {{
        api.logger.warn("Tool call denied by Koba policy: " + result.denial_reason);
        return {{
          block: true,
          blockReason: result.denial_reason || "Denied by Koba governance policy",
        }};
      }}

      // Handle pending approval
      if (result.decision === "require_approval") {{
        api.logger.info("Tool call requires approval: " + result.approval_id);
        return {{
          block: true,
          blockReason: "Requires approval (ID: " + result.approval_id + "). Approve via Koba dashboard.",
        }};
      }}

      // Store pre-auth token for recording result later
      if (result.pre_auth_token && event.toolCallId) {{
        preAuthStore.set(event.toolCallId, {{
          token: result.pre_auth_token,
          toolCallId: event.toolCallId,
          startTime: Date.now(),
        }});
      }}

      // Apply redacted parameters if provided
      if (result.redacted_params) {{
        return {{
          params: result.redacted_params,
        }};
      }}

      // Allow the tool call
      return undefined;

    }} catch (error) {{
      api.logger.error("Koba evaluation failed: " + error);

      if (config.blockOnError) {{
        return {{
          block: true,
          blockReason: "Koba governance error: " + (error instanceof Error ? error.message : String(error)),
        }};
      }}
      return undefined;
    }}
  }}, {{ priority: 100 }});

  /**
   * After tool call hook - records execution result with Koba
   */
  api.on("after_tool_call", async (event, ctx) => {{
    const preAuth = event.toolCallId ? preAuthStore.get(event.toolCallId) : undefined;

    if (!preAuth) {{
      return;
    }}

    preAuthStore.delete(event.toolCallId);

    const executionTimeMs = Date.now() - preAuth.startTime;

    log("Recording execution result for " + event.toolName + " (" + executionTimeMs + "ms)");

    try {{
      const headers = {{ "Content-Type": "application/json" }};
      if (config.apiKey) {{
        headers["Authorization"] = "Bearer " + config.apiKey;
      }}

      const response = await fetch(config.apiUrl + "/v1/audit/record", {{
        method: "POST",
        headers: headers,
        body: JSON.stringify({{
          pre_auth_token: preAuth.token,
          success: !event.isError,
          result: event.isError ? undefined : event.result,
          error: event.isError ? String(event.result) : undefined,
          execution_time_ms: executionTimeMs,
        }}),
      }});

      if (!response.ok) {{
        const errorText = await response.text();
        api.logger.error("Koba record failed: " + response.status + " - " + errorText);
        return;
      }}

      const result = await response.json();
      log("Receipt issued: " + result.receipt_id);

    }} catch (error) {{
      api.logger.error("Koba record failed: " + error);
    }}
  }}, {{ priority: 100 }});

  api.logger.info("Koba governance plugin activated");
}}

module.exports = {{
  id: "koba-governance",
  name: "Koba Governance",
  version: "1.0.0",
  description: "AI governance and audit logging via Koba (VACP)",
  activate: activate,
}};

module.exports.default = module.exports;
module.exports.activate = activate;
'''


def generate_plugin_config(koba_api_url: str, api_key: Optional[str] = None, tenant_id: str = "default") -> Dict:
    """Generate the plugin configuration file content."""
    config = {
        "id": "koba-governance",
        "name": "Koba Governance",
        "version": "1.0.0",
        "enabled": True,
        "config": {
            "apiUrl": koba_api_url,
            "tenantId": tenant_id,
            "blockOnError": False,
            "skipTools": [],
            "verbose": False,
        },
    }
    if api_key:
        config["config"]["apiKey"] = api_key
    return config


def auto_install_clawdbot_plugin(
    koba_api_url: str = "http://localhost:8000",
    api_key: Optional[str] = None,
    tenant_id: str = "default",
    force: bool = False,
) -> InstallResult:
    """
    Auto-install the Koba governance plugin into ClawdBot.

    This function:
    1. Checks that ClawdBot is installed (via `clawdbot --version`)
    2. Detects the correct plugins directory
    3. Creates the koba-governance/ folder in the plugins directory
    4. Copies index.ts, package.json, types.d.ts, tsconfig.json
    5. Generates index.js (plain JS version for direct loading)
    6. Creates a plugin config with the Koba API URL
    7. Returns success/failure with details

    Args:
        koba_api_url: URL of the running Koba instance
        api_key: Optional API key for authentication
        tenant_id: Tenant ID (default: "default")
        force: If True, overwrite existing installation

    Returns:
        InstallResult with success/failure info
    """
    # Step 1: Check ClawdBot installation
    clawdbot_version = detect_clawdbot_version()
    if clawdbot_version is None:
        return InstallResult(
            success=False,
            message="ClawdBot is not installed or not accessible.",
            error="ClawdBot not found on PATH. `clawdbot --version` failed.",
            instructions=[
                "Install ClawdBot first: npm install -g clawdbot",
                "Ensure 'clawdbot' is available on your system PATH",
                "Then retry the auto-install",
            ],
        )

    # Step 2: Detect plugins directory
    plugins_dir = detect_clawdbot_plugins_dir()
    if plugins_dir is None:
        return InstallResult(
            success=False,
            message="Could not determine ClawdBot plugins directory.",
            clawdbot_version=clawdbot_version,
            error="Unable to locate or determine a plugins directory.",
            instructions=[
                "Set the CLAWDBOT_PLUGINS_DIR environment variable to your plugins path",
                "Then retry the auto-install",
            ],
        )

    # Step 3: Create the plugin target directory
    target_dir = plugins_dir / PLUGIN_NAME
    if target_dir.exists() and not force:
        # Check if it looks like a valid existing install
        existing_pkg = target_dir / "package.json"
        if existing_pkg.exists():
            try:
                pkg_data = json.loads(existing_pkg.read_text(encoding="utf-8"))
                existing_version = pkg_data.get("version", "unknown")
                return InstallResult(
                    success=False,
                    message=f"Koba governance plugin v{existing_version} is already installed.",
                    installed_to=str(target_dir),
                    clawdbot_version=clawdbot_version,
                    error="Plugin already installed. Use force=True to overwrite.",
                    instructions=[
                        "To reinstall, use the force option in the API request",
                        f"Or manually delete {target_dir} and retry",
                    ],
                )
            except (json.JSONDecodeError, OSError):
                pass

    # Create the target directory (and parents if needed)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return InstallResult(
            success=False,
            message="Failed to create plugin directory.",
            clawdbot_version=clawdbot_version,
            error=f"Could not create directory {target_dir}: {e}",
            instructions=[
                f"Check permissions on {plugins_dir}",
                f"Or manually create {target_dir}",
            ],
        )

    # Step 4: Verify source files exist
    source_dir = PLUGIN_SOURCE_DIR
    missing_files = []
    for fname in PLUGIN_FILES:
        if not (source_dir / fname).exists():
            missing_files.append(fname)

    if missing_files:
        return InstallResult(
            success=False,
            message="Plugin source files are missing from the Koba distribution.",
            clawdbot_version=clawdbot_version,
            error=f"Missing source files: {', '.join(missing_files)}",
            instructions=[
                "Ensure your Koba installation is complete",
                f"Expected files in: {source_dir}",
            ],
        )

    # Step 5: Copy plugin source files
    installed_files: List[str] = []
    try:
        for fname in PLUGIN_FILES:
            src = source_dir / fname
            dst = target_dir / fname
            shutil.copy2(str(src), str(dst))
            installed_files.append(fname)
    except OSError as e:
        return InstallResult(
            success=False,
            message="Failed to copy plugin files.",
            clawdbot_version=clawdbot_version,
            error=f"File copy error: {e}",
            files_installed=installed_files,
            instructions=[
                f"Check write permissions on {target_dir}",
                "Some files may have been partially copied",
            ],
        )

    # Step 6: Generate and write index.js (plain JS for direct loading)
    try:
        index_js_content = generate_index_js(
            koba_api_url=koba_api_url,
            api_key=api_key,
            tenant_id=tenant_id,
        )
        index_js_path = target_dir / "index.js"
        index_js_path.write_text(index_js_content, encoding="utf-8")
        installed_files.append("index.js")
    except OSError as e:
        return InstallResult(
            success=False,
            message="Failed to generate index.js.",
            clawdbot_version=clawdbot_version,
            error=f"Could not write index.js: {e}",
            files_installed=installed_files,
            instructions=[
                f"Check write permissions on {target_dir}",
            ],
        )

    # Step 7: Generate and write plugin config
    try:
        plugin_config = generate_plugin_config(
            koba_api_url=koba_api_url,
            api_key=api_key,
            tenant_id=tenant_id,
        )
        config_path = target_dir / "plugin.json"
        config_path.write_text(
            json.dumps(plugin_config, indent=2) + "\n",
            encoding="utf-8",
        )
        installed_files.append("plugin.json")
    except OSError as e:
        # Non-fatal: the plugin can still work without the config file
        # since it reads from environment variables as fallback
        pass

    # Step 8: Copy README if it exists
    readme_src = source_dir / "README.md"
    if readme_src.exists():
        try:
            shutil.copy2(str(readme_src), str(target_dir / "README.md"))
            installed_files.append("README.md")
        except OSError:
            pass  # Non-fatal

    return InstallResult(
        success=True,
        message=(
            f"Koba governance plugin installed successfully to {target_dir}. "
            "Restart ClawdBot gateway to activate."
        ),
        installed_to=str(target_dir),
        clawdbot_version=clawdbot_version,
        files_installed=installed_files,
        instructions=[
            "Restart your ClawdBot gateway to load the plugin",
            "The plugin will automatically connect to Koba at: " + koba_api_url,
            "To verify, run: clawdbot plugins list",
            "For verbose logging, set KOBA_VERBOSE=true in your environment",
        ],
    )


def uninstall_clawdbot_plugin() -> InstallResult:
    """
    Remove the Koba governance plugin from ClawdBot.

    Returns:
        InstallResult with success/failure info
    """
    plugins_dir = detect_clawdbot_plugins_dir()
    if plugins_dir is None:
        return InstallResult(
            success=False,
            message="Could not determine ClawdBot plugins directory.",
            error="Unable to locate plugins directory.",
        )

    target_dir = plugins_dir / PLUGIN_NAME
    if not target_dir.exists():
        return InstallResult(
            success=False,
            message="Koba governance plugin is not installed.",
            error=f"Directory not found: {target_dir}",
        )

    try:
        shutil.rmtree(str(target_dir))
        return InstallResult(
            success=True,
            message=f"Koba governance plugin removed from {target_dir}.",
            instructions=[
                "Restart ClawdBot gateway to complete the uninstall",
            ],
        )
    except OSError as e:
        return InstallResult(
            success=False,
            message="Failed to remove plugin directory.",
            error=f"Could not delete {target_dir}: {e}",
            instructions=[
                f"Manually delete: {target_dir}",
            ],
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Koba ClawdBot Plugin Installer")
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the plugin instead of installing it",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="Koba API URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for Koba authentication",
    )
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="Koba tenant ID (default: default)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing installation",
    )

    args = parser.parse_args()

    if args.uninstall:
        result = uninstall_clawdbot_plugin()
    else:
        result = auto_install_clawdbot_plugin(
            koba_api_url=args.api_url,
            api_key=args.api_key,
            tenant_id=args.tenant_id,
            force=args.force,
        )

    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(0 if result.success else 1)
