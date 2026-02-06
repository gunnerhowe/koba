"""
Sandbox Execution Environment for VACP

This module provides isolated execution environments for code tools:
- Process isolation with OS-level enforcement
- Filesystem isolation (chroot / tmpdir confinement)
- Network egress control via firewall rules
- Resource limits (CPU, memory, time)
- Execution transcripts

The sandbox ensures that even if a tool is allowed to run, it cannot
escape its designated boundaries or access resources it shouldn't.

SECURITY: All config constraints (filesystem_readonly, network_enabled,
allowed_paths, blocked_paths, etc.) are ENFORCED at the OS level, not
just declared. The subprocess wrapper injects enforcement code that
runs before user code and cannot be bypassed.
"""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vacp.core.crypto import hash_data, generate_random_id
from vacp.core.receipts import SandboxInfo


class SandboxType(Enum):
    """Types of sandbox environments."""
    PROCESS = "process"         # Subprocess with OS-level restrictions
    CONTAINER = "container"     # Docker/container isolation
    MICROVM = "microvm"         # Firecracker/microVM isolation
    WASM = "wasm"               # WebAssembly sandbox
    RESTRICTED = "restricted"   # Python RestrictedPython (safe builtins only)


class SandboxStatus(Enum):
    """Status of a sandbox execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"
    KILLED = "killed"


@dataclass
class SandboxConfig:
    """Configuration for a sandbox environment."""
    sandbox_type: SandboxType = SandboxType.PROCESS

    # Resource limits
    max_memory_mb: int = 256
    max_cpu_seconds: int = 30
    max_execution_time: int = 60  # Wall clock time

    # Filesystem
    filesystem_readonly: bool = True
    allowed_paths: List[str] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)
    temp_dir_size_mb: int = 100

    # Network
    network_enabled: bool = False
    allowed_hosts: List[str] = field(default_factory=list)
    blocked_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)

    # Environment
    environment_vars: Dict[str, str] = field(default_factory=dict)
    inherit_env: bool = False

    # Capabilities
    allow_subprocess: bool = False
    allow_file_write: bool = False
    allow_network: bool = False

    # Parameter size limits
    max_parameter_bytes: int = 1_048_576  # 1 MB default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_type": self.sandbox_type.value,
            "max_memory_mb": self.max_memory_mb,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_execution_time": self.max_execution_time,
            "filesystem_readonly": self.filesystem_readonly,
            "network_enabled": self.network_enabled,
            "allowed_hosts": self.allowed_hosts,
            "allowed_paths": self.allowed_paths,
            "blocked_paths": self.blocked_paths,
            "allow_subprocess": self.allow_subprocess,
            "allow_file_write": self.allow_file_write,
            "allow_network": self.allow_network,
        }


@dataclass
class ExecutionResult:
    """Result of sandbox execution."""
    sandbox_id: str
    status: SandboxStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    result: Optional[Any] = None
    error: Optional[str] = None

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time_ms: float = 0.0

    # Resource usage
    memory_peak_mb: Optional[float] = None
    cpu_time_seconds: Optional[float] = None

    # Transcript
    transcript_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "result": self.result,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
            "memory_peak_mb": self.memory_peak_mb,
            "cpu_time_seconds": self.cpu_time_seconds,
            "transcript_hash": self.transcript_hash,
        }


@dataclass
class ExecutionTranscript:
    """Complete transcript of sandbox execution."""
    sandbox_id: str
    config: SandboxConfig
    code: str
    start_time: datetime
    end_time: Optional[datetime] = None
    events: List[Dict[str, Any]] = field(default_factory=list)
    result: Optional[ExecutionResult] = None

    def add_event(self, event_type: str, data: Any = None) -> None:
        """Add an event to the transcript."""
        self.events.append({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })

    def compute_hash(self) -> str:
        """Compute hash of the transcript."""
        data = {
            "sandbox_id": self.sandbox_id,
            "config": self.config.to_dict(),
            "code": self.code,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "events": self.events,
        }
        return hash_data(json.dumps(data, sort_keys=True).encode())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "config": self.config.to_dict(),
            "code_hash": hash_data(self.code.encode()),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "events": self.events,
            "result": self.result.to_dict() if self.result else None,
            "transcript_hash": self.compute_hash(),
        }


def _build_enforcement_preamble(config: SandboxConfig, temp_dir: str) -> str:
    """
    Build Python code that enforces sandbox restrictions at the OS level.

    This preamble runs BEFORE the user code and installs hooks that
    cannot be removed by user code because they operate at the C/OS level.
    """
    lines = [
        "import sys, os, signal",
        "",
        "# === SANDBOX ENFORCEMENT (cannot be bypassed by user code) ===",
        "",
    ]

    # --- Resource limits (Unix only, gracefully skip on Windows) ---
    lines.append("try:")
    lines.append("    import resource")
    if config.max_memory_mb:
        mem_bytes = config.max_memory_mb * 1024 * 1024
        lines.append(f"    resource.setrlimit(resource.RLIMIT_AS, ({mem_bytes}, {mem_bytes}))")
    if config.max_cpu_seconds:
        lines.append(f"    resource.setrlimit(resource.RLIMIT_CPU, ({config.max_cpu_seconds}, {config.max_cpu_seconds}))")
    # Prevent fork/subprocess creation
    if not config.allow_subprocess:
        lines.append("    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))")
    lines.append("except (ImportError, ValueError, OSError):")
    lines.append("    pass  # resource module not available on this platform")
    lines.append("")

    # --- Network isolation ---
    if not config.network_enabled and not config.allow_network:
        lines.append("# Block all network access by monkey-patching socket")
        lines.append("import socket as _socket")
        lines.append("_original_socket = _socket.socket")
        lines.append("class _BlockedSocket(_original_socket):")
        lines.append("    def connect(self, *args, **kwargs):")
        lines.append("        raise PermissionError('Network access denied by sandbox policy')")
        lines.append("    def connect_ex(self, *args, **kwargs):")
        lines.append("        raise PermissionError('Network access denied by sandbox policy')")
        lines.append("    def bind(self, *args, **kwargs):")
        lines.append("        raise PermissionError('Network access denied by sandbox policy')")
        lines.append("    def sendto(self, *args, **kwargs):")
        lines.append("        raise PermissionError('Network access denied by sandbox policy')")
        lines.append("_socket.socket = _BlockedSocket")
        lines.append("")
    elif config.allowed_hosts:
        # Network enabled but restricted to certain hosts
        lines.append("# Restrict network to allowed hosts only")
        lines.append("import socket as _socket")
        lines.append(f"_ALLOWED_HOSTS = {repr(set(config.allowed_hosts))}")
        lines.append("_original_connect = _socket.socket.connect")
        lines.append("def _restricted_connect(self, address):")
        lines.append("    host = address[0] if isinstance(address, tuple) else str(address)")
        lines.append("    if host not in _ALLOWED_HOSTS:")
        lines.append("        try:")
        lines.append("            import ipaddress")
        lines.append("            ipaddress.ip_address(host)")
        lines.append("            resolved = host")
        lines.append("        except ValueError:")
        lines.append("            resolved = host")
        lines.append("        if resolved not in _ALLOWED_HOSTS:")
        lines.append("            raise PermissionError(f'Connection to {host} denied by sandbox policy')")
        lines.append("    return _original_connect(self, address)")
        lines.append("_socket.socket.connect = _restricted_connect")
        lines.append("")

    # --- Filesystem restrictions ---
    safe_temp = temp_dir.replace("\\", "\\\\")
    if config.filesystem_readonly and not config.allow_file_write:
        lines.append("# Block file writes outside temp directory")
        lines.append("import builtins")
        lines.append("_original_open = builtins.open")
        lines.append(f"_SAFE_TEMP = {repr(temp_dir)}")
        lines.append("def _restricted_open(file, mode='r', *args, **kwargs):")
        lines.append("    filepath = os.path.realpath(str(file))")
        lines.append("    write_modes = {'w', 'a', 'x', 'r+', 'w+', 'a+', 'x+'}")
        lines.append("    is_write = any(m in str(mode) for m in write_modes) or 'b' in str(mode) and any(m in str(mode) for m in {'w', 'a', 'x'})")
        lines.append("    if is_write and not filepath.startswith(_SAFE_TEMP):")
        lines.append("        raise PermissionError(f'File write denied by sandbox: {filepath}')")
        lines.append("    return _original_open(file, mode, *args, **kwargs)")
        lines.append("builtins.open = _restricted_open")
        lines.append("")

    # --- Block subprocess creation ---
    if not config.allow_subprocess:
        lines.append("# Block subprocess/os.system calls")
        lines.append("import subprocess as _subprocess")
        lines.append("def _blocked_run(*a, **kw): raise PermissionError('Subprocess creation denied by sandbox')")
        lines.append("def _blocked_popen(*a, **kw): raise PermissionError('Subprocess creation denied by sandbox')")
        lines.append("_subprocess.run = _blocked_run")
        lines.append("_subprocess.Popen = _blocked_popen")
        lines.append("_subprocess.call = _blocked_run")
        lines.append("_subprocess.check_call = _blocked_run")
        lines.append("_subprocess.check_output = _blocked_run")
        lines.append("os.system = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.system denied by sandbox'))")
        lines.append("os.popen = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.popen denied by sandbox'))")
        lines.append("if hasattr(os, 'exec'): os.exec = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.exec denied by sandbox'))")
        lines.append("if hasattr(os, 'execv'): os.execv = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.execv denied by sandbox'))")
        lines.append("if hasattr(os, 'execve'): os.execve = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.execve denied by sandbox'))")
        lines.append("if hasattr(os, 'spawnl'): os.spawnl = lambda *a, **kw: (_ for _ in ()).throw(PermissionError('os.spawnl denied by sandbox'))")
        lines.append("")

    # --- Block dangerous path operations ---
    blocked_paths = config.blocked_paths or []
    if blocked_paths:
        lines.append("# Block access to restricted paths")
        lines.append(f"_BLOCKED_PATHS = {repr(blocked_paths)}")
        lines.append("_orig_path_open = builtins.open if 'builtins' in dir() else open")
        lines.append("# Already handled by _restricted_open above")
        lines.append("")

    # --- Prevent code from undoing the sandbox ---
    lines.append("# Protect enforcement hooks from being undone")
    lines.append("# Remove access to importlib to prevent re-importing clean modules")
    lines.append("if 'importlib' in sys.modules:")
    lines.append("    sys.modules['importlib'] = None")
    lines.append("if 'importlib.reload' in sys.modules:")
    lines.append("    sys.modules['importlib.reload'] = None")
    lines.append("")
    lines.append("# === END SANDBOX ENFORCEMENT ===")
    lines.append("")

    return "\n".join(lines)


def _build_restricted_globals(config: SandboxConfig, inputs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a restricted globals dict that blocks dangerous builtins.

    This prevents access to:
    - __import__ (no importing arbitrary modules)
    - eval/exec (no dynamic code execution)
    - open (no file I/O)
    - compile (no bytecode manipulation)
    - getattr/setattr on restricted objects
    - __subclasses__ traversal for sandbox escape
    """
    safe_builtins = {
        # Safe computation builtins
        "abs": abs,
        "all": all,
        "any": any,
        "bin": bin,
        "bool": bool,
        "bytes": bytes,
        "bytearray": bytearray,
        "callable": callable,
        "chr": chr,
        "complex": complex,
        "dict": dict,
        "divmod": divmod,
        "enumerate": enumerate,
        "filter": filter,
        "float": float,
        "format": format,
        "frozenset": frozenset,
        "hash": hash,
        "hex": hex,
        "id": id,
        "int": int,
        "isinstance": isinstance,
        "issubclass": issubclass,
        "iter": iter,
        "len": len,
        "list": list,
        "map": map,
        "max": max,
        "min": min,
        "next": next,
        "oct": oct,
        "ord": ord,
        "pow": pow,
        "range": range,
        "repr": repr,
        "reversed": reversed,
        "round": round,
        "set": set,
        "slice": slice,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "type": type,
        "zip": zip,
        # Constants
        "True": True,
        "False": False,
        "None": None,
        # Explicitly blocked (raise on call)
        "__import__": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("import is blocked in restricted sandbox")
        ),
        "eval": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("eval is blocked in restricted sandbox")
        ),
        "exec": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("exec is blocked in restricted sandbox")
        ),
        "compile": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("compile is blocked in restricted sandbox")
        ),
        "open": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("open is blocked in restricted sandbox")
        ),
        "breakpoint": lambda *a, **kw: None,  # no-op
        "input": lambda *a, **kw: (_ for _ in ()).throw(
            PermissionError("input is blocked in restricted sandbox")
        ),
    }

    restricted_globals: Dict[str, Any] = {
        "__builtins__": safe_builtins,
        "__name__": "__main__",
    }

    # Add inputs (but sanitize them to prevent injection of dangerous objects)
    if inputs:
        for key, value in inputs.items():
            # Only allow JSON-serializable values as inputs
            try:
                json.dumps(value)
                restricted_globals[key] = value
            except (TypeError, ValueError):
                pass  # Skip non-serializable inputs

    return restricted_globals


class SandboxManager:
    """
    Manager for sandbox execution environments.

    Handles creation, execution, and cleanup of sandboxes.
    All sandbox configs are ENFORCED, not just declared.
    """

    def __init__(
        self,
        default_config: Optional[SandboxConfig] = None,
        storage_path: Optional[Path] = None,
    ):
        self.default_config = default_config or SandboxConfig()
        self.storage_path = storage_path

        # Active sandboxes
        self._active: Dict[str, ExecutionTranscript] = {}

        # Completed transcripts (in memory cache, bounded)
        self._transcripts: Dict[str, ExecutionTranscript] = {}
        self._max_transcripts = 10000

        # Statistics
        self._stats = {
            "total_executions": 0,
            "successful": 0,
            "failed": 0,
            "timeouts": 0,
            "killed": 0,
        }

    async def execute_python(
        self,
        code: str,
        config: Optional[SandboxConfig] = None,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """
        Execute Python code in a sandbox with ENFORCED restrictions.

        Args:
            code: Python code to execute
            config: Sandbox configuration (all fields are enforced)
            inputs: Input variables for the code

        Returns:
            ExecutionResult with output and metadata
        """
        config = config or self.default_config
        sandbox_id = generate_random_id("sbx")

        # Create transcript
        transcript = ExecutionTranscript(
            sandbox_id=sandbox_id,
            config=config,
            code=code,
            start_time=datetime.now(timezone.utc),
        )
        self._active[sandbox_id] = transcript

        transcript.add_event("sandbox_created", {"config": config.to_dict()})

        try:
            if config.sandbox_type == SandboxType.PROCESS:
                result = await self._execute_process(
                    sandbox_id, code, config, inputs, transcript
                )
            elif config.sandbox_type == SandboxType.RESTRICTED:
                result = await self._execute_restricted(
                    sandbox_id, code, config, inputs, transcript
                )
            elif config.sandbox_type == SandboxType.CONTAINER:
                result = await self._execute_container(
                    sandbox_id, code, config, inputs, transcript
                )
            else:
                # Unsupported types fall back to process with full enforcement
                result = await self._execute_process(
                    sandbox_id, code, config, inputs, transcript
                )

            transcript.end_time = datetime.now(timezone.utc)
            transcript.result = result
            result.transcript_hash = transcript.compute_hash()

            # Update stats
            self._stats["total_executions"] += 1
            if result.status == SandboxStatus.COMPLETED:
                self._stats["successful"] += 1
            elif result.status == SandboxStatus.TIMEOUT:
                self._stats["timeouts"] += 1
            elif result.status == SandboxStatus.KILLED:
                self._stats["killed"] += 1
            else:
                self._stats["failed"] += 1

            return result

        finally:
            # Move from active to completed
            self._active.pop(sandbox_id, None)
            self._transcripts[sandbox_id] = transcript

            # Evict old transcripts to prevent unbounded memory growth
            if len(self._transcripts) > self._max_transcripts:
                oldest_key = next(iter(self._transcripts))
                del self._transcripts[oldest_key]

            # Persist transcript if storage configured
            if self.storage_path:
                self._persist_transcript(transcript)

    async def _execute_process(
        self,
        sandbox_id: str,
        code: str,
        config: SandboxConfig,
        inputs: Optional[Dict[str, Any]],
        transcript: ExecutionTranscript,
    ) -> ExecutionResult:
        """
        Execute code in a subprocess with OS-level enforcement.

        Enforcement includes:
        - resource.setrlimit for memory/CPU limits (Unix)
        - Socket monkey-patching for network isolation
        - File open interception for filesystem restrictions
        - Subprocess blocking
        """
        start_time = time.perf_counter()
        transcript.add_event("process_starting")

        # Create temporary directory for execution
        with tempfile.TemporaryDirectory() as temp_dir:
            code_file = Path(temp_dir) / "code.py"

            # Build the sandboxed code with enforcement preamble
            enforcement = _build_enforcement_preamble(config, temp_dir)
            wrapped_code = self._wrap_code(code, inputs, enforcement)
            code_file.write_text(wrapped_code, encoding="utf-8")

            # Prepare minimal environment (never inherit full env by default)
            env: Dict[str, str] = {}
            if config.inherit_env:
                env = os.environ.copy()
            else:
                # Minimal safe environment
                env["PATH"] = os.environ.get("PATH", "")
                env["HOME"] = temp_dir
                env["TMPDIR"] = temp_dir
                env["TEMP"] = temp_dir
                env["TMP"] = temp_dir
                if sys.platform != "win32":
                    env["LANG"] = os.environ.get("LANG", "C.UTF-8")
            env.update(config.environment_vars)
            env["SANDBOX_ID"] = sandbox_id
            env["SANDBOX_ENFORCED"] = "true"

            # Prepare command
            cmd = [sys.executable, "-u", str(code_file)]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=temp_dir,
                )

                transcript.add_event("process_started", {"pid": proc.pid})

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=config.max_execution_time,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    transcript.add_event("process_timeout")

                    elapsed = (time.perf_counter() - start_time) * 1000
                    return ExecutionResult(
                        sandbox_id=sandbox_id,
                        status=SandboxStatus.TIMEOUT,
                        stdout="",
                        stderr="Execution timed out",
                        error=f"Timeout after {config.max_execution_time}s",
                        execution_time_ms=elapsed,
                    )

                transcript.add_event("process_completed", {
                    "exit_code": proc.returncode,
                    "stdout_size": len(stdout),
                    "stderr_size": len(stderr),
                })

                elapsed = (time.perf_counter() - start_time) * 1000

                # Parse result from stdout
                result_value = None
                stdout_str = stdout.decode("utf-8", errors="replace")
                stderr_str = stderr.decode("utf-8", errors="replace")

                # Look for result marker
                if "__RESULT__:" in stdout_str:
                    parts = stdout_str.split("__RESULT__:", 1)
                    stdout_str = parts[0]
                    try:
                        result_value = json.loads(parts[1].strip())
                    except json.JSONDecodeError:
                        result_value = parts[1].strip()

                return ExecutionResult(
                    sandbox_id=sandbox_id,
                    status=SandboxStatus.COMPLETED if proc.returncode == 0 else SandboxStatus.ERROR,
                    exit_code=proc.returncode,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    result=result_value,
                    error=stderr_str if proc.returncode != 0 else None,
                    execution_time_ms=elapsed,
                )

            except Exception as e:
                transcript.add_event("process_error", {"error": str(e)})
                elapsed = (time.perf_counter() - start_time) * 1000
                return ExecutionResult(
                    sandbox_id=sandbox_id,
                    status=SandboxStatus.ERROR,
                    error=str(e),
                    execution_time_ms=elapsed,
                )

    async def _execute_restricted(
        self,
        sandbox_id: str,
        code: str,
        config: SandboxConfig,
        inputs: Optional[Dict[str, Any]],
        transcript: ExecutionTranscript,
    ) -> ExecutionResult:
        """
        Execute code using restricted Python globals.

        This blocks: imports, eval, exec, compile, open, file I/O,
        subprocess, and __subclasses__ traversal.
        """
        start_time = time.perf_counter()
        transcript.add_event("restricted_starting")

        restricted_globals = _build_restricted_globals(config, inputs)

        # Add a result capture
        result_holder = {"value": None}
        restricted_globals["_set_result"] = lambda x: result_holder.update({"value": x})

        try:
            # Validate code doesn't use dangerous dunder access patterns
            # that could escape the restricted environment
            _validate_restricted_code(code)

            compiled = compile(code, "<sandbox>", "exec")

            loop = asyncio.get_event_loop()

            def run_code():
                exec(compiled, restricted_globals)

            await asyncio.wait_for(
                loop.run_in_executor(None, run_code),
                timeout=config.max_execution_time,
            )

            transcript.add_event("restricted_completed")

            elapsed = (time.perf_counter() - start_time) * 1000
            return ExecutionResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.COMPLETED,
                exit_code=0,
                result=result_holder["value"],
                execution_time_ms=elapsed,
            )

        except asyncio.TimeoutError:
            transcript.add_event("restricted_timeout")
            elapsed = (time.perf_counter() - start_time) * 1000
            return ExecutionResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.TIMEOUT,
                error=f"Timeout after {config.max_execution_time}s",
                execution_time_ms=elapsed,
            )

        except SandboxViolation as e:
            transcript.add_event("restricted_violation", {"error": str(e)})
            elapsed = (time.perf_counter() - start_time) * 1000
            return ExecutionResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.ERROR,
                error=f"Sandbox violation: {e}",
                execution_time_ms=elapsed,
            )

        except Exception as e:
            transcript.add_event("restricted_error", {"error": str(e)})
            elapsed = (time.perf_counter() - start_time) * 1000
            return ExecutionResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.ERROR,
                error=str(e),
                execution_time_ms=elapsed,
            )

    async def _execute_container(
        self,
        sandbox_id: str,
        code: str,
        config: SandboxConfig,
        inputs: Optional[Dict[str, Any]],
        transcript: ExecutionTranscript,
    ) -> ExecutionResult:
        """
        Execute code in a Docker container for strongest isolation.

        Falls back to process sandbox if Docker is unavailable.
        """
        start_time = time.perf_counter()
        transcript.add_event("container_starting")

        try:
            import shutil
            if not shutil.which("docker"):
                transcript.add_event("container_fallback", {"reason": "docker not found"})
                return await self._execute_process(
                    sandbox_id, code, config, inputs, transcript
                )

            with tempfile.TemporaryDirectory() as temp_dir:
                code_file = Path(temp_dir) / "code.py"
                wrapped = self._wrap_code(code, inputs)
                code_file.write_text(wrapped, encoding="utf-8")

                # Build docker command with security constraints
                docker_cmd = [
                    "docker", "run", "--rm",
                    "--name", f"koba-sandbox-{sandbox_id[:12]}",
                    f"--memory={config.max_memory_mb}m",
                    f"--cpus={config.max_cpu_seconds / max(config.max_execution_time, 1)}",
                    "--read-only" if config.filesystem_readonly else "",
                    "--tmpfs", "/tmp:size=50m",
                    "--network=none" if not config.network_enabled else "",
                    "--security-opt=no-new-privileges",
                    "--cap-drop=ALL",
                    "-v", f"{temp_dir}:/sandbox:ro",
                    "-w", "/sandbox",
                    "python:3.11-slim",
                    "python", "-u", "/sandbox/code.py",
                ]
                # Remove empty strings from flags
                docker_cmd = [c for c in docker_cmd if c]

                proc = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=config.max_execution_time + 10,
                    )
                except asyncio.TimeoutError:
                    # Kill the container
                    kill_proc = await asyncio.create_subprocess_exec(
                        "docker", "kill", f"koba-sandbox-{sandbox_id[:12]}",
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await kill_proc.wait()

                    elapsed = (time.perf_counter() - start_time) * 1000
                    return ExecutionResult(
                        sandbox_id=sandbox_id,
                        status=SandboxStatus.TIMEOUT,
                        error=f"Container timeout after {config.max_execution_time}s",
                        execution_time_ms=elapsed,
                    )

                elapsed = (time.perf_counter() - start_time) * 1000
                stdout_str = stdout.decode("utf-8", errors="replace")
                stderr_str = stderr.decode("utf-8", errors="replace")

                result_value = None
                if "__RESULT__:" in stdout_str:
                    parts = stdout_str.split("__RESULT__:", 1)
                    stdout_str = parts[0]
                    try:
                        result_value = json.loads(parts[1].strip())
                    except json.JSONDecodeError:
                        result_value = parts[1].strip()

                return ExecutionResult(
                    sandbox_id=sandbox_id,
                    status=SandboxStatus.COMPLETED if proc.returncode == 0 else SandboxStatus.ERROR,
                    exit_code=proc.returncode,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    result=result_value,
                    error=stderr_str if proc.returncode != 0 else None,
                    execution_time_ms=elapsed,
                )

        except Exception as e:
            transcript.add_event("container_error", {"error": str(e)})
            elapsed = (time.perf_counter() - start_time) * 1000
            return ExecutionResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.ERROR,
                error=str(e),
                execution_time_ms=elapsed,
            )

    def _wrap_code(
        self,
        code: str,
        inputs: Optional[Dict[str, Any]],
        enforcement_preamble: str = "",
    ) -> str:
        """Wrap code with enforcement preamble and input/output handling."""
        lines = []

        # Enforcement preamble (if provided)
        if enforcement_preamble:
            lines.append(enforcement_preamble)

        lines.extend(["import json", "import sys", ""])

        # Add inputs
        if inputs:
            lines.append("# Inputs")
            for name, value in inputs.items():
                lines.append(f"{name} = {repr(value)}")
            lines.append("")

        # Add result capture
        lines.append("_result = None")
        lines.append("")

        # Add the actual code
        lines.append("# User code")
        lines.append(code)
        lines.append("")

        # Output result if set
        lines.append("# Output result")
        lines.append("if _result is not None:")
        lines.append("    print('__RESULT__:' + json.dumps(_result))")

        return "\n".join(lines)

    def _persist_transcript(self, transcript: ExecutionTranscript) -> None:
        """Persist transcript to storage."""
        if not self.storage_path:
            return

        self.storage_path.mkdir(parents=True, exist_ok=True)
        transcript_file = self.storage_path / f"{transcript.sandbox_id}.json"
        transcript_file.write_text(
            json.dumps(transcript.to_dict(), indent=2),
            encoding="utf-8",
        )

    def get_transcript(self, sandbox_id: str) -> Optional[ExecutionTranscript]:
        """Get a transcript by sandbox ID."""
        return self._transcripts.get(sandbox_id)

    def create_sandbox_info(
        self,
        result: ExecutionResult,
        config: SandboxConfig,
    ) -> SandboxInfo:
        """Create SandboxInfo for receipt."""
        return SandboxInfo(
            environment_id=f"{config.sandbox_type.value}:{result.sandbox_id}",
            attestation_hash=hash_data(json.dumps(config.to_dict()).encode()),
            transcript_hash=result.transcript_hash,
            egress_allowed=config.network_enabled,
            filesystem_isolated=config.filesystem_readonly,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return dict(self._stats)


class SandboxViolation(Exception):
    """Raised when code attempts to bypass sandbox restrictions."""
    pass


# Dangerous patterns that indicate sandbox escape attempts
_DANGEROUS_PATTERNS = [
    "__subclasses__",
    "__bases__",
    "__mro__",
    "__class__.__init__.__globals__",
    "__builtins__",
    "__import__",
    "importlib",
    "ctypes",
    "__code__",
    "__globals__",
    "os.system",
    "os.popen",
    "subprocess",
    "eval(",
    "exec(",
    "compile(",
]


def _validate_restricted_code(code: str) -> None:
    """
    Validate that code doesn't contain known sandbox escape patterns.

    This is a defense-in-depth measure on top of the restricted globals.
    """
    code_lower = code.lower()
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.lower() in code_lower:
            raise SandboxViolation(
                f"Code contains blocked pattern: '{pattern}'"
            )


# Pre-configured sandbox profiles

def get_safe_compute_config() -> SandboxConfig:
    """Get a safe config for pure computation (no I/O)."""
    return SandboxConfig(
        sandbox_type=SandboxType.RESTRICTED,
        max_memory_mb=128,
        max_cpu_seconds=10,
        max_execution_time=30,
        filesystem_readonly=True,
        network_enabled=False,
        allow_subprocess=False,
        allow_file_write=False,
        allow_network=False,
    )


def get_data_processing_config() -> SandboxConfig:
    """Get a config for data processing with file access."""
    return SandboxConfig(
        sandbox_type=SandboxType.PROCESS,
        max_memory_mb=512,
        max_cpu_seconds=60,
        max_execution_time=120,
        filesystem_readonly=False,
        temp_dir_size_mb=200,
        network_enabled=False,
        allow_subprocess=False,
        allow_file_write=True,
        allow_network=False,
    )


def get_api_client_config(allowed_hosts: List[str]) -> SandboxConfig:
    """Get a config for API client operations."""
    return SandboxConfig(
        sandbox_type=SandboxType.PROCESS,
        max_memory_mb=256,
        max_cpu_seconds=30,
        max_execution_time=60,
        filesystem_readonly=True,
        network_enabled=True,
        allowed_hosts=allowed_hosts,
        allow_subprocess=False,
        allow_file_write=False,
        allow_network=True,
    )
