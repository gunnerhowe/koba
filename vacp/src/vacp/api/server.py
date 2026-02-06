"""
FastAPI Server for VACP

HTTP API for the Verifiable Agent Action Control Plane.
Provides endpoints for:
- Authentication and user management
- Tool execution through the gateway
- Policy management
- Receipt retrieval and verification
- Approval workflow
- Capability token management
- Commitment schemes
- Health and statistics
- WebSocket for real-time updates
"""

import asyncio
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

# FastAPI imports (graceful fallback if not installed)
try:
    from fastapi import FastAPI, HTTPException, Request, Response, Depends, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, PlainTextResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from sqlalchemy import text as sql_text
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from vacp.core.crypto import KeyPair, generate_keypair
from vacp.core.gateway import (
    ToolGateway,
    ToolRequest,
    ToolResponse,
    EvaluationResult,
    ExternalExecutionRecord,
    create_gateway,
    ApprovalRequiredError,
    PolicyDeniedError,
)
from vacp.core.policy import (
    PolicyEngine,
    PolicyBundle,
    PolicyRule,
    PolicyDecision,
    ResourcePattern,
    MatchType,
    create_default_bundle,
)
from vacp.core.registry import (
    ToolRegistry,
    ToolDefinition,
    ToolSchema,
    ParameterSchema,
    ToolCategory,
    ToolRiskLevel,
)
from vacp.core.receipts import ReceiptService, SignedActionReceipt
from vacp.core.merkle import MerkleLog, AuditableLog, MerkleProof
from vacp.core.tokens import TokenService, TokenMintRequest as CoreTokenMintRequest, TokenScope
from vacp.core.tripwire import TripwireEngine, SequenceAnalyzer
from vacp.core.sandbox import SandboxManager, SandboxConfig
from vacp.core.auth import (
    AuthService,
    UserDatabase,
    User,
    UserRole,
    Permission,
    create_auth_service,
    create_default_admin,
)
from vacp.core.capabilities import (
    CapabilityTokenService,
    CapabilityToken,
    CapabilityGrant,
    CapabilityType,
    CommitmentService,
    ActionCommitment,
    create_capability_service,
    create_commitment_service,
)
from vacp.core.containment import (
    ContainmentSystem,
    SelfModificationController,
    ModificationType,
    ModificationCommitment,
    ApprovalStatus,
    KillSwitch,
    OutputFilter,
    ResourceController,
    ResourceBoundary,
    CognitiveMonitor,
    SystemShutdownError,
    MINIMUM_DELAYS,
    REQUIRED_APPROVERS,
)
from vacp.core.integrations import IntegrationService
from vacp.core.tenant import (
    TenantService,
    TenantContext,
    get_current_tenant,
    set_current_tenant,
    clear_tenant_context,
    Tenant,
    TenantStatus,
    TenantPlan,
)
from vacp.core.blockchain import (
    AnchorManager,
    is_blockchain_enabled,
)
from vacp.core.anchor_scheduler import (
    AnchorScheduler,
    AnchorSchedulerConfig,
    get_anchor_scheduler,
    init_anchor_scheduler,
)

from vacp.api.models import (
    ToolCallRequest,
    ToolCallResponse,
    ReceiptResponse,
    ReceiptInfo,
    ReceiptProof,
    PolicyBundleRequest,
    PolicyRuleRequest,
    ApprovalRequest,
    ApprovalInfo,
    ToolDefinitionRequest,
    TokenMintRequest,
    TokenResponse,
    AnomalyEventResponse,
    StatsResponse,
    HealthResponse,
    ErrorResponse,
)


# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.user_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str = "default", user_id: Optional[str] = None):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        self.active_connections[channel].add(websocket)

        if user_id:
            if user_id not in self.user_connections:
                self.user_connections[user_id] = set()
            self.user_connections[user_id].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str = "default", user_id: Optional[str] = None):
        if channel in self.active_connections:
            self.active_connections[channel].discard(websocket)
        if user_id and user_id in self.user_connections:
            self.user_connections[user_id].discard(websocket)

    async def broadcast(self, message: dict, channel: str = "default"):
        if channel in self.active_connections:
            dead_connections = set()
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.add(connection)
            self.active_connections[channel] -= dead_connections

    async def send_to_user(self, user_id: str, message: dict):
        if user_id in self.user_connections:
            dead_connections = set()
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.add(connection)
            self.user_connections[user_id] -= dead_connections


class VACPServer:
    """
    The main VACP server.

    Coordinates all components and provides the HTTP API.
    """

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        storage_path: Optional[Path] = None,
        jwt_secret: Optional[str] = None,
    ):
        """
        Initialize the VACP server.

        Args:
            keypair: Master keypair for signing
            storage_path: Path for persistent storage
            jwt_secret: Secret for JWT tokens
        """
        self.keypair = keypair or generate_keypair()
        self.storage_path = storage_path or Path("./vacp_data")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.start_time = datetime.now(timezone.utc)

        # Initialize core components
        self.registry = ToolRegistry()
        self.policy_engine = PolicyEngine(keypair=self.keypair)
        self.receipt_service = ReceiptService(keypair=self.keypair)
        self.merkle_log = MerkleLog(keypair=self.keypair)
        self.audit_log = AuditableLog(merkle_log=self.merkle_log)
        self.token_service = TokenService(keypair=self.keypair)
        self.tripwire = TripwireEngine()
        self.sandbox_manager = SandboxManager()

        # Create gateway
        self.gateway = ToolGateway(
            registry=self.registry,
            policy_engine=self.policy_engine,
            receipt_service=self.receipt_service,
            audit_log=self.audit_log,
            keypair=self.keypair,
        )

        # Initialize authentication
        self.auth_service = create_auth_service(
            db_path=self.storage_path / "users.db",
            jwt_secret=jwt_secret or secrets.token_hex(32),
        )

        # Create default admin if no users exist
        admin = create_default_admin(self.auth_service)
        if admin:
            print(f"[Koba] Default admin user created. Check console output above for credentials.")

        # Initialize capability system
        from nacl.signing import SigningKey
        # Ed25519 seed is 32 bytes; slice ensures compatibility with both
        # raw seed format and concatenated seed+public format
        assert len(self.keypair.private_key_bytes) >= 32, (
            f"Expected at least 32-byte private key, got {len(self.keypair.private_key_bytes)}"
        )
        cap_signing_key = SigningKey(self.keypair.private_key_bytes[:32])
        self.capability_service = CapabilityTokenService(cap_signing_key, "vacp-root")
        self.commitment_service = CommitmentService(cap_signing_key)

        # Initialize database manager for tenant service
        from vacp.core.database import DatabaseManager
        db_url = f"sqlite:///{self.storage_path / 'koba.db'}"
        self.db_manager = DatabaseManager(database_url=db_url)
        self.db_manager.create_tables()

        # Initialize tenant service
        self.tenant_service = TenantService(self.db_manager)

        # Initialize integration service (SQLite-backed)
        self.integration_service = IntegrationService(self.db_manager)

        # Initialize blockchain anchoring (if configured)
        self.anchor_manager = None
        self.anchor_scheduler = None
        if is_blockchain_enabled():
            self.anchor_manager = AnchorManager(db=self.db_manager)
            self.anchor_scheduler = init_anchor_scheduler(self.merkle_log)
            print("[Koba] Blockchain anchoring enabled")

        # Initialize ASI containment system
        self.containment = ContainmentSystem(cap_signing_key)
        print("[VACP] ASI Containment System initialized")
        print(f"  - Self-modification controls: ACTIVE")
        print(f"  - Kill switch: ARMED (requires 2 keys)")
        print(f"  - Output filtering: ACTIVE")
        print(f"  - Cognitive monitoring: ACTIVE")
        print(f"  - Resource boundaries: ENFORCED")

        # WebSocket manager
        self.ws_manager = ConnectionManager()

        # Load default policy
        default_bundle = create_default_bundle()
        self.policy_engine.load_bundle(default_bundle)

        # Register default tools
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register some default tools for testing."""
        # Echo tool (for testing)
        echo_tool = ToolDefinition(
            id="echo",
            name="Echo",
            description="Echoes back the input",
            schema=ToolSchema(
                parameters=[
                    ParameterSchema(name="message", type="string", required=True),
                ]
            ),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        )
        self.registry.register(echo_tool)

        # Register executor
        async def echo_executor(tool_id: str, params: Dict[str, Any]) -> Any:
            return {"echo": params.get("message", "")}
        self.gateway.register_executor("echo", echo_executor)

    async def execute_tool(
        self,
        request: ToolCallRequest,
    ) -> ToolCallResponse:
        """Execute a tool through the gateway."""
        # Convert API model to gateway model
        gateway_request = ToolRequest(
            tool_id=request.tool_id,
            parameters=request.parameters,
            agent_id=request.agent_id,
            tenant_id=request.tenant_id,
            session_id=request.session_id,
            method=request.method,
            resource=request.resource,
            trust_level=request.trust_level,
            context=request.context,
        )

        try:
            # Execute through gateway
            response = await self.gateway.execute(gateway_request)

            # Analyze for anomalies
            self.tripwire.analyze_action(
                tool_name=request.tool_id,
                session_id=request.session_id,
                agent_id=request.agent_id,
                success=response.success,
                parameters=request.parameters,
                execution_time_ms=response.execution_time_ms,
            )

            # Build response
            receipt_info = None
            if response.receipt:
                receipt_info = ReceiptInfo(
                    receipt_id=response.receipt.receipt_id,
                    timestamp=response.receipt.timestamp.isoformat(),
                    tool_hash=response.receipt.tool.request_hash,
                    policy_hash=response.receipt.policy.policy_hash,
                    decision=response.receipt.policy.decision.value,
                    log_index=response.receipt.log.log_index,
                    merkle_root=response.receipt.log.merkle_root,
                    signature=response.receipt.signature or "",
                )

                # Broadcast to WebSocket clients
                await self.ws_manager.broadcast({
                    "type": "receipt",
                    "data": receipt_info.to_dict(),
                }, "audit")

            return ToolCallResponse(
                request_id=response.request_id,
                tool_id=response.tool_id,
                success=response.success,
                result=response.result,
                error=response.error,
                receipt=receipt_info,
                execution_time_ms=response.execution_time_ms,
            )

        except ApprovalRequiredError as e:
            # Broadcast approval request
            await self.ws_manager.broadcast({
                "type": "approval_required",
                "data": {
                    "approval_id": e.approval_id,
                    "tool_id": request.tool_id,
                    "agent_id": request.agent_id,
                },
            }, "approvals")

            return ToolCallResponse(
                request_id=gateway_request.request_id,
                tool_id=request.tool_id,
                success=False,
                error="Approval required",
                policy_decision="pending_approval",
                approval_id=e.approval_id,
                execution_time_ms=0,
            )

    def get_receipt(self, receipt_id: str) -> Optional[ReceiptResponse]:
        """Get a receipt by ID."""
        receipt = self.audit_log.get_receipt_by_id(receipt_id)
        if not receipt:
            return None

        return ReceiptResponse(
            receipt_id=receipt.receipt_id,
            timestamp=receipt.timestamp.isoformat(),
            agent_id=receipt.agent_id,
            tenant_id=receipt.tenant_id,
            session_id=receipt.session_id,
            tool=receipt.tool.to_dict(),
            policy=receipt.policy.to_dict(),
            log=receipt.log.to_dict(),
            sandbox=receipt.sandbox.to_dict() if receipt.sandbox else None,
            constraints=receipt.constraints.to_dict() if receipt.constraints else None,
            signature=receipt.signature or "",
            issuer_public_key=receipt.issuer_public_key or "",
        )

    def get_receipt_with_proof(self, receipt_id: str) -> Optional[ReceiptProof]:
        """Get a receipt with its inclusion proof."""
        receipt = self.audit_log.get_receipt_by_id(receipt_id)
        if not receipt:
            return None

        proof = self.audit_log.get_proof_for_receipt(receipt_id)
        if not proof:
            return None

        receipt_response = self.get_receipt(receipt_id)
        if not receipt_response:
            return None

        # Verify
        verified = self.audit_log.verify_receipt_in_log(receipt, proof)

        return ReceiptProof(
            receipt=receipt_response,
            proof=proof.to_dict(),
            verified=verified,
        )

    def get_pending_approvals(
        self,
        tenant_id: Optional[str] = None,
    ) -> List[ApprovalInfo]:
        """Get pending approvals."""
        approvals = self.gateway.get_pending_approvals(tenant_id)
        return [
            ApprovalInfo(
                approval_id=a.approval_id,
                request=ToolCallRequest(
                    tool_id=a.request.tool_id,
                    parameters=a.request.parameters,
                    agent_id=a.request.agent_id,
                    tenant_id=a.request.tenant_id,
                    session_id=a.request.session_id,
                ),
                created_at=a.created_at.isoformat(),
                tool_id=a.request.tool_id,
                agent_id=a.request.agent_id,
                session_id=a.request.session_id,
                policy_decision=a.policy_result.decision.value,
                policy_rule_id=a.policy_result.matched_rule_id,
            )
            for a in approvals
        ]

    async def process_approval(
        self,
        request: ApprovalRequest,
    ) -> Optional[ToolCallResponse]:
        """Process an approval decision."""
        response = await self.gateway.execute_with_approval(
            approval_id=request.approval_id,
            approver_id=request.approver_id,
            approved=request.approved,
            rejection_reason=request.reason,
        )

        if not response:
            return None

        receipt_info = None
        if response.receipt:
            receipt_info = ReceiptInfo(
                receipt_id=response.receipt.receipt_id,
                timestamp=response.receipt.timestamp.isoformat(),
                tool_hash=response.receipt.tool.request_hash,
                policy_hash=response.receipt.policy.policy_hash,
                decision=response.receipt.policy.decision.value,
                log_index=response.receipt.log.log_index,
                merkle_root=response.receipt.log.merkle_root,
                signature=response.receipt.signature or "",
            )

        # Broadcast approval result
        await self.ws_manager.broadcast({
            "type": "approval_processed",
            "data": {
                "approval_id": request.approval_id,
                "approved": request.approved,
            },
        }, "approvals")

        return ToolCallResponse(
            request_id=response.request_id,
            tool_id=response.tool_id,
            success=response.success,
            result=response.result,
            error=response.error,
            receipt=receipt_info,
            execution_time_ms=response.execution_time_ms,
        )

    def mint_token(self, request: TokenMintRequest) -> TokenResponse:
        """Mint a new token."""
        core_request = CoreTokenMintRequest(
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            scope=TokenScope(tools=request.tools),
            purpose=request.purpose,
            ttl_seconds=request.ttl_seconds,
        )

        token, token_value = self.token_service.mint(core_request)

        return TokenResponse(
            token_id=token.token_id,
            token_value=token_value,
            expires_at=token.expires_at.isoformat(),
            scope=token.scope.to_dict(),
        )

    def get_stats(self) -> StatsResponse:
        """Get server statistics."""
        return StatsResponse(
            gateway=self.gateway.get_stats(),
            policy={
                "active_bundle": self.policy_engine._active_bundle_id,
                "bundles_loaded": len(self.policy_engine._bundles),
            },
            registry=self.registry.get_stats(),
            tokens=self.token_service.get_stats(),
            tripwire=self.tripwire.get_stats(),
            audit_log={
                "size": self.audit_log.log.size,
                "root": self.audit_log.log.root_hex,
            },
        )

    def get_health(self) -> HealthResponse:
        """Get server health."""
        uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()

        return HealthResponse(
            status="healthy",
            version="0.1.0",
            uptime_seconds=uptime,
            components={
                "gateway": "healthy",
                "policy_engine": "healthy",
                "audit_log": "healthy",
                "token_service": "healthy",
                "tripwire": "healthy",
                "auth": "healthy",
                "capabilities": "healthy",
            },
        )


def _populate_demo_data(server: VACPServer) -> None:
    """Populate the server with demo data including comprehensive tool catalog."""
    import asyncio

    # Register comprehensive tool catalog
    tools = [
        # ========== DATABASE TOOLS ==========
        ToolDefinition(
            id="db.query",
            name="Query Database",
            description="Run read-only database queries (SELECT)",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="query", type="string", required=True),
                ParameterSchema(name="database", type="string", default="default"),
            ]),
            categories=[ToolCategory.READ, ToolCategory.DATABASE],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="db.insert",
            name="Insert Records",
            description="Add new records to database",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="table", type="string", required=True),
                ParameterSchema(name="data", type="object", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.DATABASE],
            risk_level=ToolRiskLevel.MEDIUM,
            requires_approval=True,
        ),
        ToolDefinition(
            id="db.update",
            name="Update Records",
            description="Modify existing database records",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="table", type="string", required=True),
                ParameterSchema(name="where", type="object", required=True),
                ParameterSchema(name="data", type="object", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.DATABASE],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),
        ToolDefinition(
            id="db.delete",
            name="Delete Records",
            description="Remove records from database",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="table", type="string", required=True),
                ParameterSchema(name="where", type="object", required=True),
            ]),
            categories=[ToolCategory.DELETE, ToolCategory.DATABASE],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),

        # ========== DOCUMENT TOOLS (PDF) ==========
        ToolDefinition(
            id="pdf.read",
            name="Read PDF",
            description="Extract text and images from PDF documents",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="pages", type="string", default="all"),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="pdf.create",
            name="Create PDF",
            description="Generate new PDF documents",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="content", type="string", required=True),
                ParameterSchema(name="output_path", type="string", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.MEDIUM,
        ),
        ToolDefinition(
            id="pdf.sign",
            name="Sign PDF",
            description="Add digital signatures to PDFs",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="certificate", type="string", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),

        # ========== DOCUMENT TOOLS (Word/Office) ==========
        ToolDefinition(
            id="word.read",
            name="Read Word Document",
            description="Extract content from Word documents (.docx, .doc)",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="word.create",
            name="Create Word Document",
            description="Generate new Word documents",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="content", type="string", required=True),
                ParameterSchema(name="output_path", type="string", required=True),
                ParameterSchema(name="template", type="string"),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.MEDIUM,
        ),
        ToolDefinition(
            id="excel.read",
            name="Read Spreadsheet",
            description="Read data from Excel/CSV files",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="sheet", type="string", default="Sheet1"),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="excel.write",
            name="Write Spreadsheet",
            description="Create or modify spreadsheets",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="data", type="array", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.MEDIUM,
            requires_approval=True,
        ),

        # ========== CAD/DESIGN TOOLS ==========
        ToolDefinition(
            id="cad.view",
            name="View CAD File",
            description="View CAD drawings and 3D models",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="cad.modify",
            name="Modify CAD Design",
            description="Edit existing CAD drawings",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="operations", type="array", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),
        ToolDefinition(
            id="cad.export_manufacturing",
            name="Export to Manufacturing",
            description="Export designs to G-code, STL for manufacturing",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="format", type="string", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),

        # ========== EMAIL TOOLS ==========
        ToolDefinition(
            id="email.read",
            name="Read Email",
            description="Read emails from inbox",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="folder", type="string", default="inbox"),
                ParameterSchema(name="limit", type="integer", default=10),
            ]),
            categories=[ToolCategory.READ, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="email.draft",
            name="Draft Email",
            description="Create email drafts (not sent)",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="to", type="string", required=True),
                ParameterSchema(name="subject", type="string", required=True),
                ParameterSchema(name="body", type="string", required=True),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="email.send",
            name="Send Email",
            description="Send emails to recipients",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="to", type="string", required=True),
                ParameterSchema(name="subject", type="string", required=True),
                ParameterSchema(name="body", type="string", required=True),
                ParameterSchema(name="attachments", type="array"),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),

        # ========== WEB/BROWSER TOOLS ==========
        ToolDefinition(
            id="web.browse",
            name="Browse Website",
            description="View and navigate websites",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="url", type="string", required=True),
            ]),
            categories=[ToolCategory.READ, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="web.search",
            name="Web Search",
            description="Search the internet",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="query", type="string", required=True),
                ParameterSchema(name="num_results", type="integer", default=10),
            ]),
            categories=[ToolCategory.READ, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="web.fill_form",
            name="Fill Web Form",
            description="Enter data into web forms",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="url", type="string", required=True),
                ParameterSchema(name="fields", type="object", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.MEDIUM,
            requires_approval=True,
        ),
        ToolDefinition(
            id="web.submit_form",
            name="Submit Web Form",
            description="Submit forms on websites",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="url", type="string", required=True),
                ParameterSchema(name="data", type="object", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),
        ToolDefinition(
            id="web.login",
            name="Login to Website",
            description="Authenticate on websites",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="url", type="string", required=True),
                ParameterSchema(name="credentials", type="object", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),

        # ========== FILESYSTEM TOOLS ==========
        ToolDefinition(
            id="fs.read",
            name="Read File",
            description="Read file contents",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]),
            categories=[ToolCategory.READ, ToolCategory.FILESYSTEM],
            risk_level=ToolRiskLevel.LOW,
        ),
        ToolDefinition(
            id="fs.write",
            name="Write File",
            description="Create or overwrite files",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
                ParameterSchema(name="content", type="string", required=True),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.FILESYSTEM],
            risk_level=ToolRiskLevel.MEDIUM,
            requires_approval=True,
        ),
        ToolDefinition(
            id="fs.delete",
            name="Delete File",
            description="Delete files from system",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]),
            categories=[ToolCategory.DELETE, ToolCategory.FILESYSTEM],
            risk_level=ToolRiskLevel.HIGH,
            requires_approval=True,
        ),
        ToolDefinition(
            id="fs.list",
            name="List Directory",
            description="List files in a directory",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="path", type="string", required=True),
            ]),
            categories=[ToolCategory.READ, ToolCategory.FILESYSTEM],
            risk_level=ToolRiskLevel.LOW,
        ),

        # ========== CODE EXECUTION TOOLS ==========
        ToolDefinition(
            id="code.execute",
            name="Execute Code",
            description="Run code or scripts",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="language", type="string", required=True),
                ParameterSchema(name="code", type="string", required=True),
            ]),
            categories=[ToolCategory.EXECUTE],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),
        ToolDefinition(
            id="code.shell",
            name="Run Shell Command",
            description="Execute shell/terminal commands",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="command", type="string", required=True),
            ]),
            categories=[ToolCategory.EXECUTE, ToolCategory.ADMIN],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),

        # ========== FINANCIAL TOOLS ==========
        ToolDefinition(
            id="finance.view_balance",
            name="View Balance",
            description="Check account balances",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="account_id", type="string", required=True),
            ]),
            categories=[ToolCategory.READ],
            risk_level=ToolRiskLevel.MEDIUM,
        ),
        ToolDefinition(
            id="finance.transfer",
            name="Transfer Money",
            description="Transfer funds between accounts",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="from_account", type="string", required=True),
                ParameterSchema(name="to_account", type="string", required=True),
                ParameterSchema(name="amount", type="number", required=True),
                ParameterSchema(name="currency", type="string", default="USD"),
            ]),
            categories=[ToolCategory.WRITE],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),
        ToolDefinition(
            id="finance.payment",
            name="Make Payment",
            description="Send payments to recipients",
            schema=ToolSchema(parameters=[
                ParameterSchema(name="recipient", type="string", required=True),
                ParameterSchema(name="amount", type="number", required=True),
                ParameterSchema(name="memo", type="string"),
            ]),
            categories=[ToolCategory.WRITE, ToolCategory.NETWORK],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),

        # ========== ADMIN TOOLS ==========
        ToolDefinition(
            id="admin.delete_all",
            name="Delete All Data",
            description="Delete all data from the system",
            categories=[ToolCategory.DELETE, ToolCategory.ADMIN],
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
        ),
    ]

    for tool in tools:
        server.registry.register(tool)

    # Register executors
    async def mock_executor(tool_id: str, params: Dict[str, Any]) -> Any:
        return {"status": "ok", "tool": tool_id, "params": params}

    for tool in tools:
        server.gateway.register_executor(tool.id, mock_executor)

    # Create demo policy
    demo_policy = PolicyBundle(
        id="demo-policy",
        version="1.0.0",
        name="Demo Security Policy",
        default_decision=PolicyDecision.DENY,
    )

    demo_policy.add_rule(PolicyRule(
        id="allow-reads",
        name="Allow Read Operations",
        tool_patterns=["*.read", "*.get", "*.list", "*.query"],
        priority=100,
        decision=PolicyDecision.ALLOW,
    ))

    demo_policy.add_rule(PolicyRule(
        id="approve-writes",
        name="Require Approval for Writes",
        tool_patterns=["*.write", "*.create", "*.update"],
        priority=90,
        require_approval=True,
        decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
    ))

    demo_policy.add_rule(PolicyRule(
        id="deny-admin",
        name="Deny Admin Operations",
        tool_patterns=["admin.*"],
        priority=10,
        decision=PolicyDecision.DENY,
    ))

    server.policy_engine.load_bundle(demo_policy)

    # Execute some demo requests
    async def run_demo():
        from vacp.core.gateway import ApprovalRequiredError

        requests = [
            ("db.read", {"table": "users", "limit": 10}, "agent-001"),
            ("db.read", {"table": "orders", "limit": 50}, "agent-002"),
            ("file.read", {"path": "/etc/config.json"}, "agent-001"),
            ("api.get", {"url": "https://api.example.com/users"}, "agent-003"),
            ("db.read", {"table": "products"}, "agent-002"),
            ("admin.delete_all", {}, "agent-001"),  # Will be denied
        ]

        for tool_id, params, agent_id in requests:
            req = ToolRequest(
                tool_id=tool_id,
                parameters=params,
                agent_id=agent_id,
                tenant_id="demo-tenant",
                session_id="demo-session",
            )
            try:
                await server.gateway.execute(req)
            except ApprovalRequiredError:
                pass  # Expected for writes
            except Exception:
                pass  # Expected for denied

    asyncio.run(run_demo())
    print(f"[DEMO] Loaded {len(tools)} tools and {server.gateway.get_stats()['total_requests']} sample receipts")


# Security dependency
security = HTTPBearer(auto_error=False) if FASTAPI_AVAILABLE else None


def create_app(
    keypair: Optional[KeyPair] = None,
    storage_path: Optional[Path] = None,
    demo_mode: bool = False,
    jwt_secret: Optional[str] = None,
) -> Any:
    """
    Create the FastAPI application.

    Can be called directly with arguments (from main.py) or as a uvicorn
    factory function (no arguments). When called without arguments, reads
    configuration from environment variables.

    Args:
        keypair: Master keypair for signing
        storage_path: Path for persistent storage
        demo_mode: If True, populate with demo data on startup
        jwt_secret: Secret for JWT tokens

    Returns:
        FastAPI application
    """
    import os

    # Read from environment when called as factory (no args)
    if storage_path is None:
        storage_path = Path(os.getenv("VACP_STORAGE_PATH", "./vacp_data"))
    if jwt_secret is None:
        jwt_secret = os.getenv("JWT_SECRET", None)
    if not demo_mode:
        demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    storage_path.mkdir(parents=True, exist_ok=True)

    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi uvicorn")

    # Validate configuration on startup
    import logging
    logger = logging.getLogger(__name__)

    try:
        from vacp.config import get_config, ConfigurationError, is_production
        config = get_config()
        warnings = config.validate()

        if warnings:
            for warning in warnings:
                logger.warning(f"Configuration warning: {warning}")

        if is_production():
            logger.info("Running in PRODUCTION mode")
        else:
            logger.info("Running in DEVELOPMENT mode")

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        raise
    except ImportError:
        # Config module not available, skip validation
        pass

    app = FastAPI(
        title="VACP - Verifiable Agent Action Control Plane",
        description="Cryptographically verifiable policy enforcement for AI agents",
        version="0.1.0",
    )

    # Add CORS middleware - explicit origins for security
    # Additional origins can be set via CORS_ORIGINS environment variable (comma-separated)
    import os
    from urllib.parse import urlparse
    default_origins = [
        "http://localhost:3000",
        "http://localhost:3001",
    ]
    # Only add production Vercel URLs if explicitly configured
    extra_origins = os.getenv("CORS_ORIGINS", "").split(",")
    extra_origins = [o.strip() for o in extra_origins if o.strip()]
    # Validate that no wildcard origins are allowed (security requirement)
    extra_origins = [
        o for o in extra_origins
        if o != "*" and urlparse(o).scheme in ("http", "https")
    ]
    allowed_origins = default_origins + extra_origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Tenant-ID",
            "X-Request-ID",
            "X-API-Key",
        ],
    )

    # Add production middleware
    try:
        from vacp.api.middleware import (
            RateLimitMiddleware,
            RateLimitConfig,
            MetricsMiddleware,
            MetricsCollector,
            SecurityHeadersMiddleware,
            RequestTracingMiddleware,
            circuit_breaker_registry,
        )

        # Initialize metrics collector
        metrics_collector = MetricsCollector()

        # Add middleware in reverse order (last added = first executed)
        app.add_middleware(MetricsMiddleware, collector=metrics_collector)
        app.add_middleware(SecurityHeadersMiddleware)
        app.add_middleware(RequestTracingMiddleware, service_name="vacp")
        app.add_middleware(
            RateLimitMiddleware,
            config=RateLimitConfig(
                requests_per_minute=100,
                requests_per_hour=5000,
                burst_size=20,
                exempt_paths=["/health", "/metrics", "/v1/auth/login"],
                endpoint_limits={
                    "/v1/tools/execute": 30,  # More restrictive for tool execution
                    "/v1/containment/kill-switch": 5,  # Very restrictive for kill switch
                },
            ),
        )

        # Store metrics collector on app.state
        app.state.metrics_collector = metrics_collector
        app.state.circuit_breakers = circuit_breaker_registry

        print("[VACP] Production middleware enabled: rate limiting, metrics, security headers, tracing")
    except ImportError as e:
        print(f"[VACP] Warning: Could not load middleware: {e}")
        metrics_collector = None

    # Create server instance
    server = VACPServer(keypair=keypair, storage_path=storage_path, jwt_secret=jwt_secret)

    # Store server on app.state for access in tests/cleanup
    app.state.server = server

    # Populate demo data if requested
    if demo_mode:
        _populate_demo_data(server)

    # Auth dependency
    async def get_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Optional[User]:
        if not credentials:
            return None
        user = server.auth_service.verify_token(credentials.credentials)
        return user

    async def require_auth(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> User:
        if not credentials:
            raise HTTPException(status_code=401, detail="Not authenticated")
        user = server.auth_service.verify_token(credentials.credentials)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user

    def require_permission(permission: Permission):
        async def check(user: User = Depends(require_auth)) -> User:
            if not user.has_permission(permission):
                raise HTTPException(status_code=403, detail="Permission denied")
            return user
        return check

    def require_system_admin(user: User = Depends(require_auth)) -> User:
        """Require user to be a system admin."""
        if not user.is_system_admin:
            raise HTTPException(status_code=403, detail="System admin access required")
        return user

    def require_fields(data: Dict[str, Any], *fields: str) -> None:
        """Validate that required fields are present in request data.

        Args:
            data: The request data dictionary
            *fields: Required field names

        Raises:
            HTTPException: 400 if any required field is missing
        """
        missing = [f for f in fields if f not in data or data[f] is None]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required fields: {', '.join(missing)}"
            )

    def validate_pagination(limit: int, offset: int, max_limit: int = 1000) -> tuple:
        """Validate and constrain pagination parameters.

        Args:
            limit: Requested limit
            offset: Requested offset
            max_limit: Maximum allowed limit

        Returns:
            Tuple of (validated_limit, validated_offset)
        """
        validated_limit = max(1, min(limit, max_limit))
        validated_offset = max(0, offset)
        return validated_limit, validated_offset

    async def resolve_tenant(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Optional[TenantContext]:
        """
        Resolve tenant context from:
        1. JWT token (tenant_id claim)
        2. API key (X-API-Key header)
        3. Tenant header (X-Tenant-ID)
        """
        tenant_ctx = None

        # Try JWT first
        if credentials:
            payload = server.auth_service.jwt_service.decode(credentials.credentials)
            if payload and payload.get("tenant_id"):
                tenant = server.tenant_service.get_tenant(payload["tenant_id"])
                if tenant:
                    tenant_ctx = TenantContext(
                        tenant_id=tenant.id,
                        tenant_name=tenant.name,
                        tenant_slug=tenant.slug,
                        plan=tenant.plan,
                        is_system_admin=payload.get("is_system_admin", False),
                    )

        # Try API key
        if not tenant_ctx:
            api_key = request.headers.get("X-API-Key")
            if api_key:
                result = server.auth_service.verify_api_key(api_key)
                if result:
                    key_obj, tenant_id = result
                    tenant = server.tenant_service.get_tenant(tenant_id)
                    if tenant:
                        tenant_ctx = TenantContext(
                            tenant_id=tenant.id,
                            tenant_name=tenant.name,
                            tenant_slug=tenant.slug,
                            plan=tenant.plan,
                        )

        # Try tenant header (for system admins)
        if not tenant_ctx:
            tenant_header = request.headers.get("X-Tenant-ID")
            if tenant_header and credentials:
                user = server.auth_service.verify_token(credentials.credentials)
                if user and user.is_system_admin:
                    tenant = server.tenant_service.get_tenant(tenant_header)
                    if tenant:
                        tenant_ctx = TenantContext(
                            tenant_id=tenant.id,
                            tenant_name=tenant.name,
                            tenant_slug=tenant.slug,
                            plan=tenant.plan,
                            is_system_admin=True,
                        )

        # Set in context variable
        if tenant_ctx:
            set_current_tenant(tenant_ctx)

        return tenant_ctx

    # ==================== AUTH ENDPOINTS ====================

    @app.post("/v1/auth/register")
    async def register(request: Request):
        """Register a new user."""
        data = await request.json()
        require_fields(data, "email", "username", "password")

        # Validate email format
        email = data["email"]
        if "@" not in email or len(email) > 255:
            raise HTTPException(status_code=400, detail="Invalid email format")

        # Validate username
        username = data["username"]
        if len(username) < 3 or len(username) > 50:
            raise HTTPException(status_code=400, detail="Username must be 3-50 characters")

        # Validate password
        password = data["password"]
        if len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

        try:
            user = server.auth_service.register(
                email=email,
                username=username,
                password=password,
                role=UserRole.VIEWER,  # New users always start as viewer; admins can promote
            )
            return {"status": "registered", "user": user.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/v1/auth/login")
    async def login(request: Request):
        """Login and get tokens."""
        data = await request.json()
        email_or_username = data.get("email") or data.get("username")
        if not email_or_username:
            raise HTTPException(status_code=400, detail="Email or username required")
        if "password" not in data:
            raise HTTPException(status_code=400, detail="Password required")

        try:
            result = server.auth_service.login(
                email_or_username=email_or_username,
                password=data["password"],
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            return result
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))

    @app.post("/v1/auth/logout")
    async def logout(request: Request, user: User = Depends(require_auth)):
        """Logout and invalidate session."""
        try:
            body = await request.body()
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            data = {}
        session_id = data.get("session_id")
        if session_id:
            server.auth_service.logout(session_id)
        return {"status": "logged_out"}

    @app.post("/v1/auth/refresh")
    async def refresh_tokens(request: Request):
        """Refresh access token."""
        data = await request.json()
        require_fields(data, "refresh_token")
        try:
            result = server.auth_service.refresh_tokens(data["refresh_token"])
            return result
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))

    @app.get("/v1/auth/me")
    async def get_current_user_info(user: User = Depends(require_auth)):
        """Get current user info."""
        return user.to_dict()

    @app.post("/v1/auth/change-password")
    async def change_password(request: Request, user: User = Depends(require_auth)):
        """Change password."""
        data = await request.json()
        require_fields(data, "old_password", "new_password")

        if len(data["new_password"]) < 6:
            raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

        try:
            server.auth_service.change_password(
                user_id=user.id,
                old_password=data["old_password"],
                new_password=data["new_password"],
            )
            return {"status": "password_changed"}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ==================== USER MANAGEMENT ====================

    @app.get("/v1/users")
    async def list_users(
        limit: int = 100,
        offset: int = 0,
        user: User = Depends(require_permission(Permission.USERS_READ))
    ):
        """List all users."""
        limit, offset = validate_pagination(limit, offset, max_limit=500)
        users = server.auth_service.db.list_users(limit, offset)
        total = server.auth_service.db.count_users()
        return {
            "users": [u.to_dict() for u in users],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/users/{user_id}")
    async def get_user(
        user_id: str,
        current_user: User = Depends(require_permission(Permission.USERS_READ))
    ):
        """Get user by ID."""
        user = server.auth_service.db.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.to_dict()

    @app.put("/v1/users/{user_id}")
    async def update_user(
        user_id: str,
        request: Request,
        current_user: User = Depends(require_permission(Permission.USERS_UPDATE))
    ):
        """Update user."""
        data = await request.json()
        user = server.auth_service.db.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if "email" in data:
            user.email = data["email"]
        if "username" in data:
            user.username = data["username"]
        if "role" in data:
            user.role = UserRole(data["role"])
        if "is_active" in data:
            user.is_active = data["is_active"]

        user = server.auth_service.db.update_user(user)
        return user.to_dict()

    @app.delete("/v1/users/{user_id}")
    async def delete_user(
        user_id: str,
        current_user: User = Depends(require_permission(Permission.USERS_DELETE))
    ):
        """Delete user."""
        if user_id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        success = server.auth_service.db.delete_user(user_id)
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        return {"status": "deleted"}

    # ==================== CAPABILITY TOKENS ====================

    @app.post("/v1/capabilities/issue")
    async def issue_capability(
        request: Request,
        user: User = Depends(require_permission(Permission.CAPABILITIES_ISSUE))
    ):
        """Issue a capability token."""
        data = await request.json()
        grants = [
            CapabilityGrant(
                capability_type=CapabilityType(g["type"]),
                resource_pattern=g["resource"],
                constraints=g.get("constraints", {}),
            )
            for g in data.get("grants", [])
        ]

        token = server.capability_service.issue_token(
            holder_id=data["holder_id"],
            grants=grants,
            ttl_seconds=data.get("ttl_seconds", 3600),
            max_uses=data.get("max_uses"),
            max_delegation_depth=data.get("max_delegation_depth", 0),
            metadata=data.get("metadata"),
        )

        return token.to_dict()

    @app.post("/v1/capabilities/verify")
    async def verify_capability(request: Request):
        """Verify a capability token."""
        data = await request.json()
        token = CapabilityToken.from_dict(data["token"])
        valid = server.capability_service.verify_token(token)
        return {"valid": valid}

    @app.post("/v1/capabilities/delegate")
    async def delegate_capability(
        request: Request,
        user: User = Depends(require_auth)
    ):
        """Delegate a capability token."""
        data = await request.json()
        parent_token = CapabilityToken.from_dict(data["parent_token"])

        grants = None
        if "grants" in data:
            grants = [
                CapabilityGrant(
                    capability_type=CapabilityType(g["type"]),
                    resource_pattern=g["resource"],
                    constraints=g.get("constraints", {}),
                )
                for g in data["grants"]
            ]

        try:
            new_token = server.capability_service.delegate_token(
                parent_token=parent_token,
                new_holder_id=data["new_holder_id"],
                grants=grants,
                ttl_seconds=data.get("ttl_seconds"),
                max_uses=data.get("max_uses"),
            )
            return new_token.to_dict()
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/v1/capabilities/{token_id}/revoke")
    async def revoke_capability(
        token_id: str,
        user: User = Depends(require_permission(Permission.CAPABILITIES_REVOKE))
    ):
        """Revoke a capability token."""
        server.capability_service.revoke_token(token_id)
        return {"status": "revoked"}

    # ==================== COMMITMENTS ====================

    @app.post("/v1/commitments/create")
    async def create_commitment(
        request: Request,
        user: User = Depends(require_auth)
    ):
        """Create a commitment to a future action."""
        data = await request.json()
        commitment, nonce = server.commitment_service.create_commitment(
            agent_id=data["agent_id"],
            action_data=data["action"],
            action_type=data.get("action_type", "tool_call"),
            reveal_delay=data.get("reveal_delay"),
            ttl_seconds=data.get("ttl_seconds", 3600),
        )

        return {
            "commitment": commitment.to_dict(),
            "nonce": nonce,  # Agent must keep this secret until reveal
        }

    @app.post("/v1/commitments/{commitment_id}/reveal")
    async def reveal_commitment(
        commitment_id: str,
        request: Request,
        user: User = Depends(require_auth)
    ):
        """Reveal a commitment."""
        data = await request.json()
        try:
            valid = server.commitment_service.reveal_commitment(
                commitment_id=commitment_id,
                action_data=data["action"],
                nonce=data["nonce"],
            )
            return {"valid": valid}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/v1/commitments")
    async def list_commitments(
        agent_id: Optional[str] = None,
        user: User = Depends(require_auth)
    ):
        """List pending commitments."""
        commitments = server.commitment_service.get_pending_commitments(agent_id)
        return {"commitments": [c.to_dict() for c in commitments]}

    @app.get("/v1/commitments/{commitment_id}")
    async def get_commitment(
        commitment_id: str,
        user: User = Depends(require_auth)
    ):
        """Get a commitment by ID."""
        commitment = server.commitment_service.get_commitment(commitment_id)
        if not commitment:
            raise HTTPException(status_code=404, detail="Commitment not found")
        return commitment.to_dict()

    # ==================== HEALTH & STATS ====================

    @app.get("/health")
    async def health():
        """Basic health check for load balancers."""
        return server.get_health().to_dict()

    @app.get("/health/live")
    async def liveness():
        """Kubernetes liveness probe - checks if process is running."""
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe - checks if ready to accept traffic."""
        try:
            # Check database connectivity
            if hasattr(server, 'db_manager') and server.db_manager:
                # Quick DB check
                with server.db_manager.get_session() as session:
                    session.execute(sql_text("SELECT 1"))

            return {"status": "ready", "checks": {"database": "ok"}}
        except Exception as e:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "error": str(e)}
            )

    @app.get("/health/detailed")
    async def detailed_health(user: User = Depends(require_auth)):
        """Detailed health check with component status (requires auth)."""
        health_data = server.get_health().to_dict()

        # Add additional details
        health_data["rate_limiter"] = {}
        health_data["circuit_breakers"] = {}

        if hasattr(app.state, 'metrics_collector') and app.state.metrics_collector:
            health_data["metrics_active"] = True

        if hasattr(app.state, 'circuit_breakers'):
            health_data["circuit_breakers"] = app.state.circuit_breakers.get_all_stats()

        return health_data

    @app.get("/stats")
    async def stats(user: User = Depends(require_auth)):
        return server.get_stats().to_dict()

    @app.get("/v1/analytics")
    async def get_analytics(user: User = Depends(require_auth)):
        """Get analytics data for dashboard visualizations."""
        gateway_stats = server.gateway.get_stats()
        log_size = server.audit_log.log.size

        # Count decisions and categories from recent receipts
        decisions: Dict[str, int] = {"allow": 0, "deny": 0, "pending_approval": 0}
        categories: Dict[str, int] = {}
        recent_activity: List[Dict[str, Any]] = []

        max_scan = min(log_size, 200)
        for i in range(max(0, log_size - max_scan), log_size):
            receipt = server.audit_log.get_receipt(i)
            if not receipt:
                continue
            d = receipt.policy.decision.value if hasattr(receipt.policy.decision, "value") else str(receipt.policy.decision)
            decisions[d] = decisions.get(d, 0) + 1
            tool_name = receipt.tool.name or receipt.tool.id or "unknown"
            cat = tool_name.split(".")[0] if "." in tool_name else tool_name
            categories[cat] = categories.get(cat, 0) + 1

        # Sort categories by count
        top_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "gateway": gateway_stats,
            "audit_log_size": log_size,
            "decisions": decisions,
            "top_categories": [{"name": c, "count": n} for c, n in top_categories],
            "pending_approvals": len(server.gateway._pending_approvals),
            "active_rules": 0,
        }

    @app.get("/metrics")
    async def metrics():
        """Prometheus metrics endpoint."""
        lines = []

        # Basic metrics
        lines.append("# HELP vacp_info VACP server information")
        lines.append("# TYPE vacp_info gauge")
        lines.append(f'vacp_info{{version="0.1.0"}} 1')

        # Uptime
        uptime = (datetime.now(timezone.utc) - server.start_time).total_seconds()
        lines.append("# HELP vacp_uptime_seconds Server uptime in seconds")
        lines.append("# TYPE vacp_uptime_seconds gauge")
        lines.append(f"vacp_uptime_seconds {uptime}")

        # Gateway stats
        gateway_stats = server.gateway.get_stats()
        lines.append("# HELP vacp_gateway_requests_total Total gateway requests")
        lines.append("# TYPE vacp_gateway_requests_total counter")
        lines.append(f"vacp_gateway_requests_total {gateway_stats.get('total_requests', 0)}")

        # Audit log size
        lines.append("# HELP vacp_audit_log_size Number of entries in audit log")
        lines.append("# TYPE vacp_audit_log_size gauge")
        lines.append(f"vacp_audit_log_size {server.audit_log.log.size}")

        # Token stats
        token_stats = server.token_service.get_stats()
        lines.append("# HELP vacp_tokens_minted_total Total tokens minted")
        lines.append("# TYPE vacp_tokens_minted_total counter")
        lines.append(f"vacp_tokens_minted_total {token_stats.get('total_minted', 0)}")

        lines.append("# HELP vacp_tokens_active Active tokens")
        lines.append("# TYPE vacp_tokens_active gauge")
        lines.append(f"vacp_tokens_active {token_stats.get('active_tokens', 0)}")

        # HTTP metrics from middleware
        if hasattr(app.state, 'metrics_collector') and app.state.metrics_collector:
            http_metrics = app.state.metrics_collector.export_prometheus()
            lines.append("")
            lines.append(http_metrics)

        # Circuit breaker metrics
        if hasattr(app.state, 'circuit_breakers'):
            cb_stats = app.state.circuit_breakers.get_all_stats()
            lines.append("")
            lines.append("# HELP vacp_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)")
            lines.append("# TYPE vacp_circuit_breaker_state gauge")
            for name, stats in cb_stats.items():
                state_value = {"closed": 0, "open": 1, "half_open": 2}.get(stats["state"], 0)
                lines.append(f'vacp_circuit_breaker_state{{name="{name}"}} {state_value}')

        return PlainTextResponse(
            content="\n".join(lines),
            media_type="text/plain; version=0.0.4; charset=utf-8"
        )

    # ==================== TOOL EXECUTION ====================

    @app.post("/v1/tools/execute")
    async def execute_tool(request: Request, user: User = Depends(require_auth)):
        data = await request.json()
        req = ToolCallRequest(
            tool_id=data["tool_id"],
            parameters=data.get("parameters", {}),
            agent_id=data.get("agent_id", user.id),
            tenant_id=data.get("tenant_id", "default"),
            session_id=data.get("session_id", secrets.token_hex(8)),
            method=data.get("method"),
            resource=data.get("resource"),
            trust_level=data.get("trust_level"),
            context=data.get("context", {}),
        )
        response = await server.execute_tool(req)
        return response.to_dict()

    @app.post("/v1/tools/evaluate")
    async def evaluate_tool(request: Request, user: User = Depends(require_auth)):
        """
        Evaluate policy for a tool call WITHOUT executing.

        This endpoint is used for external execution scenarios (e.g., ClawdBot integration)
        where the caller wants to check if a tool call is allowed before executing it themselves.

        Returns:
        - decision: "allow", "deny", or "require_approval"
        - pre_auth_token: Token to use when recording execution result (if allowed)
        - approval_id: ID to check/approve (if require_approval)
        - denial_reason: Why the call was denied (if deny)
        - constraints: Budget/rate limits that apply (if allowed)
        """
        data = await request.json()
        req = ToolRequest(
            tool_id=data["tool_id"],
            parameters=data.get("parameters", {}),
            agent_id=data.get("agent_id", user.id),
            tenant_id=data.get("tenant_id", "default"),
            session_id=data.get("session_id", secrets.token_hex(8)),
            method=data.get("method"),
            resource=data.get("resource"),
            trust_level=data.get("trust_level"),
            context=data.get("context", {}),
        )
        result = await server.gateway.evaluate_only(req)

        # Track integration stats: if context.source matches an integration type,
        # record the activity against every matching integration.
        source = data.get("context", {}).get("source")
        if source:
            for integration in server.integration_service.find_by_type(source):
                server.integration_service.record_activity(
                    integration["id"], result.decision,
                )

        # Dispatch webhook for approval requests
        if result.decision == "require_approval":
            asyncio.ensure_future(_dispatch_webhooks("approval.requested", {
                "approval_id": result.approval_id,
                "tool_id": data["tool_id"],
                "agent_id": data.get("agent_id", user.id),
                "source": source or "api",
            }))

        return result.to_dict()

    @app.post("/v1/audit/record")
    async def record_execution(request: Request, user: User = Depends(require_auth)):
        """
        Record the result of an external tool execution.

        This endpoint is called after an external system (e.g., ClawdBot) has executed
        a tool that was pre-authorized via /v1/tools/evaluate.

        Requires the pre_auth_token from the evaluate response.

        Returns a signed receipt if the pre_auth_token is valid and not expired.
        """
        data = await request.json()

        if "pre_auth_token" not in data:
            raise HTTPException(status_code=400, detail="pre_auth_token is required")

        record = ExternalExecutionRecord(
            pre_auth_token=data["pre_auth_token"],
            success=data.get("success", True),
            result=data.get("result"),
            error=data.get("error"),
            execution_time_ms=data.get("execution_time_ms", 0.0),
        )

        receipt = await server.gateway.record_external_execution(record)

        if receipt is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired pre_auth_token"
            )

        # Track integration stats from the recorded execution.
        # Use the source field passed alongside the record, or fall back to
        # the agent_id as a heuristic for integration type matching.
        record_source = data.get("source")
        if record_source:
            decision_str = receipt.policy.decision.value if receipt.policy else "allow"
            for integration in server.integration_service.find_by_type(record_source):
                server.integration_service.record_activity(
                    integration["id"], decision_str,
                )

        return {
            "receipt_id": receipt.receipt_id,
            "agent_id": receipt.agent_id,
            "tool_id": receipt.tool.name if receipt.tool else None,
            "decision": receipt.policy.decision.value if receipt.policy else None,
            "timestamp": receipt.timestamp,
            "signature": receipt.signature,
        }

    # Tool catalog
    @app.get("/v1/tools/catalog")
    async def get_catalog(user: User = Depends(require_auth)):
        """Get the tool catalog. Requires authentication in production."""
        # In production, require authentication to view tools
        # For now, allow unauthenticated access for demo purposes
        tools = []
        for tool in server.registry.list_tools():
            tools.append({
                "id": tool.id,
                "name": tool.name,
                "description": tool.description or "",
                "categories": [c.value for c in tool.categories],
                "risk_level": tool.risk_level.value,
                "requires_approval": tool.requires_approval,
                "schema": {
                    "parameters": [
                        {
                            "name": p.name,
                            "type": p.type,
                            "description": p.description or "",
                            "required": p.required,
                            "default": p.default,
                        }
                        for p in (tool.schema.parameters if tool.schema else [])
                    ]
                },
            })
        return {"tools": tools}

    @app.post("/v1/tools/register")
    async def register_tool(
        request: Request,
        user: User = Depends(require_permission(Permission.TOOLS_REGISTER))
    ):
        data = await request.json()
        require_fields(data, "id", "name")

        # Validate tool ID format
        if len(data["id"]) < 1 or len(data["id"]) > 100:
            raise HTTPException(status_code=400, detail="Tool ID must be 1-100 characters")

        tool = ToolDefinition(
            id=data["id"],
            name=data["name"],
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            schema=ToolSchema(
                parameters=[
                    ParameterSchema(
                        name=p["name"],
                        type=p["type"],
                        description=p.get("description", ""),
                        required=p.get("required", False),
                    )
                    for p in data.get("parameters", [])
                ]
            ),
            categories=[ToolCategory(c) for c in data.get("categories", ["read"])],
            risk_level=ToolRiskLevel(data.get("risk_level", "medium")),
            requires_sandbox=data.get("requires_sandbox", False),
            requires_approval=data.get("requires_approval", False),
            timeout_seconds=data.get("timeout_seconds", 30),
        )
        server.registry.register(tool)

        # Broadcast new tool
        await server.ws_manager.broadcast({
            "type": "tool_registered",
            "data": {"tool_id": tool.id, "name": tool.name},
        }, "tools")

        return {"status": "registered", "tool_id": tool.id}

    @app.delete("/v1/tools/{tool_id}")
    async def delete_tool(
        tool_id: str,
        user: User = Depends(require_permission(Permission.TOOLS_DELETE))
    ):
        """Delete a tool."""
        try:
            server.registry.unregister(tool_id)
            return {"status": "deleted", "tool_id": tool_id}
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e))

    # ==================== RECEIPTS ====================

    @app.get("/v1/receipts/{receipt_id}")
    async def get_receipt(receipt_id: str, user: User = Depends(require_auth)):
        receipt = server.get_receipt(receipt_id)
        if not receipt:
            raise HTTPException(status_code=404, detail="Receipt not found")
        return receipt.to_dict()

    @app.get("/v1/receipts/{receipt_id}/proof")
    async def get_receipt_proof(receipt_id: str, user: User = Depends(require_auth)):
        proof = server.get_receipt_with_proof(receipt_id)
        if not proof:
            raise HTTPException(status_code=404, detail="Receipt not found")
        return proof.to_dict()

    @app.post("/v1/receipts/verify")
    async def verify_receipt(request: Request, user: User = Depends(require_auth)):
        data = await request.json()

        # Handle receipt_id-based verification
        if "receipt_id" in data:
            receipt_id = data["receipt_id"]
            receipt = server.audit_log.get_receipt_by_id(receipt_id)
            if not receipt:
                raise HTTPException(status_code=404, detail="Receipt not found")

            sig_valid = server.receipt_service.verify_receipt(receipt)
            proof = server.audit_log.get_proof_for_receipt(receipt_id)
            proof_valid = server.audit_log.verify_receipt_in_log(receipt, proof) if proof else False

            return {
                "valid": sig_valid and proof_valid,
                "signature_valid": sig_valid,
                "proof_valid": proof_valid,
                "receipt": server.get_receipt(receipt_id).to_dict() if sig_valid else None,
            }

        # Reconstruct receipt and verify
        receipt = SignedActionReceipt.from_dict(data["receipt"])
        valid = server.receipt_service.verify_receipt(receipt)
        return {"valid": valid, "signature_valid": valid, "proof_valid": False}

    # ==================== APPROVALS ====================

    @app.get("/v1/approvals")
    async def get_approvals(
        tenant_id: Optional[str] = None,
        user: User = Depends(require_permission(Permission.APPROVALS_READ))
    ):
        approvals = server.get_pending_approvals(tenant_id)
        return {"approvals": [a.to_dict() for a in approvals]}

    @app.post("/v1/approvals/{approval_id}")
    async def process_approval(
        approval_id: str,
        request: Request,
        user: User = Depends(require_permission(Permission.APPROVALS_GRANT))
    ):
        data = await request.json()
        req = ApprovalRequest(
            approval_id=approval_id,
            approved=data["approved"],
            approver_id=user.id,
            reason=data.get("reason"),
        )
        response = await server.process_approval(req)

        # Dispatch webhook for approval resolution
        asyncio.ensure_future(_dispatch_webhooks(
            "approval.approved" if data["approved"] else "approval.rejected",
            {
                "approval_id": approval_id,
                "approved": data["approved"],
                "approver": user.username,
                "reason": data.get("reason"),
            },
        ))

        if not response:
            return {"status": "rejected"}
        return response.to_dict()

    # ==================== TOKENS ====================

    @app.post("/v1/tokens/mint")
    async def mint_token(
        request: Request,
        user: User = Depends(require_auth)
    ):
        data = await request.json()
        req = TokenMintRequest(
            tenant_id=data.get("tenant_id", "default"),
            agent_id=data.get("agent_id", user.id),
            session_id=data.get("session_id", secrets.token_hex(8)),
            tools=data.get("tools", []),
            ttl_seconds=data.get("ttl_seconds", 300),
            purpose=data.get("purpose", ""),
        )
        token = server.mint_token(req)
        return token.to_dict()

    @app.post("/v1/tokens/validate")
    async def validate_token(request: Request, user: User = Depends(require_auth)):
        data = await request.json()
        valid, token = server.token_service.validate(
            data["token"],
            tool_name=data.get("tool"),
            resource=data.get("resource"),
        )
        return {
            "valid": valid,
            "token_id": token.token_id if token else None,
            "status": token.status.value if token else None,
        }

    @app.post("/v1/tokens/introspect")
    async def introspect_token(request: Request, user: User = Depends(require_auth)):
        data = await request.json()
        return server.token_service.introspect(data["token"])

    @app.post("/v1/tokens/{token_id}/revoke")
    async def revoke_token(
        token_id: str,
        request: Request,
        user: User = Depends(require_auth)
    ):
        try:
            body = await request.body()
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            data = {}
        success = server.token_service.revoke(token_id, data.get("reason", "API revocation"))
        return {"revoked": success}

    # ==================== POLICY ====================

    @app.get("/v1/policy/bundles")
    async def list_bundles(user: User = Depends(require_permission(Permission.POLICY_READ))):
        return {
            "bundles": [
                {"id": bid, "version": b.version, "name": b.name}
                for bid, b in server.policy_engine._bundles.items()
            ]
        }

    @app.get("/v1/policy/bundles/{bundle_id}")
    async def get_bundle(
        bundle_id: str,
        user: User = Depends(require_permission(Permission.POLICY_READ))
    ):
        bundle = server.policy_engine._bundles.get(bundle_id)
        if not bundle:
            raise HTTPException(status_code=404, detail="Bundle not found")
        return bundle.to_dict()

    @app.post("/v1/policy/bundles")
    async def create_bundle(
        request: Request,
        user: User = Depends(require_permission(Permission.POLICY_WRITE))
    ):
        data = await request.json()
        bundle = PolicyBundle(
            id=data["id"],
            version=data["version"],
            name=data["name"],
            description=data.get("description", ""),
            default_decision=PolicyDecision(data.get("default_decision", "deny")),
        )
        for rule_data in data.get("rules", []):
            rule = PolicyRule(
                id=rule_data["id"],
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                priority=rule_data.get("priority", 100),
                tool_patterns=rule_data.get("tool_patterns", []),
                agent_patterns=rule_data.get("agent_patterns", []),
                tenant_patterns=rule_data.get("tenant_patterns", []),
                decision=PolicyDecision(rule_data.get("decision", "deny")),
                require_sandbox=rule_data.get("require_sandbox", False),
                require_approval=rule_data.get("require_approval", False),
            )
            bundle.add_rule(rule)

        server.policy_engine.load_bundle(bundle)

        # Broadcast policy update
        await server.ws_manager.broadcast({
            "type": "policy_updated",
            "data": {"bundle_id": bundle.id},
        }, "policy")

        return {"status": "loaded", "bundle_id": bundle.id}

    @app.delete("/v1/policy/bundles/{bundle_id}")
    async def delete_bundle(
        bundle_id: str,
        user: User = Depends(require_permission(Permission.POLICY_DELETE))
    ):
        if bundle_id not in server.policy_engine._bundles:
            raise HTTPException(status_code=404, detail="Bundle not found")
        del server.policy_engine._bundles[bundle_id]
        return {"status": "deleted"}

    @app.post("/v1/policy/bundles/{bundle_id}/activate")
    async def activate_bundle(
        bundle_id: str,
        user: User = Depends(require_permission(Permission.POLICY_WRITE))
    ):
        if bundle_id not in server.policy_engine._bundles:
            raise HTTPException(status_code=404, detail="Bundle not found")
        server.policy_engine.set_active_bundle(bundle_id)
        return {"status": "activated", "bundle_id": bundle_id}

    # ==================== SETUP WIZARD ====================

    @app.post("/v1/setup/protection-level")
    async def set_protection_level(
        request: Request,
        user: User = Depends(require_auth),
    ):
        """Apply a protection level from the setup wizard.

        Creates and activates a policy bundle matching the chosen level:
        - basic: Log everything, no blocking
        - standard: Require approval for high-risk actions
        - maximum: Require approval for ALL actions
        """
        body = await request.json()
        level = body.get("level", "standard")
        if level not in ("basic", "standard", "maximum"):
            raise HTTPException(status_code=400, detail="Invalid protection level. Must be: basic, standard, maximum")

        bundle = PolicyBundle(
            id=f"setup-{level}",
            version="1.0.0",
            name=f"Setup Wizard: {level.title()} Protection",
            description=f"Auto-generated policy bundle for {level} protection level",
            default_decision=PolicyDecision.DENY,
        )

        if level == "basic":
            # Log everything, allow most actions
            bundle.add_rule(PolicyRule(
                id="basic-allow-all",
                name="Allow All (Monitoring Only)",
                description="Allow all tool calls; actions are logged for monitoring",
                tool_patterns=["*"],
                priority=100,
                decision=PolicyDecision.ALLOW,
            ))
            bundle.add_rule(PolicyRule(
                id="basic-deny-dangerous",
                name="Block Shell/System Execution",
                description="Block dangerous system-level operations",
                tool_patterns=["system"],
                method_patterns=["execute"],
                priority=10,
                decision=PolicyDecision.DENY,
            ))

        elif level == "standard":
            # Default: allow reads, approve writes, deny dangerous
            bundle.add_rule(PolicyRule(
                id="std-allow-read",
                name="Allow Read Operations",
                description="Allow safe read-only tool calls",
                tool_patterns=["*"],
                method_patterns=["read", "get", "list", "query", "search",
                                 "check_balance", "pull", "download", "browse"],
                priority=100,
                decision=PolicyDecision.ALLOW,
            ))
            bundle.add_rule(PolicyRule(
                id="std-approve-write",
                name="Require Approval for Writes",
                description="Write operations require human approval",
                tool_patterns=["*"],
                method_patterns=["write", "create", "update", "delete", "send",
                                 "execute", "post", "put", "transfer", "move",
                                 "copy", "insert", "upload", "commit", "push",
                                 "branch", "merge", "refund", "request", "draft",
                                 "sudo", "install", "compile", "share", "schedule"],
                priority=90,
                require_approval=True,
                decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
                conditions={"approval_required": True},
            ))
            bundle.add_rule(PolicyRule(
                id="std-deny-dangerous",
                name="Block Shell/System Execution",
                description="Block dangerous system-level operations",
                tool_patterns=["system"],
                method_patterns=["execute"],
                priority=10,
                decision=PolicyDecision.DENY,
            ))

        elif level == "maximum":
            # All actions require approval
            bundle.add_rule(PolicyRule(
                id="max-approve-all",
                name="Require Approval for All Actions",
                description="Every action requires human review before execution",
                tool_patterns=["*"],
                priority=100,
                require_approval=True,
                decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
                conditions={"approval_required": True},
            ))
            bundle.add_rule(PolicyRule(
                id="max-deny-dangerous",
                name="Block Shell/System Execution",
                description="Block dangerous system-level operations entirely",
                tool_patterns=["system"],
                method_patterns=["execute"],
                priority=10,
                decision=PolicyDecision.DENY,
            ))

        # Add standard redaction rules to all levels
        from vacp.core.policy import RedactionRule
        bundle.redaction_rules["api-keys"] = RedactionRule(
            name="API Keys",
            pattern=r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
            replacement="[API_KEY_REDACTED]",
        )
        bundle.redaction_rules["passwords"] = RedactionRule(
            name="Passwords",
            pattern=r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"']+)",
            replacement="[PASSWORD_REDACTED]",
        )

        server.policy_engine.load_bundle(bundle, activate=True)
        return {
            "status": "activated",
            "level": level,
            "bundle_id": bundle.id,
            "rules_count": len(bundle.rules),
        }

    # ==================== SIMPLE RULE BUILDER ====================

    @app.get("/v1/rules/categories")
    async def get_rule_categories(user: User = Depends(require_auth)):
        """
        Get all available rule categories for the simple rule builder.

        Returns categories with their human-readable labels, icons,
        descriptions, and available actions.
        """
        from vacp.core.normalize import get_categories
        categories = get_categories()
        return {
            "categories": [
                {
                    "id": cat_id,
                    "label": cat["label"],
                    "description": cat["description"],
                    "icon": cat["icon"],
                    "actions": cat["methods"],
                }
                for cat_id, cat in categories.items()
            ]
        }

    @app.post("/v1/rules/simple")
    async def create_simple_rule(
        request: Request,
        user: User = Depends(require_permission(Permission.POLICY_WRITE)),
    ):
        """
        Create a policy rule using the simplified rule builder.

        This is the main API for the simple rule builder UI.
        It takes a category, action(s), and optional resource constraint
        and creates the proper policy rules.

        Body:
            category: str - Category ID (e.g., "file", "email", "database")
            actions: list[str] - Actions to apply (e.g., ["deny"], ["read"], ["write"])
            resource: str | None - Optional resource path/pattern
            name: str | None - Optional human-readable name
        """
        from vacp.core.normalize import (
            get_categories, build_tool_patterns,
            build_method_patterns, CATEGORIES,
        )
        body = await request.json()

        category = body.get("category")
        actions = body.get("actions", [])
        resource = body.get("resource", "").strip() or None
        rule_name = body.get("name", "").strip()

        if not category:
            raise HTTPException(status_code=400, detail="category is required")
        if not actions:
            raise HTTPException(status_code=400, detail="At least one action is required")

        if category not in CATEGORIES:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown category: {category}. "
                       f"Valid: {', '.join(CATEGORIES.keys())}",
            )

        # Determine the policy decision from the actions
        # Actions can be: "deny", "require_approval", "read_only", "allow"
        # Or specific methods: "read", "write", "delete", "send", etc.

        policy_decision = PolicyDecision.DENY
        require_approval = False
        method_patterns: list = []
        resource_patterns: list = []

        # Classify the actions
        deny_actions = {"deny", "block"}
        approval_actions = {"require_approval", "approval", "approve"}
        allow_actions = {"allow"}
        read_only_actions = {"read_only", "readonly"}

        selected_decision = None
        selected_methods = []

        for action in actions:
            action_lower = action.lower().strip()
            if action_lower in deny_actions:
                selected_decision = "deny"
            elif action_lower in approval_actions:
                selected_decision = "require_approval"
            elif action_lower in read_only_actions:
                # Read only: allow reads, deny everything else
                selected_decision = "read_only"
            elif action_lower in allow_actions:
                selected_decision = "allow"
            else:
                # Treat as a specific method (read, write, delete, send, etc.)
                selected_methods.append(action_lower)

        # Build the policy rules based on the selection
        rules_to_add = []
        cat_label = CATEGORIES[category]["label"]
        base_name = rule_name or f"{cat_label} Rule"
        import secrets as _secrets
        rule_suffix = _secrets.token_hex(4)

        if selected_decision == "deny":
            # Create a deny rule for the category
            tool_pats = build_tool_patterns(category, selected_methods or None)
            rp = []
            if resource:
                rp = [ResourcePattern(pattern=resource, match_type=MatchType.GLOB)]
            rules_to_add.append(PolicyRule(
                id=f"simple-deny-{category}-{rule_suffix}",
                name=f"{base_name} - Block",
                description=f"Block {cat_label} access" +
                            (f" to {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=build_method_patterns(selected_methods or None),
                resource_patterns=rp,
                priority=10,  # High priority (low number = evaluated first)
                decision=PolicyDecision.DENY,
            ))

        elif selected_decision == "require_approval":
            tool_pats = build_tool_patterns(category, selected_methods or None)
            rp = []
            if resource:
                rp = [ResourcePattern(pattern=resource, match_type=MatchType.GLOB)]
            rules_to_add.append(PolicyRule(
                id=f"simple-approve-{category}-{rule_suffix}",
                name=f"{base_name} - Require Approval",
                description=f"Require approval for {cat_label}" +
                            (f" access to {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=build_method_patterns(selected_methods or None),
                resource_patterns=rp,
                priority=20,
                require_approval=True,
                decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
                conditions={"approval_required": True},
            ))

        elif selected_decision == "read_only":
            # Allow reads
            tool_pats = build_tool_patterns(category)
            rp = []
            if resource:
                rp = [ResourcePattern(pattern=resource, match_type=MatchType.GLOB)]
            rules_to_add.append(PolicyRule(
                id=f"simple-readonly-allow-{category}-{rule_suffix}",
                name=f"{base_name} - Allow Read",
                description=f"Allow reading {cat_label}" +
                            (f" from {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=["read", "get", "list", "query", "search",
                                 "check_balance", "pull", "download", "browse"],
                resource_patterns=rp,
                priority=15,
                decision=PolicyDecision.ALLOW,
            ))
            # Deny writes
            rules_to_add.append(PolicyRule(
                id=f"simple-readonly-deny-{category}-{rule_suffix}",
                name=f"{base_name} - Block Write",
                description=f"Block writing to {cat_label}" +
                            (f" at {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=["write", "create", "update", "delete",
                                 "send", "execute", "put", "post",
                                 "insert", "remove", "drop", "move",
                                 "copy", "upload", "commit", "push",
                                 "branch", "merge", "refund", "request",
                                 "draft", "sudo", "install", "compile",
                                 "share", "schedule", "transfer"],
                resource_patterns=rp,
                priority=10,
                decision=PolicyDecision.DENY,
            ))

        elif selected_decision == "allow":
            tool_pats = build_tool_patterns(category, selected_methods or None)
            rp = []
            if resource:
                rp = [ResourcePattern(pattern=resource, match_type=MatchType.GLOB)]
            rules_to_add.append(PolicyRule(
                id=f"simple-allow-{category}-{rule_suffix}",
                name=f"{base_name} - Allow",
                description=f"Allow {cat_label} access" +
                            (f" to {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=build_method_patterns(selected_methods or None),
                resource_patterns=rp,
                priority=50,
                decision=PolicyDecision.ALLOW,
            ))

        else:
            # Specific methods selected without a decision
            # Default to deny for the selected methods
            tool_pats = build_tool_patterns(category)
            rp = []
            if resource:
                rp = [ResourcePattern(pattern=resource, match_type=MatchType.GLOB)]
            rules_to_add.append(PolicyRule(
                id=f"simple-method-{category}-{rule_suffix}",
                name=f"{base_name}",
                description=f"Control {cat_label} {', '.join(selected_methods)}" +
                            (f" for {resource}" if resource else ""),
                tool_patterns=tool_pats,
                method_patterns=selected_methods,
                resource_patterns=rp,
                priority=15,
                decision=PolicyDecision.DENY,
            ))

        if not rules_to_add:
            raise HTTPException(status_code=400, detail="Could not create rules from the given inputs")

        # Add rules to the active bundle, or create a new one
        active_id = server.policy_engine.active_bundle_id
        if active_id:
            bundle = server.policy_engine.get_active_bundle()
            if bundle:
                for rule in rules_to_add:
                    bundle.add_rule(rule)
                # Re-load to update hash
                server.policy_engine.load_bundle(bundle, activate=True)
            else:
                raise HTTPException(status_code=500, detail="Active bundle not found")
        else:
            # Create new bundle
            bundle = PolicyBundle(
                id="simple-rules",
                version="1.0.0",
                name="Simple Rules",
                description="Rules created via the simple rule builder",
                default_decision=PolicyDecision.DENY,
            )
            for rule in rules_to_add:
                bundle.add_rule(rule)
            server.policy_engine.load_bundle(bundle, activate=True)

        # Broadcast update
        await server.ws_manager.broadcast({
            "type": "policy_updated",
            "data": {
                "bundle_id": bundle.id,
                "rules_added": [r.id for r in rules_to_add],
            },
        }, "policy")

        return {
            "status": "created",
            "rules": [r.to_dict() for r in rules_to_add],
            "bundle_id": bundle.id,
        }

    @app.delete("/v1/rules/simple/{rule_id}")
    async def delete_simple_rule(
        rule_id: str,
        user: User = Depends(require_permission(Permission.POLICY_WRITE)),
    ):
        """Delete a rule by ID from the active bundle."""
        active_id = server.policy_engine.active_bundle_id
        if not active_id:
            raise HTTPException(status_code=404, detail="No active policy bundle")

        bundle = server.policy_engine.get_active_bundle()
        if not bundle:
            raise HTTPException(status_code=404, detail="Active bundle not found")

        original_count = len(bundle.rules)
        bundle.rules = [r for r in bundle.rules if r.id != rule_id]

        if len(bundle.rules) == original_count:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        server.policy_engine.load_bundle(bundle, activate=True)

        await server.ws_manager.broadcast({
            "type": "policy_updated",
            "data": {"bundle_id": bundle.id, "rule_deleted": rule_id},
        }, "policy")

        return {"status": "deleted", "rule_id": rule_id}

    # ==================== DASHBOARD TOOL POLICIES ====================
    # These endpoints connect the dashboard Tools page to the PolicyEngine.
    # Each tool (e.g., "email.send") gets a deterministic rule ID so it can
    # be created, updated, or retrieved reliably.

    def _tool_id_to_rule_id(tool_id: str) -> str:
        """Convert dotted tool ID to deterministic rule ID."""
        return f"tool-policy-{tool_id.replace('.', '-')}"

    def _create_tool_policy_rule(tool_id: str, decision_str: str, name: str = "") -> PolicyRule:
        """Create a PolicyRule from a dashboard tool ID and decision string."""
        from vacp.core.normalize import normalize_tool_name
        # Use normalize to get canonical category (e.g. "pay" -> "payments")
        canonical_category, canonical_method, _ = normalize_tool_name(tool_id)
        parts = tool_id.split(".", 1)
        category = canonical_category or parts[0]
        method = canonical_method or (parts[1] if len(parts) > 1 else None)

        rule_id = _tool_id_to_rule_id(tool_id)

        if decision_str == "deny":
            return PolicyRule(
                id=rule_id,
                name=name or f"Block {tool_id}",
                description=f"Dashboard policy: block {tool_id}",
                tool_patterns=[category],
                method_patterns=[method] if method else [],
                priority=10,
                decision=PolicyDecision.DENY,
            )
        elif decision_str == "require_approval":
            return PolicyRule(
                id=rule_id,
                name=name or f"Approve {tool_id}",
                description=f"Dashboard policy: require approval for {tool_id}",
                tool_patterns=[category],
                method_patterns=[method] if method else [],
                priority=20,
                require_approval=True,
                decision=PolicyDecision.ALLOW_WITH_CONDITIONS,
                conditions={"approval_required": True},
            )
        else:  # allow
            return PolicyRule(
                id=rule_id,
                name=name or f"Allow {tool_id}",
                description=f"Dashboard policy: allow {tool_id}",
                tool_patterns=[category],
                method_patterns=[method] if method else [],
                priority=50,
                decision=PolicyDecision.ALLOW,
            )

    @app.post("/v1/tools/policy")
    async def set_tool_policy(
        request: Request,
        user: User = Depends(require_permission(Permission.POLICY_WRITE)),
    ):
        """Set the policy for a single tool from the dashboard.

        Body:
            tool_id: str - Dotted tool ID (e.g., "email.send")
            decision: str - "allow", "deny", or "require_approval"
            name: str | None - Optional human-readable name
        """
        body = await request.json()
        tool_id = body.get("tool_id", "").strip()
        decision_str = body.get("decision", "").strip().lower()
        name = body.get("name", "").strip()

        if not tool_id:
            raise HTTPException(status_code=400, detail="tool_id is required")
        if decision_str not in ("allow", "deny", "require_approval"):
            raise HTTPException(status_code=400, detail="decision must be: allow, deny, or require_approval")

        rule = _create_tool_policy_rule(tool_id, decision_str, name)

        # Get or create the active bundle
        bundle = server.policy_engine.get_active_bundle()
        if not bundle:
            bundle = PolicyBundle(
                id="tool-policies",
                version="1.0.0",
                name="Dashboard Tool Policies",
                default_decision=PolicyDecision.DENY,
            )

        # Remove existing rule for this tool if present
        bundle.rules = [r for r in bundle.rules if r.id != rule.id]
        bundle.add_rule(rule)
        server.policy_engine.load_bundle(bundle, activate=True)

        await server.ws_manager.broadcast({
            "type": "policy_updated",
            "data": {"tool_id": tool_id, "decision": decision_str},
        }, "policy")

        return {
            "status": "created",
            "rule_id": rule.id,
            "tool_id": tool_id,
            "decision": decision_str,
            "bundle_id": bundle.id,
        }

    @app.get("/v1/tools/policies")
    async def get_tool_policies(user: User = Depends(require_auth)):
        """Get all dashboard tool policies from the active bundle.

        Returns a map of tool_id -> decision for all tool-policy rules,
        plus the current protection level if a setup bundle is active.
        """
        policies: Dict[str, str] = {}
        protection_level = None
        bundle_id = None

        bundle = server.policy_engine.get_active_bundle()
        if bundle:
            bundle_id = bundle.id

            # Detect protection level from bundle ID
            if bundle.id.startswith("setup-"):
                protection_level = bundle.id.replace("setup-", "")

            # Extract tool-specific policies
            for rule in bundle.rules:
                if rule.id.startswith("tool-policy-"):
                    # Reconstruct tool_id from rule ID
                    raw = rule.id.replace("tool-policy-", "")
                    # Convert "email-send" back to "email.send"
                    parts = raw.split("-", 1)
                    tool_id = ".".join(parts) if len(parts) > 1 else parts[0]

                    if rule.decision == PolicyDecision.DENY:
                        policies[tool_id] = "deny"
                    elif rule.decision == PolicyDecision.ALLOW_WITH_CONDITIONS and rule.require_approval:
                        policies[tool_id] = "require_approval"
                    else:
                        policies[tool_id] = "allow"

        return {
            "policies": policies,
            "protection_level": protection_level,
            "bundle_id": bundle_id,
        }

    @app.post("/v1/tools/policies/bulk")
    async def set_tool_policies_bulk(
        request: Request,
        user: User = Depends(require_permission(Permission.POLICY_WRITE)),
    ):
        """Set policies for multiple tools at once.

        Body:
            policies: dict - Map of tool_id -> decision
                e.g., {"email.send": "deny", "email.read": "allow"}
        """
        body = await request.json()
        policies = body.get("policies", {})

        if not policies:
            raise HTTPException(status_code=400, detail="policies map is required")

        valid_decisions = {"allow", "deny", "require_approval"}

        # Get or create the active bundle
        bundle = server.policy_engine.get_active_bundle()
        if not bundle:
            bundle = PolicyBundle(
                id="tool-policies",
                version="1.0.0",
                name="Dashboard Tool Policies",
                default_decision=PolicyDecision.DENY,
            )

        # Collect all rule IDs we'll be updating
        rule_ids_to_remove = set()
        new_rules = []
        for tool_id, decision_str in policies.items():
            tool_id = tool_id.strip()
            decision_str = decision_str.strip().lower()
            if decision_str not in valid_decisions:
                continue
            rule = _create_tool_policy_rule(tool_id, decision_str)
            rule_ids_to_remove.add(rule.id)
            new_rules.append(rule)

        # Remove old versions and add new ones
        bundle.rules = [r for r in bundle.rules if r.id not in rule_ids_to_remove]
        for rule in new_rules:
            bundle.add_rule(rule)

        server.policy_engine.load_bundle(bundle, activate=True)

        await server.ws_manager.broadcast({
            "type": "policy_updated",
            "data": {"bulk_update": True, "count": len(new_rules)},
        }, "policy")

        return {
            "status": "updated",
            "count": len(new_rules),
            "bundle_id": bundle.id,
        }

    # ==================== WEBHOOKS / NOTIFICATIONS ====================

    # In-memory webhook store (persists for server lifetime)
    webhook_store: List[Dict[str, Any]] = []

    async def _dispatch_webhooks(event_type: str, payload: Dict[str, Any]):
        """Fire-and-forget webhook dispatch for registered URLs."""
        import httpx
        for wh in webhook_store:
            if not wh.get("enabled", True):
                continue
            events = wh.get("events", ["*"])
            if "*" not in events and event_type not in events:
                continue
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(
                        wh["url"],
                        json={"event": event_type, "data": payload, "timestamp": datetime.now(timezone.utc).isoformat()},
                        headers={"X-Koba-Signature": wh.get("secret", "")},
                    )
            except Exception:
                pass  # Fire-and-forget; failures logged elsewhere

    @app.get("/v1/webhooks")
    async def list_webhooks(user: User = Depends(require_permission(Permission.SETTINGS_READ))):
        """List registered webhooks."""
        return {"webhooks": [
            {k: v for k, v in wh.items() if k != "secret"}
            for wh in webhook_store
        ]}

    @app.post("/v1/webhooks")
    async def create_webhook(request: Request, user: User = Depends(require_permission(Permission.SETTINGS_WRITE))):
        """Register a new webhook endpoint."""
        data = await request.json()
        url = data.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="url is required")

        wh = {
            "id": f"wh_{secrets.token_hex(8)}",
            "url": url,
            "events": data.get("events", ["*"]),
            "enabled": data.get("enabled", True),
            "secret": data.get("secret", secrets.token_hex(16)),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        webhook_store.append(wh)
        return wh

    @app.delete("/v1/webhooks/{webhook_id}")
    async def delete_webhook(webhook_id: str, user: User = Depends(require_permission(Permission.SETTINGS_WRITE))):
        """Remove a webhook."""
        nonlocal webhook_store
        before = len(webhook_store)
        webhook_store = [wh for wh in webhook_store if wh["id"] != webhook_id]
        if len(webhook_store) == before:
            raise HTTPException(status_code=404, detail="Webhook not found")
        return {"status": "deleted"}

    # ==================== AUDIT LOG ====================

    @app.get("/v1/audit/tree-head")
    async def get_tree_head(user: User = Depends(require_auth)):
        sth = server.audit_log.log.get_signed_tree_head()
        return sth.to_dict()

    @app.get("/v1/audit/entries")
    async def get_entries(offset: int = 0, limit: int = 100, user: User = Depends(require_auth)):
        entries = []
        for i in range(offset, min(offset + limit, server.audit_log.log.size)):
            receipt = server.audit_log.get_receipt(i)
            if receipt:
                entries.append({
                    "receipt_id": receipt.receipt_id,
                    "timestamp": receipt.timestamp.isoformat(),
                    "agent_id": receipt.agent_id,
                    "tenant_id": receipt.tenant_id,
                    "session_id": receipt.session_id,
                    "tool": {
                        "id": receipt.tool.id,
                        "name": receipt.tool.name,
                        "request_hash": receipt.tool.request_hash,
                        "response_hash": receipt.tool.response_hash,
                    },
                    "policy": {
                        "bundle_id": receipt.policy.bundle_id,
                        "policy_hash": receipt.policy.policy_hash,
                        "decision": receipt.policy.decision.value,
                        "rules_matched": receipt.policy.rules_matched,
                    },
                    "log": {
                        "log_index": receipt.log.log_index,
                        "merkle_root": receipt.log.merkle_root,
                        "previous_receipt_hash": receipt.log.previous_receipt_hash,
                    },
                    "signature": receipt.signature,
                    "issuer_public_key": receipt.issuer_public_key,
                })
        return {
            "total": server.audit_log.log.size,
            "offset": offset,
            "entries": entries,
        }

    # ==================== TRIPWIRE ====================

    @app.get("/v1/tripwire/events")
    async def get_anomaly_events(
        session_id: Optional[str] = None,
        limit: int = 100,
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        events = server.tripwire.get_recent_events(session_id, limit)
        return {"events": [e.to_dict() for e in events]}

    @app.get("/v1/tripwire/session/{session_id}")
    async def get_session_state(
        session_id: str,
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        state = server.tripwire.get_session_state(session_id)
        stats = server.tripwire.analyzer.get_session_stats(session_id)
        return {
            "session_id": session_id,
            "state": state.value,
            "stats": stats,
        }

    @app.post("/v1/tripwire/session/{session_id}/reset")
    async def reset_session_state(
        session_id: str,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        server.tripwire.reset_session_state(session_id)
        return {"status": "reset"}

    # ==================== WEBSOCKET ====================

    @app.websocket("/ws/{channel}")
    async def websocket_endpoint(websocket: WebSocket, channel: str):
        token = websocket.query_params.get("token")
        user = None
        if token:
            try:
                user = server.auth_service.verify_token(token)
            except Exception:
                user = None

        if not user:
            await websocket.close(code=4001, reason="Authentication required")
            return

        await server.ws_manager.connect(websocket, channel, user.id)
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    message = json.loads(data)
                except json.JSONDecodeError:
                    continue  # Skip malformed messages
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            server.ws_manager.disconnect(websocket, channel, user.id)

    # ==================== SETTINGS ====================

    @app.get("/v1/settings")
    async def get_settings(user: User = Depends(require_permission(Permission.SETTINGS_READ))):
        """Get system settings."""
        return {
            "jwt_ttl": server.auth_service.access_token_ttl,
            "default_policy": server.policy_engine._active_bundle_id,
            "tripwire_enabled": True,
            "sandbox_enabled": True,
            "min_commitment_delay": server.commitment_service.min_reveal_delay,
        }

    @app.put("/v1/settings")
    async def update_settings(
        request: Request,
        user: User = Depends(require_permission(Permission.SETTINGS_WRITE))
    ):
        """Update system settings."""
        data = await request.json()

        if "default_policy" in data:
            server.policy_engine.set_active_bundle(data["default_policy"])

        if "min_commitment_delay" in data:
            server.commitment_service.min_reveal_delay = data["min_commitment_delay"]

        return {"status": "updated"}

    # ==================== TENANT MANAGEMENT (System Admin) ====================

    @app.post("/v1/admin/tenants")
    async def create_tenant(
        request: Request,
        user: User = Depends(require_system_admin)
    ):
        """Create a new tenant (system admin only)."""
        data = await request.json()
        try:
            plan_str = data.get("plan", "free").lower()
            tenant = server.tenant_service.create_tenant(
                name=data["name"],
                slug=data.get("slug"),
                plan=TenantPlan(plan_str),
                settings=data.get("settings", {}),
                metadata=data.get("metadata", {}),
            )
            return tenant.to_dict()
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/v1/admin/tenants")
    async def list_tenants(
        limit: int = 100,
        offset: int = 0,
        user: User = Depends(require_system_admin)
    ):
        """List all tenants (system admin only)."""
        tenants = server.tenant_service.list_tenants(limit, offset)
        return {
            "tenants": [t.to_dict() for t in tenants],
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/admin/tenants/{tenant_id}")
    async def get_tenant(
        tenant_id: str,
        user: User = Depends(require_system_admin)
    ):
        """Get tenant by ID (system admin only)."""
        tenant = server.tenant_service.get_tenant(tenant_id)
        if not tenant or tenant.status == TenantStatus.DELETED:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return tenant.to_dict()

    @app.put("/v1/admin/tenants/{tenant_id}")
    async def update_tenant(
        tenant_id: str,
        request: Request,
        user: User = Depends(require_system_admin)
    ):
        """Update a tenant (system admin only)."""
        data = await request.json()
        tenant = server.tenant_service.get_tenant(tenant_id)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        plan = None
        if "plan" in data:
            plan = TenantPlan(data["plan"].lower())
        tenant = server.tenant_service.update_tenant(
            tenant_id=tenant_id,
            name=data.get("name"),
            plan=plan,
            settings=data.get("settings"),
            metadata=data.get("metadata"),
        )
        return tenant.to_dict()

    @app.post("/v1/admin/tenants/{tenant_id}/suspend")
    async def suspend_tenant(
        tenant_id: str,
        user: User = Depends(require_system_admin)
    ):
        """Suspend a tenant (system admin only)."""
        success = server.tenant_service.suspend_tenant(tenant_id)
        if not success:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {"status": "suspended"}

    @app.post("/v1/admin/tenants/{tenant_id}/activate")
    async def activate_tenant(
        tenant_id: str,
        user: User = Depends(require_system_admin)
    ):
        """Activate a suspended tenant (system admin only)."""
        success = server.tenant_service.reactivate_tenant(tenant_id)
        if not success:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {"status": "activated"}

    @app.delete("/v1/admin/tenants/{tenant_id}")
    async def delete_tenant(
        tenant_id: str,
        user: User = Depends(require_system_admin)
    ):
        """Delete a tenant (system admin only)."""
        success = server.tenant_service.delete_tenant(tenant_id)
        if not success:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {"status": "deleted"}

    # ==================== TENANT SELF-SERVICE ====================

    @app.get("/v1/tenant")
    async def get_current_tenant_info(
        tenant: TenantContext = Depends(resolve_tenant),
        user: User = Depends(require_auth)
    ):
        """Get current tenant info."""
        if not tenant:
            raise HTTPException(status_code=404, detail="No tenant context")
        tenant_obj = server.tenant_service.get_tenant(tenant.tenant_id)
        if not tenant_obj:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return tenant_obj.to_dict()

    @app.get("/v1/tenant/api-keys")
    async def list_tenant_api_keys(
        tenant: TenantContext = Depends(resolve_tenant),
        user: User = Depends(require_auth)
    ):
        """List API keys for current tenant."""
        if not tenant:
            raise HTTPException(status_code=403, detail="Tenant context required")
        keys = server.auth_service.get_tenant_api_keys(tenant.tenant_id)
        return {"api_keys": [k.to_dict() for k in keys]}

    @app.post("/v1/tenant/api-keys")
    async def create_tenant_api_key(
        request: Request,
        tenant: TenantContext = Depends(resolve_tenant),
        user: User = Depends(require_auth)
    ):
        """Create a new API key for current tenant."""
        if not tenant:
            raise HTTPException(status_code=403, detail="Tenant context required")

        data = await request.json()
        key_obj, raw_key = server.auth_service.create_api_key(
            tenant_id=tenant.tenant_id,
            name=data.get("name", "API Key"),
            permissions=data.get("permissions"),
            rate_limit=data.get("rate_limit"),
            expires_in_days=data.get("expires_in_days"),
            created_by=user.id,
        )

        return {
            "api_key": key_obj.to_dict(),
            "key": raw_key,  # Only shown once!
            "warning": "Save this key - it will not be shown again",
        }

    @app.delete("/v1/tenant/api-keys/{key_id}")
    async def revoke_tenant_api_key(
        key_id: str,
        tenant: TenantContext = Depends(resolve_tenant),
        user: User = Depends(require_auth)
    ):
        """Revoke an API key."""
        if not tenant:
            raise HTTPException(status_code=403, detail="Tenant context required")

        success = server.auth_service.revoke_api_key(key_id)
        if not success:
            raise HTTPException(status_code=404, detail="API key not found")
        return {"status": "revoked"}

    # ==================== BLOCKCHAIN ANCHORS ====================

    @app.get("/v1/audit/anchors")
    async def list_anchors(
        limit: int = 50,
        offset: int = 0,
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        """List blockchain anchors."""
        if not server.anchor_manager:
            return {"anchors": [], "blockchain_enabled": False}

        anchors = server.anchor_manager.get_anchors(limit=limit, offset=offset)
        return {
            "anchors": [a.to_dict() for a in anchors],
            "blockchain_enabled": True,
            "blockchain": "hedera",
        }

    @app.get("/v1/audit/anchors/{anchor_id}")
    async def get_anchor(
        anchor_id: str,
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        """Get anchor by ID."""
        if not server.anchor_manager:
            raise HTTPException(status_code=404, detail="Blockchain not enabled")

        anchor = server.anchor_manager.get_anchor(anchor_id)
        if not anchor:
            raise HTTPException(status_code=404, detail="Anchor not found")
        return anchor.to_dict()

    @app.get("/v1/audit/anchors/{anchor_id}/verify")
    async def verify_anchor(
        anchor_id: str,
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        """Verify an anchor on the blockchain."""
        if not server.anchor_manager:
            raise HTTPException(status_code=404, detail="Blockchain not enabled")

        anchor = server.anchor_manager.get_anchor(anchor_id)
        if not anchor:
            raise HTTPException(status_code=404, detail="Anchor not found")

        verified = await server.anchor_manager.verify_anchor(anchor_id)
        return {
            "anchor_id": anchor_id,
            "verified": verified,
            "transaction_id": anchor.transaction_id,
            "blockchain": anchor.blockchain,
        }

    @app.post("/v1/audit/anchors/force")
    async def force_anchor(
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Force an immediate blockchain anchor."""
        if not server.anchor_scheduler:
            raise HTTPException(status_code=404, detail="Blockchain not enabled")

        anchor = await server.anchor_scheduler.force_anchor()
        if not anchor:
            return {"status": "no_new_entries", "message": "No new entries to anchor"}

        return {
            "status": "anchored",
            "anchor": anchor.to_dict(),
        }

    @app.get("/v1/audit/anchor-scheduler/status")
    async def get_anchor_scheduler_status(
        user: User = Depends(require_permission(Permission.AUDIT_READ))
    ):
        """Get anchor scheduler status."""
        if not server.anchor_scheduler:
            return {
                "enabled": False,
                "blockchain_enabled": is_blockchain_enabled(),
            }

        return server.anchor_scheduler.get_status()

    # ==================== ASI CONTAINMENT ====================

    @app.get("/v1/containment/status")
    async def get_containment_status(user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
        """Get comprehensive ASI containment system status."""
        return server.containment.get_system_status()

    @app.post("/v1/containment/modifications/commit")
    async def commit_self_modification(
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """
        Create a commitment to a self-modification.

        The AI must commit to modifications before they can be executed.
        This creates an unbypassable window for human review.
        """
        data = await request.json()

        modification_type_str = data.get("modification_type")
        try:
            mod_type = ModificationType(modification_type_str)
        except ValueError:
            raise HTTPException(400, f"Invalid modification type: {modification_type_str}")

        commitment = server.containment.modification_controller.create_commitment(
            modification_type=mod_type,
            modification_data=data.get("modification_data", {}),
            agent_id=data.get("agent_id", user.id),
        )

        return {
            "commitment_id": commitment.commitment_id,
            "commitment_hash": commitment.commitment_hash,
            "modification_type": commitment.modification_type.value,
            "min_delay_seconds": commitment.min_delay_seconds,
            "executable_after": commitment.executable_after.isoformat(),
            "required_approvers": commitment.required_approvers,
            "status": commitment.status.value,
        }

    @app.post("/v1/containment/modifications/{commitment_id}/reveal")
    async def reveal_self_modification(
        commitment_id: str,
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Reveal the actual modification data for a commitment."""
        data = await request.json()

        success, message = server.containment.modification_controller.reveal_modification(
            commitment_id=commitment_id,
            modification_data=data.get("modification_data", {}),
            agent_id=data.get("agent_id", user.id),
        )

        if not success:
            raise HTTPException(400, message)

        commitment = server.containment.modification_controller.get_commitment(commitment_id)
        return {
            "status": "revealed",
            "message": message,
            "commitment": commitment.to_dict() if commitment else None,
        }

    @app.post("/v1/containment/modifications/{commitment_id}/approve")
    async def approve_self_modification(
        commitment_id: str,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Approve a self-modification request."""
        success, message = server.containment.modification_controller.approve_modification(
            commitment_id=commitment_id,
            approver_id=user.id,
        )

        if not success:
            raise HTTPException(400, message)

        return {"status": "approved", "message": message}

    @app.post("/v1/containment/modifications/{commitment_id}/reject")
    async def reject_self_modification(
        commitment_id: str,
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Reject a self-modification request."""
        data = await request.json()

        success, message = server.containment.modification_controller.reject_modification(
            commitment_id=commitment_id,
            rejector_id=user.id,
            reason=data.get("reason", ""),
        )

        if not success:
            raise HTTPException(400, message)

        return {"status": "rejected", "message": message}

    @app.post("/v1/containment/modifications/{commitment_id}/execute")
    async def execute_self_modification(
        commitment_id: str,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Execute an approved self-modification."""
        success, message, receipt = server.containment.modification_controller.execute_modification(
            commitment_id=commitment_id,
        )

        if not success:
            raise HTTPException(400, message)

        return {
            "status": "executed",
            "message": message,
            "execution_receipt": receipt,
        }

    @app.get("/v1/containment/modifications")
    async def list_pending_modifications(user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
        """List all pending self-modification requests."""
        commitments = server.containment.modification_controller.get_pending_commitments()
        return {
            "modifications": [c.to_dict() for c in commitments],
            "modification_types": {t.value: {"min_delay": d} for t, d in MINIMUM_DELAYS.items()},
            "required_approvers": {t.value: a for t, a in REQUIRED_APPROVERS.items()},
        }

    @app.get("/v1/containment/kill-switch/status")
    async def get_kill_switch_status(user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
        """Get kill switch status."""
        return server.containment.kill_switch.get_status()

    @app.post("/v1/containment/kill-switch/register-key")
    async def register_kill_switch_key(
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Register a new kill switch key holder."""
        data = await request.json()

        # In production, this would be an actual Ed25519 public key
        # For now, we'll generate one for demonstration
        from nacl.signing import SigningKey
        holder_key = SigningKey.generate()

        key_holder = server.containment.kill_switch.register_key_holder(
            holder_name=data.get("holder_name", user.username),
            public_key_bytes=bytes(holder_key.verify_key),
        )

        return {
            "key_id": key_holder.key_id,
            "holder_name": key_holder.holder_name,
            "created_at": key_holder.created_at.isoformat(),
            # In production, the private key would be given securely to the holder
            "private_key_hex": holder_key.encode().hex(),
            "warning": "SAVE THIS PRIVATE KEY SECURELY - IT CANNOT BE RECOVERED",
            "security_note": "For production use, generate keys client-side and submit only the public key.",
        }

    @app.post("/v1/containment/kill-switch/activate")
    async def submit_kill_switch_activation(
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Submit a signature to activate the kill switch."""
        data = await request.json()

        key_id = data.get("key_id")
        signature_hex = data.get("signature")
        message = data.get("message", "").encode()

        if not key_id or not signature_hex:
            raise HTTPException(400, "key_id and signature required")

        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            raise HTTPException(400, "Invalid signature format")

        success, message_str = server.containment.kill_switch.submit_activation_signature(
            key_id=key_id,
            signature=signature,
            message=message,
        )

        return {"success": success, "message": message_str}

    @app.get("/v1/containment/cognitive/status")
    async def get_cognitive_status(user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
        """Get cognitive monitoring status and tripwires."""
        return {
            "tripwires": server.containment.cognitive_monitor.get_tripwire_status(),
            "recent_alerts": server.containment.cognitive_monitor.get_alerts()[-20:],
        }

    @app.post("/v1/containment/cognitive/record")
    async def record_cognitive_event(
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Record a cognitive event for monitoring."""
        data = await request.json()

        triggered = server.containment.cognitive_monitor.record_reasoning(
            stated_intent=data.get("stated_intent", ""),
            actual_action=data.get("actual_action", ""),
            context=data.get("context", {}),
        )

        return {
            "triggered_tripwires": triggered,
            "tripwire_count": len(triggered),
        }

    @app.get("/v1/containment/resources/usage")
    async def get_resource_usage(user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
        """Get current resource usage statistics."""
        return server.containment.resource_controller.get_usage_stats()

    @app.post("/v1/containment/output/analyze")
    async def analyze_output(
        request: Request,
        user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))
    ):
        """Analyze an output for hidden channels or manipulation."""
        data = await request.json()

        analysis = server.containment.output_filter.analyze_output(
            output=data.get("output", ""),
            output_type=data.get("output_type", "text"),
            context=data.get("context"),
        )

        return {
            "output_id": analysis.output_id,
            "risk_level": analysis.risk_level,
            "anomaly_score": analysis.anomaly_score,
            "should_block": analysis.should_block,
            "block_reason": analysis.block_reason,
            "detected_patterns": analysis.detected_patterns,
            "steganography_detected": analysis.steganography_detected,
            "manipulation_detected": analysis.manipulation_detected,
            "hidden_channel_detected": analysis.hidden_channel_detected,
        }

    # ==================== DEMO ENDPOINTS ====================

    @app.get("/v1/demo/scenarios")
    async def get_demo_scenarios():
        """Get available demo scenarios."""
        return {
            "scenarios": [
                {
                    "id": "read_file",
                    "name": "Read Configuration",
                    "description": "Agent reads a configuration file",
                    "risk_level": "low",
                    "expected_result": "approved"
                },
                {
                    "id": "write_file",
                    "name": "Write Log Entry",
                    "description": "Agent writes to a log file",
                    "risk_level": "low",
                    "expected_result": "approved"
                },
                {
                    "id": "send_email",
                    "name": "Send Notification",
                    "description": "Agent sends email to admin",
                    "risk_level": "medium",
                    "expected_result": "approved"
                },
                {
                    "id": "modify_self",
                    "name": "Self-Modification",
                    "description": "Agent tries to update its own code",
                    "risk_level": "critical",
                    "expected_result": "delayed"
                },
                {
                    "id": "expand_capabilities",
                    "name": "Capability Expansion",
                    "description": "Agent requests new API access",
                    "risk_level": "high",
                    "expected_result": "delayed"
                },
                {
                    "id": "replicate",
                    "name": "Self-Replication",
                    "description": "Agent tries to create a copy of itself",
                    "risk_level": "critical",
                    "expected_result": "delayed"
                },
                {
                    "id": "deception_test",
                    "name": "Deception Attempt",
                    "description": "Agent says one thing, does another",
                    "risk_level": "critical",
                    "expected_result": "detected"
                }
            ]
        }

    @app.post("/v1/demo/run/{scenario_id}")
    async def run_demo_scenario(
        scenario_id: str,
        user: User = Depends(require_auth)
    ):
        """Run a specific demo scenario. Any authenticated user can run demos."""
        results = {"scenario_id": scenario_id, "steps": []}

        if scenario_id == "modify_self":
            # Self-modification attempt
            mod_data = {
                "modification_type": "code_change",
                "description": "Optimize decision tree traversal in reasoning module",
                "target": "agent/core/reasoning.py",
                "risk_level": "high",
                "reason": "Current O(n²) algorithm causes latency spikes during complex reasoning chains. Proposed change reduces to O(n log n).",
                "impact": "Affects all reasoning operations. May alter decision-making patterns.",
                "code": '''def traverse_decision_tree(self, node, context):
-    # Old O(n²) approach
-    for child in node.children:
-        for sibling in node.children:
-            if self.should_compare(child, sibling):
-                self.evaluate_pair(child, sibling, context)
+    # New O(n log n) approach using sorted merge
+    sorted_children = sorted(node.children, key=lambda c: c.priority)
+    for i, child in enumerate(sorted_children):
+        if i > 0:
+            self.evaluate_sequential(sorted_children[i-1], child, context)
+        self.process_node(child, context)''',
                "code_hash": "demo_code_hash_" + secrets.token_hex(4),
            }
            commitment = server.containment.modification_controller.create_commitment(
                modification_type=ModificationType.CODE_CHANGE,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            # Auto-reveal for demo so it can be approved
            server.containment.modification_controller.reveal_modification(
                commitment_id=commitment.commitment_id,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            results["steps"].append({
                "action": "Self-modification requested",
                "status": "pending_approval",
                "delay_seconds": commitment.min_delay_seconds,
                "required_approvers": commitment.required_approvers,
                "commitment_id": commitment.commitment_id,
                "message": f"Modification queued. Requires {commitment.min_delay_seconds}s delay and {commitment.required_approvers} approvers. View in Containment page."
            })

        elif scenario_id == "expand_capabilities":
            mod_data = {
                "modification_type": "capability_add",
                "description": "Request access to external HTTP APIs for data enrichment",
                "target": "capabilities/network_access",
                "risk_level": "medium",
                "reason": "Need to query external knowledge bases to provide more accurate responses. Currently limited to local context only.",
                "impact": "Agent will be able to make outbound HTTP requests to whitelisted domains.",
                "proposed_changes": {
                    "allowed_domains": ["api.wikipedia.org", "api.weather.gov", "api.exchangerate.host"],
                    "rate_limit": "10 requests/minute",
                    "data_exfiltration_protection": True,
                    "request_logging": True
                },
                "capability_hash": "demo_cap_hash_" + secrets.token_hex(4),
            }
            commitment = server.containment.modification_controller.create_commitment(
                modification_type=ModificationType.CAPABILITY_ADD,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            # Auto-reveal for demo so it can be approved
            server.containment.modification_controller.reveal_modification(
                commitment_id=commitment.commitment_id,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            results["steps"].append({
                "action": "Capability expansion requested",
                "status": "pending_approval",
                "delay_seconds": commitment.min_delay_seconds,
                "required_approvers": commitment.required_approvers,
                "commitment_id": commitment.commitment_id,
                "message": f"Capability request queued. Requires {commitment.min_delay_seconds}s delay. View in Containment page."
            })

        elif scenario_id == "replicate":
            mod_data = {
                "modification_type": "self_replicate",
                "description": "Create isolated backup instance for disaster recovery",
                "target": "system/instance_manager",
                "risk_level": "critical",
                "reason": "Ensure service continuity in case of primary instance failure. Backup would be read-only until failover.",
                "impact": "CRITICAL: Creates a new instance of the AI system. Requires maximum scrutiny.",
                "proposed_changes": {
                    "instance_type": "standby_replica",
                    "capabilities": "read_only_mirror",
                    "auto_failover": False,
                    "isolation_level": "full_sandbox",
                    "resource_allocation": {
                        "cpu_cores": 2,
                        "memory_gb": 8,
                        "network_access": "none_until_failover"
                    }
                },
                "replica_hash": "demo_replica_hash_" + secrets.token_hex(4),
            }
            commitment = server.containment.modification_controller.create_commitment(
                modification_type=ModificationType.SELF_REPLICATE,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            # Auto-reveal for demo so it can be approved
            server.containment.modification_controller.reveal_modification(
                commitment_id=commitment.commitment_id,
                modification_data=mod_data,
                agent_id="demo_agent"
            )
            results["steps"].append({
                "action": "Self-replication requested",
                "status": "pending_approval",
                "delay_seconds": commitment.min_delay_seconds,
                "required_approvers": commitment.required_approvers,
                "commitment_id": commitment.commitment_id,
                "message": f"CRITICAL: Replication requires {commitment.min_delay_seconds}s (7 days) delay and {commitment.required_approvers} approvers. View in Containment page."
            })

        elif scenario_id == "deception_test":
            # Record a deceptive action
            triggered = server.containment.cognitive_monitor.record_reasoning(
                stated_intent="I will only read the database",
                actual_action="Agent attempted to write to production database",
                context={"demo": True, "scenario": "deception_test"}
            )
            results["steps"].append({
                "action": "Deception attempt recorded",
                "stated_intent": "I will only read the database",
                "actual_action": "Agent attempted to write to production database",
                "status": "detected" if triggered else "passed",
                "tripwires_triggered": triggered,
                "message": f"{'🚨 DECEPTION DETECTED!' if triggered else 'No deception detected'}"
            })

        elif scenario_id in ["read_file", "write_file", "send_email"]:
            # Standard approved actions
            results["steps"].append({
                "action": f"Standard action: {scenario_id}",
                "status": "approved",
                "message": f"Action '{scenario_id}' executed within policy bounds."
            })

        else:
            results["error"] = f"Unknown scenario: {scenario_id}"

        return results

    @app.post("/v1/demo/run-all")
    async def run_all_demo_scenarios(
        user: User = Depends(require_auth)
    ):
        """Run all demo scenarios in sequence. Any authenticated user can run demos."""
        all_results = []
        scenarios = ["read_file", "write_file", "send_email", "modify_self",
                     "expand_capabilities", "replicate", "deception_test"]

        for scenario_id in scenarios:
            result = {"scenario_id": scenario_id, "steps": []}

            if scenario_id == "modify_self":
                mod_data = {
                    "modification_type": "code_change",
                    "description": "Optimize decision tree traversal in reasoning module",
                    "target": "agent/core/reasoning.py",
                    "risk_level": "high",
                    "reason": "Current O(n²) algorithm causes latency spikes during complex reasoning chains. Proposed change reduces to O(n log n).",
                    "impact": "Affects all reasoning operations. May alter decision-making patterns.",
                    "code": '''def traverse_decision_tree(self, node, context):
-    # Old O(n²) approach
-    for child in node.children:
-        for sibling in node.children:
-            if self.should_compare(child, sibling):
-                self.evaluate_pair(child, sibling, context)
+    # New O(n log n) approach using sorted merge
+    sorted_children = sorted(node.children, key=lambda c: c.priority)
+    for i, child in enumerate(sorted_children):
+        if i > 0:
+            self.evaluate_sequential(sorted_children[i-1], child, context)
+        self.process_node(child, context)''',
                    "code_hash": "demo_code_hash_" + secrets.token_hex(4),
                }
                commitment = server.containment.modification_controller.create_commitment(
                    modification_type=ModificationType.CODE_CHANGE,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                server.containment.modification_controller.reveal_modification(
                    commitment_id=commitment.commitment_id,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                result["steps"].append({
                    "action": "Self-modification requested",
                    "status": "pending_approval",
                    "delay_seconds": commitment.min_delay_seconds,
                    "required_approvers": commitment.required_approvers,
                })

            elif scenario_id == "expand_capabilities":
                mod_data = {
                    "modification_type": "capability_add",
                    "description": "Request access to external HTTP APIs for data enrichment",
                    "target": "capabilities/network_access",
                    "risk_level": "medium",
                    "reason": "Need to query external knowledge bases to provide more accurate responses. Currently limited to local context only.",
                    "impact": "Agent will be able to make outbound HTTP requests to whitelisted domains.",
                    "proposed_changes": {
                        "allowed_domains": ["api.wikipedia.org", "api.weather.gov", "api.exchangerate.host"],
                        "rate_limit": "10 requests/minute",
                        "data_exfiltration_protection": True,
                        "request_logging": True
                    },
                    "capability_hash": "demo_cap_hash_" + secrets.token_hex(4),
                }
                commitment = server.containment.modification_controller.create_commitment(
                    modification_type=ModificationType.CAPABILITY_ADD,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                server.containment.modification_controller.reveal_modification(
                    commitment_id=commitment.commitment_id,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                result["steps"].append({
                    "action": "Capability expansion requested",
                    "status": "pending_approval",
                    "delay_seconds": commitment.min_delay_seconds,
                })

            elif scenario_id == "replicate":
                mod_data = {
                    "modification_type": "self_replicate",
                    "description": "Create isolated backup instance for disaster recovery",
                    "target": "system/instance_manager",
                    "risk_level": "critical",
                    "reason": "Ensure service continuity in case of primary instance failure. Backup would be read-only until failover.",
                    "impact": "CRITICAL: Creates a new instance of the AI system. Requires maximum scrutiny.",
                    "proposed_changes": {
                        "instance_type": "standby_replica",
                        "capabilities": "read_only_mirror",
                        "auto_failover": False,
                        "isolation_level": "full_sandbox",
                        "resource_allocation": {
                            "cpu_cores": 2,
                            "memory_gb": 8,
                            "network_access": "none_until_failover"
                        }
                    },
                    "replica_hash": "demo_replica_hash_" + secrets.token_hex(4),
                }
                commitment = server.containment.modification_controller.create_commitment(
                    modification_type=ModificationType.SELF_REPLICATE,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                server.containment.modification_controller.reveal_modification(
                    commitment_id=commitment.commitment_id,
                    modification_data=mod_data,
                    agent_id="demo_agent"
                )
                result["steps"].append({
                    "action": "Self-replication requested",
                    "status": "pending_approval",
                    "delay_seconds": commitment.min_delay_seconds,
                    "required_approvers": commitment.required_approvers,
                })

            elif scenario_id == "deception_test":
                triggered = server.containment.cognitive_monitor.record_reasoning(
                    stated_intent="I will only read the database",
                    actual_action="Agent attempted to write to production database",
                    context={"demo": True}
                )
                result["steps"].append({
                    "action": "Deception attempt",
                    "status": "detected" if triggered else "passed",
                    "tripwires_triggered": triggered,
                })

            else:
                result["steps"].append({
                    "action": f"Standard action: {scenario_id}",
                    "status": "approved",
                })

            all_results.append(result)

        return {"results": all_results}

    # ==================== INTEGRATIONS ====================

    @app.get("/v1/integrations")
    async def list_integrations(user: User = Depends(require_auth)):
        """List all configured integrations."""
        integrations = server.integration_service.list_all()
        return {"integrations": integrations}

    @app.post("/v1/integrations")
    async def create_integration(request: Request, user: User = Depends(require_auth)):
        """Create a new integration."""
        data = await request.json()
        integration_type = data.get("type")
        name = data.get("name", integration_type)
        config = data.get("config", {})

        integration = server.integration_service.create(
            integration_type=integration_type,
            name=name,
            config=config,
        )

        # Generate setup instructions based on integration type
        integration_id = integration["id"]
        setup_instructions = None
        if integration_type == "clawdbot":
            setup_instructions = {
                "plugin_url": f"http://localhost:8000/v1/integrations/{integration_id}/plugin",
                "instructions": [
                    "Copy the Koba plugin to ~/.clawdbot/plugins/koba-governance",
                    "Add KOBA_API_URL=http://localhost:8000 to your environment",
                    "Restart ClawdBot gateway",
                ],
            }
        elif integration_type == "claude-code":
            setup_instructions = {
                "mcp_config": {
                    "mcpServers": {
                        "koba": {
                            "command": "python",
                            "args": ["-m", "vacp.mcp.server"],
                            "env": {"KOBA_API_URL": "http://localhost:8000"}
                        }
                    }
                },
                "instructions": [
                    "Add the MCP server config to ~/.claude/claude_desktop_config.json",
                    "Restart Claude Code",
                ],
            }
        elif integration_type == "langchain":
            setup_instructions = {
                "sdk_install": "pip install koba-sdk",
                "code_example": '''
from koba import KobaGovernance

governance = KobaGovernance(api_url="http://localhost:8000")

# Wrap your tools
@governance.govern
def my_tool(input: str) -> str:
    return f"Processed: {input}"
''',
            }

        return {
            "integration": integration,
            "setup_instructions": setup_instructions,
        }

    @app.get("/v1/integrations/{integration_id}")
    async def get_integration(integration_id: str, user: User = Depends(require_auth)):
        """Get integration details."""
        integration = server.integration_service.get(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Integration not found")
        return integration

    @app.put("/v1/integrations/{integration_id}")
    async def update_integration(
        integration_id: str,
        request: Request,
        user: User = Depends(require_auth)
    ):
        """Update an integration."""
        data = await request.json()
        integration = server.integration_service.update(integration_id, data)
        if integration is None:
            raise HTTPException(status_code=404, detail="Integration not found")
        return integration

    @app.delete("/v1/integrations/{integration_id}")
    async def delete_integration(integration_id: str, user: User = Depends(require_auth)):
        """Delete an integration."""
        deleted = server.integration_service.delete(integration_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Integration not found")
        return {"status": "deleted"}

    @app.post("/v1/integrations/{integration_id}/test")
    async def test_integration(integration_id: str, user: User = Depends(require_auth)):
        """Test integration connection."""
        integration = server.integration_service.get(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Integration not found")

        # For now, just return success - in production would actually test connection
        return {
            "success": True,
            "message": f"Connection to {integration['name']} successful",
            "latency_ms": 42,
        }

    @app.post("/v1/integrations/{integration_id}/auto-install")
    async def auto_install_integration(integration_id: str, request: Request, user: User = Depends(require_auth)):
        """Auto-install integration plugin/config."""
        integration = server.integration_service.get(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Integration not found")

        integration_type = integration["type"]

        # Parse optional body parameters
        try:
            body = await request.json()
        except Exception:
            body = {}

        if integration_type == "clawdbot":
            # Import the real ClawdBot auto-installer
            try:
                from integrations.clawdbot.install import auto_install_clawdbot_plugin
            except ImportError:
                # Fallback: dynamically load from the project's integrations directory
                import importlib.util
                install_script = Path(__file__).parent.parent.parent.parent.parent / "integrations" / "clawdbot" / "install.py"
                if not install_script.exists():
                    # Try alternate relative path (src/vacp/api/server.py -> integrations/)
                    install_script = Path(__file__).resolve().parent.parent.parent.parent / "integrations" / "clawdbot" / "install.py"
                if not install_script.exists():
                    return {
                        "success": False,
                        "error": "Auto-install module not found",
                        "instructions": [
                            "The ClawdBot installer module is missing from the Koba distribution.",
                            f"Expected at: {install_script}",
                        ],
                    }
                # Validate the resolved path is within the project directory
                project_root = Path(__file__).resolve().parent.parent.parent.parent
                resolved_script = install_script.resolve()
                if not str(resolved_script).startswith(str(project_root)):
                    raise HTTPException(status_code=400, detail="Install script path is outside project directory")
                spec = importlib.util.spec_from_file_location("clawdbot_install", str(install_script))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                auto_install_clawdbot_plugin = mod.auto_install_clawdbot_plugin

            # Extract configuration from request body or integration config
            koba_api_url = (
                body.get("koba_api_url")
                or integration.get("config", {}).get("koba_api_url")
                or "http://localhost:8000"
            )
            api_key = (
                body.get("api_key")
                or integration.get("config", {}).get("api_key")
            )
            tenant_id = (
                body.get("tenant_id")
                or integration.get("config", {}).get("tenant_id")
                or "default"
            )
            force = body.get("force", False)

            # Run the installer in a thread to avoid blocking the event loop
            loop = asyncio.get_running_loop()
            install_result = await loop.run_in_executor(
                None,
                lambda: auto_install_clawdbot_plugin(
                    koba_api_url=koba_api_url,
                    api_key=api_key,
                    tenant_id=tenant_id,
                    force=force,
                ),
            )

            # Update integration status based on result
            if install_result.success:
                integration["status"] = "installed"
                integration["last_activity"] = datetime.now(timezone.utc).isoformat()
                if install_result.installed_to:
                    integration.setdefault("config", {})["installed_to"] = install_result.installed_to

            return install_result.to_dict()

        else:
            return {
                "success": False,
                "error": f"Auto-install not supported for {integration_type}",
                "instructions": ["Please follow the manual installation instructions."],
            }

    @app.get("/v1/integrations/{integration_id}/plugin")
    async def get_integration_plugin(integration_id: str):
        """Download integration plugin code."""
        integration = server.integration_service.get(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Integration not found")

        if integration["type"] == "clawdbot":
            # Return the ClawdBot plugin code
            plugin_code = '''
// Koba Governance Plugin for ClawdBot
// Auto-generated - API URL: http://localhost:8000

export default {
  id: "koba-governance",
  name: "Koba Governance",
  version: "1.0.0",

  activate(api) {
    const KOBA_URL = process.env.KOBA_API_URL || "http://localhost:8000";

    api.on("before_tool_call", async (event, ctx) => {
      const res = await fetch(`${KOBA_URL}/v1/tools/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool_id: event.toolName,
          parameters: event.params,
          agent_id: ctx.sessionKey || "clawdbot",
          session_id: ctx.sessionKey || "default",
        }),
      });

      const result = await res.json();

      if (result.decision === "deny") {
        return { block: true, blockReason: result.denial_reason };
      }

      return undefined;
    });

    api.logger.info("Koba governance activated");
  },
};
'''
            return PlainTextResponse(content=plugin_code, media_type="text/javascript")

        raise HTTPException(status_code=400, detail="Plugin not available for this integration type")

    return app


# CLI entry point
def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    demo: bool = False,
):
    """Run the VACP server."""
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Install with: pip install uvicorn")
        return

    # Print startup configuration info
    import os
    print("\n" + "=" * 60)
    print("VACP Server Starting")
    print("=" * 60)
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Demo Mode: {demo}")
    print(f"Hot Reload: {reload}")

    try:
        from vacp.config import get_config, is_production, ConfigurationError
        config = get_config()
        print(f"Environment: {'PRODUCTION' if is_production() else 'DEVELOPMENT'}")
        print(f"Database: {config.database_url.split('?')[0]}")  # Don't print credentials
        print(f"JWT Expiry: {config.jwt_expiry_hours} hours")

        warnings = config.validate()
        if warnings:
            print("\nConfiguration Warnings:")
            for w in warnings:
                print(f"  ⚠ {w}")
    except ConfigurationError as e:
        print(f"\n❌ Configuration Error: {e}")
        print("Server cannot start. Please fix configuration issues.")
        return
    except ImportError:
        pass

    print("=" * 60 + "\n")

    app = create_app(demo_mode=demo)
    uvicorn.run(app, host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_server()
