"""
Blockchain Anchoring Service

Provides immutable timestamping and anchoring of Merkle tree heads
to external blockchain systems. Supported backends:

1. Hedera Consensus Service (HCS) - Primary, enterprise-grade
2. Ethereum (via smart contract) - Alternative
3. Local timestamping - Fallback for development/testing

The anchoring provides:
- Immutable proof of existence at a specific time
- Third-party verification independent of VACP
- Compliance with audit requirements (SOC 2, HIPAA)
- Tamper-evident audit trails
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# HTTP clients
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    import urllib.request
    import urllib.error

# Hedera SDK
try:
    from hedera import (
        Client,
        AccountId,
        PrivateKey,
        TopicId,
        TopicMessageSubmitTransaction,
        TopicCreateTransaction,
        TransactionId,
    )
    HEDERA_SDK_AVAILABLE = True
except ImportError:
    HEDERA_SDK_AVAILABLE = False

# Web3 for Ethereum
try:
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

from .database import (
    DatabaseManager, BlockchainAnchorModel, BlockchainAnchor,
    generate_id, get_db, SQLALCHEMY_AVAILABLE
)
from .merkle import SignedTreeHead
from .crypto import KeyPair, sign_message, verify_signature

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Status
# ============================================================================

class AnchorStatus(Enum):
    """Status of an anchoring operation."""
    PENDING = "pending"
    SUBMITTED = "submitted"
    CONFIRMED = "confirmed"
    FAILED = "failed"


class AnchorNetwork(Enum):
    """Supported blockchain networks."""
    HEDERA_MAINNET = "hedera-mainnet"
    HEDERA_TESTNET = "hedera-testnet"
    HEDERA_PREVIEWNET = "hedera-previewnet"
    ETHEREUM_MAINNET = "ethereum-mainnet"
    ETHEREUM_SEPOLIA = "ethereum-sepolia"
    ETHEREUM_GOERLI = "ethereum-goerli"
    LOCAL = "local"


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class HederaConfig:
    """Configuration for Hedera network."""
    operator_id: str = ""  # e.g., "0.0.12345"
    operator_key: str = ""  # Private key in DER hex format
    topic_id: str = ""  # e.g., "0.0.67890"
    network: str = "testnet"  # testnet, mainnet, previewnet

    # Relay URL for SDK-less operation
    relay_url: str = ""

    # Mirror node URLs
    mirror_urls: Dict[str, str] = field(default_factory=lambda: {
        "testnet": "https://testnet.mirrornode.hedera.com",
        "mainnet": "https://mainnet-public.mirrornode.hedera.com",
        "previewnet": "https://previewnet.mirrornode.hedera.com",
    })

    # Connection settings
    timeout_seconds: int = 30
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "HederaConfig":
        """Load configuration from environment variables."""
        return cls(
            operator_id=os.getenv("HEDERA_OPERATOR_ID", ""),
            operator_key=os.getenv("HEDERA_OPERATOR_KEY", ""),
            topic_id=os.getenv("HEDERA_TOPIC_ID", ""),
            network=os.getenv("HEDERA_NETWORK", "testnet"),
            relay_url=os.getenv("HEDERA_RELAY_URL", ""),
        )

    @property
    def mirror_url(self) -> str:
        return self.mirror_urls.get(self.network, self.mirror_urls["testnet"])

    def is_configured(self) -> bool:
        """Check if all required fields are configured."""
        return bool(self.operator_id and self.operator_key and self.topic_id)

    def is_sdk_available(self) -> bool:
        """Check if Hedera SDK is available."""
        return HEDERA_SDK_AVAILABLE and self.is_configured()


@dataclass
class EthereumConfig:
    """Configuration for Ethereum network."""
    rpc_url: str = ""
    private_key: str = ""
    contract_address: str = ""  # Optional anchor contract
    chain_id: int = 1  # 1=mainnet, 5=goerli, 11155111=sepolia

    # Gas settings
    gas_limit: int = 100000
    max_fee_per_gas: Optional[int] = None  # wei
    max_priority_fee: Optional[int] = None  # wei

    @classmethod
    def from_env(cls) -> "EthereumConfig":
        """Load configuration from environment variables."""
        return cls(
            rpc_url=os.getenv("ETHEREUM_RPC_URL", ""),
            private_key=os.getenv("ETHEREUM_PRIVATE_KEY", ""),
            contract_address=os.getenv("ETHEREUM_CONTRACT_ADDRESS", ""),
            chain_id=int(os.getenv("ETHEREUM_CHAIN_ID", "1")),
        )

    def is_configured(self) -> bool:
        """Check if required fields are configured."""
        return bool(self.rpc_url and self.private_key)


# ============================================================================
# Anchor Data Structures
# ============================================================================

@dataclass
class AnchorData:
    """Data to be anchored on blockchain."""
    tree_size: int
    merkle_root: str
    tree_head_signature: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_message(self) -> bytes:
        """Convert to message bytes for blockchain."""
        payload = {
            "type": "koba_merkle_anchor",
            "version": "1.0",
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "signature": self.tree_head_signature,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    @classmethod
    def from_message(cls, message: bytes) -> "AnchorData":
        """Parse from blockchain message."""
        payload = json.loads(message.decode("utf-8"))
        return cls(
            tree_size=payload["tree_size"],
            merkle_root=payload["merkle_root"],
            tree_head_signature=payload["signature"],
            timestamp=datetime.fromisoformat(payload["timestamp"]),
            metadata=payload.get("metadata", {}),
        )

    @classmethod
    def from_signed_tree_head(cls, sth: SignedTreeHead) -> "AnchorData":
        """Create from a SignedTreeHead."""
        return cls(
            tree_size=sth.tree_size,
            merkle_root=sth.root_hash.hex() if isinstance(sth.root_hash, bytes) else sth.root_hash,
            tree_head_signature=sth.signature or "",
            timestamp=sth.timestamp,
            metadata={"signer": sth.signer_public_key} if sth.signer_public_key else {},
        )


@dataclass
class AnchorRecord:
    """
    Complete record of an anchoring operation.

    Contains all information needed to verify the anchor independently.
    """
    # Identification
    anchor_id: str

    # Tree head information
    tree_size: int
    merkle_root: str
    tree_head_signature: str
    tree_head_timestamp: datetime

    # Anchoring information
    anchor_network: str
    anchor_timestamp: Optional[datetime] = None

    # Network-specific details
    transaction_id: Optional[str] = None
    topic_id: Optional[str] = None  # Hedera
    contract_address: Optional[str] = None  # Ethereum
    block_number: Optional[int] = None

    # Verification data
    consensus_timestamp: Optional[datetime] = None
    running_hash: Optional[str] = None  # Hedera running hash
    sequence_number: Optional[int] = None

    # Status
    status: AnchorStatus = AnchorStatus.PENDING
    error_message: Optional[str] = None
    retry_count: int = 0

    # Local signature (for local anchors)
    local_signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "anchor_id": self.anchor_id,
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "tree_head_signature": self.tree_head_signature,
            "tree_head_timestamp": self.tree_head_timestamp.isoformat(),
            "anchor_network": self.anchor_network,
            "anchor_timestamp": self.anchor_timestamp.isoformat() if self.anchor_timestamp else None,
            "transaction_id": self.transaction_id,
            "topic_id": self.topic_id,
            "contract_address": self.contract_address,
            "block_number": self.block_number,
            "consensus_timestamp": self.consensus_timestamp.isoformat() if self.consensus_timestamp else None,
            "running_hash": self.running_hash,
            "sequence_number": self.sequence_number,
            "status": self.status.value,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "local_signature": self.local_signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnchorRecord":
        """Deserialize from dictionary."""
        return cls(
            anchor_id=data["anchor_id"],
            tree_size=data["tree_size"],
            merkle_root=data["merkle_root"],
            tree_head_signature=data.get("tree_head_signature", ""),
            tree_head_timestamp=datetime.fromisoformat(data["tree_head_timestamp"]),
            anchor_network=data.get("anchor_network", ""),
            anchor_timestamp=datetime.fromisoformat(data["anchor_timestamp"]) if data.get("anchor_timestamp") else None,
            transaction_id=data.get("transaction_id"),
            topic_id=data.get("topic_id"),
            contract_address=data.get("contract_address"),
            block_number=data.get("block_number"),
            consensus_timestamp=datetime.fromisoformat(data["consensus_timestamp"]) if data.get("consensus_timestamp") else None,
            running_hash=data.get("running_hash"),
            sequence_number=data.get("sequence_number"),
            status=AnchorStatus(data.get("status", "pending")),
            error_message=data.get("error_message"),
            retry_count=data.get("retry_count", 0),
            local_signature=data.get("local_signature"),
        )

    def get_verification_instructions(self) -> str:
        """Get human-readable verification instructions."""
        if self.anchor_network.startswith("hedera"):
            network = self.anchor_network.split("-")[1] if "-" in self.anchor_network else "mainnet"
            base_url = "https://hashscan.io" if network == "mainnet" else f"https://hashscan.io/{network}"
            return f"""
To verify this anchor independently:
1. Go to {base_url}/topic/{self.topic_id}
2. Find message with sequence number {self.sequence_number}
3. Verify the message content contains merkle_root: {self.merkle_root}
4. Verify consensus timestamp matches: {self.consensus_timestamp}
"""
        elif self.anchor_network.startswith("ethereum"):
            network = self.anchor_network.split("-")[1] if "-" in self.anchor_network else "mainnet"
            base_url = "https://etherscan.io" if network == "mainnet" else f"https://{network}.etherscan.io"
            return f"""
To verify this anchor independently:
1. Go to {base_url}/tx/{self.transaction_id}
2. Decode the transaction input data
3. Verify it contains merkle_root: {self.merkle_root}
4. Check block number: {self.block_number}
"""
        else:
            return "Local anchor - for development/testing only. Verify against local anchor store."


# ============================================================================
# Abstract Backend Interface
# ============================================================================

class BlockchainAnchorBackend(ABC):
    """Abstract base class for blockchain anchoring backends."""

    @abstractmethod
    async def anchor(self, data: AnchorData) -> AnchorRecord:
        """
        Anchor data to blockchain.

        Args:
            data: Data to anchor

        Returns:
            AnchorRecord with transaction details
        """
        pass

    @abstractmethod
    async def verify(self, record: AnchorRecord) -> bool:
        """
        Verify an anchor against blockchain.

        Args:
            record: Anchor record to verify

        Returns:
            True if anchor is valid
        """
        pass

    @abstractmethod
    async def get_status(self, record: AnchorRecord) -> AnchorStatus:
        """Get current status of an anchor."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available and configured."""
        pass


# ============================================================================
# Hedera Implementation
# ============================================================================

class HederaAnchorBackend(BlockchainAnchorBackend):
    """
    Hedera Consensus Service (HCS) anchoring backend.

    Features:
    - Real Hedera SDK integration when available
    - Fallback to mirror node REST API
    - Async operation with aiohttp
    - Retry logic with exponential backoff
    """

    def __init__(self, config: Optional[HederaConfig] = None):
        """Initialize Hedera backend."""
        self.config = config or HederaConfig.from_env()
        self._client = None
        self._session: Optional[aiohttp.ClientSession] = None

    def is_available(self) -> bool:
        """Check if Hedera is configured."""
        return self.config.is_configured() or bool(self.config.relay_url)

    async def _get_session(self) -> Optional[aiohttp.ClientSession]:
        """Get or create aiohttp session."""
        if not AIOHTTP_AVAILABLE:
            return None
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            )
        return self._session

    async def _close_session(self):
        """Close aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _get_hedera_client(self):
        """Get or create Hedera SDK client."""
        if not HEDERA_SDK_AVAILABLE:
            return None

        if self._client is not None:
            return self._client

        try:
            if self.config.network == "mainnet":
                self._client = Client.forMainnet()
            elif self.config.network == "previewnet":
                self._client = Client.forPreviewnet()
            else:
                self._client = Client.forTestnet()

            operator_id = AccountId.fromString(self.config.operator_id)
            operator_key = PrivateKey.fromString(self.config.operator_key)
            self._client.setOperator(operator_id, operator_key)

            return self._client
        except Exception as e:
            logger.error(f"Failed to create Hedera client: {e}")
            return None

    async def anchor(self, data: AnchorData) -> AnchorRecord:
        """Anchor data to HCS topic."""
        anchor_id = generate_id("anc")
        now = datetime.now(timezone.utc)

        record = AnchorRecord(
            anchor_id=anchor_id,
            tree_size=data.tree_size,
            merkle_root=data.merkle_root,
            tree_head_signature=data.tree_head_signature,
            tree_head_timestamp=data.timestamp,
            anchor_network=f"hedera-{self.config.network}",
            topic_id=self.config.topic_id,
            status=AnchorStatus.PENDING,
        )

        message = data.to_message()

        # Try SDK first
        if self.config.is_sdk_available():
            try:
                result = await self._anchor_via_sdk(message)
                record.transaction_id = result["transaction_id"]
                record.consensus_timestamp = result.get("consensus_timestamp")
                record.sequence_number = result.get("sequence_number")
                record.running_hash = result.get("running_hash")
                record.anchor_timestamp = now
                record.status = AnchorStatus.CONFIRMED
                logger.info(f"Anchored via Hedera SDK: {record.transaction_id}")
                return record
            except Exception as e:
                logger.warning(f"Hedera SDK anchoring failed: {e}, trying relay")

        # Try relay service
        if self.config.relay_url:
            try:
                result = await self._anchor_via_relay(message)
                record.transaction_id = result["transaction_id"]
                record.consensus_timestamp = result.get("consensus_timestamp")
                record.sequence_number = result.get("sequence_number")
                record.anchor_timestamp = now
                record.status = AnchorStatus.CONFIRMED
                logger.info(f"Anchored via relay: {record.transaction_id}")
                return record
            except Exception as e:
                logger.error(f"Relay anchoring failed: {e}")
                record.error_message = str(e)
                record.status = AnchorStatus.FAILED

        # No available method
        if record.status == AnchorStatus.PENDING:
            record.status = AnchorStatus.FAILED
            record.error_message = "No Hedera anchoring method available (SDK or relay)"

        return record

    async def _anchor_via_sdk(self, message: bytes) -> Dict[str, Any]:
        """Anchor using Hedera SDK."""
        client = self._get_hedera_client()
        if client is None:
            raise RuntimeError("Hedera SDK not available")

        topic_id = TopicId.fromString(self.config.topic_id)

        # Create and execute transaction
        transaction = (
            TopicMessageSubmitTransaction()
            .setTopicId(topic_id)
            .setMessage(message)
        )

        # Execute synchronously (SDK doesn't support async natively)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: transaction.execute(client)
        )

        # Get receipt
        receipt = await loop.run_in_executor(
            None,
            lambda: response.getReceipt(client)
        )

        return {
            "transaction_id": str(response.transactionId),
            "consensus_timestamp": datetime.fromtimestamp(
                receipt.consensusTimestamp.getEpochSecond(),
                tz=timezone.utc
            ) if hasattr(receipt, 'consensusTimestamp') else None,
            "sequence_number": receipt.topicSequenceNumber if hasattr(receipt, 'topicSequenceNumber') else None,
            "running_hash": receipt.topicRunningHash.hex() if hasattr(receipt, 'topicRunningHash') and receipt.topicRunningHash else None,
        }

    async def _anchor_via_relay(self, message: bytes) -> Dict[str, Any]:
        """Anchor via relay service."""
        session = await self._get_session()
        if session is None:
            raise RuntimeError("HTTP client not available")

        payload = {
            "topic_id": self.config.topic_id,
            "message": base64.b64encode(message).decode("utf-8"),
        }

        async with session.post(
            f"{self.config.relay_url}/api/v1/anchor",
            json=payload,
        ) as response:
            if response.status != 200:
                text = await response.text()
                raise RuntimeError(f"Relay returned {response.status}: {text}")

            data = await response.json()
            return {
                "transaction_id": data["transaction_id"],
                "consensus_timestamp": datetime.fromisoformat(data["consensus_timestamp"]) if data.get("consensus_timestamp") else None,
                "sequence_number": data.get("sequence_number"),
            }

    async def verify(self, record: AnchorRecord) -> bool:
        """Verify anchor against mirror node."""
        if not record.anchor_network.startswith("hedera"):
            return False

        if not record.topic_id or not record.sequence_number:
            logger.warning("Cannot verify: missing topic_id or sequence_number")
            return False

        try:
            session = await self._get_session()
            if session is None:
                # Fallback to sync requests
                return self._verify_sync(record)

            url = f"{self.config.mirror_url}/api/v1/topics/{record.topic_id}/messages/{record.sequence_number}"

            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Mirror node returned {response.status}")
                    return False

                data = await response.json()

            # Decode and verify message
            message_b64 = data.get("message", "")
            message_bytes = base64.b64decode(message_b64)
            anchor_data = AnchorData.from_message(message_bytes)

            # Verify content matches
            if anchor_data.merkle_root != record.merkle_root:
                logger.error(f"Merkle root mismatch: {anchor_data.merkle_root} != {record.merkle_root}")
                return False

            if anchor_data.tree_size != record.tree_size:
                logger.error(f"Tree size mismatch: {anchor_data.tree_size} != {record.tree_size}")
                return False

            return True

        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

    def _verify_sync(self, record: AnchorRecord) -> bool:
        """Synchronous verification fallback."""
        if REQUESTS_AVAILABLE:
            try:
                url = f"{self.config.mirror_url}/api/v1/topics/{record.topic_id}/messages/{record.sequence_number}"
                response = requests.get(url, timeout=30)
                if response.status_code != 200:
                    return False
                data = response.json()
                message_bytes = base64.b64decode(data.get("message", ""))
                anchor_data = AnchorData.from_message(message_bytes)
                return (
                    anchor_data.merkle_root == record.merkle_root and
                    anchor_data.tree_size == record.tree_size
                )
            except Exception as e:
                logger.error(f"Sync verification failed: {e}")
                return False
        return False

    async def get_status(self, record: AnchorRecord) -> AnchorStatus:
        """Get status of anchor."""
        if record.status == AnchorStatus.CONFIRMED:
            if await self.verify(record):
                return AnchorStatus.CONFIRMED
            return AnchorStatus.FAILED
        return record.status


# ============================================================================
# Ethereum Implementation
# ============================================================================

class EthereumAnchorBackend(BlockchainAnchorBackend):
    """
    Ethereum anchoring backend.

    Supports:
    - Direct data embedding in transactions
    - Optional smart contract for batch anchoring
    """

    # Simple anchor contract ABI
    CONTRACT_ABI = [
        {
            "inputs": [{"type": "bytes32", "name": "hash"}],
            "name": "anchor",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"type": "bytes32", "name": "hash"}],
            "name": "isAnchored",
            "outputs": [{"type": "bool"}],
            "stateMutability": "view",
            "type": "function",
        },
    ]

    def __init__(self, config: Optional[EthereumConfig] = None):
        """Initialize Ethereum backend."""
        self.config = config or EthereumConfig.from_env()
        self._web3 = None

    def is_available(self) -> bool:
        """Check if Ethereum is configured."""
        return WEB3_AVAILABLE and self.config.is_configured()

    def _get_web3(self) -> Optional[Any]:
        """Get or create Web3 instance."""
        if not WEB3_AVAILABLE:
            return None

        if self._web3 is not None:
            return self._web3

        try:
            self._web3 = Web3(Web3.HTTPProvider(self.config.rpc_url))

            # Add POA middleware for testnets
            if self.config.chain_id in [5, 11155111]:  # Goerli, Sepolia
                self._web3.middleware_onion.inject(geth_poa_middleware, layer=0)

            return self._web3
        except Exception as e:
            logger.error(f"Failed to create Web3 instance: {e}")
            return None

    async def anchor(self, data: AnchorData) -> AnchorRecord:
        """Anchor data to Ethereum."""
        anchor_id = generate_id("eth")
        now = datetime.now(timezone.utc)

        network_name = {
            1: "mainnet",
            5: "goerli",
            11155111: "sepolia"
        }.get(self.config.chain_id, f"chain-{self.config.chain_id}")

        record = AnchorRecord(
            anchor_id=anchor_id,
            tree_size=data.tree_size,
            merkle_root=data.merkle_root,
            tree_head_signature=data.tree_head_signature,
            tree_head_timestamp=data.timestamp,
            anchor_network=f"ethereum-{network_name}",
            contract_address=self.config.contract_address,
            status=AnchorStatus.PENDING,
        )

        web3 = self._get_web3()
        if web3 is None:
            record.status = AnchorStatus.FAILED
            record.error_message = "Web3 not available"
            return record

        try:
            from eth_account import Account
            account = Account.from_key(self.config.private_key)

            # Create anchor data
            anchor_data = self._create_anchor_data(data)

            if self.config.contract_address:
                tx_result = await self._anchor_via_contract(web3, account, anchor_data)
            else:
                tx_result = await self._anchor_via_data(web3, account, anchor_data)

            record.transaction_id = tx_result["hash"]
            record.block_number = tx_result["block_number"]
            record.anchor_timestamp = now
            record.status = AnchorStatus.CONFIRMED

            logger.info(f"Anchored to Ethereum: tx={record.transaction_id}, block={record.block_number}")

        except Exception as e:
            logger.error(f"Ethereum anchoring failed: {e}")
            record.status = AnchorStatus.FAILED
            record.error_message = str(e)
            record.retry_count += 1

        return record

    def _create_anchor_data(self, data: AnchorData) -> bytes:
        """Create data to embed in transaction."""
        # Magic bytes + version + payload
        magic = b"VACP"
        version = b"\x01"
        payload = json.dumps({
            "tree_size": data.tree_size,
            "merkle_root": data.merkle_root,
            "timestamp": data.timestamp.isoformat(),
        }, sort_keys=True).encode("utf-8")
        return magic + version + payload

    async def _anchor_via_contract(self, web3, account, anchor_data: bytes) -> Dict[str, Any]:
        """Anchor using smart contract."""
        contract = web3.eth.contract(
            address=self.config.contract_address,
            abi=self.CONTRACT_ABI,
        )

        # Hash the anchor data
        data_hash = web3.keccak(anchor_data)

        # Build transaction
        nonce = web3.eth.get_transaction_count(account.address)

        tx_params = {
            "chainId": self.config.chain_id,
            "from": account.address,
            "nonce": nonce,
            "gas": self.config.gas_limit,
        }

        # Use EIP-1559 if available
        if self.config.max_fee_per_gas:
            tx_params["maxFeePerGas"] = self.config.max_fee_per_gas
            tx_params["maxPriorityFeePerGas"] = self.config.max_priority_fee or web3.eth.max_priority_fee
        else:
            tx_params["gasPrice"] = web3.eth.gas_price

        tx = contract.functions.anchor(data_hash).build_transaction(tx_params)

        # Sign and send
        signed = account.sign_transaction(tx)
        tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)

        # Wait for receipt
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "hash": tx_hash.hex(),
            "block_number": receipt["blockNumber"],
        }

    async def _anchor_via_data(self, web3, account, anchor_data: bytes) -> Dict[str, Any]:
        """Anchor by embedding data in transaction."""
        nonce = web3.eth.get_transaction_count(account.address)

        # Calculate gas for data
        data_gas = 21000 + len(anchor_data) * 16  # Base + calldata cost

        tx_params = {
            "chainId": self.config.chain_id,
            "from": account.address,
            "to": account.address,  # Send to self
            "value": 0,
            "nonce": nonce,
            "gas": data_gas,
            "data": anchor_data,
        }

        if self.config.max_fee_per_gas:
            tx_params["maxFeePerGas"] = self.config.max_fee_per_gas
            tx_params["maxPriorityFeePerGas"] = self.config.max_priority_fee or web3.eth.max_priority_fee
        else:
            tx_params["gasPrice"] = web3.eth.gas_price

        signed = account.sign_transaction(tx_params)
        tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)

        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "hash": tx_hash.hex(),
            "block_number": receipt["blockNumber"],
        }

    async def verify(self, record: AnchorRecord) -> bool:
        """Verify anchor on Ethereum."""
        if not record.anchor_network.startswith("ethereum"):
            return False

        web3 = self._get_web3()
        if web3 is None:
            return False

        try:
            tx = web3.eth.get_transaction(record.transaction_id)
            if tx is None:
                return False

            # Verify transaction is confirmed
            receipt = web3.eth.get_transaction_receipt(record.transaction_id)
            if receipt is None or receipt["status"] != 1:
                return False

            # Verify block number
            if record.block_number and tx["blockNumber"] != record.block_number:
                return False

            # Verify data contains our anchor
            if tx["input"]:
                data = bytes(tx["input"])
                if data.startswith(b"VACP\x01"):
                    payload = json.loads(data[5:].decode("utf-8"))
                    if payload.get("merkle_root") == record.merkle_root:
                        return True

            return False

        except Exception as e:
            logger.error(f"Ethereum verification failed: {e}")
            return False

    async def get_status(self, record: AnchorRecord) -> AnchorStatus:
        """Get status of Ethereum anchor."""
        if not record.transaction_id:
            return record.status

        web3 = self._get_web3()
        if web3 is None:
            return record.status

        try:
            receipt = web3.eth.get_transaction_receipt(record.transaction_id)
            if receipt is None:
                return AnchorStatus.SUBMITTED
            if receipt["status"] == 1:
                return AnchorStatus.CONFIRMED
            return AnchorStatus.FAILED
        except Exception:
            return record.status


# ============================================================================
# Local Implementation (Development/Testing)
# ============================================================================

class LocalAnchorBackend(BlockchainAnchorBackend):
    """
    Local timestamping backend for development and testing.

    Creates signed timestamp records stored locally.
    NOT suitable for production - no external verification.
    """

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        signing_key: Optional[KeyPair] = None,
    ):
        """Initialize local backend."""
        self.storage_path = storage_path or Path("./data/anchors")
        self.signing_key = signing_key
        self._sequence = 0
        self._anchors: Dict[str, AnchorRecord] = {}

        # Load existing anchors
        self._load_anchors()

    def is_available(self) -> bool:
        """Local backend is always available."""
        return True

    def _load_anchors(self):
        """Load anchors from storage."""
        if not self.storage_path.exists():
            return

        for anchor_file in self.storage_path.glob("*.json"):
            try:
                data = json.loads(anchor_file.read_text())
                record = AnchorRecord.from_dict(data)
                self._anchors[record.anchor_id] = record
                if record.sequence_number and record.sequence_number > self._sequence:
                    self._sequence = record.sequence_number
            except Exception as e:
                logger.warning(f"Failed to load anchor {anchor_file}: {e}")

    def _save_anchor(self, record: AnchorRecord):
        """Save anchor to storage."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        anchor_file = self.storage_path / f"{record.anchor_id}.json"
        anchor_file.write_text(json.dumps(record.to_dict(), indent=2))

    async def anchor(self, data: AnchorData) -> AnchorRecord:
        """Create local anchor record."""
        self._sequence += 1
        anchor_id = generate_id("loc")
        now = datetime.now(timezone.utc)

        record = AnchorRecord(
            anchor_id=anchor_id,
            tree_size=data.tree_size,
            merkle_root=data.merkle_root,
            tree_head_signature=data.tree_head_signature,
            tree_head_timestamp=data.timestamp,
            anchor_network="local",
            anchor_timestamp=now,
            sequence_number=self._sequence,
            status=AnchorStatus.CONFIRMED,
        )

        # Sign if we have a key
        if self.signing_key:
            record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode("utf-8")
            signature = sign_message(record_bytes, self.signing_key.private_key_bytes)
            record.local_signature = base64.b64encode(signature).decode("utf-8")

        # Store a copy (to avoid external modifications)
        self._anchors[anchor_id] = AnchorRecord.from_dict(record.to_dict())
        self._save_anchor(record)

        logger.info(f"Created local anchor: {anchor_id}, seq={self._sequence}")

        return record

    async def verify(self, record: AnchorRecord) -> bool:
        """Verify local anchor exists and signature is valid."""
        if record.anchor_network != "local":
            return False

        stored = self._anchors.get(record.anchor_id)
        if stored is None:
            # Try loading from disk
            anchor_file = self.storage_path / f"{record.anchor_id}.json"
            if anchor_file.exists():
                stored = AnchorRecord.from_dict(json.loads(anchor_file.read_text()))
            else:
                return False

        # Verify content matches
        if stored.merkle_root != record.merkle_root:
            return False

        # Verify signature if present and we have the key
        if stored.local_signature and self.signing_key:
            try:
                stored_copy = AnchorRecord.from_dict(stored.to_dict())
                stored_copy.local_signature = None
                record_bytes = json.dumps(stored_copy.to_dict(), sort_keys=True).encode("utf-8")
                signature = base64.b64decode(stored.local_signature)
                return verify_signature(
                    record_bytes,
                    signature,
                    self.signing_key.public_key_bytes,
                )
            except Exception:
                return False

        return True

    async def get_status(self, record: AnchorRecord) -> AnchorStatus:
        """Get status of local anchor."""
        return record.status


# ============================================================================
# Anchor Service (High-Level Interface)
# ============================================================================

class AnchorService:
    """
    High-level service for managing blockchain anchoring.

    Provides:
    - Automatic backend selection and failover
    - Retry logic with exponential backoff
    - Batch anchoring
    - Database persistence
    - Export for audits
    """

    def __init__(
        self,
        hedera_config: Optional[HederaConfig] = None,
        ethereum_config: Optional[EthereumConfig] = None,
        local_storage: Optional[Path] = None,
        signing_key: Optional[KeyPair] = None,
        db: Optional[DatabaseManager] = None,
        prefer_backend: Optional[str] = None,  # "hedera", "ethereum", "local"
    ):
        """
        Initialize anchor service.

        Args:
            hedera_config: Hedera configuration
            ethereum_config: Ethereum configuration
            local_storage: Path for local anchor storage
            signing_key: Key for signing local anchors
            db: Database manager
            prefer_backend: Preferred backend
        """
        self.hedera = HederaAnchorBackend(hedera_config)
        self.ethereum = EthereumAnchorBackend(ethereum_config)
        self.local = LocalAnchorBackend(local_storage, signing_key)

        self.db = db or get_db()
        self.prefer_backend = prefer_backend

        # Retry settings
        self.max_retries = 3
        self.base_delay = 1.0
        self.max_delay = 30.0

    def _select_backend(self) -> BlockchainAnchorBackend:
        """Select the best available backend."""
        if self.prefer_backend == "hedera" and self.hedera.is_available():
            return self.hedera
        if self.prefer_backend == "ethereum" and self.ethereum.is_available():
            return self.ethereum
        if self.prefer_backend == "local":
            return self.local

        # Priority: Hedera > Ethereum > Local
        if self.hedera.is_available():
            return self.hedera
        if self.ethereum.is_available():
            return self.ethereum
        return self.local

    async def anchor(
        self,
        tree_head: SignedTreeHead,
        backend: Optional[str] = None,
        force: bool = False,
    ) -> AnchorRecord:
        """
        Anchor a signed tree head with automatic retries.

        Args:
            tree_head: The tree head to anchor
            backend: Optional specific backend
            force: If True, anchor even if already anchored

        Returns:
            AnchorRecord with anchoring details
        """
        data = AnchorData.from_signed_tree_head(tree_head)

        # Check for existing anchor
        if not force:
            existing = self._get_existing_anchor(data.merkle_root)
            if existing:
                logger.debug(f"Merkle root already anchored: {data.merkle_root[:16]}...")
                return existing

        # Select backend
        if backend == "hedera":
            anchor_backend = self.hedera
        elif backend == "ethereum":
            anchor_backend = self.ethereum
        elif backend == "local":
            anchor_backend = self.local
        else:
            anchor_backend = self._select_backend()

        # Retry loop
        delay = self.base_delay
        last_error = None

        for attempt in range(self.max_retries):
            try:
                record = await anchor_backend.anchor(data)

                if record.status == AnchorStatus.CONFIRMED:
                    self._store_anchor(record)
                    return record

                if record.status == AnchorStatus.FAILED:
                    last_error = record.error_message
                    logger.warning(f"Anchor attempt {attempt + 1} failed: {last_error}")

            except Exception as e:
                last_error = str(e)
                logger.warning(f"Anchor attempt {attempt + 1} error: {e}")

            await asyncio.sleep(delay)
            delay = min(delay * 2, self.max_delay)

        # Fallback to local
        if anchor_backend != self.local:
            logger.warning("Falling back to local anchoring")
            record = await self.local.anchor(data)
            record.error_message = f"Fallback after: {last_error}"
            self._store_anchor(record)
            return record

        # Complete failure
        return AnchorRecord(
            anchor_id=generate_id("fail"),
            tree_size=data.tree_size,
            merkle_root=data.merkle_root,
            tree_head_signature=data.tree_head_signature,
            tree_head_timestamp=data.timestamp,
            anchor_network="none",
            status=AnchorStatus.FAILED,
            error_message=f"All attempts failed: {last_error}",
            retry_count=self.max_retries,
        )

    async def anchor_batch(
        self,
        tree_heads: List[SignedTreeHead],
        backend: Optional[str] = None,
    ) -> List[AnchorRecord]:
        """Anchor multiple tree heads."""
        tasks = [self.anchor(th, backend) for th in tree_heads]
        return await asyncio.gather(*tasks)

    async def verify(self, anchor_id: str) -> bool:
        """Verify an anchor by ID."""
        record = self.get_anchor(anchor_id)
        if record is None:
            return False

        anchor_record = self._anchor_record_from_model(record)

        if anchor_record.anchor_network.startswith("hedera"):
            return await self.hedera.verify(anchor_record)
        elif anchor_record.anchor_network.startswith("ethereum"):
            return await self.ethereum.verify(anchor_record)
        elif anchor_record.anchor_network == "local":
            return await self.local.verify(anchor_record)

        return False

    def get_anchor(self, anchor_id: str) -> Optional[BlockchainAnchor]:
        """Get anchor by ID from database."""
        if not SQLALCHEMY_AVAILABLE:
            return None
        with self.db.get_session() as session:
            return session.query(BlockchainAnchorModel).filter(
                BlockchainAnchorModel.id == anchor_id
            ).first()

    def get_anchor_by_merkle_root(self, merkle_root: str) -> Optional[BlockchainAnchor]:
        """Get anchor by Merkle root."""
        if not SQLALCHEMY_AVAILABLE:
            return None
        with self.db.get_session() as session:
            return session.query(BlockchainAnchorModel).filter(
                BlockchainAnchorModel.merkle_root == merkle_root
            ).first()

    def _get_existing_anchor(self, merkle_root: str) -> Optional[AnchorRecord]:
        """Check if merkle root is already anchored. Returns AnchorRecord to avoid DetachedInstanceError."""
        if not SQLALCHEMY_AVAILABLE:
            return None
        try:
            with self.db.get_session() as session:
                model = session.query(BlockchainAnchorModel).filter(
                    BlockchainAnchorModel.merkle_root == merkle_root
                ).first()
                if model:
                    # Convert to AnchorRecord within session context
                    return self._anchor_record_from_model(model)
                return None
        except Exception:
            return None

    def _store_anchor(self, record: AnchorRecord) -> None:
        """Store anchor record in database."""
        if not SQLALCHEMY_AVAILABLE:
            return
        try:
            with self.db.get_session() as session:
                model = BlockchainAnchorModel(
                    id=record.anchor_id,
                    tree_size=record.tree_size,
                    merkle_root=record.merkle_root,
                    tree_head_signature=record.tree_head_signature,
                    chain=record.anchor_network.split("-")[0] if "-" in record.anchor_network else record.anchor_network,
                    network=record.anchor_network.split("-")[1] if "-" in record.anchor_network else "",
                    topic_id=record.topic_id,
                    sequence_number=record.sequence_number,
                    transaction_id=record.transaction_id,
                    transaction_hash=hashlib.sha256(record.merkle_root.encode()).hexdigest(),
                    block_number=record.block_number,
                    timestamp=record.tree_head_timestamp,
                    anchored_at=record.anchor_timestamp or datetime.now(timezone.utc),
                    verified=record.status == AnchorStatus.CONFIRMED,
                    verification_data=json.dumps({
                        "consensus_timestamp": record.consensus_timestamp.isoformat() if record.consensus_timestamp else None,
                        "running_hash": record.running_hash,
                        "local_signature": record.local_signature,
                    }),
                )
                session.add(model)
        except Exception as e:
            logger.error(f"Failed to store anchor: {e}")

    def _anchor_record_from_model(self, model: BlockchainAnchorModel) -> AnchorRecord:
        """Convert database model to AnchorRecord."""
        verification_data = {}
        if model.verification_data:
            try:
                verification_data = json.loads(model.verification_data)
            except Exception:
                pass

        return AnchorRecord(
            anchor_id=model.id,
            tree_size=model.tree_size,
            merkle_root=model.merkle_root,
            tree_head_signature=model.tree_head_signature or "",
            tree_head_timestamp=model.timestamp,
            anchor_network=f"{model.chain}-{model.network}" if model.network else model.chain,
            anchor_timestamp=model.anchored_at,
            transaction_id=model.transaction_id,
            topic_id=model.topic_id,
            block_number=model.block_number,
            sequence_number=model.sequence_number,
            consensus_timestamp=datetime.fromisoformat(verification_data["consensus_timestamp"]) if verification_data.get("consensus_timestamp") else None,
            running_hash=verification_data.get("running_hash"),
            local_signature=verification_data.get("local_signature"),
            status=AnchorStatus.CONFIRMED if model.verified else AnchorStatus.PENDING,
        )

    def list_anchors(
        self,
        limit: int = 100,
        offset: int = 0,
        network: Optional[str] = None,
    ) -> List[AnchorRecord]:
        """List anchor records."""
        if not SQLALCHEMY_AVAILABLE:
            return []
        with self.db.get_session() as session:
            query = session.query(BlockchainAnchorModel)

            if network:
                query = query.filter(BlockchainAnchorModel.chain == network)

            query = query.order_by(BlockchainAnchorModel.anchored_at.desc())
            query = query.offset(offset).limit(limit)

            return [self._anchor_record_from_model(m) for m in query.all()]

    def get_statistics(self) -> Dict[str, Any]:
        """Get anchoring statistics."""
        if not SQLALCHEMY_AVAILABLE:
            return {"error": "Database not available"}

        with self.db.get_session() as session:
            total = session.query(BlockchainAnchorModel).count()
            verified = session.query(BlockchainAnchorModel).filter(
                BlockchainAnchorModel.verified == True
            ).count()

            by_chain = {}
            for chain in ["hedera", "ethereum", "local"]:
                count = session.query(BlockchainAnchorModel).filter(
                    BlockchainAnchorModel.chain == chain
                ).count()
                if count > 0:
                    by_chain[chain] = count

            return {
                "total_anchors": total,
                "verified_anchors": verified,
                "by_chain": by_chain,
                "backends_available": {
                    "hedera": self.hedera.is_available(),
                    "ethereum": self.ethereum.is_available(),
                    "local": True,
                },
            }

    def export_anchors(
        self,
        output_path: Path,
        format: str = "json",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """
        Export anchor records for audit.

        Args:
            output_path: Path to write export
            format: Export format ("json" or "csv")
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Number of records exported
        """
        if not SQLALCHEMY_AVAILABLE:
            return 0

        with self.db.get_session() as session:
            query = session.query(BlockchainAnchorModel)

            if start_date:
                query = query.filter(BlockchainAnchorModel.anchored_at >= start_date)
            if end_date:
                query = query.filter(BlockchainAnchorModel.anchored_at <= end_date)

            query = query.order_by(BlockchainAnchorModel.anchored_at.asc())
            models = query.all()

            # Convert to AnchorRecords within session context
            records = [self._anchor_record_from_model(m) for m in models]

        if format == "json":
            data = {
                "version": 1,
                "exported": datetime.now(timezone.utc).isoformat(),
                "count": len(records),
                "statistics": self.get_statistics(),
                "records": [r.to_dict() for r in records],
            }
            output_path.write_text(json.dumps(data, indent=2))

        elif format == "csv":
            import csv
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "anchor_id", "anchor_network", "status",
                    "tree_size", "merkle_root", "anchor_timestamp",
                    "transaction_id", "sequence_number", "block_number",
                ])
                writer.writeheader()
                for record in records:
                    writer.writerow({
                        "anchor_id": record.anchor_id,
                        "anchor_network": record.anchor_network,
                        "status": record.status.value,
                        "tree_size": record.tree_size,
                        "merkle_root": record.merkle_root,
                        "anchor_timestamp": record.anchor_timestamp.isoformat() if record.anchor_timestamp else "",
                        "transaction_id": record.transaction_id or "",
                        "sequence_number": record.sequence_number or "",
                        "block_number": record.block_number or "",
                    })

        return len(records)


# ============================================================================
# Legacy Compatibility (AnchorManager)
# ============================================================================

class AnchorManager:
    """
    Legacy compatibility wrapper around AnchorService.

    Maintains backward compatibility with existing code.
    """

    def __init__(
        self,
        service: Optional[AnchorService] = None,
        db: Optional[DatabaseManager] = None,
    ):
        """Initialize anchor manager."""
        self.db = db or get_db()
        self.service = service or AnchorService(db=self.db)

    async def anchor_tree_head(
        self,
        sth: SignedTreeHead,
        force: bool = False,
    ) -> Optional[AnchorRecord]:
        """Anchor a signed tree head."""
        return await self.service.anchor(sth, force=force)

    async def verify_anchor(self, anchor_id: str) -> bool:
        """Verify an anchor."""
        return await self.service.verify(anchor_id)

    def get_anchors(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AnchorRecord]:
        """Get anchors with pagination."""
        return self.service.list_anchors(limit=limit, offset=offset)


# ============================================================================
# Utility Functions
# ============================================================================

def is_blockchain_enabled() -> bool:
    """Check if blockchain anchoring is enabled and configured."""
    # Check for simulate mode (for testing)
    if os.getenv("HEDERA_SIMULATE", "").lower() in ("true", "1", "yes"):
        return True

    hedera_config = HederaConfig.from_env()
    ethereum_config = EthereumConfig.from_env()
    return hedera_config.is_configured() or ethereum_config.is_configured()


def get_anchor_service(
    db: Optional[DatabaseManager] = None,
    prefer_backend: Optional[str] = None,
) -> AnchorService:
    """Get the default anchor service."""
    return AnchorService(db=db, prefer_backend=prefer_backend)


def get_anchor_manager(db: Optional[DatabaseManager] = None) -> AnchorManager:
    """Get the default anchor manager."""
    return AnchorManager(db=db)


async def anchor_tree_head(
    tree_head: SignedTreeHead,
    backend: Optional[str] = None,
) -> AnchorRecord:
    """Convenience function to anchor a tree head."""
    service = AnchorService()
    return await service.anchor(tree_head, backend)


# ============================================================================
# Backwards Compatibility Aliases
# ============================================================================

# Alias for legacy code expecting HederaAnchorService
HederaAnchorService = HederaAnchorBackend

# Alias for legacy code expecting BlockchainAnchor
BlockchainAnchor = AnchorRecord
