"""
Merkle Transparency Log

This module implements a tamper-evident append-only log using a Merkle tree.
It provides:

1. Append-only semantics: entries can only be added, never modified
2. Inclusion proofs: prove an entry exists in the log
3. Consistency proofs: prove the log only grows (no tampering)
4. Signed tree heads: cryptographic commitment to log state

The design is inspired by Certificate Transparency (RFC 6962) and
provides the foundation for verifiable audit trails.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict, Tuple, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from vacp.core.receipts import SignedActionReceipt

from vacp.core.crypto import (
    KeyPair,
    sign_message,
    verify_signature,
    encode_signature,
    decode_signature,
    encode_public_key,
    decode_public_key,
    hash_data,
)


def merkle_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash for Merkle tree."""
    return hashlib.sha256(data).digest()


def leaf_hash(entry: bytes) -> bytes:
    """
    Compute hash of a leaf node.
    Prefixed with 0x00 to distinguish from internal nodes.
    """
    return merkle_hash(b"\x00" + entry)


def internal_hash(left: bytes, right: bytes) -> bytes:
    """
    Compute hash of an internal node.
    Prefixed with 0x01 to distinguish from leaf nodes.
    """
    return merkle_hash(b"\x01" + left + right)


@dataclass
class MerkleProof:
    """
    An inclusion proof for a Merkle tree.

    Contains the sibling hashes needed to recompute the root
    from a leaf, along with directional information.
    """
    leaf_index: int
    tree_size: int
    hashes: List[bytes]
    directions: List[bool]  # True = hash goes on right, False = left

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "hashes": [h.hex() for h in self.hashes],
            "directions": self.directions,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MerkleProof":
        return cls(
            leaf_index=data["leaf_index"],
            tree_size=data["tree_size"],
            hashes=[bytes.fromhex(h) for h in data["hashes"]],
            directions=data["directions"],
        )

    def verify(self, leaf_data: bytes, expected_root: bytes) -> bool:
        """
        Verify this proof against expected root.

        Args:
            leaf_data: The original leaf entry data
            expected_root: The expected Merkle root

        Returns:
            True if proof is valid
        """
        current = leaf_hash(leaf_data)

        for sibling_hash, goes_right in zip(self.hashes, self.directions):
            if goes_right:
                current = internal_hash(current, sibling_hash)
            else:
                current = internal_hash(sibling_hash, current)

        return current == expected_root


@dataclass
class ConsistencyProof:
    """
    A consistency proof between two tree states.

    Proves that tree at size m is a prefix of tree at size n.
    """
    first_size: int
    second_size: int
    hashes: List[bytes]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "first_size": self.first_size,
            "second_size": self.second_size,
            "hashes": [h.hex() for h in self.hashes],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConsistencyProof":
        return cls(
            first_size=data["first_size"],
            second_size=data["second_size"],
            hashes=[bytes.fromhex(h) for h in data["hashes"]],
        )


@dataclass
class SignedTreeHead:
    """
    A signed commitment to the current log state.

    This is periodically published and can be used to:
    1. Detect log equivocation (different views for different clients)
    2. Anchor to external systems (e.g., blockchain)
    """
    tree_size: int
    root_hash: bytes
    timestamp: datetime
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash.hex(),
            "timestamp": self.timestamp.isoformat(),
        }
        if self.signature:
            d["signature"] = self.signature
        if self.signer_public_key:
            d["signer"] = self.signer_public_key
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedTreeHead":
        return cls(
            tree_size=data["tree_size"],
            root_hash=bytes.fromhex(data["root_hash"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            signature=data.get("signature"),
            signer_public_key=data.get("signer"),
        )

    def canonical_bytes(self) -> bytes:
        """Get bytes for signing (excludes signature)."""
        return json.dumps({
            "tree_size": self.tree_size,
            "root_hash": self.root_hash.hex(),
            "timestamp": self.timestamp.isoformat(),
        }, sort_keys=True).encode("utf-8")


class MerkleLog:
    """
    A Merkle tree-based append-only log.

    Provides:
    - O(log n) inclusion proofs
    - O(log n) consistency proofs
    - Efficient append operations
    - Persistent storage support

    The tree is built incrementally as entries are added.
    """

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        storage_path: Optional[Path] = None,
    ):
        """
        Initialize the Merkle log.

        Args:
            keypair: Keypair for signing tree heads
            storage_path: Optional path for persistent storage
        """
        self.keypair = keypair
        self.storage_path = storage_path

        # In-memory storage
        self._entries: List[bytes] = []
        self._leaf_hashes: List[bytes] = []
        self._tree_cache: Dict[Tuple[int, int], bytes] = {}

        # Load from storage if available
        if storage_path and storage_path.exists():
            self._load_from_storage()

    @property
    def size(self) -> int:
        """Current number of entries in the log."""
        return len(self._entries)

    @property
    def root(self) -> bytes:
        """Current Merkle root hash."""
        if not self._entries:
            return merkle_hash(b"")
        return self._compute_root(0, len(self._leaf_hashes))

    @property
    def root_hex(self) -> str:
        """Current Merkle root as hex string."""
        return f"sha256:{self.root.hex()}"

    def append(self, entry: bytes) -> int:
        """
        Append an entry to the log.

        Args:
            entry: The entry bytes to append

        Returns:
            The index of the new entry
        """
        index = len(self._entries)
        self._entries.append(entry)
        self._leaf_hashes.append(leaf_hash(entry))
        self._invalidate_cache(index)

        if self.storage_path:
            self._persist_entry(index, entry)

        return index

    def append_json(self, obj: Any) -> int:
        """Append a JSON-serializable object."""
        entry = json.dumps(obj, sort_keys=True).encode("utf-8")
        return self.append(entry)

    def get_entry(self, index: int) -> Optional[bytes]:
        """Get an entry by index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def get_entry_json(self, index: int) -> Optional[Any]:
        """Get an entry as JSON object."""
        entry = self.get_entry(index)
        if entry:
            return json.loads(entry.decode("utf-8"))
        return None

    def get_inclusion_proof(self, index: int) -> Optional[MerkleProof]:
        """
        Generate an inclusion proof for an entry.

        Args:
            index: The index of the entry

        Returns:
            MerkleProof or None if index is invalid
        """
        if index < 0 or index >= len(self._entries):
            return None

        tree_size = len(self._entries)
        hashes: List[bytes] = []
        directions: List[bool] = []

        # Generate proof by recursively descending the tree structure
        # that matches _compute_root's splitting logic
        self._build_inclusion_proof(index, 0, tree_size, hashes, directions)

        # Reverse because we built from root to leaf, but verify from leaf to root
        hashes.reverse()
        directions.reverse()

        return MerkleProof(
            leaf_index=index,
            tree_size=tree_size,
            hashes=hashes,
            directions=directions,
        )

    def _build_inclusion_proof(
        self,
        target_idx: int,
        start: int,
        count: int,
        hashes: List[bytes],
        directions: List[bool],
    ) -> None:
        """
        Recursively build inclusion proof following _compute_root's tree structure.

        Args:
            target_idx: The leaf index we're proving
            start: Start of current subtree
            count: Size of current subtree
            hashes: List to append sibling hashes to
            directions: List to append direction flags to
        """
        if count <= 1:
            # Base case - at the leaf
            return

        # Split the same way _compute_root does
        split = 1 << (count - 1).bit_length() - 1
        if split >= count:
            split = count // 2

        left_start = start
        left_count = split
        right_start = start + split
        right_count = count - split

        # Determine which subtree contains our target
        if target_idx < right_start:
            # Target is in left subtree
            # We need the right subtree's hash as sibling
            sibling_hash = self._compute_root(right_start, right_count)
            hashes.append(sibling_hash)
            directions.append(True)  # Sibling goes on right
            # Recurse into left subtree
            self._build_inclusion_proof(target_idx, left_start, left_count, hashes, directions)
        else:
            # Target is in right subtree
            # We need the left subtree's hash as sibling
            sibling_hash = self._compute_root(left_start, left_count)
            hashes.append(sibling_hash)
            directions.append(False)  # Sibling goes on left
            # Recurse into right subtree
            self._build_inclusion_proof(target_idx, right_start, right_count, hashes, directions)

    def verify_inclusion(
        self,
        index: int,
        entry: bytes,
        proof: MerkleProof,
        root: Optional[bytes] = None,
    ) -> bool:
        """
        Verify an inclusion proof.

        Args:
            index: Expected leaf index
            entry: The entry data
            proof: The inclusion proof
            root: Expected root (uses current if None)

        Returns:
            True if proof is valid
        """
        if root is None:
            root = self.root

        if proof.leaf_index != index:
            return False

        return proof.verify(entry, root)

    def get_signed_tree_head(self) -> SignedTreeHead:
        """
        Get a signed tree head for the current state.

        Returns:
            SignedTreeHead with current root and signature
        """
        sth = SignedTreeHead(
            tree_size=self.size,
            root_hash=self.root,
            timestamp=datetime.now(timezone.utc),
        )

        if self.keypair:
            signature_bytes = sign_message(
                sth.canonical_bytes(),
                self.keypair.private_key_bytes,
            )
            sth.signature = encode_signature(signature_bytes)
            sth.signer_public_key = encode_public_key(self.keypair.public_key_bytes)

        return sth

    def verify_signed_tree_head(self, sth: SignedTreeHead) -> bool:
        """
        Verify a signed tree head.

        Args:
            sth: The signed tree head to verify

        Returns:
            True if signature is valid
        """
        if not sth.signature or not sth.signer_public_key:
            return False

        try:
            signature_bytes = decode_signature(sth.signature)
            public_key_bytes = decode_public_key(sth.signer_public_key)
            return verify_signature(
                sth.canonical_bytes(),
                signature_bytes,
                public_key_bytes,
            )
        except Exception:
            return False

    def get_consistency_proof(
        self,
        first_size: int,
        second_size: Optional[int] = None,
    ) -> Optional[ConsistencyProof]:
        """
        Generate a consistency proof between two tree sizes.

        Proves that the tree at first_size is a prefix of tree at second_size.

        Args:
            first_size: Size of the older tree
            second_size: Size of the newer tree (current if None)

        Returns:
            ConsistencyProof or None if invalid
        """
        if second_size is None:
            second_size = self.size

        if first_size < 0 or first_size > second_size or second_size > self.size:
            return None

        if first_size == 0:
            return ConsistencyProof(
                first_size=first_size,
                second_size=second_size,
                hashes=[],
            )

        hashes = self._compute_consistency_hashes(first_size, second_size)

        return ConsistencyProof(
            first_size=first_size,
            second_size=second_size,
            hashes=hashes,
        )

    def _compute_root(self, start: int, count: int) -> bytes:
        """Compute Merkle root for a range of leaves."""
        if count == 0:
            return merkle_hash(b"")
        if count == 1:
            return self._leaf_hashes[start]

        # Check cache
        cache_key = (start, count)
        if cache_key in self._tree_cache:
            return self._tree_cache[cache_key]

        # Split and recurse
        split = 1 << (count - 1).bit_length() - 1
        if split >= count:
            split = count // 2

        left = self._compute_root(start, split)
        right = self._compute_root(start + split, count - split)
        result = internal_hash(left, right)

        self._tree_cache[cache_key] = result
        return result

    def _get_subtree_hash(self, index: int, level_span: int, total_size: int) -> bytes:
        """Get hash of subtree at given position."""
        start = index * level_span
        count = min(level_span, total_size - start)
        if count <= 0:
            return merkle_hash(b"")
        if count == 1 and level_span == 1:
            return self._leaf_hashes[start]
        return self._compute_root(start, count)

    def _compute_consistency_hashes(self, m: int, n: int) -> List[bytes]:
        """Compute hashes for consistency proof from size m to size n.

        Follows RFC 6962 Section 2.1.2 consistency proof algorithm:
        Proves that the first m leaves of the tree with n leaves
        generate the same hash as the tree with m leaves.
        """
        hashes: List[bytes] = []

        if m == n or m == 0:
            return hashes

        # RFC 6962: find the largest power of 2 less than n
        # and use it to decompose the proof
        self._subproof(m, n, hashes, True)
        return hashes

    def _subproof(self, m: int, n: int, hashes: List[bytes], is_complete: bool) -> None:
        """RFC 6962 consistency subproof algorithm."""
        if m == n:
            if not is_complete:
                hashes.append(self._compute_root(0, m) if m > 0 else merkle_hash(b""))
            return

        # Find the largest power of 2 less than n
        k = 1
        while k * 2 < n:
            k *= 2

        if m <= k:
            # m is in the left subtree
            self._subproof_range(m, k, 0, hashes, is_complete)
            hashes.append(self._compute_root(k, n - k))
        else:
            # m spans into the right subtree
            self._subproof_range(m - k, n - k, k, hashes, False)
            hashes.append(self._compute_root(0, k))

    def _subproof_range(self, m: int, n: int, offset: int, hashes: List[bytes], is_complete: bool) -> None:
        """Recursive subproof for a range starting at offset."""
        if m == n:
            if not is_complete:
                hashes.append(self._compute_root(offset, m))
            return

        k = 1
        while k * 2 < n:
            k *= 2

        if m <= k:
            self._subproof_range(m, k, offset, hashes, is_complete)
            hashes.append(self._compute_root(offset + k, n - k))
        else:
            self._subproof_range(m - k, n - k, offset + k, hashes, False)
            hashes.append(self._compute_root(offset, k))

    def _invalidate_cache(self, index: int) -> None:
        """Invalidate cache entries affected by new leaf."""
        # Simple approach: clear all cache entries that might be affected
        keys_to_remove = []
        for (start, count) in self._tree_cache:
            if start <= index < start + count:
                keys_to_remove.append((start, count))
        for key in keys_to_remove:
            del self._tree_cache[key]

    def _persist_entry(self, index: int, entry: bytes) -> None:
        """Persist an entry to storage."""
        if not self.storage_path:
            return

        self.storage_path.mkdir(parents=True, exist_ok=True)
        entry_path = self.storage_path / f"entry_{index:010d}.bin"
        entry_path.write_bytes(entry)

        # Also persist metadata
        meta_path = self.storage_path / "meta.json"
        meta = {
            "size": len(self._entries),
            "root": self.root.hex(),
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        meta_path.write_text(json.dumps(meta, indent=2))

    def _load_from_storage(self) -> None:
        """Load log from persistent storage."""
        if not self.storage_path:
            return

        meta_path = self.storage_path / "meta.json"
        if not meta_path.exists():
            return

        meta = json.loads(meta_path.read_text())
        size = meta["size"]

        for i in range(size):
            entry_path = self.storage_path / f"entry_{i:010d}.bin"
            if entry_path.exists():
                entry = entry_path.read_bytes()
                self._entries.append(entry)
                self._leaf_hashes.append(leaf_hash(entry))

    def export_log(self) -> Dict[str, Any]:
        """Export the entire log for backup/transfer."""
        return {
            "version": 1,
            "size": self.size,
            "root": self.root.hex(),
            "entries": [entry.hex() for entry in self._entries],
            "exported": datetime.now(timezone.utc).isoformat(),
        }

    def import_log(self, data: Dict[str, Any]) -> bool:
        """
        Import a log from exported data.

        Args:
            data: Exported log data

        Returns:
            True if import successful
        """
        if data.get("version") != 1:
            return False

        self._entries = []
        self._leaf_hashes = []
        self._tree_cache = {}

        for entry_hex in data["entries"]:
            entry = bytes.fromhex(entry_hex)
            self._entries.append(entry)
            self._leaf_hashes.append(leaf_hash(entry))

        # Verify root matches
        if self.root.hex() != data["root"]:
            # Rollback
            self._entries = []
            self._leaf_hashes = []
            return False

        return True


class AuditableLog:
    """
    High-level wrapper around MerkleLog specifically for receipts.

    Provides convenient methods for working with SignedActionReceipts
    and integrates with the ReceiptService.
    """

    def __init__(
        self,
        merkle_log: Optional[MerkleLog] = None,
        keypair: Optional[KeyPair] = None,
        storage_path: Optional[Path] = None,
    ):
        """Initialize the auditable log."""
        self.log = merkle_log or MerkleLog(keypair=keypair, storage_path=storage_path)
        self._receipt_index: Dict[str, int] = {}

    def append_receipt(self, receipt: "SignedActionReceipt") -> int:
        """Append a receipt and return its log index."""
        from vacp.core.receipts import SignedActionReceipt

        entry = receipt.to_json().encode("utf-8")
        index = self.log.append(entry)
        self._receipt_index[receipt.receipt_id] = index
        return index

    def get_receipt(self, index: int) -> Optional["SignedActionReceipt"]:
        """Get a receipt by log index."""
        from vacp.core.receipts import SignedActionReceipt

        entry = self.log.get_entry(index)
        if entry:
            return SignedActionReceipt.from_json(entry.decode("utf-8"))
        return None

    def get_receipt_by_id(self, receipt_id: str) -> Optional["SignedActionReceipt"]:
        """Get a receipt by its receipt_id."""
        index = self._receipt_index.get(receipt_id)
        if index is not None:
            return self.get_receipt(index)
        return None

    def get_proof_for_receipt(self, receipt_id: str) -> Optional[MerkleProof]:
        """Get an inclusion proof for a receipt."""
        index = self._receipt_index.get(receipt_id)
        if index is not None:
            return self.log.get_inclusion_proof(index)
        return None

    def verify_receipt_in_log(
        self,
        receipt: "SignedActionReceipt",
        proof: MerkleProof,
    ) -> bool:
        """Verify a receipt is in the log using the proof."""
        entry = receipt.to_json().encode("utf-8")
        return self.log.verify_inclusion(
            proof.leaf_index,
            entry,
            proof,
        )
