"""
Anchor Scheduler

Provides:
- Background task for periodic blockchain anchoring
- Configurable anchoring triggers (time-based, count-based)
- Retry logic for failed anchors
"""

import os
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable, Any
from dataclasses import dataclass

from .blockchain import (
    AnchorManager, BlockchainAnchor,
    is_blockchain_enabled
)
from .merkle import MerkleLog
from .database import DatabaseManager, get_db

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class AnchorSchedulerConfig:
    """Configuration for anchor scheduling."""

    # Time-based trigger: anchor every N minutes
    interval_minutes: int = 60

    # Count-based trigger: anchor after N new receipts
    min_receipts: int = 100

    # Maximum time between anchors (even if min_receipts not reached)
    max_interval_minutes: int = 1440  # 24 hours

    # Retry configuration
    retry_attempts: int = 3
    retry_delay_seconds: int = 60

    # Whether to anchor on startup
    anchor_on_startup: bool = True

    # Whether scheduler is enabled
    enabled: bool = True

    @classmethod
    def from_env(cls) -> "AnchorSchedulerConfig":
        """Load configuration from environment variables."""
        return cls(
            interval_minutes=int(os.getenv("ANCHOR_INTERVAL_MINUTES", "60")),
            min_receipts=int(os.getenv("ANCHOR_MIN_RECEIPTS", "100")),
            max_interval_minutes=int(os.getenv("ANCHOR_MAX_INTERVAL_MINUTES", "1440")),
            retry_attempts=int(os.getenv("ANCHOR_RETRY_ATTEMPTS", "3")),
            retry_delay_seconds=int(os.getenv("ANCHOR_RETRY_DELAY_SECONDS", "60")),
            anchor_on_startup=os.getenv("ANCHOR_ON_STARTUP", "true").lower() == "true",
            enabled=os.getenv("ANCHOR_ENABLED", "false").lower() == "true",
        )


# ============================================================================
# Anchor Scheduler
# ============================================================================

class AnchorScheduler:
    """
    Schedules and executes blockchain anchoring.

    Triggers anchoring based on:
    1. Time interval (e.g., every 60 minutes)
    2. Receipt count (e.g., after 100 new receipts)
    3. Maximum interval (e.g., at least once per 24 hours)

    The scheduler runs as a background task and integrates with
    the Merkle log to get the current tree head for anchoring.
    """

    def __init__(
        self,
        merkle_log: MerkleLog,
        config: Optional[AnchorSchedulerConfig] = None,
        anchor_manager: Optional[AnchorManager] = None,
        db: Optional[DatabaseManager] = None,
    ):
        """
        Initialize anchor scheduler.

        Args:
            merkle_log: Merkle log to get tree heads from
            config: Scheduler configuration
            anchor_manager: Blockchain anchor manager
            db: Database manager
        """
        self.merkle_log = merkle_log
        self.config = config or AnchorSchedulerConfig.from_env()
        self.db = db or get_db()
        self.anchor_manager = anchor_manager or AnchorManager(db=self.db)

        # State
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_anchor_time: Optional[datetime] = None
        self._last_anchor_tree_size: int = 0
        self._receipts_since_anchor: int = 0

        # Callbacks
        self._on_anchor_success: Optional[Callable[[BlockchainAnchor], Any]] = None
        self._on_anchor_failure: Optional[Callable[[Exception], Any]] = None

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    def on_anchor_success(self, callback: Callable[[BlockchainAnchor], Any]) -> None:
        """Set callback for successful anchors."""
        self._on_anchor_success = callback

    def on_anchor_failure(self, callback: Callable[[Exception], Any]) -> None:
        """Set callback for anchor failures."""
        self._on_anchor_failure = callback

    def notify_new_receipt(self) -> None:
        """
        Notify scheduler of a new receipt.

        Call this whenever a new receipt is added to the log.
        The scheduler uses this to track when to anchor based on count.
        """
        self._receipts_since_anchor += 1

    async def start(self) -> None:
        """Start the scheduler background task."""
        if self._running:
            logger.warning("Anchor scheduler already running")
            return

        if not self.config.enabled:
            logger.info("Anchor scheduler is disabled")
            return

        if not is_blockchain_enabled():
            logger.warning("Blockchain anchoring is not configured, scheduler disabled")
            return

        self._running = True
        self._task = asyncio.create_task(self._run())
        logger.info(
            f"Anchor scheduler started: interval={self.config.interval_minutes}min, "
            f"min_receipts={self.config.min_receipts}"
        )

        # Initial anchor on startup if configured
        if self.config.anchor_on_startup:
            await self._check_and_anchor(force=False)

    async def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("Anchor scheduler stopped")

    async def _run(self) -> None:
        """Main scheduler loop."""
        check_interval = min(60, self.config.interval_minutes * 60)  # Check at least every minute

        while self._running:
            try:
                await asyncio.sleep(check_interval)
                await self._check_and_anchor()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(check_interval)

    async def _check_and_anchor(self, force: bool = False) -> Optional[BlockchainAnchor]:
        """
        Check if anchoring is needed and perform it.

        Args:
            force: If True, anchor regardless of triggers

        Returns:
            Anchor record if anchoring was performed
        """
        should_anchor = force

        # Check time-based trigger
        if not should_anchor and self._last_anchor_time:
            time_since_anchor = datetime.now(timezone.utc) - self._last_anchor_time
            if time_since_anchor >= timedelta(minutes=self.config.interval_minutes):
                should_anchor = True
                logger.debug(f"Time trigger: {time_since_anchor}")

        # Check count-based trigger
        if not should_anchor and self._receipts_since_anchor >= self.config.min_receipts:
            should_anchor = True
            logger.debug(f"Count trigger: {self._receipts_since_anchor} receipts")

        # Check max interval trigger
        if not should_anchor and self._last_anchor_time:
            time_since_anchor = datetime.now(timezone.utc) - self._last_anchor_time
            if time_since_anchor >= timedelta(minutes=self.config.max_interval_minutes):
                should_anchor = True
                logger.debug(f"Max interval trigger: {time_since_anchor}")

        # First anchor ever
        if not should_anchor and self._last_anchor_time is None:
            # Only anchor if there are entries in the log
            if self.merkle_log.size > 0:
                should_anchor = True
                logger.debug("Initial anchor trigger")

        # Check if tree has grown since last anchor
        current_size = self.merkle_log.size
        if should_anchor and current_size <= self._last_anchor_tree_size:
            logger.debug(f"No new entries since last anchor (size={current_size})")
            should_anchor = False

        if not should_anchor:
            return None

        # Perform anchoring
        return await self._perform_anchor()

    async def _perform_anchor(self) -> Optional[BlockchainAnchor]:
        """Perform the actual anchoring with retry logic."""
        # Get current signed tree head
        sth = self.merkle_log.get_signed_tree_head()
        if not sth:
            logger.warning("Cannot anchor: no signed tree head available")
            return None

        # Attempt anchoring with retries
        last_error: Optional[Exception] = None
        for attempt in range(self.config.retry_attempts):
            try:
                anchor = await self.anchor_manager.anchor_tree_head(sth)

                # Update state
                self._last_anchor_time = datetime.now(timezone.utc)
                self._last_anchor_tree_size = sth.tree_size
                self._receipts_since_anchor = 0

                logger.info(
                    f"Successfully anchored: tree_size={sth.tree_size}, "
                    f"root={sth.root_hash[:16]}..., tx={anchor.transaction_id}"
                )

                # Callback
                if self._on_anchor_success:
                    try:
                        self._on_anchor_success(anchor)
                    except Exception as e:
                        logger.error(f"Anchor success callback error: {e}")

                return anchor

            except Exception as e:
                last_error = e
                logger.warning(
                    f"Anchor attempt {attempt + 1}/{self.config.retry_attempts} failed: {e}"
                )
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay_seconds)

        # All retries failed
        logger.error(f"Anchoring failed after {self.config.retry_attempts} attempts")
        if self._on_anchor_failure and last_error:
            try:
                self._on_anchor_failure(last_error)
            except Exception as e:
                logger.error(f"Anchor failure callback error: {e}")

        return None

    async def force_anchor(self) -> Optional[BlockchainAnchor]:
        """
        Force an immediate anchor regardless of triggers.

        Returns:
            Anchor record if successful
        """
        return await self._check_and_anchor(force=True)

    def get_status(self) -> dict:
        """Get scheduler status."""
        return {
            "running": self._running,
            "enabled": self.config.enabled,
            "last_anchor_time": self._last_anchor_time.isoformat() if self._last_anchor_time else None,
            "last_anchor_tree_size": self._last_anchor_tree_size,
            "receipts_since_anchor": self._receipts_since_anchor,
            "config": {
                "interval_minutes": self.config.interval_minutes,
                "min_receipts": self.config.min_receipts,
                "max_interval_minutes": self.config.max_interval_minutes,
            },
        }


# ============================================================================
# Global Instance
# ============================================================================

_scheduler: Optional[AnchorScheduler] = None


def get_anchor_scheduler() -> Optional[AnchorScheduler]:
    """Get the global anchor scheduler instance."""
    return _scheduler


def init_anchor_scheduler(
    merkle_log: MerkleLog,
    config: Optional[AnchorSchedulerConfig] = None,
) -> AnchorScheduler:
    """
    Initialize the global anchor scheduler.

    Args:
        merkle_log: Merkle log to anchor
        config: Scheduler configuration

    Returns:
        Initialized scheduler (not started)
    """
    global _scheduler
    _scheduler = AnchorScheduler(merkle_log, config)
    return _scheduler


async def start_anchor_scheduler(
    merkle_log: MerkleLog,
    config: Optional[AnchorSchedulerConfig] = None,
) -> AnchorScheduler:
    """
    Initialize and start the anchor scheduler.

    Args:
        merkle_log: Merkle log to anchor
        config: Scheduler configuration

    Returns:
        Running scheduler
    """
    scheduler = init_anchor_scheduler(merkle_log, config)
    await scheduler.start()
    return scheduler


async def stop_anchor_scheduler() -> None:
    """Stop the global anchor scheduler."""
    global _scheduler
    if _scheduler:
        await _scheduler.stop()
        _scheduler = None
