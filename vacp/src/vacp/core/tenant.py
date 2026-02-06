"""
Tenant Management Service

Provides:
- TenantContext for request-scoped tenant information
- TenantService for tenant CRUD operations
- API key management
- Tenant provisioning workflow
"""

import json
import re
import secrets
import hashlib
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .database import (
    DatabaseManager, TenantModel, UserModel, APIKeyModel, PolicyBundleModel,
    Tenant, APIKey, TenantStatus, TenantPlan, UserRole, APIKeyStatus,
    ResourceLimits, PLAN_LIMITS, generate_id, generate_api_key, hash_api_key,
    get_db, SQLALCHEMY_AVAILABLE
)

if SQLALCHEMY_AVAILABLE:
    from sqlalchemy.orm import Session as SQLASession


# ============================================================================
# Tenant Context (Request-Scoped)
# ============================================================================

@dataclass
class TenantContext:
    """
    Request-scoped tenant context.

    This context is set at the beginning of each request and contains
    information about the current tenant making the request.
    """
    tenant_id: str
    tenant_name: str
    tenant_slug: str
    plan: TenantPlan
    is_system_admin: bool = False
    user_id: Optional[str] = None
    user_role: Optional[UserRole] = None
    api_key_id: Optional[str] = None
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    settings: Dict[str, Any] = field(default_factory=dict)

    def has_permission(self, required_permission: str) -> bool:
        """Check if current context has a permission."""
        if self.is_system_admin:
            return True
        # Add more permission checks based on user_role
        return False

    def can_use_feature(self, feature: str) -> bool:
        """Check if tenant's plan allows a feature."""
        # Enterprise gets everything
        if self.plan == TenantPlan.ENTERPRISE:
            return True
        # Check settings for feature flags
        return self.settings.get("features", {}).get(feature, False)


# Thread-safe context variable for current tenant
_current_tenant: ContextVar[Optional[TenantContext]] = ContextVar(
    "current_tenant", default=None
)


def get_current_tenant() -> Optional[TenantContext]:
    """Get the current request's tenant context."""
    return _current_tenant.get()


def set_current_tenant(ctx: Optional[TenantContext]) -> None:
    """Set the current request's tenant context."""
    _current_tenant.set(ctx)


def require_tenant() -> TenantContext:
    """
    Get tenant context or raise error.

    Raises:
        TenantRequiredError: If no tenant context is set
    """
    ctx = get_current_tenant()
    if not ctx:
        raise TenantRequiredError("No tenant context available")
    return ctx


def clear_tenant_context() -> None:
    """Clear the current tenant context."""
    _current_tenant.set(None)


# ============================================================================
# Exceptions
# ============================================================================

class TenantError(Exception):
    """Base exception for tenant operations."""
    pass


class TenantRequiredError(TenantError):
    """Raised when tenant context is required but not available."""
    pass


class TenantNotFoundError(TenantError):
    """Raised when a tenant is not found."""
    pass


class TenantSuspendedError(TenantError):
    """Raised when trying to use a suspended tenant."""
    pass


class TenantSlugExistsError(TenantError):
    """Raised when tenant slug already exists."""
    pass


class APIKeyError(Exception):
    """Base exception for API key operations."""
    pass


class APIKeyNotFoundError(APIKeyError):
    """Raised when API key is not found."""
    pass


class APIKeyInvalidError(APIKeyError):
    """Raised when API key is invalid or revoked."""
    pass


class ResourceLimitExceededError(TenantError):
    """Raised when a resource limit is exceeded."""
    def __init__(self, resource: str, limit: int, current: int):
        self.resource = resource
        self.limit = limit
        self.current = current
        super().__init__(f"Resource limit exceeded for {resource}: {current}/{limit}")


# ============================================================================
# Tenant Service
# ============================================================================

class TenantService:
    """
    Service for managing tenants.

    Handles:
    - Tenant CRUD operations
    - Tenant provisioning
    - API key management
    - Resource limit enforcement
    """

    # Regex for valid slug: lowercase letters, numbers, hyphens, 3-50 chars
    SLUG_PATTERN = re.compile(r'^[a-z][a-z0-9-]{2,49}$')

    # Reserved slugs that cannot be used
    RESERVED_SLUGS = {
        'admin', 'api', 'app', 'auth', 'default', 'help', 'internal',
        'koba', 'login', 'logout', 'public', 'root', 'static', 'system',
        'tenant', 'tenants', 'user', 'users', 'www',
    }

    def __init__(self, db: Optional[DatabaseManager] = None):
        """
        Initialize tenant service.

        Args:
            db: Database manager. If None, uses global instance.
        """
        self.db = db or get_db()

    def _is_valid_slug(self, slug: str) -> bool:
        """Check if slug is valid and not reserved."""
        if not self.SLUG_PATTERN.match(slug):
            return False
        if slug in self.RESERVED_SLUGS:
            return False
        return True

    def _generate_slug(self, name: str) -> str:
        """Generate a URL-safe slug from tenant name."""
        # Convert to lowercase, replace spaces with hyphens
        slug = name.lower().strip()
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        slug = re.sub(r'-+', '-', slug)  # Remove multiple hyphens
        slug = slug.strip('-')

        # Truncate if too long
        if len(slug) > 50:
            slug = slug[:50].rstrip('-')

        # Ensure minimum length
        if len(slug) < 3:
            slug = f"{slug}-tenant"

        return slug

    # --------------------------------------------------------------------------
    # Tenant CRUD
    # --------------------------------------------------------------------------

    def create_tenant(
        self,
        name: str,
        slug: Optional[str] = None,
        plan: TenantPlan = TenantPlan.FREE,
        settings: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tenant:
        """
        Create a new tenant.

        Args:
            name: Tenant display name
            slug: URL-safe identifier (generated from name if not provided)
            plan: Subscription plan
            settings: Tenant-specific settings
            metadata: Additional metadata

        Returns:
            Created tenant

        Raises:
            TenantSlugExistsError: If slug already exists
            ValueError: If slug is invalid
        """
        # Generate or validate slug
        if slug:
            slug = slug.lower().strip()
            if not self._is_valid_slug(slug):
                raise ValueError(f"Invalid slug: {slug}")
        else:
            slug = self._generate_slug(name)

        # Ensure uniqueness
        if self.get_tenant_by_slug(slug):
            # Try appending random suffix
            original_slug = slug
            for _ in range(5):
                slug = f"{original_slug[:40]}-{secrets.token_hex(3)}"
                if not self.get_tenant_by_slug(slug):
                    break
            else:
                raise TenantSlugExistsError(f"Slug already exists: {original_slug}")

        now = datetime.now(timezone.utc)
        resource_limits = PLAN_LIMITS.get(plan, ResourceLimits())

        with self.db.get_session() as session:
            model = TenantModel(
                id=generate_id("ten"),
                name=name,
                slug=slug,
                status=TenantStatus.ACTIVE.value,
                plan=plan.value,
                created_at=now,
                updated_at=now,
                settings=json.dumps(settings or {}),
                resource_limits=json.dumps(resource_limits.to_dict()),
                metadata_=json.dumps(metadata or {}),
            )
            session.add(model)
            session.flush()  # Get the ID

            return Tenant.from_model(model)

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID."""
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.id == tenant_id
            ).first()
            if model:
                return Tenant.from_model(model)
        return None

    def get_tenant_by_slug(self, slug: str) -> Optional[Tenant]:
        """Get tenant by slug."""
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.slug == slug.lower()
            ).first()
            if model:
                return Tenant.from_model(model)
        return None

    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        plan: Optional[TenantPlan] = None,
        settings: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Tenant]:
        """
        Update tenant details.

        Args:
            tenant_id: Tenant ID
            name: New name (optional)
            plan: New plan (optional)
            settings: New settings (merged with existing)
            metadata: New metadata (merged with existing)

        Returns:
            Updated tenant or None if not found
        """
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.id == tenant_id
            ).first()
            if not model:
                return None

            if name:
                model.name = name
            if plan:
                model.plan = plan.value
                # Update resource limits if plan changed
                model.resource_limits = json.dumps(
                    PLAN_LIMITS.get(plan, ResourceLimits()).to_dict()
                )
            if settings:
                existing = json.loads(model.settings) if model.settings else {}
                existing.update(settings)
                model.settings = json.dumps(existing)
            if metadata:
                existing = json.loads(model.metadata_) if model.metadata_ else {}
                existing.update(metadata)
                model.metadata_ = json.dumps(existing)

            model.updated_at = datetime.now(timezone.utc)
            session.flush()

            return Tenant.from_model(model)

    def suspend_tenant(self, tenant_id: str, reason: str = "") -> Optional[Tenant]:
        """
        Suspend a tenant.

        Args:
            tenant_id: Tenant to suspend
            reason: Suspension reason

        Returns:
            Updated tenant or None if not found
        """
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.id == tenant_id
            ).first()
            if not model:
                return None

            model.status = TenantStatus.SUSPENDED.value
            metadata = json.loads(model.metadata_) if model.metadata_ else {}
            metadata["suspension_reason"] = reason
            metadata["suspended_at"] = datetime.now(timezone.utc).isoformat()
            model.metadata_ = json.dumps(metadata)
            model.updated_at = datetime.now(timezone.utc)

            return Tenant.from_model(model)

    def reactivate_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Reactivate a suspended tenant."""
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.id == tenant_id
            ).first()
            if not model:
                return None

            model.status = TenantStatus.ACTIVE.value
            metadata = json.loads(model.metadata_) if model.metadata_ else {}
            metadata["reactivated_at"] = datetime.now(timezone.utc).isoformat()
            model.metadata_ = json.dumps(metadata)
            model.updated_at = datetime.now(timezone.utc)

            return Tenant.from_model(model)

    def delete_tenant(self, tenant_id: str, hard_delete: bool = False) -> bool:
        """
        Delete a tenant.

        Args:
            tenant_id: Tenant to delete
            hard_delete: If True, permanently remove all data

        Returns:
            True if tenant was deleted
        """
        with self.db.get_session() as session:
            model = session.query(TenantModel).filter(
                TenantModel.id == tenant_id
            ).first()
            if not model:
                return False

            if hard_delete:
                # Delete all related data
                session.query(APIKeyModel).filter(
                    APIKeyModel.tenant_id == tenant_id
                ).delete()
                session.query(PolicyBundleModel).filter(
                    PolicyBundleModel.tenant_id == tenant_id
                ).delete()
                # Note: Add more related tables as needed
                session.delete(model)
            else:
                # Soft delete
                model.status = TenantStatus.DELETED.value
                metadata = json.loads(model.metadata_) if model.metadata_ else {}
                metadata["deleted_at"] = datetime.now(timezone.utc).isoformat()
                model.metadata_ = json.dumps(metadata)
                model.updated_at = datetime.now(timezone.utc)

            return True

    def list_tenants(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[TenantStatus] = None,
        plan: Optional[TenantPlan] = None,
    ) -> List[Tenant]:
        """
        List tenants with optional filtering.

        Args:
            limit: Maximum results
            offset: Skip first N results
            status: Filter by status
            plan: Filter by plan

        Returns:
            List of tenants
        """
        with self.db.get_session() as session:
            query = session.query(TenantModel)

            if status:
                query = query.filter(TenantModel.status == status.value)
            else:
                # By default, exclude deleted
                query = query.filter(TenantModel.status != TenantStatus.DELETED.value)

            if plan:
                query = query.filter(TenantModel.plan == plan.value)

            query = query.order_by(TenantModel.created_at.desc())
            query = query.offset(offset).limit(limit)

            return [Tenant.from_model(m) for m in query.all()]

    def count_tenants(self, include_deleted: bool = False) -> int:
        """Count total tenants."""
        with self.db.get_session() as session:
            query = session.query(TenantModel)
            if not include_deleted:
                query = query.filter(TenantModel.status != TenantStatus.DELETED.value)
            return query.count()

    # --------------------------------------------------------------------------
    # API Key Management
    # --------------------------------------------------------------------------

    def create_api_key(
        self,
        tenant_id: str,
        name: str,
        permissions: Optional[List[str]] = None,
        rate_limit_rpm: int = 60,
        expires_in_days: Optional[int] = None,
        created_by: Optional[str] = None,
    ) -> Tuple[str, APIKey]:
        """
        Create a new API key for a tenant.

        Args:
            tenant_id: Tenant ID
            name: Key name/description
            permissions: List of permission strings
            rate_limit_rpm: Requests per minute limit
            expires_in_days: Days until expiration (None = never)
            created_by: User ID who created the key

        Returns:
            Tuple of (full_key, APIKey object)
            Note: The full key is only returned once!

        Raises:
            TenantNotFoundError: If tenant doesn't exist
            ResourceLimitExceededError: If tenant has too many keys
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise TenantNotFoundError(f"Tenant not found: {tenant_id}")

        # Check resource limits
        current_keys = self.count_api_keys(tenant_id)
        limit = tenant.resource_limits.max_api_keys
        if limit > 0 and current_keys >= limit:
            raise ResourceLimitExceededError("api_keys", limit, current_keys)

        # Generate key
        full_key, key_prefix, key_hash = generate_api_key()

        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_in_days:
            expires_at = now + timedelta(days=expires_in_days)

        with self.db.get_session() as session:
            model = APIKeyModel(
                id=generate_id("key"),
                tenant_id=tenant_id,
                name=name,
                key_prefix=key_prefix,
                key_hash=key_hash,
                permissions=json.dumps(permissions or []),
                rate_limit_rpm=rate_limit_rpm,
                status=APIKeyStatus.ACTIVE.value,
                created_at=now,
                expires_at=expires_at,
                created_by=created_by,
            )
            session.add(model)
            session.flush()

            api_key = APIKey.from_model(model)

        return full_key, api_key

    def validate_api_key(self, key: str) -> Optional[Tuple[APIKey, Tenant]]:
        """
        Validate an API key and return associated tenant.

        Args:
            key: Full API key string

        Returns:
            Tuple of (APIKey, Tenant) if valid, None if invalid

        Also updates last_used_at timestamp.
        """
        if not key or not key.startswith("koba_"):
            return None

        key_hash = hash_api_key(key)
        key_prefix = key[:12]

        with self.db.get_session() as session:
            model = session.query(APIKeyModel).filter(
                APIKeyModel.key_prefix == key_prefix,
                APIKeyModel.key_hash == key_hash,
            ).first()

            if not model:
                return None

            # Check status
            if model.status != APIKeyStatus.ACTIVE.value:
                return None

            # Check expiration
            if model.expires_at and model.expires_at < datetime.now(timezone.utc):
                model.status = APIKeyStatus.EXPIRED.value
                return None

            # Update last used
            model.last_used_at = datetime.now(timezone.utc)

            # Get tenant
            tenant_model = session.query(TenantModel).filter(
                TenantModel.id == model.tenant_id
            ).first()

            if not tenant_model:
                return None

            # Check tenant status
            if tenant_model.status != TenantStatus.ACTIVE.value:
                return None

            return APIKey.from_model(model), Tenant.from_model(tenant_model)

    def get_api_key(self, key_id: str) -> Optional[APIKey]:
        """Get API key by ID."""
        with self.db.get_session() as session:
            model = session.query(APIKeyModel).filter(
                APIKeyModel.id == key_id
            ).first()
            if model:
                return APIKey.from_model(model)
        return None

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        with self.db.get_session() as session:
            model = session.query(APIKeyModel).filter(
                APIKeyModel.id == key_id
            ).first()
            if not model:
                return False

            model.status = APIKeyStatus.REVOKED.value
            return True

    def list_api_keys(
        self,
        tenant_id: str,
        include_revoked: bool = False,
    ) -> List[APIKey]:
        """List API keys for a tenant."""
        with self.db.get_session() as session:
            query = session.query(APIKeyModel).filter(
                APIKeyModel.tenant_id == tenant_id
            )

            if not include_revoked:
                query = query.filter(APIKeyModel.status == APIKeyStatus.ACTIVE.value)

            query = query.order_by(APIKeyModel.created_at.desc())

            return [APIKey.from_model(m) for m in query.all()]

    def count_api_keys(self, tenant_id: str) -> int:
        """Count active API keys for a tenant."""
        with self.db.get_session() as session:
            return session.query(APIKeyModel).filter(
                APIKeyModel.tenant_id == tenant_id,
                APIKeyModel.status == APIKeyStatus.ACTIVE.value,
            ).count()

    # --------------------------------------------------------------------------
    # Tenant Context Resolution
    # --------------------------------------------------------------------------

    def resolve_tenant_context(
        self,
        api_key: Optional[str] = None,
        tenant_slug: Optional[str] = None,
        user_id: Optional[str] = None,
        user_tenant_id: Optional[str] = None,
        user_role: Optional[str] = None,
        is_system_admin: bool = False,
    ) -> Optional[TenantContext]:
        """
        Resolve tenant context from various sources.

        Priority:
        1. API key (contains tenant)
        2. User's tenant (from JWT)
        3. Subdomain/slug

        Args:
            api_key: Full API key string
            tenant_slug: Tenant slug from subdomain
            user_id: User ID from JWT
            user_tenant_id: Tenant ID from JWT
            user_role: User role from JWT
            is_system_admin: Whether user is system admin

        Returns:
            TenantContext if resolved, None otherwise
        """
        tenant: Optional[Tenant] = None
        api_key_obj: Optional[APIKey] = None

        # Priority 1: API Key
        if api_key:
            result = self.validate_api_key(api_key)
            if result:
                api_key_obj, tenant = result

        # Priority 2: User's tenant from JWT
        if not tenant and user_tenant_id:
            tenant = self.get_tenant(user_tenant_id)

        # Priority 3: Subdomain
        if not tenant and tenant_slug:
            tenant = self.get_tenant_by_slug(tenant_slug)

        if not tenant:
            return None

        # Check tenant status
        if tenant.status == TenantStatus.SUSPENDED:
            raise TenantSuspendedError(f"Tenant is suspended: {tenant.slug}")
        if tenant.status == TenantStatus.DELETED:
            return None

        return TenantContext(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            tenant_slug=tenant.slug,
            plan=tenant.plan,
            is_system_admin=is_system_admin,
            user_id=user_id,
            user_role=UserRole(user_role) if user_role else None,
            api_key_id=api_key_obj.id if api_key_obj else None,
            resource_limits=tenant.resource_limits,
            settings=tenant.settings,
        )


# ============================================================================
# Provisioning
# ============================================================================

class TenantProvisioner:
    """
    Handles tenant provisioning workflow.

    Creates tenant with:
    - Initial admin user
    - Default API key
    - Default policy bundle
    """

    def __init__(
        self,
        tenant_service: Optional[TenantService] = None,
        db: Optional[DatabaseManager] = None,
    ):
        self.tenant_service = tenant_service or TenantService(db)
        self.db = db or get_db()

    def provision_tenant(
        self,
        name: str,
        slug: Optional[str] = None,
        plan: TenantPlan = TenantPlan.FREE,
        admin_email: str = None,
        admin_username: str = None,
        admin_password: str = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Provision a new tenant with initial setup.

        Args:
            name: Tenant name
            slug: URL slug
            plan: Subscription plan
            admin_email: Initial admin email
            admin_username: Initial admin username
            admin_password: Initial admin password
            settings: Tenant settings

        Returns:
            Dict with tenant, admin_user, and api_key info
        """
        from .auth import PasswordHasher  # Import here to avoid circular import

        # 1. Create tenant
        tenant = self.tenant_service.create_tenant(
            name=name,
            slug=slug,
            plan=plan,
            settings=settings,
        )

        result = {
            "tenant": tenant.to_dict(),
            "admin_user": None,
            "api_key": None,
        }

        # 2. Create admin user if credentials provided
        if admin_email and admin_password:
            now = datetime.now(timezone.utc)
            username = admin_username or "admin"

            with self.db.get_session() as session:
                user_model = UserModel(
                    id=generate_id("usr"),
                    tenant_id=tenant.id,
                    email=admin_email,
                    username=username,
                    password_hash=PasswordHasher.hash(admin_password),
                    role=UserRole.TENANT_OWNER.value,
                    is_system_admin=False,
                    created_at=now,
                    updated_at=now,
                    is_active=True,
                )
                session.add(user_model)
                session.flush()

                result["admin_user"] = {
                    "id": user_model.id,
                    "email": user_model.email,
                    "username": user_model.username,
                    "role": user_model.role,
                }

                # 3. Create default API key
                full_key, api_key = self.tenant_service.create_api_key(
                    tenant_id=tenant.id,
                    name="Default API Key",
                    permissions=["*"],  # Full access
                    created_by=user_model.id,
                )

                result["api_key"] = {
                    "key": full_key,  # Only shown once!
                    "id": api_key.id,
                    "name": api_key.name,
                }

        return result


# ============================================================================
# Default Tenant Creation
# ============================================================================

def create_default_tenant(db: Optional[DatabaseManager] = None) -> Optional[Tenant]:
    """
    Create the default tenant if it doesn't exist.

    Returns:
        Default tenant or None if it already exists
    """
    service = TenantService(db)

    # Check if default tenant exists
    existing = service.get_tenant_by_slug("default")
    if existing:
        return None

    return service.create_tenant(
        name="Default Tenant",
        slug="default",
        plan=TenantPlan.ENTERPRISE,
        settings={"is_default": True},
    )
