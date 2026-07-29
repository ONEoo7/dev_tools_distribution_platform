"""What a registered source is, and what it is allowed to become.

A `Source` is the operator-supplied half of "add a repo". The other half — the
`app-<id>` delegation in `targets.json` — cannot be created from here at all,
because `targets` signs with an offline key (`dist_core.roles.TARGETS_POLICY`)
and PLAN.md 8.2 forbids the web application from mutating TUF metadata under
any circumstances. `SourceStatus` is where that shows up: a source validated
against the forge lands in `PENDING_DELEGATION` and stays there until a human
runs the ceremony. Nothing in this package can move it past that point.

The fields below are the inputs to a `ProvenancePolicy`. They are stored rather
than derived because they are a *pin*: the point of recording a repository's
numeric id is that a later mismatch is detectable, which requires having
written down what was true when the operator made the decision.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Forge(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


class SourceStatus(StrEnum):
    """Where a source is between "typed into a form" and "being ingested".

    The order is a ratchet in one direction only for the step that matters:
    nothing but a signing ceremony moves `PENDING_DELEGATION` to `ACTIVE`.
    """

    #: Created, never checked against the forge.
    DRAFT = "draft"
    #: A validation job is queued or running.
    VALIDATING = "validating"
    #: The forge disagreed: no such project, no releases, unusable tag.
    INVALID = "invalid"
    #: Validated. Waiting on the offline ceremony that creates `app-<id>`.
    PENDING_DELEGATION = "pending_delegation"
    #: Delegation exists; the worker will poll this source.
    ACTIVE = "active"
    #: Operator stopped polling. Delegation is untouched.
    PAUSED = "paused"


class JobKind(StrEnum):
    #: Ask the forge what it knows about this project. Read-only, no ingest.
    VALIDATE = "validate"
    #: Fetch the latest release and run it through the ingestion policy.
    POLL = "poll"
    #: Sign an approved artifact into the repository and make it current.
    #: Claimed only by the signing worker, which is the one component holding
    #: the online keys and the only one that may write TUF metadata.
    PUBLISH = "publish"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Source:
    """One forge project registered as a source of installers for one app."""

    id: uuid.UUID
    app_id: str
    forge: Forge
    project: str
    api_base: str
    project_url: str
    status: SourceStatus

    #: Selects offline key custody for the app's delegated role, and therefore
    #: whether ingestion may ever promote without a human. Mirrors the
    #: `critical` argument to `dist_core.roles.app_role_policy`.
    critical: bool

    #: The release asset that is the installer. May carry `{version}`, which
    #: `ForgeRelease.resolve_asset_name` substitutes from the tag — without it,
    #: a versioned filename matches exactly one release and then fails every
    #: poll. A release carrying several platforms' artifacts needs one source
    #: per app id.
    asset_name: str
    tag_prefix: str
    require_tag_ref_prefix: str
    max_asset_bytes: int

    #: Where this source's artifact is published. One source is one artifact,
    #: so these belong to the source rather than being decided at signing time
    #: — a signer that hardcodes a platform misfiles artifacts silently.
    channel: str = "stable"
    platform: str = "windows"
    arch: str = "amd64"

    # -- GitHub: certificate identity (PLAN.md 4.1, "Certificate identity")
    workflow_uri: str | None = None
    oidc_issuer: str | None = None
    repository_id: str | None = None
    repository_owner_id: str | None = None
    runner_environment: str = "github-hosted"

    # -- GitLab: pinned builder key (PLAN.md 4.1, "Fixed key")
    builder_id: str | None = None
    builder_keyid: str | None = None
    builder_public_key_pem: str | None = None
    attestation_asset: str = "provenance.intoto.jsonl"

    created_at: datetime | None = None
    updated_at: datetime | None = None
    created_by: str = ""
    last_error: str | None = None

    @property
    def pollable(self) -> bool:
        """Whether the worker may fetch releases for this source.

        `PENDING_DELEGATION` is excluded deliberately. Polling it would fill
        quarantine with artifacts that cannot be promoted, and would make the
        UI look like the app is live when no client can receive it.
        """
        return self.status is SourceStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class Job:
    """A unit of work for one of the two credential-holding services.

    `kind` decides which: the ingest worker claims `validate` and `poll` and
    holds the forge token; the signing worker claims `publish` and holds the
    online keys. Neither claims the other's work, so a compromise of one does
    not become an instruction the other will carry out.
    """

    id: uuid.UUID
    source_id: uuid.UUID
    kind: JobKind
    state: JobState
    requested_by: str
    requested_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    attempts: int = 0
    #: What this job acts on, fixed when it was queued. A publish job names its
    #: artifact by digest so the signer signs what ingestion approved rather
    #: than whatever is newest in quarantine by the time it runs.
    payload: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One operator action, recorded before it takes effect.

    PLAN.md 8.2 requires control actions to be auditable. Registering a source
    is a control action: it is the decision about whose builds this system will
    consider signing.
    """

    id: int
    at: datetime
    actor: str
    action: str
    source_id: uuid.UUID | None
    detail: dict[str, Any]
