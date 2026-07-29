"""Turning what an operator typed into a `Source`, or refusing to.

Everything here is operator input, and an operator is trusted to make policy
decisions but not to hand-type a URL that is about to become a path segment, a
TUF role name, or an egress destination. The checks are therefore about shape,
not about authority:

- `app_id` becomes a TUF role name and a filename, so it is held to
  `dist_core.roles.APP_ID_PATTERN` here as well as there.
- `project` and `asset_name` become URL path segments in requests the worker
  makes, so neither may carry a traversal or a scheme.
- `api_base`, `workflow_uri` and `oidc_issuer` must be HTTPS. The worker's
  egress allowlist is derived from `api_base`, so a typo there is a request to
  a host nobody approved.

None of this establishes that the repository should be trusted. That is what
provenance verification and the delegation ceremony are for.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from dist_core.roles import APP_ID_PATTERN
from dist_registry.models import Forge, Source, SourceStatus

#: `owner/repo`, or a GitLab group path of up to four segments. Deliberately
#: narrow: every character permitted here ends up in a URL the worker fetches.
#:
#: The charset alone is not enough. Dot is legitimate in a repository name
#: (`my.app`), so a pattern that admits it also admits `owner/../../etc` — and
#: on the GitHub path the project is interpolated into the URL directly, where
#: an HTTP client resolves the dot segments away and lands on a different
#: endpoint. `_no_traversal` is what actually stops that; the pattern only
#: bounds the alphabet.
_PROJECT = re.compile(r"\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){1,4}\Z")

#: A release asset filename, optionally carrying `{version}`. No separators, no
#: leading dot.
#:
#: Braces are permitted so that a name whose version changes every release can
#: still be matched — see `dist_ingest.forge.VERSION_PLACEHOLDER`. They widen
#: the alphabet only; the substituted value comes from the tag, which
#: `dist_ingest.forge` has already constrained to digits, dots and a
#: pre-release suffix, so substitution cannot introduce a separator.
_ASSET = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+{}-]{0,127}\Z")

#: The only placeholder recognised. Anything else between braces is a typo the
#: operator will otherwise discover as a polling failure days later.
_ASSET_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

_TAG_PREFIX = re.compile(r"\A[A-Za-z0-9._-]{0,16}\Z")

MAX_ASSET_BYTES_CEILING = 8 * 1024 * 1024 * 1024

DEFAULT_API_BASE = {
    Forge.GITHUB: "https://api.github.com",
    Forge.GITLAB: "https://gitlab.com",
}

DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

#: Where GitHub Actions keeps workflows, and the file most projects publish
#: from. Used to derive the workflow URI when the operator leaves it blank —
#: `<project_url>/.github/workflows/release.yml`.
#:
#: Derived rather than typed because the alternative is an operator
#: transcribing their own repository path into a URL by hand, which is both
#: tedious and the kind of thing a typo hides in. A wrong value fails closed:
#: the certificate SAN will not match and every release is rejected, so the
#: cost of the default being wrong is a source that never promotes, not one
#: that promotes something it should not.
DEFAULT_WORKFLOW_PATH = ".github/workflows/release.yml"


def derived_workflow_uri(project_url: str) -> str:
    """The workflow URI implied by a project URL."""
    return f"{project_url}/{DEFAULT_WORKFLOW_PATH}"


def _suggest_app_id(typed: str) -> str | None:
    """A usable application id resembling what was typed, if there is one.

    Offered rather than applied. The id becomes a TUF role name and a path
    segment and cannot be changed afterwards, so silently correcting it would
    save a keystroke and cost the operator their only chance to notice that the
    stored value is not the one they meant.

    Returns `None` when nothing salvageable falls out, rather than proposing
    something arbitrary.
    """
    candidate = re.sub(r"[^a-z0-9]+", "-", typed.strip().lower()).strip("-")
    if candidate == typed or not APP_ID_PATTERN.match(candidate):
        return None
    return candidate


def _suggest_project(typed: str) -> str | None:
    """The `owner/repo` inside a pasted project URL, if that is what was typed.

    Pasting the browser URL is the obvious thing to do, and the field wants the
    path alone because the host is configured separately as the API base —
    which is also why this only ever suggests. Accepting a URL outright would
    silently discard the host it carries, so a self-hosted URL pasted here
    would register against the default forge and fail later as a project that
    does not exist.
    """
    parts = urlsplit(typed)
    if not parts.scheme or not parts.hostname:
        return None

    candidate = parts.path.strip("/").removesuffix(".git")
    if not candidate or not _PROJECT.match(candidate) or not _no_traversal(candidate):
        return None
    return candidate


class FormError(ValueError):
    """The form was not usable. The message is shown to the operator."""


def _text(data: dict[str, Any], key: str, default: str = "") -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise FormError(f"{key} must be text")
    return value.strip()


def _https(value: str, field: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise FormError(f"{field} must be an https:// URL with a host")
    if parts.query or parts.fragment:
        raise FormError(f"{field} must not carry a query string or fragment")
    return value.rstrip("/")


def _require(value: str, field: str) -> str:
    if not value:
        raise FormError(f"{field} is required")
    return value


def source_from_form(data: dict[str, Any], *, actor: str) -> Source:
    """Build a `Source` from submitted form fields.

    Raises:
        FormError: on anything unusable, with a message meant for the operator.
    """
    app_id = _require(_text(data, "app_id"), "Application id")
    if not APP_ID_PATTERN.match(app_id):
        message = (
            "application id must be lower case letters, digits and hyphens, 2 to 63 characters"
        )
        suggestion = _suggest_app_id(app_id)
        if suggestion:
            message += f" — did you mean {suggestion!r}?"
        raise FormError(message)

    raw_forge = _require(_text(data, "forge"), "Forge")
    try:
        forge = Forge(raw_forge)
    except ValueError as exc:
        raise FormError(f"unknown forge {raw_forge!r}") from exc

    project = _require(_text(data, "project"), "Project")
    if not _PROJECT.match(project) or not _no_traversal(project):
        message = "project must look like 'owner/repo', with no scheme and no '..'"
        suggestion = _suggest_project(project)
        if suggestion:
            host = urlsplit(project).hostname
            message += (
                f" — did you mean {suggestion!r}? The host ({host}) belongs in API base, not here."
            )
        raise FormError(message)

    api_base = _https(_text(data, "api_base") or DEFAULT_API_BASE[forge], "API base")

    asset_name = _require(_text(data, "asset_name"), "Installer asset")
    if not _ASSET.match(asset_name):
        raise FormError("installer asset must be a bare filename with no path separators")
    for found in _ASSET_PLACEHOLDER.findall(asset_name):
        if found != "version":
            raise FormError(
                f"unknown placeholder {'{' + found + '}'!r} in the installer asset; "
                "only {version} is substituted"
            )
    if asset_name.count("{") != asset_name.count("}"):
        raise FormError("unbalanced braces in the installer asset name")

    tag_prefix = _text(data, "tag_prefix", "v")
    if not _TAG_PREFIX.match(tag_prefix):
        raise FormError("tag prefix may only contain letters, digits, dot, dash and underscore")

    ref_prefix = _text(data, "require_tag_ref_prefix") or "refs/tags/"
    if not ref_prefix.startswith("refs/"):
        raise FormError(
            "the required ref prefix must start with 'refs/' — it is what stops a build "
            "from an unprotected branch being accepted"
        )

    max_asset_bytes = _positive_int(data, "max_asset_bytes", 2 * 1024 * 1024 * 1024)
    if max_asset_bytes > MAX_ASSET_BYTES_CEILING:
        raise FormError(f"the asset cap may not exceed {MAX_ASSET_BYTES_CEILING} bytes")

    common: dict[str, Any] = {
        "id": uuid.uuid4(),
        "app_id": app_id,
        "forge": forge,
        "project": project,
        "api_base": api_base,
        "project_url": _project_url(forge, api_base, project),
        "status": SourceStatus.DRAFT,
        "critical": _checkbox(data, "critical"),
        "asset_name": asset_name,
        "tag_prefix": tag_prefix,
        "require_tag_ref_prefix": ref_prefix,
        "max_asset_bytes": max_asset_bytes,
        "created_by": actor,
    }

    if forge is Forge.GITHUB:
        return Source(**common, **_github_fields(data, common["project_url"]))
    return Source(**common, **_gitlab_fields(data))


#: What an operator may change on a source that already exists.
#:
#: Everything absent from this list defines *what is trusted* rather than how a
#: trusted thing is handled, and a delegation was granted on the strength of
#: it. `app_id` names the TUF role that signs; `project`, `forge`, `api_base`
#: and `project_url` decide whose releases those signatures cover;
#: `workflow_uri`, `oidc_issuer`, `runner_environment` and the builder pins are
#: the provenance policy; `repository_id` and `repository_owner_id` were read
#: from the forge by the worker and never typed by anyone.
#:
#: Allowing any of those to be edited would turn "change a setting" into
#: "re-point a delegation somebody already approved" — the whole reason
#: `add_source` refuses to accept a status and activation runs through
#: `mark_delegated`. Getting those wrong is what deleting and re-registering is
#: for, because it puts the source back through validation.
#:
#: What remains either selects among artifacts of a release that has already
#: been verified, or constrains which releases qualify at all.
EDITABLE_FIELDS = frozenset(
    {
        "asset_name",
        "tag_prefix",
        "require_tag_ref_prefix",
        "max_asset_bytes",
        "critical",
        "channel",
        "platform",
        "arch",
    }
)


def source_edit_from_form(data: dict[str, Any], existing: Source) -> dict[str, Any]:
    """Validate an edit, returning only the fields that actually changed.

    Reuses the same validators as registration — a rule that holds when a
    source is created and not when it is edited is not a rule.

    Returns:
        A mapping of column name to new value, empty when nothing changed.

    Raises:
        FormError: on anything unusable, with a message meant for the operator.
    """
    asset_name = _require(_text(data, "asset_name"), "Installer asset")
    if not _ASSET.match(asset_name):
        raise FormError("installer asset must be a bare filename with no path separators")
    for found in _ASSET_PLACEHOLDER.findall(asset_name):
        if found != "version":
            raise FormError(
                f"unknown placeholder {'{' + found + '}'!r} in the installer asset; "
                "only {version} is substituted"
            )
    if asset_name.count("{") != asset_name.count("}"):
        raise FormError("unbalanced braces in the installer asset name")

    tag_prefix = _text(data, "tag_prefix", existing.tag_prefix)
    if not _TAG_PREFIX.match(tag_prefix):
        raise FormError("tag prefix may only contain letters, digits, dot, dash and underscore")

    ref_prefix = _text(data, "require_tag_ref_prefix") or existing.require_tag_ref_prefix
    if not ref_prefix.startswith("refs/"):
        raise FormError(
            "the required ref prefix must start with 'refs/' — it is what stops a build "
            "from an unprotected branch being accepted"
        )

    max_asset_bytes = _positive_int(data, "max_asset_bytes", existing.max_asset_bytes)
    if max_asset_bytes > MAX_ASSET_BYTES_CEILING:
        raise FormError(f"the asset cap may not exceed {MAX_ASSET_BYTES_CEILING} bytes")

    proposed: dict[str, Any] = {
        "asset_name": asset_name,
        "tag_prefix": tag_prefix,
        "require_tag_ref_prefix": ref_prefix,
        "max_asset_bytes": max_asset_bytes,
        "critical": _checkbox(data, "critical"),
        "channel": _slug(data, "channel", existing.channel, "Channel"),
        "platform": _slug(data, "platform", existing.platform, "Platform"),
        "arch": _slug(data, "arch", existing.arch, "Architecture"),
    }

    # Only what differs, so the audit entry records the change rather than the
    # whole form, and an accidental save writes nothing.
    return {k: v for k, v in proposed.items() if getattr(existing, k) != v}


_SLUG = re.compile(r"\A[a-z0-9][a-z0-9-]{0,31}\Z")


def _slug(data: dict[str, Any], key: str, default: str, field: str) -> str:
    """A single path segment in a TUF target name.

    Constrained rather than trusted: these become directory names under the
    application's delegated prefix, so anything that could climb out of it is
    refused here as well as where the path is built.
    """
    value = _text(data, key) or default
    if not _SLUG.match(value):
        raise FormError(f"{field} must be lower case letters, digits and hyphens")
    return value


def _github_fields(data: dict[str, Any], project_url: str) -> dict[str, Any]:
    """The certificate-identity pins (PLAN.md 4.1).

    `repository_id` and `repository_owner_id` are absent on purpose: they are
    read from the forge by the worker during validation, not typed. An operator
    copying a numeric id by hand is an operator who can paste the wrong one,
    and the whole value of pinning it is that it was not guessed.

    The workflow URI follows from the project unless it is given, so the common
    case needs no typing. It is derived rather than left blank because it is a
    pin: something has to be stored, and `<project>/.github/workflows/release.yml`
    is both the convention and visible on the source's page afterwards.
    """
    submitted = _text(data, "workflow_uri")
    workflow_uri = _https(submitted or derived_workflow_uri(project_url), "Release workflow URI")
    if "@" in workflow_uri:
        raise FormError(
            "give the workflow without a ref — the ref changes every release and is "
            "checked separately against the required ref prefix"
        )
    return {
        "workflow_uri": workflow_uri,
        "oidc_issuer": _https(_text(data, "oidc_issuer") or DEFAULT_OIDC_ISSUER, "OIDC issuer"),
        "runner_environment": _text(data, "runner_environment") or "github-hosted",
    }


def _gitlab_fields(data: dict[str, Any]) -> dict[str, Any]:
    """The pinned builder key (PLAN.md 4.1).

    The PEM is parsed rather than stored as typed. A key that does not load is
    a source that would reject every release with an error pointing at the
    attestation instead of at this form.
    """
    pem = _require(_text(data, "builder_public_key_pem"), "Builder public key")
    try:
        serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise FormError(f"builder public key is not a usable PEM public key: {exc}") from exc

    return {
        "builder_id": _require(_text(data, "builder_id"), "Builder id"),
        "builder_keyid": _require(_text(data, "builder_keyid"), "Builder key id"),
        "builder_public_key_pem": pem,
        "attestation_asset": _text(data, "attestation_asset") or "provenance.intoto.jsonl",
    }


def _project_url(forge: Forge, api_base: str, project: str) -> str:
    """The project URL the attestation must name.

    Checked by `provenance.check_statement` against the SLSA
    `resolvedDependencies` entry, so it has to be the web URL rather than the
    API base — which differ on GitHub and coincide on GitLab.
    """
    if forge is Forge.GITHUB:
        host = (
            "github.com"
            if api_base == DEFAULT_API_BASE[Forge.GITHUB]
            else urlsplit(api_base).hostname
        )
        return f"https://{host}/{project}"
    return f"{api_base}/{project}"


def _no_traversal(path: str) -> bool:
    """No segment is `.` or `..`.

    Checked against the segments rather than by searching for the substring:
    `my..app` is an odd but legitimate repository name, and `..` as a whole
    segment is the only form that resolves anywhere.
    """
    return all(segment not in {".", ".."} for segment in path.split("/"))


def _checkbox(data: dict[str, Any], key: str) -> bool:
    return _text(data, key).lower() in {"on", "true", "1", "yes"}


def _positive_int(data: dict[str, Any], key: str, default: int) -> int:
    raw = _text(data, key)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise FormError(f"{key} must be a whole number") from exc
    if value <= 0:
        raise FormError(f"{key} must be greater than zero")
    return value
