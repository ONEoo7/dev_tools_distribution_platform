"""What the add-source form refuses.

An operator is trusted to decide whose builds to accept. They are not trusted
to hand-type a string that is about to become a TUF role name, a URL path
segment, or an egress destination — not because they are adversarial, but
because a typo in any of those is silent.
"""

from __future__ import annotations

import pytest

from dist_admin.forms import FormError, source_from_form
from dist_registry.models import Forge, SourceStatus

GITHUB = {
    "app_id": "git-assistant",
    "forge": "github",
    "project": "ONEoo7/ai_tools_git_assistant",
    "asset_name": "git-assistant-0.1.0-windows-x64.zip",
    "workflow_uri": "https://github.com/ONEoo7/ai_tools_git_assistant/.github/workflows/release.yml",
}

# A syntactically valid ed25519 public key. Only its parseability matters here.
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""

GITLAB = {
    "app_id": "internal-tool",
    "forge": "gitlab",
    "project": "platform/tools/internal-tool",
    "api_base": "https://gitlab.example.com",
    "asset_name": "internal-tool-setup.exe",
    "builder_id": "https://gitlab.example.com/platform/tools/internal-tool/-/ci",
    "builder_keyid": "a1b2c3",
    "builder_public_key_pem": PUBLIC_KEY,
}


def test_a_github_form_yields_a_draft_source() -> None:
    source = source_from_form(dict(GITHUB), actor="alice")

    assert source.forge is Forge.GITHUB
    assert source.app_id == "git-assistant"
    assert source.project_url == "https://github.com/ONEoo7/ai_tools_git_assistant"
    assert source.created_by == "alice"
    # Never anything else, whatever was submitted.
    assert source.status is SourceStatus.DRAFT


def test_the_numeric_ids_are_not_taken_from_the_form() -> None:
    """They are read from the forge during validation.

    The value of pinning a repository id is that it was not guessed. Accepting
    one here would let a mistyped id pin the wrong repository, or a copied one
    pin a repository the operator never looked at.
    """
    source = source_from_form(
        {**GITHUB, "repository_id": "999", "repository_owner_id": "999"}, actor="alice"
    )

    assert source.repository_id is None
    assert source.repository_owner_id is None


def test_a_gitlab_form_yields_a_pinned_builder() -> None:
    source = source_from_form(dict(GITLAB), actor="bob")

    assert source.forge is Forge.GITLAB
    assert source.builder_keyid == "a1b2c3"
    assert source.project_url == "https://gitlab.example.com/platform/tools/internal-tool"


def test_critical_selects_offline_custody() -> None:
    source = source_from_form({**GITHUB, "critical": "on"}, actor="alice")
    assert source.critical is True


# ------------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    "app_id",
    [
        "Git-Assistant",  # upper case: not a usable role name
        "a",  # too short
        "app_id",  # underscore
        "../etc/passwd",
        "app/../other",
        "",
    ],
)
def test_an_app_id_that_is_not_a_usable_role_name_is_refused(app_id: str) -> None:
    with pytest.raises(FormError):
        source_from_form({**GITHUB, "app_id": app_id}, actor="alice")


@pytest.mark.parametrize(
    "project",
    [
        "owner",  # no repo
        "owner/../../etc",
        "https://github.com/owner/repo",  # a URL, not a path
        "owner/repo?x=1",
        "owner//repo",
    ],
)
def test_a_project_path_that_could_alter_a_request_is_refused(project: str) -> None:
    with pytest.raises(FormError):
        source_from_form({**GITHUB, "project": project}, actor="alice")


@pytest.mark.parametrize(
    "asset",
    ["../../etc/passwd", "sub/dir/app.exe", "", ".hidden"],
)
def test_an_asset_name_with_a_path_in_it_is_refused(asset: str) -> None:
    with pytest.raises(FormError, match="asset"):
        source_from_form({**GITHUB, "asset_name": asset}, actor="alice")


@pytest.mark.parametrize(
    "api_base",
    [
        "http://api.github.com",  # plaintext
        "ftp://example.com",
        "api.github.com",  # no scheme
        "https://",  # no host
    ],
)
def test_a_non_https_api_base_is_refused(api_base: str) -> None:
    """The worker's egress allowlist is derived from this field.

    A typo here is a request to a host nobody approved.
    """
    with pytest.raises(FormError, match="API base"):
        source_from_form({**GITHUB, "api_base": api_base}, actor="alice")


def test_a_workflow_uri_carrying_a_ref_is_refused() -> None:
    """The SAN is `<workflow_uri>@<ref>` and the ref changes every release.

    Pinning it whole would mean a configuration edit per release, so the form
    takes the ref-invariant part and the ref is checked separately.
    """
    with pytest.raises(FormError, match="without a ref"):
        source_from_form(
            {**GITHUB, "workflow_uri": f"{GITHUB['workflow_uri']}@refs/tags/v1.0.0"},
            actor="alice",
        )


def test_a_ref_prefix_that_would_admit_branch_builds_is_refused() -> None:
    with pytest.raises(FormError, match="refs/"):
        source_from_form({**GITHUB, "require_tag_ref_prefix": "anything"}, actor="alice")


def test_a_builder_key_that_does_not_load_is_refused_at_the_form() -> None:
    """Rather than at every release, with an error pointing at the attestation."""
    with pytest.raises(FormError, match="PEM public key"):
        source_from_form({**GITLAB, "builder_public_key_pem": "not a key"}, actor="bob")


def test_an_unreasonable_asset_cap_is_refused() -> None:
    with pytest.raises(FormError, match="cap"):
        source_from_form({**GITHUB, "max_asset_bytes": str(64 * 1024**3)}, actor="alice")


def test_an_unknown_forge_is_refused() -> None:
    with pytest.raises(FormError, match="unknown forge"):
        source_from_form({**GITHUB, "forge": "bitbucket"}, actor="alice")
