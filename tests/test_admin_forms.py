"""What the add-source form refuses.

An operator is trusted to decide whose builds to accept. They are not trusted
to hand-type a string that is about to become a TUF role name, a URL path
segment, or an egress destination — not because they are adversarial, but
because a typo in any of those is silent.
"""

from __future__ import annotations

import uuid

import pytest

from dist_admin.forms import (
    EDITABLE_FIELDS,
    FormError,
    source_edit_from_form,
    source_from_form,
)
from dist_registry.models import Forge, Source, SourceStatus

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


# --------------------------------------------------- the {version} placeholder


def test_a_versioned_asset_name_is_accepted() -> None:
    source = source_from_form(
        {**GITHUB, "asset_name": "git-assistant-{version}-windows-x64.zip"}, actor="alice"
    )
    assert source.asset_name == "git-assistant-{version}-windows-x64.zip"


@pytest.mark.parametrize(
    "asset",
    [
        "app-{ver}-x64.zip",
        "app-{Version}-x64.zip",
        "app-{}-x64.zip",
        "app-{version}-{platform}.zip",
    ],
)
def test_an_unknown_placeholder_is_refused(asset: str) -> None:
    """Caught here rather than days later as a polling failure.

    A misspelled placeholder is not substituted, so the name never matches and
    the source fails every poll -- with nothing to suggest the cause is a typo
    in a field nobody has looked at since it was registered.
    """
    with pytest.raises(FormError, match="placeholder"):
        source_from_form({**GITHUB, "asset_name": asset}, actor="alice")


@pytest.mark.parametrize("asset", ["app-{version-x64.zip", "app-version}-x64.zip"])
def test_unbalanced_braces_are_refused(asset: str) -> None:
    with pytest.raises(FormError, match=r"brace|placeholder"):
        source_from_form({**GITHUB, "asset_name": asset}, actor="alice")


def test_braces_do_not_open_a_path_separator() -> None:
    # Widening the alphabet must not widen what a name can express.
    for hostile in ["{version}/../evil.zip", "a{version}/b.zip", r"{version}\evil.zip"]:
        with pytest.raises(FormError, match="asset"):
            source_from_form({**GITHUB, "asset_name": hostile}, actor="alice")


# ------------------------------------------------ the form's own required set
#
# The template marks each field required or optional. These pin that marking to
# what the parser actually enforces, so a marker cannot drift into decoration:
# a field labelled optional that is in fact required sends an operator hunting
# through a validation error for a field they were told to leave alone.

GITHUB_REQUIRED = ("app_id", "forge", "project", "asset_name")
GITHUB_OPTIONAL = (
    "workflow_uri",
    "api_base",
    "tag_prefix",
    "oidc_issuer",
    "runner_environment",
    "require_tag_ref_prefix",
    "max_asset_bytes",
    "critical",
)

GITLAB_REQUIRED = (
    "app_id",
    "forge",
    "project",
    "asset_name",
    "builder_id",
    "builder_keyid",
    "builder_public_key_pem",
)
GITLAB_OPTIONAL = (
    "api_base",
    "tag_prefix",
    "attestation_asset",
    "require_tag_ref_prefix",
    "max_asset_bytes",
    "critical",
)


@pytest.mark.parametrize("field", GITHUB_REQUIRED)
def test_a_github_form_missing_a_required_field_is_refused(field: str) -> None:
    with pytest.raises(FormError):
        source_from_form({**GITHUB, field: ""}, actor="alice")


@pytest.mark.parametrize("field", GITLAB_REQUIRED)
def test_a_gitlab_form_missing_a_required_field_is_refused(field: str) -> None:
    with pytest.raises(FormError):
        source_from_form({**GITLAB, field: ""}, actor="alice")


@pytest.mark.parametrize("field", GITHUB_OPTIONAL)
def test_a_github_optional_field_may_be_left_blank(field: str) -> None:
    # Blank must fall back to the default rather than raise -- that is what
    # "(optional)" promises in the form.
    source = source_from_form({**GITHUB, field: ""}, actor="alice")
    assert source.app_id == "git-assistant"


@pytest.mark.parametrize("field", GITLAB_OPTIONAL)
def test_a_gitlab_optional_field_may_be_left_blank(field: str) -> None:
    source = source_from_form({**GITLAB, field: ""}, actor="alice")
    assert source.app_id == "internal-tool"


def test_the_optional_defaults_are_the_ones_the_form_shows() -> None:
    """A blank field must produce the value the template pre-fills.

    If they disagree, the form shows one thing and stores another, and the
    difference only surfaces when a poll behaves unexpectedly.
    """
    source = source_from_form(dict(GITHUB), actor="alice")
    assert source.api_base == "https://api.github.com"
    assert source.tag_prefix == "v"
    assert source.oidc_issuer == "https://token.actions.githubusercontent.com"
    assert source.runner_environment == "github-hosted"
    assert source.require_tag_ref_prefix == "refs/tags/"
    assert source.max_asset_bytes == 2 * 1024 * 1024 * 1024
    assert source.critical is False


# ------------------------------------------ deriving the workflow URI


def test_a_blank_workflow_uri_follows_the_project() -> None:
    form = {k: v for k, v in GITHUB.items() if k != "workflow_uri"}
    source = source_from_form(form, actor="alice")

    assert source.workflow_uri == (
        "https://github.com/ONEoo7/ai_tools_git_assistant/.github/workflows/release.yml"
    )


def test_the_derived_uri_matches_a_real_attestation() -> None:
    """Pinned against what GitHub actually put in the certificate.

    The derivation is only useful if it produces the string the SAN carries.
    This value came from the live attestation for ai_tools_git_assistant
    v0.1.0, with the `@refs/tags/v0.1.0` suffix removed -- the ref is checked
    separately, which is why the form refuses a URI carrying one.
    """
    from dist_admin.forms import derived_workflow_uri

    san = (
        "https://github.com/ONEoo7/ai_tools_git_assistant"
        "/.github/workflows/release.yml@refs/tags/v0.1.0"
    )
    assert (
        derived_workflow_uri("https://github.com/ONEoo7/ai_tools_git_assistant")
        == (san.split("@refs/")[0])
    )


def test_an_explicit_workflow_uri_is_not_overridden() -> None:
    # A project whose release workflow is named something else must still be
    # able to say so.
    source = source_from_form(
        {
            **GITHUB,
            "workflow_uri": "https://github.com/ONEoo7/ai_tools_git_assistant"
            "/.github/workflows/publish.yml",
        },
        actor="alice",
    )
    assert source.workflow_uri.endswith("/publish.yml")


def test_the_derived_uri_follows_a_self_hosted_host() -> None:
    # Derived from the project URL, which already accounts for the API base.
    form = {k: v for k, v in GITHUB.items() if k != "workflow_uri"}
    source = source_from_form(
        {**form, "api_base": "https://github.internal.example"}, actor="alice"
    )
    assert source.workflow_uri.startswith("https://github.internal.example/")
    assert source.workflow_uri.endswith("/.github/workflows/release.yml")


def test_deriving_does_not_apply_to_gitlab() -> None:
    # GitLab pins a key, not a workflow identity; there is nothing to derive.
    source = source_from_form(dict(GITLAB), actor="bob")
    assert source.workflow_uri is None


# ---------------------------------------------- the application id suggestion


def test_an_underscored_id_is_refused_with_a_usable_suggestion() -> None:
    """The repository name is the most likely thing to be pasted here.

    Underscores are legal in a repository name and not in a TUF role name, so
    this is the mistake the form should expect and answer, rather than print a
    regex at.
    """
    with pytest.raises(FormError, match="did you mean 'ai-tools-git-assistant'"):
        source_from_form({**GITHUB, "app_id": "ai_tools_git_assistant"}, actor="alice")


@pytest.mark.parametrize(
    "typed, suggested",
    [
        ("My.App", "my-app"),
        ("Git_Assistant", "git-assistant"),
        ("  spaced name  ", "spaced-name"),
        ("trailing---", "trailing"),
    ],
)
def test_the_suggestion_is_a_valid_id(typed: str, suggested: str) -> None:
    from dist_admin.forms import _suggest_app_id

    assert _suggest_app_id(typed) == suggested
    # Whatever is offered must itself pass, or the operator retypes it and is
    # refused a second time.
    source = source_from_form({**GITHUB, "app_id": suggested}, actor="alice")
    assert source.app_id == suggested


@pytest.mark.parametrize("typed", ["", "_", "---", "!!!"])
def test_nothing_is_suggested_when_nothing_salvageable_remains(typed: str) -> None:
    from dist_admin.forms import _suggest_app_id

    assert _suggest_app_id(typed) is None


def test_the_error_does_not_print_a_regex() -> None:
    # The previous message showed the raw pattern, which tells an operator
    # what the machine wants rather than what to type.
    with pytest.raises(FormError) as caught:
        source_from_form({**GITHUB, "app_id": "Bad_Id"}, actor="alice")
    assert "[a-z0-9]" not in str(caught.value)


def test_a_valid_id_is_never_silently_rewritten() -> None:
    # The id cannot be changed after registration, so correcting it for the
    # operator would remove their only chance to notice it is not what they
    # meant.
    source = source_from_form({**GITHUB, "app_id": "git-assistant"}, actor="alice")
    assert source.app_id == "git-assistant"


# ------------------------------------------------ the project path suggestion


def test_a_pasted_project_url_is_refused_with_the_path_extracted() -> None:
    """Pasting the browser URL is the obvious thing to do.

    The field wants the path alone because the host is configured separately,
    so the error has to say which part to keep and where the rest goes.
    """
    with pytest.raises(FormError, match="did you mean 'ONEoo7/ai_tools_git_assistant'"):
        source_from_form(
            {**GITHUB, "project": "https://github.com/ONEoo7/ai_tools_git_assistant"},
            actor="alice",
        )


def test_the_error_says_where_the_host_belongs() -> None:
    with pytest.raises(FormError, match="API base"):
        source_from_form(
            {**GITHUB, "project": "https://github.com/ONEoo7/ai_tools_git_assistant"},
            actor="alice",
        )


@pytest.mark.parametrize(
    "pasted, expected",
    [
        ("https://github.com/owner/repo", "owner/repo"),
        ("https://github.com/owner/repo.git", "owner/repo"),
        ("https://github.com/owner/repo/", "owner/repo"),
        ("https://gitlab.example.com/group/sub/proj", "group/sub/proj"),
    ],
)
def test_the_extracted_path_is_itself_valid(pasted: str, expected: str) -> None:
    from dist_admin.forms import _suggest_project

    assert _suggest_project(pasted) == expected
    # Offering a value that is refused on retype is worse than offering none.
    source = source_from_form({**GITHUB, "project": expected}, actor="alice")
    assert source.project == expected


@pytest.mark.parametrize(
    "pasted",
    [
        "owner/repo",  # already correct: nothing to suggest
        "https://github.com/",  # no path
        "https://github.com/owner",  # not owner/repo
        "https://github.com/owner/../../etc",  # traversal survives extraction
        "not a url",
    ],
)
def test_nothing_is_suggested_when_extraction_would_not_help(pasted: str) -> None:
    from dist_admin.forms import _suggest_project

    assert _suggest_project(pasted) is None


def test_a_pasted_url_is_never_silently_accepted() -> None:
    """Accepting it would discard the host it carries.

    A self-hosted URL pasted here would otherwise register against the default
    forge, and surface much later as a project that does not exist.
    """
    with pytest.raises(FormError):
        source_from_form(
            {**GITHUB, "project": "https://github.internal.example/owner/repo"}, actor="alice"
        )


# --------------------------------------------------------------- build identity


def test_the_source_digest_is_stable_and_short() -> None:
    from dist_core.buildinfo import source_digest

    first = source_digest()
    assert first == source_digest()
    assert len(first) == 8
    assert all(c in "0123456789abcdef" for c in first)


def test_the_digest_covers_content_not_location() -> None:
    """A checkout and an image built from it must agree.

    They install the same packages at different paths, so a digest that mixed
    in absolute paths would differ for identical code -- and answer a question
    nobody asked.
    """
    import hashlib
    from pathlib import Path

    from dist_core.buildinfo import TRACKED_PACKAGES, _package_dir

    directory = _package_dir("dist_core")
    assert directory is not None
    assert "dist_core" in TRACKED_PACKAGES

    # Recompute for one package the way the digest does, from a different
    # working directory, and confirm the bytes hashed are path-relative.
    def relative_hash(root: Path) -> str:
        h = hashlib.sha256()
        for p in sorted(root.rglob("*.py"), key=lambda q: q.relative_to(root).as_posix()):
            if "__pycache__" in p.parts:
                continue
            h.update(p.relative_to(root).as_posix().encode())
            h.update(p.read_bytes())
        return h.hexdigest()

    assert relative_hash(directory) == relative_hash(directory.resolve())


def test_the_description_names_the_service() -> None:
    from dist_core.buildinfo import describe

    line = describe("dist-ingest.worker")
    assert line.startswith("dist-ingest.worker starting")
    assert "source " in line


def test_an_absent_build_ref_is_omitted_rather_than_printed_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "built unknown at unknown" is noise on every line of every log for
    # anyone who does not pass the build arguments.
    from dist_core.buildinfo import describe

    monkeypatch.delenv("DIST_BUILD_REF", raising=False)
    assert "built" not in describe("svc")

    monkeypatch.setenv("DIST_BUILD_REF", "ce856bc")
    monkeypatch.setenv("DIST_BUILD_TIME", "2026-07-28T04:26:10Z")
    assert "built ce856bc at 2026-07-28T04:26:10Z" in describe("svc")


# ------------------------------------------------------------- editing


def an_existing_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "app_id": "git-assistant",
        "forge": Forge.GITHUB,
        "project": "ONEoo7/ai_tools_git_assistant",
        "api_base": "https://api.github.com",
        "project_url": "https://github.com/ONEoo7/ai_tools_git_assistant",
        "status": SourceStatus.ACTIVE,
        "critical": False,
        "asset_name": "git-assistant-{version}-windows-x64.zip",
        "tag_prefix": "v",
        "require_tag_ref_prefix": "refs/tags/",
        "max_asset_bytes": 2 * 1024 * 1024 * 1024,
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def edit_form(**overrides: object) -> dict[str, object]:
    source = an_existing_source()
    data: dict[str, object] = {
        "asset_name": source.asset_name,
        "tag_prefix": source.tag_prefix,
        "require_tag_ref_prefix": source.require_tag_ref_prefix,
        "max_asset_bytes": str(source.max_asset_bytes),
        "channel": source.channel,
        "platform": source.platform,
        "arch": source.arch,
    }
    data.update(overrides)
    return data


def test_only_what_changed_is_returned() -> None:
    # So the audit entry records the change, and an accidental save is a no-op.
    source = an_existing_source()
    assert source_edit_from_form(edit_form(), source) == {}


def test_the_asset_name_can_be_changed() -> None:
    """The case this exists for: switching a channel from the portable zip to
    the installer, which is a different artifact of the same verified release."""
    source = an_existing_source()
    changed = source_edit_from_form(
        edit_form(asset_name="git-assistant-{version}-windows-x64-setup.exe"), source
    )
    assert changed == {"asset_name": "git-assistant-{version}-windows-x64-setup.exe"}


def test_identity_fields_in_the_form_are_ignored() -> None:
    """A field absent from the form is not a field that cannot be submitted.

    Anyone can post whatever they like, so what protects the delegation is that
    these are never read -- not that the template omits them.
    """
    source = an_existing_source()
    changed = source_edit_from_form(
        edit_form(
            app_id="something-else",
            project="attacker/repo",
            project_url="https://github.com/attacker/repo",
            api_base="https://api.evil.example",
            workflow_uri="https://github.com/attacker/repo/.github/workflows/x.yml",
            repository_id="999",
            status="active",
        ),
        source,
    )
    assert changed == {}


def test_the_same_validators_apply_as_on_registration() -> None:
    source = an_existing_source()
    with pytest.raises(FormError, match="bare filename"):
        source_edit_from_form(edit_form(asset_name="../../etc/passwd"), source)
    with pytest.raises(FormError, match="only \\{version\\}"):
        source_edit_from_form(edit_form(asset_name="app-{platform}.exe"), source)
    with pytest.raises(FormError, match="refs/"):
        source_edit_from_form(edit_form(require_tag_ref_prefix="heads/main"), source)


@pytest.mark.parametrize("bad", ["../etc", "Windows", "win dows", "a" * 40])
def test_a_channel_segment_that_could_escape_the_prefix_is_refused(bad: str) -> None:
    # These become directory names under the application's delegated prefix.
    source = an_existing_source()
    with pytest.raises(FormError):
        source_edit_from_form(edit_form(channel=bad, platform=bad, arch=bad), source)


def test_a_blank_field_means_unchanged_rather_than_empty() -> None:
    """Submitting nothing keeps what is there.

    The alternative -- treating blank as a value -- would let a form posted
    without these fields blank the path segments a published release lands
    under.
    """
    source = an_existing_source()
    changed = source_edit_from_form(edit_form(channel="", platform="", arch=""), source)
    assert changed == {}


def test_the_editable_set_and_the_store_whitelist_agree() -> None:
    """Two lists that must not drift.

    The form decides what is offered; the store decides what is possible. If
    the store's set grew a column the form does not know about, nothing would
    fail -- it would simply become writable by anyone posting a form.
    """
    from dist_registry.store import _UPDATABLE_COLUMNS

    assert EDITABLE_FIELDS == _UPDATABLE_COLUMNS


# ---------------------------------------------------------------- styling


def test_every_class_a_template_uses_exists_in_the_stylesheet() -> None:
    """A class name with no rule behind it fails silently.

    `class="button-secondary"` was invented rather than looked up, matched
    nothing, and rendered as default blue link text sitting beside real
    buttons. Nothing errored -- which is exactly why it needs a test.
    """
    import re
    from importlib import resources

    files = resources.files("dist_admin")
    css = (files / "static" / "app.css").read_text(encoding="utf-8")
    defined = set(re.findall(r"\.([a-zA-Z][\w-]*)", css))

    used: set[str] = set()
    templates = files / "templates"
    for entry in templates.iterdir():
        if not entry.name.endswith(".html"):
            continue
        for attr in re.findall(r'class="([^"]*)"', entry.read_text(encoding="utf-8")):
            # Remove Jinja expressions before splitting, not after. A class
            # list is often part literal and part template -- `status
            # status-{{ source.status }}` -- and filtering word-by-word cannot
            # work: `source.status` sits *inside* the braces and carries none
            # of its own, so it survives as a plausible-looking class name.
            # The substitution leaves a marker rather than a blank, so a name
            # the template *builds* stays recognisable as partial.
            # `status-{{ source.status }}` is not the class `status-`; its real
            # names are `status-active`, `status-draft` and so on, and only the
            # data knows which. Blanking instead of marking reported `status-`
            # as missing, which is neither true nor actionable.
            literal = re.sub(r"\{[{%].*?[%}]\}", "\x00", attr, flags=re.DOTALL)
            used.update(part for part in literal.split() if "\x00" not in part)

    missing = used - defined
    assert not missing, f"template classes with no rule in app.css: {sorted(missing)}"
