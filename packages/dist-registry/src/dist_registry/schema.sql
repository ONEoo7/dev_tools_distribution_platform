-- Operational schema for the admin plane and the ingest worker.
--
-- Applied by `dist_registry.db.migrate`, which runs every statement in one
-- transaction and records the version. Everything here is idempotent so that
-- two containers starting at once cannot half-apply it.
--
-- This database holds no signing keys and no TUF metadata. It holds the
-- decisions an operator made and the queue between the two services. Losing it
-- costs the source registry; it cannot cost the trust root.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer     PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sources (
    id                      uuid        PRIMARY KEY,
    -- Matches dist_core.roles.APP_ID_PATTERN. Enforced here as well as in
    -- Python because this id becomes a TUF role name and a filename, and a
    -- second writer to this table must not be able to skip the check.
    app_id                  text        NOT NULL UNIQUE
                                        CHECK (app_id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    forge                   text        NOT NULL CHECK (forge IN ('github', 'gitlab')),
    project                 text        NOT NULL,
    api_base                text        NOT NULL,
    project_url             text        NOT NULL,
    status                  text        NOT NULL CHECK (status IN (
                                            'draft', 'validating', 'invalid',
                                            'pending_delegation', 'active', 'paused')),
    critical                boolean     NOT NULL DEFAULT false,

    asset_name              text        NOT NULL,
    tag_prefix              text        NOT NULL DEFAULT 'v',
    require_tag_ref_prefix  text        NOT NULL DEFAULT 'refs/tags/',
    max_asset_bytes         bigint      NOT NULL DEFAULT 2147483648,

    workflow_uri            text,
    oidc_issuer             text,
    repository_id           text,
    repository_owner_id     text,
    runner_environment      text        NOT NULL DEFAULT 'github-hosted',

    builder_id              text,
    builder_keyid           text,
    builder_public_key_pem  text,
    attestation_asset       text        NOT NULL DEFAULT 'provenance.intoto.jsonl',

    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    created_by              text        NOT NULL DEFAULT '',
    last_error              text,

    -- A source cannot reach `active` without the pins its forge's provenance
    -- path requires. The UI checks this too; the constraint is what makes the
    -- check unavoidable rather than merely present.
    CONSTRAINT github_active_needs_certificate_identity CHECK (
        status <> 'active' OR forge <> 'github' OR (
            workflow_uri IS NOT NULL AND oidc_issuer IS NOT NULL
            AND repository_id IS NOT NULL AND repository_owner_id IS NOT NULL)),
    CONSTRAINT gitlab_active_needs_builder_key CHECK (
        status <> 'active' OR forge <> 'gitlab' OR (
            builder_id IS NOT NULL AND builder_keyid IS NOT NULL
            AND builder_public_key_pem IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS jobs (
    id           uuid        PRIMARY KEY,
    source_id    uuid        NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    kind         text        NOT NULL CHECK (kind IN ('validate', 'poll')),
    state        text        NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
    requested_by text        NOT NULL DEFAULT '',
    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    result       jsonb,
    error        text
);

-- The worker claims with FOR UPDATE SKIP LOCKED over this order.
CREATE INDEX IF NOT EXISTS jobs_queued ON jobs (requested_at) WHERE state = 'queued';

-- At most one unfinished job per source. Two concurrent "check now" clicks
-- must not produce two downloads of the same release.
CREATE UNIQUE INDEX IF NOT EXISTS jobs_one_open_per_source
    ON jobs (source_id) WHERE state IN ('queued', 'running');

CREATE TABLE IF NOT EXISTS audit_log (
    id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text        NOT NULL,
    action    text        NOT NULL,
    -- Deliberately not a foreign key: deleting a source must not delete the
    -- record that someone added it.
    source_id uuid,
    detail    jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at DESC);

CREATE TABLE IF NOT EXISTS operators (
    username      text        PRIMARY KEY,
    password_hash bytea       NOT NULL,
    salt          bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    disabled      boolean     NOT NULL DEFAULT false
);

-- Sessions are server-side so that logging out actually ends one. Only the
-- hash of the cookie value is stored: a read of this table is then not enough
-- to impersonate a live session.
CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 bytea       PRIMARY KEY,
    username     text        NOT NULL REFERENCES operators(username) ON DELETE CASCADE,
    csrf_token   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
