-- Roundelay's retained state, in Postgres.
--
-- Two things here are load-bearing rather than tidy.
--
-- The workspace row carries next_seq, and an append takes it FOR UPDATE before
-- it does anything else. That is what allocates positions under the same
-- serialisation as the commit: without it a sequence hands out 100 and 101, 101
-- commits first, a reader advances its cursor past it, and 100 is never served
-- again — silent, permanent loss that nothing detects.
--
-- And every unique constraint is named after the refusal it produces, so the
-- 23505 → code mapping is a lookup on the constraint name rather than a pile of
-- pre-flight SELECTs that race anyway.

create table if not exists workspace (
    workspace_id bytea  primary key,
    next_seq     bigint not null default 1,
    genesis_seq  bigint,
    root_pk      bytea
);

create table if not exists op (
    workspace_id  bytea    not null,
    seq           bigint   not null,
    class         smallint not null,
    key_epoch     bigint   not null,
    op_id         bytea    not null,
    author        bytea    not null,
    author_key_id bytea    not null,
    author_seq    bigint   not null,
    -- The position of the op that marked this one reprised; 0 while unmarked.
    reprised_by   bigint   not null default 0,
    -- Materialised at hard_prune time from the bytes about to be dropped, never
    -- taken from the payload that asked for the destruction.
    envelope_hash bytea    not null,
    -- Null once a hard_prune has dropped the bytes. Every other column on the
    -- row is the tombstone and survives for ever.
    envelope      bytea,
    primary key (workspace_id, seq),
    constraint op_id_already_used    unique (workspace_id, author, op_id),
    constraint author_chain_conflict unique (workspace_id, author, author_seq)
);

create index if not exists op_by_class on op (workspace_id, class, seq);

create table if not exists member (
    workspace_id  bytea  not null,
    member_id     bytea  not null,
    kind          text   not null,
    holder_ref    bytea  not null,
    control_pk    bytea  not null,
    content_pk    bytea  not null,
    kex_pk        bytea  not null,
    registered_at bigint not null,
    primary key (workspace_id, member_id)
);

-- Several intervals per key name, per member, per Workspace. end_seq is
-- write-once: a partial unique index enforces at most one open interval.
create table if not exists key_interval (
    id           bigserial primary key,
    workspace_id bytea  not null,
    member_id    bytea  not null,
    key_name     text   not null,
    pk           bytea  not null,
    key_id       bytea  not null,
    start_seq    bigint not null,
    end_seq      bigint
);

create unique index if not exists key_interval_one_open
    on key_interval (workspace_id, member_id, key_name) where end_seq is null;
create index if not exists key_interval_lookup
    on key_interval (workspace_id, member_id, key_name, start_seq);

create table if not exists grant_row (
    workspace_id bytea   not null,
    grant_id     bytea   not null,
    member_id    bytea   not null,
    role         text    not null,
    granter      bytea,
    granter_root boolean not null,
    start_seq    bigint  not null,
    end_seq      bigint,
    constraint grant_id_already_used primary key (workspace_id, grant_id)
);

create index if not exists grant_by_member on grant_row (workspace_id, member_id);

create table if not exists delegation (
    workspace_id  bytea  not null,
    delegation_id bytea  not null,
    pk            bytea  not null,
    start_seq     bigint not null,
    end_seq       bigint,
    constraint delegation_id_already_used primary key (workspace_id, delegation_id)
);

create table if not exists role_table (
    workspace_id bytea  not null,
    at_seq       bigint not null,
    entries      jsonb  not null,
    primary key (workspace_id, at_seq)
);

create table if not exists amend (
    workspace_id bytea  not null,
    amend_id     bytea  not null,
    member_id    bytea  not null,
    at_seq       bigint not null,
    constraint amend_id_already_used primary key (workspace_id, amend_id)
);

create table if not exists epoch (
    workspace_id bytea   not null,
    epoch        bigint  not null,
    digest       bytea   not null,
    -- Null until the set is uploaded. An epoch in that window is omitted from
    -- GET /epoch-keys: an empty blob would look like a wrap that fails to open.
    escrow_wrap  bytea,
    rotate_seq   bigint  not null default 0,
    published    boolean not null default false,
    primary key (workspace_id, epoch)
);

create table if not exists member_wrap (
    workspace_id bytea  not null,
    epoch        bigint not null,
    member_id    bytea  not null,
    kex_key_id   bytea  not null,
    wrap         bytea  not null,
    constraint duplicate_keywrap_member primary key (workspace_id, epoch, member_id)
);

create table if not exists ext_binding (
    id           bigserial primary key,
    workspace_id bytea    not null,
    member_id    bytea    not null,
    op_class     smallint not null,
    name         text     not null,
    start_seq    bigint   not null,
    end_seq      bigint
);

create unique index if not exists ext_binding_one_open
    on ext_binding (workspace_id, member_id, op_class) where end_seq is null;

-- ── the identity plane ──────────────────────────────────────────────────────
--
-- None of it is in the log, nothing derives from it, and a replacement rebuilt
-- from the log is complete without it.

create table if not exists device (
    member_id  bytea primary key,
    control_pk bytea not null,
    content_pk bytea not null,
    kex_pk     bytea not null
);

-- One pending challenge per device, so a second request replaces the first
-- rather than widening the guessing surface.
create table if not exists challenge (
    member_id bytea       primary key,
    nonce     bytea       not null,
    expires   timestamptz not null
);

-- Fixed-window counters: the window opens at the first counted request and is
-- not extended by later ones.
create table if not exists rate_window (
    scope  text        not null,
    key    bytea       not null,
    opened timestamptz not null,
    count  int         not null,
    primary key (scope, key)
);

-- Stored by an irreversible hash: a server must not be able to reconstruct a
-- live refresh token from its own storage.
create table if not exists refresh_token (
    token_hash bytea       primary key,
    member_id  bytea       not null,
    expires    timestamptz not null
);

create index if not exists refresh_by_member on refresh_token (member_id);

-- ── the vault ───────────────────────────────────────────────────────────────
--
-- A slot is keyed by locator alone: no owner, no Workspace.

create table if not exists vault_slot (
    locator     bytea  primary key,
    version     bigint not null,
    blob        bytea  not null,
    sig         bytea  not null,
    -- Not write-once: it moves when a write carries a different root_pk and is
    -- signed by the key currently pinned.
    pinned_root bytea  not null
);

create index if not exists vault_by_root on vault_slot (pinned_root);

-- Append-only, one row per read served.
create table if not exists vault_fetch (
    id       bigserial   primary key,
    locator  bytea       not null,
    fetched  timestamptz not null
);
