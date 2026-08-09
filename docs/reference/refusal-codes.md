# Reference — Refusal codes

Every code the core can emit. **A code not listed here is not a code.**

- **Det.** — whether a retry can change the outcome. A client MUST terminalise a
  deterministic refusal rather than re-attempt it for ever
  ([Compatibility](../05-compatibility.md)). A **no** is not always *wait and it
  clears* — the quota codes and the *not yet* refusals are the middle case, where
  waiting never helps and an act of the client's own does: bind, fold, register, then
  retry.
- **Where** — which document specifies the rule: [Log](../01-the-log.md),
  [Identity](../02-identity.md), [Authority](../03-authority.md),
  [Keys](../04-keys.md), [Compat](../05-compatibility.md).

Every refusal has the shape `{"detail": {"code": …, …extra fields…}}`. On
`POST /v1/w/{w}/ops`, a per-op refusal always also carries the batch `index`.

## Server codes

| Code | Status | Raised on | Extra fields | Det. | Where |
|---|---|---|---|---|---|
| `admission_refused` | 403 | `POST /v1/members` | — | yes | Identity |
| `already_revoked` | 422 | `POST …/ops` revoke, revoke_delegation | `index` | yes | Authority |
| `author_chain_conflict` | 409 | `POST …/ops` | `index`, `author_seq`, `expected_author_seq` — **all absent on the race form** | no | Log |
| `author_key_class_mismatch` | 422 | `POST …/ops` | `index`, `op_class` | yes | Authority |
| `author_member_mismatch` | 403 | `POST …/ops` | `index` | yes | Log |
| `bad_grant_signature` | 422 | `POST …/ops` grant | `index` | yes | Authority |
| `bad_member_challenge` | 401, 422 | `POST /v1/members/{m}/token` | — | yes | Identity |
| `bad_revoke_signature` | 422 | `POST …/ops` revoke | `index` | yes | Authority |
| `bad_root_signature` | 422 | `POST …/ops` control; `POST /v1/members` | `index` where per-op | yes | Authority |
| `bad_vault_signature` | 403 | `PUT …/vault` | — | yes | Keys |
| `batch_too_large` | 413 | `POST …/ops` | `max_ops` | yes | Log |
| `cert_granter_mismatch` | 422 | `POST …/ops` grant, revoke | `index` | yes | Authority |
| `cert_key_mismatch` | 422 | `POST …/ops` genesis, register; `POST /v1/members` | `index` where per-op | yes | Authority |
| `cert_member_mismatch` | 422 | `POST …/ops` genesis, register; `POST /v1/members` | `index` where per-op | yes | Authority |
| `cert_root_pk_mismatch` | 422 | `POST …/ops` handover; `POST /v1/members` | `index` where per-op | yes | Authority |
| `cert_workspace_mismatch` | 422 | `POST …/ops` control | `index` | yes | Authority |
| `control_chain_break` | 422 | `POST …/ops` control | `index`, `expected_prev_control_hash` — **absent on a genesis, and where no genesis exists** | yes | Authority |
| `delegate_pk_in_use` | 422 | `POST …/ops` delegate | `index` | yes | Authority |
| `delegation_id_already_used` | 409 | `POST …/ops` delegate | `index` | yes | Authority |
| `duplicate_keywrap_member` | 422 | `PUT …/keywraps` | `index` | yes | Keys |
| `encrypted_control_op` | 422 | `POST …/ops` | `index` | yes | Keys |
| `encrypted_prune_op` | 422 | `POST …/ops` | `index` | yes | Keys |
| `encrypted_server_read_op` | 422 | `POST …/ops` | `index` | yes | Keys |
| `envelope_too_short` | 422 | `POST …/ops` | `index` | yes | Log |
| `ext_class_already_bound` | 409 | `POST …/ops` ext_binding | `index`, `op_class` | no | Log |
| `ext_class_not_active` | 422 | `POST …/ops` extension classes | `index`, `op_class` | no | Log |
| `ext_class_not_bound` | 422 | `POST …/ops` ext_binding | `index`, `op_class` | no | Log |
| `ext_class_not_enabled` | 422 | `POST …/ops` ext_binding | `index`, `op_class` | yes | Log |
| `ext_name_mismatch` | 422 | `POST …/ops` ext_binding, extension classes | `index`, `op_class`, `expected` | yes | Log |
| `genesis_not_first` | 409 | `POST …/ops` genesis | `index` | yes | Authority |
| `grant_id_already_used` | 409 | `POST …/ops` grant | `index` | yes | Authority |
| `hard_prune_target_is_prune` | 422 | `POST …/ops` hard_prune | `index`, `seq` | yes | Log |
| `hard_prune_target_not_reprised` | 422 | `POST …/ops` hard_prune | `index`, `seq` | no | Log |
| `invalid_body_length` | 422 | `POST …/ops` server-read classes | `index` | yes | Log |
| `invalid_credential` | 401 | any authenticated route | — | yes | Identity |
| `invalid_refresh_token` | 401 | `POST /v1/members/{m}/token/refresh` | — | yes | Identity |
| `kex_key_id_not_registered` | 422 | `PUT …/keywraps` | `index` | yes | Keys |
| `key_epoch_stale` | 409 | `POST …/ops` | `index`, `key_epoch`, `current_epoch` | no | Keys |
| `key_epoch_unknown` | 409 | `POST …/ops` | `index`, `key_epoch`, `current_epoch` | no | Keys |
| `key_id_not_derived_from_sign_pk` | 422 | `POST /v1/members` | — | yes | Identity |
| `keywrap_already_written` | 409 | `PUT …/keywraps` | `epoch` | yes | Keys |
| `keywrap_digest_mismatch` | 422 | `PUT …/keywraps` | `epoch`, `expected_digest` | yes | Keys |
| `keywrap_requires_owner` | 403 | `PUT …/keywraps` | `revoked` | no | Keys |
| `malformed_base64` | 422 | `POST …/ops` | `index` | yes | Log |
| `malformed_control_payload` | 422 | `POST …/ops` control; `POST /v1/members` | `index` where per-op | yes | Authority |
| `malformed_escrow_wrap` | 422 | `PUT …/keywraps` | `expected_bytes` | yes | Keys |
| `malformed_ext_binding_payload` | 422 | `POST …/ops` ext_binding | `index` | yes | Log |
| `malformed_kex_key_id` | 422 | `PUT …/keywraps` | `index` | yes | Keys |
| `malformed_kex_pk` | 422 | `POST /v1/members` | `expected_bytes` | yes | Identity |
| `malformed_key_epoch` | 422 | `PUT …/keywraps` | `epoch` | yes | Keys |
| `malformed_key_id` | 422 | `POST /v1/members` | — | yes | Identity |
| `malformed_keywrap` | 422 | `PUT …/keywraps` | `index`, `expected_bytes` | yes | Keys |
| `malformed_keywrap_digest` | 422 | `PUT …/keywraps` | `expected_bytes` | yes | Keys |
| `malformed_prune_payload` | 422 | `POST …/ops` `0x81` | `index` | yes | Log |
| `malformed_request` | 422 | any route | `fields` | yes | Compat |
| `malformed_root_pk` | 422 | `PUT …/vault`; `POST /v1/members`; `POST …/ops` delegate, handover | `expected_bytes`, `index` where per-op | yes | Keys |
| `malformed_sign_pk` | 422 | `POST /v1/members` | `expected_bytes` | yes | Identity |
| `malformed_vault_blob` | 422 | `PUT …/vault` | — | yes | Keys |
| `malformed_vault_signature` | 422 | `PUT …/vault` | `expected_bytes` | yes | Keys |
| `malformed_vault_version` | 422 | `PUT …/vault` | — | yes | Keys |
| `member_challenge_rate_limited` | 429 | `POST /v1/members/{m}/challenge` | `retry_after_seconds` | no | Identity |
| `member_id_already_registered` | 409 | `POST /v1/members` | — | yes | Identity |
| `member_kind_forbidden` | 422 | `POST …/ops` grant | `index`, `member_kind` | yes | Authority |
| `member_quota_exhausted` | 402 | `POST …/ops` | `index` — **the first op at which the bound was crossed** | no | Log |
| `member_register_not_first` | 422 | `POST …/ops` genesis, register | `index`, `author_seq` | yes | Authority |
| `missing_keywrap_digest` | 422 | `PUT …/keywraps` | `epoch` | yes | Keys |
| `no_live_grant` | 403 | device routes | `index` where per-op, `revoked` | no | Authority |
| `no_registration` | 403 | Workspace-scoped device routes | — | no | Authority |
| `no_vault_record` | 404 | `GET …/vault` | — | no | Keys |
| `non_zero_padding` | 422 | `POST …/ops` server-read classes | `index` | yes | Log |
| `not_found` | 404 | any unrouted path, including a misshapen locator | — | yes | Compat |
| `owner_grant_requires_root` | 422 | `POST …/ops` grant | `index` | yes | Authority |
| `owner_revoke_requires_root` | 422 | `POST …/ops` revoke | `index` | yes | Authority |
| `payload_overruns_body` | 422 | `POST …/ops` server-read classes | `index` | yes | Log |
| `prune_duplicate_target` | 422 | `POST …/ops` `0x81` | `index` | yes | Log |
| `prune_reprise_not_found` | 422 | `POST …/ops` prune | `index`, `reprise_op_id` | no | Log |
| `prune_target_already_reprised` | 422 | `POST …/ops` prune | `index`, `seq` | no | Log |
| `prune_target_attestation_mismatch` | 422 | `POST …/ops` `0x81` | `index`, `seq` | yes | Log |
| `prune_target_is_control` | 422 | `POST …/ops` prune | `index`, `seq` | yes | Log |
| `prune_target_is_its_own_reprise` | 422 | `POST …/ops` prune | `index`, `seq` | yes | Log |
| `prune_target_is_prune` | 422 | `POST …/ops` prune | `index`, `seq` | yes | Log |
| `prune_target_is_server_read` | 422 | `POST …/ops` prune | `index`, `seq` | yes | Log |
| `prune_target_not_found` | 422 | `POST …/ops` `0x81` | `index`, `seq` | no | Log |
| `prune_targets_empty` | 422 | `POST …/ops` `0x81` | `index` | yes | Log |
| `prune_targets_too_many` | 422 | `POST …/ops` `0x81` | `index` | yes | Log |
| `request_too_large` | 413 | any route | — | yes | Compat |
| `role_forbids_op_class` | 403 | `POST …/ops` | `index`, `op_class`, `roles` | no | Authority |
| `role_forbids_prune_type` | 403 | `POST …/ops` `0x81` | `index`, `prune_type`, `roles` | no | Authority |
| `rotate_epoch_conflict` | 409 | `POST …/ops` rotate | `index`, `from_epoch`, `expected_from_epoch` | no | Keys |
| `rotate_not_materialised` | 409 | `PUT …/keywraps` | `epoch` | no | Keys |
| `store_unavailable` | 503 | any route — `GET /health/db` is where you ask for it | — | no | Compat |
| `truncated_envelope` | 422 | `POST …/ops` | `index` | yes | Log |
| `unknown_delegation` | 422 | `POST …/ops` revoke_delegation | `index` | no | Authority |
| `unknown_grant` | 422 | `POST …/ops` revoke | `index` | no | Authority |
| `unknown_grantee` | 422 | `POST …/ops` grant | `index` | no | Authority |
| `unknown_keywrap_member` | 422 | `PUT …/keywraps` | `index` | no | Keys |
| `unknown_member` | 404 | `POST /v1/members/{m}/challenge` | — | no | Identity |
| `unknown_member_kind` | 422 | `POST …/ops` genesis, register; `POST /v1/members` | `index` where per-op | yes | Authority |
| `unknown_request_field` | 422 | any versioned route | `fields` | yes | Compat |
| `unknown_role` | 422 | `POST …/ops` grant | `index` | yes | Authority |
| `unsupported_contract_version` | 404 | any version-shaped path | `requested`, `served` | yes | Compat |
| `unsupported_control_type` | 422 | `POST …/ops` control | `index`, `type` | yes | Authority |
| `unsupported_ext_binding_type` | 422 | `POST …/ops` ext_binding | `index`, `type` | yes | Log |
| `unsupported_op_class` | 422 | `POST …/ops` | `index` | yes | Log |
| `unsupported_prune_type` | 422 | `POST …/ops` `0x81` | `index`, `type` | yes | Log |
| `unsupported_suite` | 422 | `POST …/ops` | `index` | yes | Log |
| `vault_fetch_rate_limited` | 429 | `GET …/vault` | `retry_after_seconds` | no | Keys |
| `vault_requires_genesis` | 403 | `PUT …/vault` first write | — | no | Identity |
| `vault_version_regression` | 409 | `PUT …/vault` | `stored_version` | yes | Keys |
| `workspace_mismatch` | 422 | `POST …/ops` | `index` | yes | Log |
| `workspace_not_created` | 409 | `POST …/ops`; `POST /v1/members` | `index` where per-op | no | Authority |
| `workspace_not_reachable` | 403 | `POST …/ops` genesis; `POST /v1/members` | `index` where per-op | yes | Authority |
| `workspace_quota_exhausted` | 402 | `POST …/ops` | — | no | Log |

One hundred and thirteen. Admission is refused under `admission_refused` whatever mechanism a
server uses, so the vocabulary stays closed even though the gate is not specified.

**[S]** `fields` — on `malformed_request` as on `unknown_request_field` — always
names **paths**: dot-separated from the request body, decimal indices for array
positions, a query parameter as a single segment; every offending one, sorted
lexicographically ([Compat §4](../05-compatibility.md#4-unknown-fields-are-refused)).
Under `malformed_request` that is the duplicated key, the parameter whose value is
out of range, or a **required member omitted from a body object** — `key_ids.<name>`
on the one object that has any ([Identity §4](../02-identity.md#4-how-a-device-gets-a-credential)).

**[S]** The `roles` array carried by `role_forbids_op_class` and
`role_forbids_prune_type` is likewise **sorted lexicographically**
([Authority §9](../03-authority.md#9-stage-2--permission-checks-on-ordinary-ops)).

## Client codes

Raised by a device against bytes it pulled — never by the server. Listed because the
vocabulary is shared: a client surfaces every code verbatim, whichever side produced
it.

| Code | Meaning | Where |
|---|---|---|
| `bad_signature` | the envelope's signature does not verify | Log |
| `aead_failure` | the body did not open under the epoch key | Keys |
| `plaintext_at_encrypted_epoch` | unsealed content at a log position after the Workspace's first `rotate` — or at any position, where epoch 0 is keyed | Keys |

## Signal close codes

| Code | Cause | Client stance |
|---|---|---|
| `4400` | no token in time, or a binary first frame | protocol error |
| `4401` | invalid token, or not a device token | park until the token refreshes |
| `4403` | no accepted registration here, or the device is revoked | terminal — do not retry blindly |

`4403` merges two causes the HTTP surface keeps apart. It is the **one sanctioned
exception** to the no-merging rule, because a close frame carries no body and the
client's response is identical either way.

## Codes that must never be merged

| Keep apart | Why |
|---|---|
| `cert_root_pk_mismatch` vs `bad_root_signature` | *this document names the wrong Root* is a rebuild; *these bytes are forged* is not |
| `unknown_grant` vs `unknown_grantee` | a failed revocation is not an invalid grantee |
| `unknown_delegation` vs `unknown_grant` | different objects, different remedies |
| `key_epoch_stale` vs `key_epoch_unknown` | too old is a catch-up; too new is an impossible epoch |
| `ext_class_not_enabled` vs `unsupported_op_class` | *that class is not turned on here* versus *this op's own class is not served* |
| `encrypted_control_op` vs `encrypted_prune_op` | different remedies |
| `prune_target_is_control` vs `prune_target_is_prune` | different reasons for exemption |
| `bad_vault_signature` vs `vault_version_regression` | *you do not control this slot* is terminal; *you are behind* is a re-read |
| `no_registration` vs `no_live_grant` | *you are not a member here* needs a registration; *you have no permission* needs a grant |
| `workspace_not_reachable` vs `no_registration` | *that id is not yours to found* versus *you have not been let in* |
| `admission_refused` vs `workspace_not_created` | *you may not found one* is for the operator; *that one does not exist yet* is a client ordering bug |
| `workspace_quota_exhausted` vs `member_quota_exhausted` | *this Workspace is full* is everyone's problem and everyone's fold; *you have written too much* is one author's |
| `member_quota_exhausted` vs `member_challenge_rate_limited` | one is a ceiling and waiting never clears it; the other clears itself in `retry_after_seconds` |

## One code with two occasions

**[S]** `cert_root_pk_mismatch` is raised on a handover whose `from_root_pk` is not the
Workspace's current Root, and on a `member_register` certificate at `POST /v1/members`
presenting a Root that is not that Workspace's current Root. Both mean **the Root this
certificate names is not the one in force**, and both are repaired the same way:
re-read the log and rebuild the document against the Root it actually reports.

> Listed explicitly because two occasions under one code looks like the merging the
> rule above forbids, and it is not. The test is whether a client learns something
> different and does something different. Here it learns the same thing and does the
> same thing; only the door it arrived at differs, and that is already in the
> response.
