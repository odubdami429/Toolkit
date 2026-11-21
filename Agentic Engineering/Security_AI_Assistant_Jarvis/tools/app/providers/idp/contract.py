"""Identity-provider domain contract (tool prefix ``idp_``, env prefix ``IDP``).

Vendor-neutral specification of what the identity-provider specialist can do: look up users, groups and applications,
search the sign-in/admin audit log, and two containment writes (suspend/unsuspend one user, clear one user's sessions).
It also specifies ``user_groups(client, email)``, the read the AI-tool entitlement check
(``providers/insider_risk/ai_entitlement.py``) uses. No automatic actions in this domain. An adapter for a real
product implements this contract (see ``example.py`` / ``example_write.py``) and must pass ``tests/test_contracts.py``
and ``tests/test_contract_idp.py``.

Configuration (org.env / tools.env)
-----------------------------------
``IDP_PROVIDER`` (adapter key), ``IDP_BASE_URL`` (bare https origin of the IdP org/tenant API), ``IDP_CONSOLE_URL``
(admin console origin, for ``admin_url`` links), credentials as ``IDP_API_TOKEN`` or ``IDP_CLIENT_ID`` with
``IDP_CLIENT_SECRET`` / ``IDP_PRIVATE_KEY_B64`` (+ ``IDP_KEY_ID``). A client id needs a secret or a private key.

Credential scope: reads need read-only users, groups, apps and audit-log scopes. The writes additionally need
user-lifecycle (suspend/unsuspend) and session-management rights on ordinary users; never grant the credential rights
over administrators (the product should refuse those changes itself).

Common envelope
---------------
Every tool returns a JSON object with ``status``. Shared statuses: ``invalid_input`` (nothing sent; fix the input named
in ``message``), ``not_found``, ``ambiguous`` (several matches; ``candidates`` listed), ``refused`` (a deliberate
boundary), ``error`` (``message``, optional ``hint``, ``http_status``, ``error_code``, ``error_summary``,
``failed_block``), ``not_implemented`` (the example skeleton). Most results carry ``next_step`` and ``now`` (ISO-8601
UTC). A failure is never evidence about a user.

Read tools
----------
``idp_get_user(user)``
    ``user``: email, full name, or the IdP's opaque user id. Returns ``status: ok`` with ``query {subject,
    lookup_kind: id|email|name}``, ``matched_candidates``, ``user {id, login, email, name, status, created,
    activated, last_login, password_changed, status_changed, title, department, manager, employee_type}``, ``groups
    [{id, name, type}]``, ``apps [{id, label, status, hidden}]``, ``factors [{type, provider, status}]``, ``signals
    {status, is_active, status_is_notable, active_factor_count, distinct_factor_kinds, no_active_mfa, group_count,
    app_count, hidden_app_count, admin_like_groups}`` and ``admin_url``. ``status`` values are neutral lowercase
    (``USER_STATUSES``). Cannot see administrator role assignments.

``idp_get_group(group, max_members?)``
    Group name (contains-match) or id. ``max_members`` default ``DEFAULT_GROUP_MEMBERS``, max ``MAX_GROUP_MEMBERS``.
    Returns ``group {id, name, description, type, created, last_membership_updated}``, ``counts {members, apps}``
    (true totals), ``members [{id, login, name, status}]`` (capped), ``apps [{id, label, status}]``, ``admin_url``.

``idp_get_app(app, max_users?)``
    Dashboard label (or fragment) or id. ``max_users`` default ``DEFAULT_APP_USERS``, max ``MAX_APP_USERS``. Returns
    ``app {id, label, name, status, sign_on_mode, created, last_updated, oauth {grant_types, redirect_uris,
    response_types, client_id}}``, ``groups [{id, name}]`` (up to ``MAX_APP_GROUPS``), ``users [{id, login, name,
    scope: direct|group}]``, ``counts {direct_user_assignments, users, groups}``, ``admin_url``.

``idp_search_logs(lookback_hours?, until_hours_ago?, user?, event_types?, outcome?, severity?, ip?, q?, limit?,
max_events?)``
    The sign-in and admin audit log over a RELATIVE window (absolute dates are refused: ``ABSOLUTE_TIME_PARAMS``).
    ``lookback_hours`` default ``DEFAULT_LOG_LOOKBACK_H``, max ``MAX_LOG_LOOKBACK_H``; more than
    ``UNSCOPED_MAX_LOOKBACK_H`` hours requires a scope (user, event_types, ip or q). ``until_hours_ago`` < lookback.
    ``event_types``: up to ``MAX_EVENT_TYPES`` dotted lowercase names, a trailing ``.*`` is a prefix match.
    ``outcome`` in ``LOG_OUTCOMES``, ``severity`` in ``LOG_SEVERITIES`` (neutral lowercase; the adapter maps them),
    ``ip`` one address (no CIDR), ``q`` free text up to ``MAX_LOG_Q`` characters, ``limit`` page size (adapter
    max), ``max_events`` full records listed (default ``DEFAULT_LOG_EVENTS``, max ``MAX_LOG_EVENTS``; 0 =
    aggregates only). Pagination is automatic up to the adapter's page cap. Returns ``query {since, until, filter,
    user}``, ``counts {events_fetched, pages_fetched, truncated, truncation_reason}``, ``aggregates {event_types,
    outcomes, ips [{ip, count, city, country, asn, first_seen, last_seen}], actors, targets, user_agents}`` (over
    everything fetched) and ``events [{time, event_type, display_message, outcome, reason, severity, actor, targets,
    ip, geo, user_agent, session_id}]``. An unknown event type silently returning zero events is why event types are
    shape-checked.

Write tools (analyst-requested only; no automatic actions)
----------------------------------------------------------
Every write result carries ``written`` (false: nothing changed; true: accepted; null: may or may not have applied,
then also ``outcome_unknown: true``), ``requested_by`` (the verified requester the server passes; never model input),
``reason`` and ``performed_as`` (the credential's identity, since the product's log records the change under it).

``idp_set_user_suspension(user, action, reason)``
    ONE user by exact email/login or user id (names refused: resolve with ``idp_get_user`` first). ``action`` in
    ``SUSPENSION_ACTIONS``; other lifecycle verbs (deactivate, reactivate, unlock, delete, ...) are refused with a
    pointer to the console. Reads the new status back. Statuses: ``suspended``, ``unsuspended``, ``uncertain``
    (accepted, read-back disagrees), ``no_change`` (already in that state), ``refused``, ``not_found``,
    ``ambiguous``, ``invalid_input``, ``error``. Fields: ``action``, ``user {id, login, name, title, department}``,
    ``from``, ``to``, ``confirmed_status``, ``status_changed_at``, ``admin_url``, ``summary``.

``idp_clear_user_sessions(user, reason, revoke_oauth_tokens?)``
    End ALL of ONE user's IdP sessions and, by default, revoke the OAuth tokens the IdP issued to their apps.
    Statuses: ``sessions_cleared``, ``refused``, ``not_found``, ``ambiguous``, ``invalid_input``, ``error``. Fields:
    ``user``, ``revoke_oauth_tokens``, ``confirmed_by`` (most products have no session list to read back; the audit
    event confirms it), ``admin_url``.

``user_groups(client, email)`` (module function, not a model tool)
    Resolve ONE user by exact login/email and list their group NAMES. Never raises. Returns ``{"status": "ok" |
    "not_found" | "ambiguous" | "error", "email": <normalised>, "user_status": <neutral status or None>, "groups":
    [names], "truncated": <True when the list hit the adapter's cap>, "message"?: <why, for anything but ok>}``.
    Groups only for ``ok``; every other status has ``groups: []`` and ``truncated: false``.

Guardrails an implementation MUST enforce
-----------------------------------------
* Exact allowlist of outbound requests (method, path, query keys), checked before any network I/O. Every subject is
  resolved through a search/list answer; the id used in a write path comes from that answer, never from model input.
  Never call administrator-role endpoints. No redirects. Secrets (tokens, client assertions, private keys) never
  appear in a result or log line.
* Writes need a verified requester (refused without one); any ``requested_by`` argument is ignored.
* ``reason`` >= ``MIN_REASON`` characters and not a placeholder ("test", "n/a", "as requested", ...).
* ONE user per call, exact identifier only, exactly one match (else ``not_found`` / ``ambiguous``).
* Suspension refuses: the API credential's own account (suspending it kills every IdP tool); service accounts
  (``PROTECTED_ACCOUNT_PATTERN`` on the login's local part); the requester's own account; accounts holding
  administrator roles where the product reports them (an administrator's suspension is a human decision in the
  console); deprovisioned / staged / never-activated accounts; and reactivation (unsuspend only returns a SUSPENDED
  account to active). Already-in-state is ``no_change`` without a request. Read the status back; never assume it.
* Clearing sessions refuses the credential's own account and service accounts.
* A change that fails mid-request or with a 5xx is ``written: null`` / ``outcome_unknown``; never retried
  automatically. Results are capped (~40 kB).
"""

from __future__ import annotations

from typing import Any

PREFIX = "IDP"
TOOL_PREFIX = "idp_"

MAX_SUBJECT = 256
DEFAULT_GROUP_MEMBERS, MAX_GROUP_MEMBERS = 100, 500
DEFAULT_APP_USERS, MAX_APP_USERS = 50, 200
MAX_APP_GROUPS = 100
DEFAULT_LOG_LOOKBACK_H, MAX_LOG_LOOKBACK_H = 24, 2160
UNSCOPED_MAX_LOOKBACK_H = 72
DEFAULT_LOG_PAGE, MAX_LOG_PAGE = 1000, 1000
MAX_LOG_PAGES = 12
DEFAULT_LOG_EVENTS, MAX_LOG_EVENTS = 25, 500
MAX_EVENT_TYPES = 20
MAX_LOG_Q = 128
LOG_OUTCOMES = ("success", "failure", "skipped", "allow", "deny", "challenge", "unknown")
LOG_SEVERITIES = ("debug", "info", "warn", "error")
ABSOLUTE_TIME_PARAMS = ("since", "until", "start_date", "end_date", "start_time", "end_time", "date", "start", "end")
USER_STATUSES = ("active", "suspended", "deprovisioned", "staged", "provisioned", "locked_out", "recovery",
                 "password_expired")

MIN_REASON = 20
MAX_REASON = 1000
SUSPENSION_ACTIONS = ("suspend", "unsuspend")
#: Lifecycle verbs the suspension tool refuses, with why (shown to the model).
NEAR_MISS_ACTIONS = {
    "deactivate": "Deactivation deprovisions the account and removes app assignments: it is offboarding, not "
                  "suspension.",
    "reactivate": "Reactivation is for deprovisioned accounts and re-sends an activation email.",
    "activate": "Activation is for staged/provisioned accounts.",
    "unlock": "Unlocking clears a password lockout.",
    "delete": "Deletion is permanent.",
    "clear-sessions": "Clearing sessions is a separate tool: idp_clear_user_sessions.",
}
#: Service-account local parts the writes refuse.
PROTECTED_ACCOUNT_PATTERN = r"^(svc|service)[-_.]"

_REASON_DESC = (f"Why, with a ticket, alert or thread reference. At least {MIN_REASON} characters; it is the audit "
                "record.")

TOOLS: list[dict] = [
    {
        "name": "idp_get_user",
        "description": (
            "Look up one identity-provider user by email, name, or id. Returns profile, account status, group "
            "memberships, assigned app labels, enrolled MFA factors, `signals` (no active MFA, admin-like groups, "
            "notable status) and an admin console link (admin_url). Use for \"who is X\", \"what can X access\", "
            "\"is X's account active\", \"does X have MFA\". Several matches return `ambiguous` with candidates. "
            "Read-only. Cannot see administrator role assignments."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Email (first.last@<org domain>), full name, or the "
                         "IdP user id. Email is most reliable."},
            },
            "required": ["user"],
        },
    },
    {
        "name": "idp_get_group",
        "description": (
            "Look up one identity-provider group by name or id. Returns the group profile, its true member and app "
            "counts, a capped member list, and the apps it grants. Use for \"who is in group X\" or \"what does "
            "group X give access to\". Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "Group name or a fragment of it (contains-match), or the "
                          "group id."},
                "max_members": {"type": "number", "description": f"Default {DEFAULT_GROUP_MEMBERS}, max "
                                f"{MAX_GROUP_MEMBERS}. The true total is always reported separately."},
            },
            "required": ["group"],
        },
    },
    {
        "name": "idp_get_app",
        "description": (
            "Look up one identity-provider application by dashboard label or id. Returns configuration, sign-on "
            "mode, OAuth settings including redirect URIs, assigned groups, and assigned users (direct and "
            "group-inherited; counts.direct_user_assignments counts the direct ones). Use for \"who has access to "
            "app X\" or \"how is app X configured\". Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {
                "app": {"type": "string", "description": "Dashboard label or a fragment, or the app id."},
                "max_users": {"type": "number", "description": f"Default {DEFAULT_APP_USERS}, max {MAX_APP_USERS}. "
                              f"Group assignments are returned up to {MAX_APP_GROUPS} regardless."},
            },
            "required": ["app"],
        },
    },
    {
        "name": "idp_search_logs",
        "description": (
            "Search the identity provider's sign-in and admin audit log over a relative time window, optionally "
            "scoped to one person. Returns aggregates (event types, outcomes, IPs with geolocation, actors) over "
            "everything fetched plus individual events. Use for any question about what actually happened: "
            "sign-ins, failures, MFA changes, admin actions. Time is always in hours before now; never compute a "
            "date. Paginates automatically. Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {
                "lookback_hours": {"type": "number", "description": f"Hours back from now. Default "
                                   f"{DEFAULT_LOG_LOOKBACK_H}, max {MAX_LOG_LOOKBACK_H}. Over "
                                   f"{UNSCOPED_MAX_LOOKBACK_H} hours requires a scope: user, event_types, ip or q."},
                "until_hours_ago": {"type": "number", "description": "Default 0. Must be < lookback_hours. "
                                    "Yesterday = 48 / 24."},
                "user": {"type": "string", "description": "Email, name, or id. Matches actor and target events."},
                "event_types": {"type": "string", "description": "Comma-separated dotted lowercase event types; a "
                                f"trailing .* is a prefix match (e.g. user.session.*). Max {MAX_EVENT_TYPES}."},
                "outcome": {"type": "string", "enum": list(LOG_OUTCOMES)},
                "severity": {"type": "string", "enum": list(LOG_SEVERITIES)},
                "ip": {"type": "string", "description": "Single IPv4/IPv6 address, no CIDR."},
                "q": {"type": "string", "description": f"Free text, max {MAX_LOG_Q} characters."},
                "limit": {"type": "number", "description": f"Rows per page (default and max {MAX_LOG_PAGE}). The "
                          "tool paginates, so this is page size, not a total."},
                "max_events": {"type": "number", "description": f"Full event records returned. Default "
                               f"{DEFAULT_LOG_EVENTS}, max {MAX_LOG_EVENTS}. 0 = aggregates only. Does not limit "
                               "what is analysed."},
            },
        },
    },
]

LIST_TOOLS: list[dict] = []

WRITE_TOOLS: list[dict] = [
    {
        "name": "idp_set_user_suspension",
        "description": (
            "WRITE. Suspend or unsuspend ONE identity-provider user, given an exact email/login or user id (resolve "
            "names with idp_get_user first). Suspension blocks new sign-ins and keeps groups and apps; unsuspend "
            "returns a suspended account to active. Only on an explicit analyst request. Requires `reason`. Refuses "
            "the API credential's own account, service accounts, the requester's own account, administrators, "
            "deprovisioned/staged accounts and reactivation; already-in-state is `no_change`. Reads the new status "
            "back. Statuses: suspended, unsuspended, uncertain, no_change, refused, not_found, ambiguous, "
            "invalid_input, error (check `written`). The requester is recorded automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Exact email/login or IdP user id."},
                "action": {"type": "string", "enum": list(SUSPENSION_ACTIONS)},
                "reason": {"type": "string", "description": _REASON_DESC},
            },
            "required": ["user", "action", "reason"],
        },
    },
    {
        "name": "idp_clear_user_sessions",
        "description": (
            "WRITE. Clear ALL of ONE identity-provider user's sessions, given an exact email/login or user id "
            "(resolve names with idp_get_user first), and by default also revoke the OAuth tokens the IdP issued "
            "to their apps. The user must sign in again with MFA. Only on an explicit analyst request. Requires "
            "`reason`. Refuses the API credential's own account and service accounts. There is usually no "
            "read-back: the audit-log event confirms it. Statuses: sessions_cleared, refused, not_found, ambiguous, "
            "invalid_input, error (check `written`). The requester is recorded automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Exact email/login or IdP user id."},
                "reason": {"type": "string", "description": _REASON_DESC},
                "revoke_oauth_tokens": {"type": "boolean", "description": "Also revoke OAuth tokens the IdP issued "
                                        "to the user's apps (default true). false ends sign-in sessions only."},
            },
            "required": ["user", "reason"],
        },
    },
]

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
LIST_TOOL_NAMES = frozenset(t["name"] for t in LIST_TOOLS)
WRITE_TOOL_NAMES = frozenset(t["name"] for t in WRITE_TOOLS)
ALL_TOOL_NAMES = TOOL_NAMES | LIST_TOOL_NAMES | WRITE_TOOL_NAMES

#: Statuses ``user_groups`` may return.
USER_GROUPS_STATUSES = ("ok", "not_found", "ambiguous", "error")


def tool(name: str) -> dict[str, Any] | None:
    """The schema for one tool of this domain, or None."""
    return next((t for t in TOOLS + LIST_TOOLS + WRITE_TOOLS if t["name"] == name), None)
