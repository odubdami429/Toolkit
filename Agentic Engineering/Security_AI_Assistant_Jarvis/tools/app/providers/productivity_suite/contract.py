"""Productivity suite domain contract (tool prefix ``suite_``, env prefix ``SUITE``).

Vendor-neutral specification of what the productivity suite specialist can do: the suite's user directory, its audit
logs, the third-party OAuth grants a user holds, and two containment writes. An adapter for a real product implements
this contract (see ``example.py`` / ``example_write.py`` for the skeleton) and must pass ``tests/test_contracts.py``
and ``tests/test_contract_productivity_suite.py``.

Configuration (org.env / tools.env)
-----------------------------------
``SUITE_PROVIDER`` (adapter key), ``SUITE_BASE_URL`` (bare https origin of the suite's admin API),
``SUITE_CONSOLE_URL`` (admin console origin, for links), credentials as ``SUITE_API_TOKEN`` or ``SUITE_CLIENT_ID`` with
``SUITE_CLIENT_SECRET`` / ``SUITE_PRIVATE_KEY_B64``. ``SUITE_ORG_WIDE_APPS`` (optional, comma-separated, lowercase):
apps the organisation granted to everyone through an administrator (enterprise indexers, security tooling); they are
not per-user grants and ``suite_revoke_token`` refuses them.

Credential scope: the READ credential needs read-only directory and audit-log access. ``suite_list_tokens`` and the
two writes need the user-security scope (grant list, grant revocation, sign-out), which most suites have no read-only
variant of; keep it on a separate writer credential so the read client never carries it.

Common envelope
---------------
Every tool returns a JSON object with ``status``. Shared statuses: ``invalid_input`` (nothing sent; fix the input named
in ``message``), ``not_found``, ``ambiguous`` (several matches, candidates listed), ``refused`` (a deliberate
boundary), ``error`` (``message``, optional ``hint``), ``not_implemented`` (the example skeleton). Most results carry
``next_step`` (an instruction to the model) and ``now`` (ISO-8601 UTC). Failures are never evidence about a user.

Read tools
----------
``suite_get_user(user)``
    ``user``: email (primary or alias) or a name ('First Last' or one name word). Returns ``status: ok`` with
    ``lookup {by: email|name, input}``, ``user {primary_email, user_id, name, suspended, suspension_reason, archived,
    is_admin, is_delegated_admin, mfa_enrolled, mfa_enforced, last_login_time, never_logged_in, creation_time,
    org_unit, aliases, matched_alias, recovery_email, recovery_phone, title, department, manager, country,
    admin_url}`` (an ALLOWLIST: nothing else from the directory object) and ``flags`` (e.g. "account is SUSPENDED",
    "SUPER ADMIN", "has never logged in"). A name matching several people is ``ambiguous`` with candidates.

``suite_search_activity(application, user?, lookback_hours?, until_hours_ago?, event_name?, ip?, filters?, match?,
human_only?, max_events?)``
    Searches ONE audit log (``APPLICATIONS``) for one user or org-wide over a RELATIVE window (no absolute dates),
    following pagination up to the adapter's page/time budget. Returns ``status: ok`` with ``query`` (the effective
    query and window), ``counts {activities_fetched, events_analyzed, events_returned, events_truncated,
    truncation_reason, window_truncated, pages_fetched, stopped_because, window_first_event, window_last_event}``,
    ``aggregates`` over EVERYTHING fetched (event_names, actors, ips with region/asn/first/last seen, regions, asns,
    direct_events vs via_apps, external_domains, per-application parameter tallies, and for ``token`` an
    ``oauth_apps`` summary with broad scopes flagged), ``notable`` (watched event names with examples) and the newest
    ``events``. ``window_truncated: true`` means the oldest part of the window was NOT read.

``suite_list_tokens(user)`` (LIST_TOOLS: a read that runs on the writer's credential)
    The third-party OAuth grants ONE user holds right now: ``user {primary_email, user_id, name, suspended,
    matched_alias}``, ``counts {total, broad}``, ``tokens [{client_id, display_text, scopes, scope_count,
    broad_scopes, native_app, anonymous}]`` sorted broad-scope first.

Write tools (analyst-requested only; no automatic actions in this domain)
-------------------------------------------------------------------------
Every write result carries ``written``: false (nothing changed), true (accepted), null (may or may not have applied;
then also ``outcome_unknown: true``), plus ``requested_by`` (the verified requester the server passes; never model
input) and ``reason``.

``suite_revoke_token(user, client_id, reason)``
    Revoke ONE grant from ONE user, then confirm by read-back. Statuses: ``revoked`` (confirmed absent),
    ``uncertain`` (accepted but still listed), ``no_change`` (the user holds no such grant), ``ambiguous`` (a display
    name matched several grants), ``refused``. Fields: ``user``, ``app {client_id, display_text}``,
    ``scopes_revoked``, ``broad_scopes_revoked``, ``grants_before``, ``grants_after``, ``confirmed_absent``,
    ``performed_as``, ``admin_url``, ``summary``.

``suite_sign_out_user(user, reason)``
    End every web and device session of ONE user. Statuses: ``signed_out``, ``no_change`` (account suspended, so it
    has no session), ``refused``. Fields: ``user {primary_email, user_id, name, org_unit, is_admin, matched_alias}``,
    ``confirmed_by``, ``does_not_cover`` (OAuth grants, password, app passwords, the IdP session), ``admin_url``.

Guardrails an implementation MUST enforce
-----------------------------------------
* Exact allowlist of outbound requests (method, path, query keys), checked before any network I/O; the user segment
  of a path always comes from the directory's own answer, never from model input. No redirects followed.
* Writes need a verified requester (refused without one); any ``requested_by`` argument is ignored.
* ``reason`` >= ``MIN_REASON`` characters and not a placeholder ("test", "n/a", "as requested", ...).
* ONE user and ONE grant per call (lists refused, so each change is reported separately).
* Never act on service accounts (local part starting ``svc``/``service`` followed by ``-``, ``_`` or ``.``):
  integrations run as them; a human acts in the admin console.
* Org-wide (administrator-granted) apps are not per-user grants: refuse revoking them (``SUITE_ORG_WIDE_APPS``).
* A change call that fails with a 5xx or a network error is ``written: null`` / ``outcome_unknown``; never retry a
  write automatically. Read back after revoking.
* Secrets the client holds never appear in a result; results are capped (~40 kB).
"""

from __future__ import annotations

from typing import Any

PREFIX = "SUITE"
TOOL_PREFIX = "suite_"

MIN_REASON = 20
MAX_REASON = 1000
MAX_SUBJECT = 256
DEFAULT_LOOKBACK_H, MAX_LOOKBACK_H = 168, 4320
UNSCOPED_MAX_HOURS = 24  # org-wide with no event_name, ip or filters
DEFAULT_MAX_EVENTS, MAX_EVENTS = 25, 100
MAX_FILTERS = 5
MAX_MATCH = 128
FILTER_OPERATORS = ("==", "<>", "<", "<=", ">", ">=")

#: Audit logs a suite exposes (neutral names; an adapter maps them to its product's log names).
APPLICATIONS = (
    "admin", "browser", "calendar", "chat", "files", "groups", "login", "mail", "meetings", "mobile", "rules", "sso",
    "token", "user_accounts",
)
APPLICATION_ALIASES = {
    "oauth": "token", "tokens": "token", "logins": "login", "email": "mail", "drive": "files", "file": "files",
    "documents": "files", "docs": "files", "admin_console": "admin", "accounts": "user_accounts",
    "user_account": "user_accounts", "group": "groups", "saml": "sso", "meet": "meetings", "devices": "mobile",
}
#: Absolute-time parameters the search refuses: time is always relative (lookback_hours / until_hours_ago).
ABSOLUTE_TIME_PARAMS = ("since", "until", "start", "end", "start_date", "end_date", "start_time", "end_time",
                        "startTime", "endTime", "date")
#: Service-account local parts the writes refuse.
PROTECTED_ACCOUNT_PATTERN = r"^(svc|service)[-_.]"

_REASON_DESC = (f"Why (>= {MIN_REASON} characters), with the ticket, alert or thread it came from. The record of the "
                "change.")

TOOLS: list[dict] = [
    {
        "name": "suite_get_user",
        "description": (
            "Look up ONE productivity suite account by email (primary or alias) or by name ('First Last' or one name "
            "word) and return its current directory security profile: suspended/archived, admin flags, MFA "
            "enrolment, last login, creation time, org unit, title, department, manager, aliases, recovery "
            "email/phone, an admin console link (admin_url), and a `flags` list. A name matching several people "
            "returns status `ambiguous` with candidates. Current state only, not history. Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Email address (aliases accepted) or a person's name."},
            },
            "required": ["user"],
        },
    },
    {
        "name": "suite_search_activity",
        "description": (
            "Search ONE productivity suite audit log for one user or org-wide over a relative window, following "
            "pagination. Applications: " + ", ".join(APPLICATIONS) + ". ONE event_name per call. Returns "
            "`aggregates` over everything fetched (event names, actors, IPs with region/ASN/first/last seen, "
            "regions, ASNs, direct vs app-impersonated activity, external domains, per-application parameter "
            "tallies, and for token an oauth_apps summary with broad scopes flagged), `notable` watched events with "
            "examples, and the newest `events`. `counts.window_truncated` says whether the whole window was read. "
            f"Org-wide searches longer than {UNSCOPED_MAX_HOURS} hours need event_name, ip or filters. Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {
                "application": {"type": "string", "enum": list(APPLICATIONS),
                                "description": "Which audit log. Sign-ins: login. OAuth grants: token. Account "
                                               "security changes: user_accounts. Admin console changes: admin."},
                "user": {"type": "string", "description": "The user's email. Omit, or 'all', for org-wide."},
                "lookback_hours": {"type": "integer", "description": f"Where the window starts, in hours ago. "
                                   f"Default {DEFAULT_LOOKBACK_H}, max {MAX_LOOKBACK_H}."},
                "until_hours_ago": {"type": "integer", "description": "Where the window ends, in hours ago. "
                                    "Default 0 (now)."},
                "event_name": {"type": "string", "description": "ONE event name, e.g. suspicious_login, "
                               "login_failure, authorize, revoke, download, change_user_access."},
                "ip": {"type": "string", "description": "One IP address (the actor's)."},
                "filters": {"description": f"Server-side event-parameter filters (max {MAX_FILTERS}): a list of "
                            "{parameter, operator, value} (operators == <> < <= > >=) or an object {parameter: "
                            "value}, e.g. {\"app_name\": \"ExampleApp\"}.",
                            "anyOf": [{"type": "array", "items": {"type": "object"}}, {"type": "object"},
                                      {"type": "string"}]},
                "match": {"type": "string", "description": "Case-insensitive substring applied after fetching, over "
                          "every event field."},
                "human_only": {"type": "boolean", "description": "true drops activity apps performed while "
                               "impersonating the user (e.g. enterprise indexers)."},
                "max_events": {"type": "integer", "description": f"How many events to LIST (default "
                               f"{DEFAULT_MAX_EVENTS}, max {MAX_EVENTS}). Never limits what is counted."},
            },
            "required": ["application"],
        },
    },
]

LIST_TOOLS: list[dict] = [
    {
        "name": "suite_list_tokens",
        "description": (
            "List the third-party OAuth grants ONE user holds right now: client_id, app name (display_text), scopes, "
            "and broad scopes flagged. Sorted broad-scope first. Current state only; the `token` audit log in "
            "suite_search_activity has the history. Apps granted org-wide by an administrator never appear here. "
            "Read-only."),
        "input_schema": {
            "type": "object",
            "properties": {"user": {"type": "string", "description": "The user's exact email address."}},
            "required": ["user"],
        },
    },
]

WRITE_TOOLS: list[dict] = [
    {
        "name": "suite_revoke_token",
        "description": (
            "WRITE. Revoke ONE third-party OAuth grant from ONE user, then confirm it's gone on read-back. Only on an "
            "explicit request from the analyst for that app and that account. Take `client_id` from suite_list_tokens "
            "(an exact display name also works when it matches one grant). Refuses service accounts and apps granted "
            "org-wide by an administrator; an app the user doesn't hold is `no_change`. Before revoking, check the "
            "app isn't security tooling the team relies on. Returns `revoked`, `uncertain`, `no_change`, "
            "`ambiguous` or `refused` with `written`. The requester is recorded automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "The user's exact email address."},
                "client_id": {"type": "string", "description": "The grant's OAuth client id from suite_list_tokens."},
                "reason": {"type": "string", "description": _REASON_DESC},
            },
            "required": ["user", "client_id", "reason"],
        },
    },
    {
        "name": "suite_sign_out_user",
        "description": (
            "WRITE. Sign ONE user out of every productivity suite web and device session (they must sign in again). "
            "Only on an explicit request from the analyst for that account. Doesn't revoke OAuth grants, change the "
            "password, or end the identity provider session (which signs them straight back in through SSO). Refuses "
            "service accounts; a suspended account is `no_change`. Returns `signed_out` with `written`. The "
            "requester is recorded automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "The user's exact email address."},
                "reason": {"type": "string", "description": _REASON_DESC},
            },
            "required": ["user", "reason"],
        },
    },
]

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
LIST_TOOL_NAMES = frozenset(t["name"] for t in LIST_TOOLS)
WRITE_TOOL_NAMES = frozenset(t["name"] for t in WRITE_TOOLS)
ALL_TOOL_NAMES = TOOL_NAMES | LIST_TOOL_NAMES | WRITE_TOOL_NAMES


def tool(name: str) -> dict[str, Any] | None:
    """The schema for one tool of this domain, or None."""
    return next((t for t in TOOLS + LIST_TOOLS + WRITE_TOOLS if t["name"] == name), None)
