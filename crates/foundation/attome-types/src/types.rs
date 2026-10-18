use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;

/// The platform's canonical offset-pagination envelope (guidelines §12).
///
/// `page` echoes the page the server actually served. Every offset list is
/// one-based (D-793): page 1 is the first page, and the offset is
/// `(page - 1) * page_size`.
///
/// Under concurrent writes, an insert or delete ahead of the current offset
/// shifts every later page, which can duplicate or skip rows across two
/// requests — an accepted tradeoff of offset pagination, not a bug.
/// `CursorPage<T>` below exists for the access pattern that needs to avoid
/// that failure mode instead.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(
    description = "The platform's canonical list envelope (guidelines §12). \
                        `total` is the size of the whole set, not of `items`. \
                   `page` echoes the page served; every offset list is one-based \
                   (D-793): page 1 is the first page."
)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// One field-level failure inside `ErrorResponse.details` (BTY-16b): the
/// field the caller sent, a stable machine-readable `code` the client maps
/// to localized text (e.g. `required`, `too_long`, `invalid_format`,
/// `not_allowed`), and the English server-side `message`.
///
/// A list, not a single error, so one 422 can answer with every bad field at
/// once (BTY-F11) instead of making a form discover them one round-trip at a
/// time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FieldError {
    /// The offending field, as the caller addressed it (e.g. `email` or
    /// `amount`).
    pub field: String,
    /// Stable machine-readable failure code for this field, independent of
    /// the message text.
    pub code: String,
    /// Human-readable, English, server-side detail for this field.
    pub message: String,
}

impl FieldError {
    /// Every failure's message in one line, for a caller that shows text
    /// (A3-T1): a single failure reads exactly as its own message.
    pub fn summary(errors: &[FieldError]) -> String {
        errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// One business-rule `error` policy that fired (D-789 §3.3), inside a
/// `rule_violation` body's `details.rules`. Carries names and the rule's own
/// message, never a record value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleFailure {
    pub rule_id: Uuid,
    /// The rule's display name (its name when it has none).
    pub rule_name: String,
    /// The field the policy is attached to, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub message: String,
}

/// `details` of a `rule_violation` response (D-789): the field of the first
/// failing policy, when it names one, and every blocking `error` policy that
/// fired, the first (by rule display order) being the one `rule_id` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleViolationDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub rules: Vec<RuleFailure>,
}

/// One field a business rule locks for the writer (D-789 §3.5): `effect` is
/// `hidden` or `disabled`. No value is ever echoed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LockedField {
    pub field: String,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub effect: String,
}

/// `details` of a `field_locked` / `field_locked_required` response: every
/// refused field, the first being the one the top-level `field` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FieldLockedDetails {
    pub fields: Vec<LockedField>,
}

/// `ErrorResponse.details`: its shape depends on the `error` code —
/// a list of [`FieldError`] on `validation_error`, [`RuleViolationDetails`] on
/// `rule_violation`, [`FieldLockedDetails`] on `field_locked` and
/// `field_locked_required` (D-789).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum ErrorDetails {
    Fields(Vec<FieldError>),
    RuleViolation(RuleViolationDetails),
    FieldLocked(FieldLockedDetails),
}

/// The error body every `AppError` serializes to (`error.rs`'s `into_response`),
/// plus the `request_id` that `attome_server`'s response middleware injects
/// (D-043). Declared as its own type purely so `#[utoipa::path(responses(...))]`
/// has something to point `body =` at — nothing constructs it, because
/// `into_response` builds the JSON directly.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(
    description = "Standard error envelope. `error` is a stable machine-readable code; \
                   `message` is human-readable and never contains internal detail.",
    example = json!({
        "error": "validation_error",
        "message": "validation error: name is required",
        "request_id": "018f0a1b-2c3d-7e4f-8a9b-0c1d2e3f4a5b"
    })
)]
pub struct ErrorResponse {
    /// Stable machine-readable code — `not_found`, `unauthorized`, `forbidden`,
    /// `attribute_not_writable`, `limit_exceeded`,
    /// `conflict`, `version_conflict`, `duplicate_detected`, `idempotency_conflict`,
    /// `validation_error`, `customer_tests_failed`, `feature_unavailable`, `feature_hidden`,
    /// `rate_limit_exceeded`, `overloaded`, `capability_unavailable`,
    /// `metadata_authoring_locked`, `transition_not_allowed`,
    /// `rule_violation`, `field_locked`, `field_locked_required`,
    /// `reauth_required`, `server_timeout`, `query_timeout`, `read_only`, `payload_too_large`,
    /// `idempotency_outcome_unknown`, `idempotency_replay_unavailable`,
    /// `method_not_allowed`, or
    /// `internal_error` — one per `AppError` variant (`FieldLocked` answers
    /// two: plain and required) (`attome-types/src/error.rs`); M01 Core C-23
    /// found this list four codes short of the taxonomy it documents.
    pub error: String,
    pub message: String,
    /// Z14-T1 (RFC 9457): `about:blank`; the problem is named by `code`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub problem_type: Option<String>,
    /// The HTTP status phrase, e.g. `Not Found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The HTTP status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The same text as `message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The same value as `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Whether the same request may succeed later (the error catalogue's
    /// verdict for `code`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    /// The request path the problem happened at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Every field-level failure on a `validation_error`, as
    /// `{attribute, rule, message, fix}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<serde_json::Value>>,
    /// Present on responses that passed through the request-id middleware
    /// (D-043); absent on the few pre-middleware rejection paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Present on a `rule_violation` response (D-472): the id of the
    /// `xrm_core_rule` whose failing expression produced this 422, so a
    /// client can highlight or re-check the exact rule without parsing
    /// `message`. Omitted on every other code, and on any response that
    /// does not name a rule.
    /// Also present on `field_locked` / `field_locked_required` (D-789): the
    /// business rule that locks `field`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<Uuid>,
    /// Present on `field_locked` / `field_locked_required` (D-789): the first
    /// refused field (every one is in `details.fields`); on
    /// `attribute_not_writable` (Q15-T4): the attribute the caller may not
    /// write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Present on `field_locked` / `field_locked_required`: the display name
    /// of the rule that locks `field`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    /// Present on `field_locked` / `field_locked_required`: `hidden` or
    /// `disabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// Structured detail, shaped by `error` (see [`ErrorDetails`]): every
    /// field-level failure on a `validation_error` response when the raiser
    /// has a field list, so a form can render them all at once; every firing
    /// rule on a `rule_violation` response from a business rule; every
    /// refused field on `field_locked` / `field_locked_required`. Omitted
    /// otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
    /// Present on a version conflict: the `row_version` the server currently
    /// holds, so a caller can re-read and retry instead of guessing what the
    /// winner wrote. Omitted when the conflict is not version-based.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<i64>,
    /// Present on a version conflict: the server's current row for the
    /// fields the caller touched, as a JSON object. The owning engine filters
    /// sensitive columns out before building it (BTY-16c's precondition), so
    /// this is a deliberate filtered projection — never a raw row dump.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_state: Option<serde_json::Value>,
    /// Present on `duplicate_detected` (A15-T4): the existing records the
    /// save matches that the caller may read (record, rule, score).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<serde_json::Value>,
    /// Present on `duplicate_detected`: how many more matches the caller may
    /// not read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<i64>,
    /// Present on a `rate_limit_exceeded` response when the limiter knows its
    /// window: seconds to wait before retrying, equal by construction to the
    /// `Retry-After` header on the same response (BTY-11a). Omitted when the
    /// limit that was hit has no known window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_sec: Option<u64>,
}

/// The `reauth_required` body (D-510 rule 6): the standard envelope plus the
/// operation that needs a step-up and the factors that can satisfy it.
/// Documentation-only, like [`ErrorResponse`]: `error.rs`'s `into_response`
/// builds the JSON.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(
    description = "A sensitive operation needs a fresh step-up on the caller's own session. \
                   Never an expired session: the client prompts for a step-up and must not \
                   refresh or sign out.",
    example = json!({
        "error": "reauth_required",
        "message": "re-authentication is required for this operation",
        "operation": "api_key_create",
        "acceptable_factors": ["password", "federated"],
        "request_id": "018f0a1b-2c3d-7e4f-8a9b-0c1d2e3f4a5b"
    })
)]
pub struct ReauthRequiredResponse {
    /// Always `reauth_required`.
    pub error: String,
    pub message: String,
    /// Present on responses that passed through the request-id middleware
    /// (D-043).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The protected operation, from the route: `identity_link` or
    /// `api_key_create`.
    pub operation: String,
    /// The factors a step-up for this operation accepts now: `totp`,
    /// `recovery_code`, `password` and `federated`, or the single
    /// `totp_enrollment_required` when the account has none.
    pub acceptable_factors: Vec<String>,
}

/// A 401 from a route guarded by a step-up (D-510): either the standard
/// envelope (`unauthorized`, for a missing session or a session without a live
/// refresh family) or a [`ReauthRequiredResponse`]. Clients tell them apart by
/// `error`. Documentation-only.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum UnauthorizedResponse {
    ReauthRequired(ReauthRequiredResponse),
    Unauthorized(Box<ErrorResponse>),
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: i64, page_size: i64) -> Self {
        Self {
            items,
            total,
            page,
            page_size,
        }
    }
}

/// The platform's canonical keyset-pagination envelope (guidelines §12) —
/// the generic counterpart to `PaginatedResponse<T>` for an access pattern
/// that genuinely needs cursor rather than offset paging (a large or
/// unbounded scan, where computing an exact `total` would mean a full-table
/// count on every page). Before this existed, a handler with that access
/// pattern had nowhere to reach for a shared shape and invented its own
/// `{items, next_cursor}`-shaped struct ad hoc (C-25) — `query/execute`'s own
/// tabular/cursor response predates this type and is deliberately NOT
/// migrated onto it (guidelines §12's own carve-out: column metadata plus a
/// keyset cursor is a materially different shape from a plain item list, not
/// a bespoke duplicate of this one).
///
/// `next_cursor` is an opaque, serialized token — `None` means "no further
/// page." `total` is optional: a route that can count its window cheaply
/// once sets it on the first page (`with_total`) and leaves it out on
/// continuation pages, where the count would be a repeated full scan (the
/// change feed does this). Callers whose native cursor is not already a string (e.g. a
/// `Uuid` primary key, as `xrm_entity_engine::query_exec`'s own keyset
/// cursor is) format it to one; nothing here is coupled to any single
/// cursor encoding.
///
/// This is not "immune to mutation" in some absolute sense — the guarantee
/// is specifically about inserts/deletes relative to the cursor position.
/// With a deterministic keyset ordering, a page request re-queries `WHERE
/// ordering_key > last_seen` (rather than `OFFSET n`), so it avoids
/// `PaginatedResponse<T>`'s offset-shifting failure mode by construction:
/// a row inserted or deleted elsewhere in the set does not shift which
/// rows the next request sees. This is the reason to prefer it for large
/// or high-churn traversals — see the module-level carve-out above for why
/// `query/execute`'s own tabular/cursor shape isn't simply migrated onto
/// this type.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(
    description = "The platform's canonical keyset-pagination envelope (guidelines §12), for \
                        an access pattern where an exact `total` would need an unbounded scan. \
                        `next_cursor` is opaque; `None` means there is no further page. `total`, \
                        when present, is the exact size of the whole window; routes that send it \
                        send it on the first page only."
)]
pub struct CursorPage<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Exact size of the whole window, when the route counts it (first page
    /// only); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
}

impl<T> CursorPage<T> {
    pub fn new(items: Vec<T>, next_cursor: Option<String>) -> Self {
        Self {
            items,
            next_cursor,
            total: None,
        }
    }

    /// Attaches the window's exact size (set it on the first page only).
    pub fn with_total(mut self, total: Option<i64>) -> Self {
        self.total = total;
        self
    }
}

/// Which base an offset-paginated operation uses for its `page` parameter.
/// Every list is one-based (D-793 retired the zero-based `ZeroLegacy` base
/// and moved its lists over): page 1 is the first page, and `OnePageQuery`
/// below publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageBase {
    /// Page 1 is the first page (D-347, D-793).
    One,
}

impl PageBase {
    /// The smallest page this base can serve.
    pub const fn first_page(self) -> i64 {
        match self {
            PageBase::One => 1,
        }
    }
}

/// Ceiling on any accepted `page`. It exists to bound the offset arithmetic, not to bound a real page count.
pub const MAX_PAGE: i64 = 1_000_000;

/// A resolved, safe offset window: the page actually served, the page size
/// actually used, and the `OFFSET` to bind. `PageWindow::resolve` is
/// the one place the per-endpoint page base is turned into an offset, so
/// every list that uses it agrees with the base its own OpenAPI description
/// states instead of hand-rolling a third convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageWindow {
    /// The page served, clamped to the base floor and to `MAX_PAGE`.
    pub page: i64,
    /// The page size served, clamped to `1..=MAX_PAGE_SIZE`.
    pub page_size: i64,
    /// The `OFFSET` to bind: `(page - first_page) * page_size`.
    pub offset: i64,
}

impl PageWindow {
    /// Resolves a client-supplied `page`/`page_size` pair against a
    /// declared base. Pure integer arithmetic: the size clamps to
    /// `1..=MAX_PAGE_SIZE` (so a zero, negative or huge request can never
    /// produce a zero-row or unbounded query), the page clamps to the base
    /// floor and `MAX_PAGE`, and the offset saturates rather than
    /// overflowing. Missing values take `default_size` and the base is first
    /// page.
    pub fn resolve(
        page: Option<i64>,
        page_size: Option<i64>,
        base: PageBase,
        default_size: i64,
    ) -> Self {
        let page_size = page_size.unwrap_or(default_size).clamp(1, MAX_PAGE_SIZE);
        let first = base.first_page();
        let page = page.unwrap_or(first).clamp(first, MAX_PAGE);
        let offset = page.saturating_sub(first).saturating_mul(page_size);
        Self {
            page,
            page_size,
            offset,
        }
    }
}

/// The standard query for a **one-based** offset list (D-347, D-793): `page`
/// defaults to 1 (the first page) and `page_size` to `DEFAULT_PAGE_SIZE`, both
/// clamped exactly as `PageWindow::resolve` clamps them. Offset lists take
/// `Query<OnePageQuery>` and call `window()` rather than declaring a local
/// paging struct (no script checks this, D-768; it is held by review).
#[derive(Debug, Clone, Copy, serde::Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OnePageQuery {
    /// One-based (D-347): page 1 is the first page. Values below 1 are
    /// clamped up to 1 rather than rejected, matching the legacy lists.
    pub page: Option<i64>,
    /// Rows per page, clamped to `1..=MAX_PAGE_SIZE`. Defaults to
    /// `DEFAULT_PAGE_SIZE`.
    pub page_size: Option<i64>,
}

impl OnePageQuery {
    /// The clamped, bindable window this query asks for.
    pub fn window(&self) -> PageWindow {
        PageWindow::resolve(self.page, self.page_size, PageBase::One, DEFAULT_PAGE_SIZE)
    }
}

pub const DEFAULT_PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;

const _: () = {
    assert!(DEFAULT_PAGE_SIZE > 0);
    assert!(DEFAULT_PAGE_SIZE <= MAX_PAGE_SIZE);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wires_every_field_through_unchanged() {
        let resp = PaginatedResponse::new(vec![1, 2, 3], 42, 2, 10);
        assert_eq!(resp.items, vec![1, 2, 3]);
        assert_eq!(resp.total, 42);
        assert_eq!(resp.page, 2);
        assert_eq!(resp.page_size, 10);
    }

    #[test]
    fn new_preserves_an_empty_item_list_distinctly_from_zero_total() {
        // A caller filtering client-side must be able to tell "no items on
        // this page" apart from "no items at all" via `total`.
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 0, 1, 50);
        assert!(resp.items.is_empty());
        assert_eq!(resp.total, 0);

        let resp_with_more: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 100, 5, 50);
        assert!(resp_with_more.items.is_empty());
        assert_eq!(resp_with_more.total, 100);
    }

    #[test]
    fn cursor_page_new_wires_both_fields_through_unchanged() {
        let page = CursorPage::new(vec![1, 2, 3], Some("abc".to_owned()));
        assert_eq!(page.items, vec![1, 2, 3]);
        assert_eq!(page.next_cursor, Some("abc".to_owned()));
    }

    #[test]
    fn cursor_page_none_next_cursor_means_no_further_page() {
        let page: CursorPage<i32> = CursorPage::new(vec![1], None);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn cursor_page_omits_next_cursor_from_json_when_none() {
        let page: CursorPage<i32> = CursorPage::new(vec![1], None);
        let json = serde_json::to_value(&page).unwrap();
        assert!(
            json.get("next_cursor").is_none(),
            "a None next_cursor must be omitted, not serialized as null: {json:?}"
        );
    }

    #[test]
    fn cursor_page_includes_next_cursor_from_json_when_some() {
        let page = CursorPage::new(vec![1], Some("xyz".to_owned()));
        let json = serde_json::to_value(&page).unwrap();
        assert_eq!(json["next_cursor"], "xyz");
    }

    // ── BTY-P0.1 → BTY-F1 (S1): the published paging text must be true ───────

    /// The `///` lines in the block immediately above `marker`: everything
    /// back to the preceding blank line, with the `#[derive(...)]` /
    /// `#[schema(...)]` attribute lines filtered out.
    fn doc_block_above(src: &str, marker: &str) -> String {
        let idx = src
            .find(marker)
            .unwrap_or_else(|| panic!("{marker:?} not found"));
        let head = &src[..idx];
        let start = head.rfind("\n\n").map(|p| p + 1).unwrap_or(0);
        head[start..]
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("///"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn published_property_names<T: utoipa::PartialSchema>() -> Vec<String> {
        let schema = <T as utoipa::PartialSchema>::schema();
        match schema {
            utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(object)) => {
                object.properties.keys().cloned().collect()
            }
            _ => panic!("expected an inline object schema"),
        }
    }

    /// S3/BTY-F4 (D-472): the structured `rule_id` that
    /// `into_response` already adds to a `rule_violation` body must be
    /// published on the ErrorResponse schema, not exist only in JSON that
    /// happens to be built at runtime.
    #[test]
    fn error_response_publishes_rule_id() {
        let names = published_property_names::<ErrorResponse>();
        for expected in ["error", "message", "request_id", "rule_id"] {
            assert!(
                names.contains(&expected.to_string()),
                "ErrorResponse schema lacks {expected}: {names:?}"
            );
        }
    }

    /// S3/BTY-16a: the four structured extras must be declared on the
    /// ErrorResponse schema — the copy `generate:api` publishes — and
    /// `FieldError`, the `details` item shape, must publish its three
    /// fields, or a client cannot read a single one of them.
    #[test]
    fn error_response_publishes_the_structured_extras() {
        let names = published_property_names::<ErrorResponse>();
        for expected in [
            "details",
            "current_version",
            "current_state",
            "retry_after_sec",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "ErrorResponse schema lacks {expected}: {names:?}"
            );
        }
        let field_names = published_property_names::<FieldError>();
        for expected in ["field", "code", "message"] {
            assert!(
                field_names.contains(&expected.to_string()),
                "FieldError schema lacks {expected}: {field_names:?}"
            );
        }
    }

    // ── BTY-6: the D-347 paging primitive ───────────────────────────────────

    #[test]
    fn page_window_one_based_clamps_zero_to_one() {
        // page=0 is below One's floor: clamp up, and the offset stays 0 so a
        // caller that sends 0 gets the first page rather than a negative
        // OFFSET (which Postgres rejects).
        let window = PageWindow::resolve(Some(0), Some(50), PageBase::One, DEFAULT_PAGE_SIZE);
        assert_eq!(window.page, 1);
        assert_eq!(window.offset, 0);

        let second = PageWindow::resolve(Some(2), Some(50), PageBase::One, DEFAULT_PAGE_SIZE);
        assert_eq!(second.page, 2);
        assert_eq!(second.offset, 50);

        // An absent page is the base's first page.
        let defaulted = PageWindow::resolve(None, None, PageBase::One, DEFAULT_PAGE_SIZE);
        assert_eq!(defaulted.page, 1);
        assert_eq!(defaulted.page_size, DEFAULT_PAGE_SIZE);
        assert_eq!(defaulted.offset, 0);
    }

    #[test]
    fn page_window_zero_or_negative_page_is_the_first_page() {
        // D-793: no zero-based list remains, so page 0 (an old caller) and a
        // negative page both clamp to page 1 instead of going negative.
        for bad in [0, -5] {
            let window = PageWindow::resolve(Some(bad), Some(20), PageBase::One, DEFAULT_PAGE_SIZE);
            assert_eq!(window.page, 1, "page {bad} must clamp up to 1");
            assert_eq!(window.offset, 0);
        }
    }

    #[test]
    fn page_window_clamps_size_to_max() {
        let huge = PageWindow::resolve(Some(1), Some(10_000), PageBase::One, DEFAULT_PAGE_SIZE);
        assert_eq!(huge.page_size, MAX_PAGE_SIZE);

        for bad in [0, -1, i64::MIN] {
            let window = PageWindow::resolve(Some(1), Some(bad), PageBase::One, DEFAULT_PAGE_SIZE);
            assert_eq!(window.page_size, 1, "page_size {bad} must clamp up to 1");
        }

        // A non-positive default_size must not produce a zero-row query.
        let defaulted = PageWindow::resolve(None, None, PageBase::One, 0);
        assert_eq!(defaulted.page_size, 1);
    }

    #[test]
    fn page_window_offset_never_overflows() {
        let window = PageWindow::resolve(
            Some(i64::MAX),
            Some(i64::MAX),
            PageBase::One,
            DEFAULT_PAGE_SIZE,
        );
        assert_eq!(window.page, MAX_PAGE);
        assert_eq!(window.page_size, MAX_PAGE_SIZE);
        assert_eq!(window.offset, (MAX_PAGE - 1) * MAX_PAGE_SIZE);
        assert!(window.offset >= 0);
    }

    /// The published one-based query must resolve to the one-based base, and
    /// its own doc must name that base (the BTY-7 guard reads it).
    #[test]
    fn one_page_query_is_one_based_and_publishes_its_base() {
        let defaulted = OnePageQuery {
            page: None,
            page_size: None,
        };
        assert_eq!(defaulted.window().page, 1);
        assert_eq!(defaulted.window().offset, 0);
        let zero = OnePageQuery {
            page: Some(0),
            page_size: Some(10),
        };
        assert_eq!(zero.window().page, 1);
        assert_eq!(zero.window().offset, 0);
    }

    /// D-793: the schema description (the copy `generate:api` writes into
    /// `openapi.json` and both `api-types.ts`) and the Rust doc both state the
    /// one base, and neither still mentions the retired zero-based lists.
    #[test]
    fn paginated_schema_states_the_one_based_contract() {
        let schema = <PaginatedResponse<()> as utoipa::PartialSchema>::schema();
        let description = match schema {
            utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(object)) => {
                object.description.unwrap_or_default()
            }
            _ => panic!("expected an inline object schema for PaginatedResponse"),
        };
        assert!(
            description.contains("D-793") && description.contains("one-based"),
            "PaginatedResponse schema description must state the one-based contract: {description}"
        );
        assert!(
            !description.contains("zero-based"),
            "no zero-based list remains (D-793): {description}"
        );

        let doc = doc_block_above(include_str!("types.rs"), "pub struct PaginatedResponse");
        assert!(
            doc.contains("D-793") && doc.contains("one-based") && !doc.contains("zero-based"),
            "PaginatedResponse doc comment must state the one-based contract only: {doc}"
        );
    }
}
