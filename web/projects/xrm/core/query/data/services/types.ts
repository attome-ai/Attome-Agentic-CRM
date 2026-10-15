export interface QueryColumnDef {
  name:           string;
  display_name:   string;
  data_type:      string;
  is_visible:     boolean;
  is_sortable:    boolean;
  is_searchable:  boolean;
  is_clickable:   boolean;
  route_template: string;
  /** Logical name of the entity a `data_type: "lookup"` column points to —
   * absent/`null` for every other column. Metadata-derived, never read from
   * or writable through an admin's `table_definition` (the server always
   * recomputes it), so the view editor's column drafts never need to set it. */
  lookup_target_entity?: string | null;
  /** Per-value color/icon presentation hints for a `data_type: "choice"`
   * column, keyed by choice value — absent/`null` for every other column,
   * and for a choice column with no configured styles. Metadata-derived,
   * same as `lookup_target_entity`. */
  choice_styles?: Record<string, { color?: string | null; icon?: string | null }> | null;
}

export interface QueryExecParams {
  query_id?:            string;
  view_id?:             string;
  entity_logical_name?: string;
  entity?:              string;
  page?:      number;
  page_size?: number;
  search?:    string;
  order_by?:  string;
  order_dir?: 'asc' | 'desc';
  filters?:   { field: string; op: string; value?: string }[];
  // P-stored-query-containment (D-126): the server's default flipped to
  // keyset/cursor mode (no total) when neither of these is set — pass
  // include_total: true for page-number-style UIs that need an exact count,
  // or after_id to continue an existing cursor page (export/infinite-scroll).
  include_total?: boolean;
  after_id?:      string;
  /** D-521: run this exact published version of the query (a published
   * dashboard's pinned dependency). The query must still be active and every
   * authorization gate still applies; only the SQL comes from the version. */
  query_version_id?: string;
}

export interface QueryExecResponse {
  metadata: {
    query_id:  string;
    view_id:   string | null;
    record_no: string | null;
    entity_logical_name: string | null;
    can_edit_query: boolean;
    /** D-429's view `kind` (chart follow-up, migration 0447) — `null` when
     * this execution has no bound view. Lets a non-admin caller (the
     * dashboard widget viewer) render `kind`-specific settings without a
     * second, admin-gated `GET /api/v1/admin/views/{id}` call. */
    view_kind:     string | null;
    view_metadata: Record<string, unknown> | null;
  };
  data: {
    columns:     QueryColumnDef[];
    records:     Record<string, unknown>[];
    // null in cursor mode (D-126) — only meaningful when include_total: true
    // was sent (or query.cursor_default is false server-side).
    total:       number | null;
    // A13-T2: `total` is the planner's estimate (a large result is not counted).
    total_estimated?: boolean;
    page:        number;
    page_size:   number;
    total_pages: number | null;
    // Present only in cursor mode; pass back as after_id for the next page.
    next_cursor?: string | null;
  };
}
