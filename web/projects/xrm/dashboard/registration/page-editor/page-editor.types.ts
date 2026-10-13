/** `GET /api/v1/attome-dashboard/widget-types` response shape — only the fields
 * the palette needs (same subset `dashboard-editor.component.ts`'s own
 * `WidgetTypeDescriptor` already used for its plain add-widget dropdown). */
export interface WidgetTypeDescriptor {
  type_id:      string;
  display_name: string;
  category:     string;
}

/** A move/resize commit, or an inline field edit (name/query_id) — always a
 * plain-field patch, since move/resize/rename are all generic entity CRUD
 * (guidelines §9: "reorder is just a field update"). */
export interface WidgetPositionCommit {
  widgetId: string;
  patch:    Record<string, unknown>;
}
