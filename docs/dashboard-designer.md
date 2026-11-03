# Dashboard designer

`/xrm/dashboard/{id}/design` edits a dashboard's draft on the shared canvas: its pages, their sections
(sections can hold sections) and the widgets in each section, as one tree.

- Add a page, a section, or a widget from the widget registry into what is selected; drag to reorder
  or to move a widget into another section; undo and redo freely. The property panel edits names, a
  section's type and layout, and a widget's place and size on the 12-column grid.
- The preview lays out the selected page at desktop (12 columns, as stored), tablet (6 columns, each
  span halved) and phone (one column) widths.
- Saving writes only what changed, as ordinary record writes: new pages, sections and widgets first
  (a widget in a new section is created after it), then updates carrying the edited fields, the new
  order and the new parent with the record's `If-Match` row version, then deletes, deepest first. A
  stale row version is reported as a conflict to reload.

## Personal and shared dashboards

A dashboard whose visibility is `private` is personal: only its owner (or an administrator) can read
or change it, and saving it in the designer publishes it at once
(`POST /api/v1/attome-dashboard/{id}/publish-personal`; the health gate still applies, review and the
four-eyes approval do not). **Share** (`POST /api/v1/attome-dashboard/{id}/share` with `team`,
`organization` or `public`) clears its published version and returns it to draft, so what others see
goes through review and publish like every shared dashboard.
