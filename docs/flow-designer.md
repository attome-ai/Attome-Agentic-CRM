# Flow designer

The flow designer edits a flow's draft version on the canvas
(`/xrm/workflow/definitions/{id}/versions/{version}/design`; the classic
editor stays at the same address without `/design`, and each links to the
other).

- **Steps.** The palette lists every step type; type to search by name. A new
  step is placed below the last one and selected.
- **Connections.** Each step shows its inputs on one side and its outputs on
  the other, each with its type (`any`, `json`, `record_id`, `text`). Drag
  from an output to an input, or click an output and then an input (this
  works from the keyboard too). While you drag, the inputs that accept the
  connection are marked and the others are dimmed; a refused drop says why: the
  types do not meet, a trigger takes no input, the two ports are already
  connected, or the connection would make a loop. These are the checks the
  engine makes when the version is published, so a flow that connects here
  does not fail publishing on them. Every step but a trigger also has an
  `on_error` output.
- **Settings.** The selected step's settings form comes from its type, the
  same fields the classic editor shows.
- **Groups and notes.** Select steps (Ctrl or Cmd adds to the selection) and
  choose Group to frame them under a name; Note adds a note to the canvas.
  Both are saved with the flow and do not change how it runs.
- **Sub-flows.** A sub-flow step has an open button that goes to the flow it
  runs (its draft if it has one, else its latest version).
- **Editing.** Drag a step's header to move it, or use the arrow keys (Alt
  with an arrow moves it further). Delete removes the selected step with its
  connections, or the selected connection. Undo and redo are unlimited.
  Save stores the draft; Publish needs it saved first. A published version
  opens read-only.

In Arabic the canvas mirrors: inputs on the right, the flow running to the
left.
