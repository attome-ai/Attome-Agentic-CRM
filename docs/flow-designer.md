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
- **Data mapping.** Below a selected step's settings, the panel lists the
  step's inputs and what feeds each one, then the typed outputs of every earlier
  step (those not connected to it yet are marked; steps after it are left out).
  Drag an output onto an input, or choose an output and then an input. It makes
  the same connection as the canvas, under the same checks, and a refusal says
  why. A step's input is the value a connection carries; to reach inside a JSON
  value, use a Map Fields step.
- **Problems.** On a draft, what publishing would refuse is checked on every
  change: each problem marks its step and is listed under the canvas, and
  choosing one selects the step. Publishing stays the last word: a condition's
  expression and a module step's settings are only checked there.
- **Comparing versions.** Compare versions shows what differs from another
  version of the flow, the one before by default: steps added and removed,
  settings and connections changed. It compares the graph as it stands, saved or
  not. Moving a step, groups and notes are no difference.
- **Test run and coverage.** Test run simulates the saved version with an empty
  trigger payload (nothing is written): the path it took lights up, each step is
  marked as ran, failed or skipped, and the list gives each step's result. Test
  coverage runs the flow's test cases and shades the steps none reached. Either
  clears when the graph changes.
- **A run on the graph.** A run's page links to Open on the graph
  (`/xrm/workflow/instances/{id}/graph`): the flow as that version had it, each
  step marked by its state and the path taken lit, kept up to date while the run
  goes on. Selecting a step shows each of its runs (one a loop round): when, how
  long, the error, and what went in and came out, with credentials masked. Step
  back and Step forward replay the run from its record, the graph as it stood at
  each step. A large input and output kept in file storage are not shown here.
- **Phones.** On a narrow screen the designer opens a list of the steps in
  running order, with each step's problems; choosing one opens its settings.
  Canvas and Steps switch between the two on any screen.
- **Editing.** Drag a step's header to move it, or use the arrow keys (Alt
  with an arrow moves it further). Delete removes the selected step with its
  connections, or the selected connection. Undo and redo are unlimited.
  Save stores the draft; Publish needs it saved first. A published version
  opens read-only.

In Arabic the canvas mirrors: inputs on the right, the flow running to the
left.
