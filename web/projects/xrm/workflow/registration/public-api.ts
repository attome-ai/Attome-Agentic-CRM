// Split out from `@attome/xrm/workflow` (D-314 packaging: xrm barrel
// splitting) — this entry holds only the thin `workflow_definition`
// list/form overrides that `EntityRouteRegistry` needs, kept separate from
// the parent entry's heavier components (WorkflowGraphEditorComponent's node
// canvas, WorkflowCreatePageComponent, WorkflowInstanceListComponent,
// WorkflowInstanceDetailComponent). The app's composition root
// (`src/app/attome-metadata-form-loaders.ts`) lazily `import()`s this entry and
// calls `registerWorkflowEntityForms` only once an entity that needs it is
// actually routed to — see EntityRouteRegistry's doc comment for why (a
// static import here would force the graph editor into the same eager
// chunk — ng-packagr bundles one entry point as one unit, so importing
// anything from the parent entry pulls all of it in — same reasoning as
// `core/admin/data`'s own doc comment).
export { WorkflowDefinitionListComponent }   from './workflow-definition/list/workflow-definition-list/workflow-definition-list.component';
export { WorkflowDefinitionFormComponent }   from './workflow-definition/form/workflow-definition-form/workflow-definition-form.component';
export { registerWorkflowEntityForms }       from './provide-workflow-entity-forms';
