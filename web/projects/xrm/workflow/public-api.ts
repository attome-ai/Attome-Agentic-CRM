// The workflow *list* is no longer bespoke: workflow_definition is a
// registered XRM entity (`attome_workflow::seed`), so browsing it goes through
// the generic /xrm/workflow/definition/list page, with thin list/form
// overrides registered by `registerWorkflowEntityForms`
// (`@attome/xrm/workflow/registration` — a separate, lighter entry point so
// registering the override doesn't force the graph editor below into the
// same eager chunk; see that entry's public-api.ts doc comment). What lives
// here is what the generic pages cannot express — creating a workflow, its
// versions, and the node canvas.
export { WorkflowAdminService }              from './services/workflow-admin.service';
export { WorkflowCreatePageComponent }       from './workflow-definition/page/workflow-create-page/workflow-create-page.component';
export { WorkflowGraphEditorComponent }      from './workflow-definition/editor/workflow-graph-editor/workflow-graph-editor.component';
export { WorkflowInstanceListComponent }     from './workflow-instance/list/workflow-instance-list/workflow-instance-list.component';
export { WorkflowInstanceDetailComponent }   from './workflow-instance/detail/workflow-instance-detail/workflow-instance-detail.component';
export { WorkflowTemplateGalleryComponent }  from './workflow-template/template-gallery.component';
export type {
  DefinitionListItem, DefinitionDetail, VersionSummary, VersionDetail,
  CreateDefinitionBody, UpdateDefinitionBody, CreateVersionBody, UpdateVersionGraphBody,
  Graph, GraphNode, GraphEdge, NodeTypeSpec, NodeTypePort,
  NodeConfigField, NodeConfigKind,
  InstanceListItem, InstanceDetail, NodeRunSummary, StartInstanceBody,
} from './services/workflow-admin.service';
export {
  NODE_TYPES, nodeTypeSpec, NODE_CONFIG_SCHEMA, nodeConfigFields,
} from './services/workflow-admin.service';
