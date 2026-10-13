import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { WorkflowDefinitionListComponent } from './workflow-definition/list/workflow-definition-list/workflow-definition-list.component';
import { WorkflowDefinitionFormComponent } from './workflow-definition/form/workflow-definition-form/workflow-definition-form.component';

// 'workflow_definition' -> both halves. Workflows browse and edit through
// the generic metadata-driven pages (registered server-side by
// `attome_workflow::seed`), so the overrides here are deliberately thin: the list
// is the stock grid with its New button re-pointed at the custom create page,
// and the form is the stock field set plus a link to the node designer. See
// each component's own doc comment.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerWorkflowEntityForms(registry: EntityRouteRegistry): void {
  registry.register('workflow_definition', {
    listComponent: WorkflowDefinitionListComponent,
    formComponent: WorkflowDefinitionFormComponent,
  });
}
