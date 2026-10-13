import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { KnowledgeDataSourceFormComponent } from './knowledge-data-source/form/knowledge-data-source-form/knowledge-data-source-form.component';
import { KnowledgeDataItemFormComponent } from './knowledge-data-item/form/knowledge-data-item-form/knowledge-data-item-form.component';

// Split out from `@attome/xrm/webcrawl` (D-314 packaging: xrm barrel
// splitting) — same reasoning as every other `*/registration` entry: a
// static import of this file must not drag in the parent entry's heavier
// list components (WebcrawlTargetListComponent, WebcrawlPageListComponent).
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerWebcrawlEntityForms(registry: EntityRouteRegistry): void {
  registry.register('knowledge_data_source', { formComponent: KnowledgeDataSourceFormComponent });
  registry.register('knowledge_data_item', { formComponent: KnowledgeDataItemFormComponent });
}
