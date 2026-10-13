import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { SavedSearchFormComponent } from './forms/saved-search-form/saved-search-form.component';

// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerSearchEntityForms(registry: EntityRouteRegistry): void {
  registry.register('saved_search', { formComponent: SavedSearchFormComponent });
}
