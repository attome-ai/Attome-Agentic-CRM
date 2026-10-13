import { Routes } from '@angular/router';
import { unsavedChangesGuard } from '@attome/xrm/core/entity';
import { PageEditorComponent } from './page-editor.component';

/** The Page Editor's own route (`/xrm/dashboard/page/editor`), loaded lazily
 * through `loadChildren` so its leave guard (Dashboard 10/10 Phase 1.4) lives
 * in this entry point's chunk rather than the shell's. */
export const PAGE_EDITOR_ROUTES: Routes = [
  { path: '', component: PageEditorComponent, canDeactivate: [unsavedChangesGuard] },
];
