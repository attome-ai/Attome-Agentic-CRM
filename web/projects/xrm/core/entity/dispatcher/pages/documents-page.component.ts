import { ChangeDetectionStrategy, Component } from '@angular/core';
import { DocumentFolderBrowserComponent } from '@attome/xrm/core/entity';

/**
 * The system-wide Documents page (D-36x) — `xrm-shell.routes.ts`'s literal
 * `documents` route. Renders `DocumentFolderBrowserComponent` in root mode
 * (all three inputs `null`), the same component the per-record Documents tab
 * uses scoped to one record — see that component's own doc comment for why
 * reusing it, rather than a second implementation, is what keeps this page
 * and every record's tab looking at the same data by construction.
 */
@Component({
  selector: 'xrm-documents-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DocumentFolderBrowserComponent],
  template: `
    <div class="xdp-page">
      <h1 class="xdp-title">Documents</h1>
      <attome-document-folder-browser [entityName]="null" [recordId]="null" [folder]="null" />
    </div>
  `,
  styles: [`
    .xdp-page { padding: 24px; display: flex; flex-direction: column; gap: 16px; }
    .xdp-title { margin: 0; font-size: 20px; font-weight: 600; color: var(--color-text-primary, #e5eefc); }
  `],
})
export class DocumentsPageComponent {}
