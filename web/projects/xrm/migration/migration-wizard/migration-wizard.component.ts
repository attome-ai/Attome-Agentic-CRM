import { JsonPipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ATTOME_CONFIG, ApiService, TranslatePipe } from '@attome/base';
import { CsvImportComponent } from '../csv-import/csv-import.component';

interface MigrationProject {
  id: string;
  name: string;
  source_kind: string;
  source_ref: string | null;
  target_entity: string;
  mapping_ref: string | null;
  status: string;
}

interface DataMappingListItem {
  id: string;
  name: string;
  target_entity: string;
  source_kind: string;
}

interface StagedImportResponse {
  id: string;
  status: string;
  total: number;
  passed: number;
  failed: number;
  rejected: number;
  sample_diff?: unknown[];
}

interface MigrationRunItem {
  item_index: number;
  record_id: string;
  operation: string;
  rollback_status: string;
  rollback_error: string | null;
}

interface MigrationRunDetail {
  id: string;
  project_id: string;
  staged_import_id: string;
  entity_logicalname: string;
  operation: string;
  mode: string;
  import_status: string;
  total: number;
  rejected: number;
  validation_report: unknown;
  rollback_status: string;
  rollback_error: string | null;
  rollback_items: MigrationRunItem[];
}

/**
 * M17 (Data Migration, D-433) — source -> mapping -> dry run -> approve ->
 * run -> report, one wizard over the platform's EXISTING mechanisms:
 * `POST /api/v1/admin/migration-projects` (this module's own project/run
 * admin surface), `POST /api/v1/{entity}/staged-import` (`mapping_ref` +
 * `mode: "dry_run"`, both M12/M17), `POST .../staged-import/{id}/approve`,
 * and `POST /api/v1/admin/migration-projects/{id}/runs/{run_id}/rollback`.
 * Nothing here talks to the database directly or duplicates validation —
 * every button is a thin call onto one of those routes.
 *
 * Two sources: a CSV file (U11, D-606 — `CsvImportComponent`, the default:
 * parsed in the browser, mapped into a D-408 `data_mapping`, staged
 * in chunks of at most 500 records, resumable), or `records` pasted as JSON
 * (a `{ data: {...} }` array, the exact staged-import record envelope) for
 * the advanced path that also offers update and rollback.
 */
@Component({
  selector: 'xrm-migration-wizard',
  standalone: true,
  imports: [FormsModule, JsonPipe, TranslatePipe, CsvImportComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="migration-wizard">
      <h2>{{ 'csvImport.wizardTitle' | translate }}</h2>

      <div class="btn-group mb-3" role="radiogroup" [attr.aria-label]="'csvImport.sourceLabel' | translate">
        <label class="me-3">
          <input type="radio" name="migration-source-mode" value="csv" data-testid="wizard-mode-csv"
                 [checked]="sourceMode() === 'csv'" (change)="sourceMode.set('csv')" />
          {{ 'csvImport.sourceCsv' | translate }}
        </label>
        <label>
          <input type="radio" name="migration-source-mode" value="json" data-testid="wizard-mode-json"
                 [checked]="sourceMode() === 'json'" (change)="sourceMode.set('json')" />
          {{ 'csvImport.sourceJson' | translate }}
        </label>
      </div>

      @if (sourceMode() === 'csv') {
        <xrm-csv-import />
      } @else {
      <!-- Step 1: source / project -->
      <section class="card p-3 mb-3">
        <h3 class="h5">1. Source</h3>
        @if (!project()) {
          <div class="mb-2">
            <label class="form-label" for="migration-project-name">Project name</label>
            <input id="migration-project-name" class="form-control" [(ngModel)]="projectName" />
          </div>
          <div class="mb-2">
            <label class="form-label" for="migration-target-entity">Target entity (logical name)</label>
            <input
              id="migration-target-entity"
              class="form-control"
              [(ngModel)]="targetEntity"
              (blur)="loadMappings()"
            />
          </div>
          <div class="mb-2">
            <label class="form-label" for="migration-source-kind">Source kind</label>
            <select id="migration-source-kind" class="form-select" [(ngModel)]="sourceKind">
              <option value="csv">csv</option>
              <option value="json">json</option>
              <option value="connector">connector</option>
            </select>
          </div>
          <div class="mb-2">
            <label class="form-label" for="migration-source-ref">Source reference (file set / connector ref)</label>
            <input id="migration-source-ref" class="form-control" [(ngModel)]="sourceRef" />
          </div>
          <div class="mb-2">
            <label class="form-label" for="migration-mapping-ref">Field mapping (optional — M12)</label>
            <select id="migration-mapping-ref" class="form-select" [(ngModel)]="mappingRef">
              <option [ngValue]="null">-- none --</option>
              @for (mapping of mappings(); track mapping.id) {
                <option [ngValue]="mapping.id">{{ mapping.name }}</option>
              }
            </select>
          </div>
          <button
            class="btn btn-primary"
            type="button"
            [disabled]="busy() || !targetEntity.trim()"
            (click)="createProject()"
          >
            Create project
          </button>
        } @else {
          <p>
            <strong>{{ project()!.name }}</strong> — target
            <code>{{ project()!.target_entity }}</code>
            @if (project()!.mapping_ref) {
              (mapping <code>{{ project()!.mapping_ref }}</code>)
            }
          </p>
        }
      </section>

      <!-- Step 2: records + dry run / stage -->
      @if (project() && !stagedImport()) {
        <section class="card p-3 mb-3">
          <h3 class="h5">2. Records &amp; dry run</h3>
          <div class="mb-2">
            <label class="form-label" for="migration-operation">Operation</label>
            <select id="migration-operation" class="form-select" [(ngModel)]="operation">
              <option value="create">create</option>
              <option value="update">update</option>
            </select>
          </div>
          <div class="mb-2">
            <label class="form-label" for="migration-records-json">
              Records (JSON array of <code>&#123; id?, expected_row_version?, data &#125;</code>)
            </label>
            <textarea id="migration-records-json" class="form-control" rows="8" [(ngModel)]="recordsJson"></textarea>
          </div>
          @if (stageError()) {
            <p class="text-danger small">{{ stageError() }}</p>
          }
          <div class="d-flex gap-2">
            <button
              class="btn btn-outline-secondary"
              type="button"
              [disabled]="busy()"
              (click)="submit('dry_run')"
            >
              Dry run
            </button>
            <button
              class="btn btn-primary"
              type="button"
              [disabled]="busy()"
              (click)="submit('stage')"
            >
              Stage for approval
            </button>
          </div>
        </section>
      }

      <!-- Step 3: validation report -->
      @if (stagedImport(); as staged) {
        <section class="card p-3 mb-3">
          <h3 class="h5">3. Validation report</h3>
          <p>
            {{ staged.total }} total — {{ staged.passed }} passed,
            {{ staged.failed }} failed, {{ staged.rejected }} rejected.
          </p>
          @if (staged.sample_diff?.length) {
            <details>
              <summary>Sample diff ({{ staged.sample_diff!.length }} record(s))</summary>
              <pre>{{ staged.sample_diff | json }}</pre>
            </details>
          }
          @if (isDryRun()) {
            <p class="text-muted small">
              This was a dry run — nothing was written. Resubmit without dry run to stage it
              for approval.
            </p>
            <button class="btn btn-outline-secondary" type="button" (click)="resetSubmission()">
              Back to records
            </button>
          } @else {
            <button
              class="btn btn-primary"
              type="button"
              [disabled]="busy() || !!run()"
              (click)="linkAndApprove()"
            >
              4. Approve &amp; run
            </button>
          }
        </section>
      }

      <!-- Step 5/6: run status + report + rollback -->
      @if (run(); as r) {
        <section class="card p-3 mb-3">
          <h3 class="h5">5. Run</h3>
          <p>
            Import status: <strong>{{ r.import_status }}</strong> —
            {{ r.total }} total, {{ r.rejected }} rejected.
          </p>
          <p>Rollback status: <strong>{{ r.rollback_status }}</strong></p>
          @if (r.rollback_items.length) {
            <table class="table table-sm">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Record</th>
                  <th>Op</th>
                  <th>Rollback</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                @for (item of r.rollback_items; track item.item_index) {
                  <tr>
                    <td>{{ item.item_index }}</td>
                    <td><code>{{ item.record_id }}</code></td>
                    <td>{{ item.operation }}</td>
                    <td>{{ item.rollback_status }}</td>
                    <td>{{ item.rollback_error }}</td>
                  </tr>
                }
              </tbody>
            </table>
          }
          <div class="d-flex gap-2">
            <button class="btn btn-outline-secondary" type="button" (click)="refresh()">
              Refresh
            </button>
            <a class="btn btn-outline-secondary" [href]="errorsUrl()" target="_blank" rel="noopener">
              Download error report
            </a>
            @if (r.import_status === 'approved' && r.rollback_status === 'none') {
              <button
                class="btn btn-outline-danger"
                type="button"
                [disabled]="busy()"
                (click)="rollback()"
              >
                Roll back this run
              </button>
            }
          </div>
        </section>
      }
      }
    </div>
  `,
})
export class MigrationWizardComponent {
  private readonly api = inject(ApiService);
  private readonly config = inject(ATTOME_CONFIG);

  /** CSV file (U11) or pasted JSON records. */
  protected readonly sourceMode = signal<'csv' | 'json'>('csv');

  // Step 1 — plain mutable properties (not signals): `[(ngModel)]` outside a
  // `<form>` needs a settable property, and this file follows the same
  // OnPush + plain-property + ngModel pattern `record-shares.component.ts`
  // already established, rather than introducing signal-bound `ngModel`.
  protected projectName = '';
  protected targetEntity = '';
  protected sourceKind: 'csv' | 'json' | 'connector' = 'json';
  protected sourceRef = '';
  protected mappingRef: string | null = null;
  protected readonly mappings = signal<DataMappingListItem[]>([]);
  protected readonly project = signal<MigrationProject | null>(null);

  // Step 2/3
  protected operation: 'create' | 'update' = 'create';
  protected recordsJson = '[\n  { "data": {} }\n]';
  protected readonly stagedImport = signal<StagedImportResponse | null>(null);
  protected readonly stageError = signal<string | null>(null);
  protected readonly lastMode = signal<'dry_run' | 'stage'>('dry_run');

  // Step 4/5
  protected readonly run = signal<MigrationRunDetail | null>(null);

  protected readonly busy = signal(false);

  protected readonly isDryRun = computed(() => this.lastMode() === 'dry_run');

  protected loadMappings(): void {
    const target = this.targetEntity.trim();
    if (!target) {
      this.mappings.set([]);
      return;
    }
    this.api
      .get<{ items: DataMappingListItem[] }>('/api/v1/admin/data/mappings', {
        target_entity: target,
      })
      .subscribe({
        next: page => this.mappings.set(page.items),
        error: () => this.mappings.set([]),
      });
  }

  protected createProject(): void {
    const target = this.targetEntity.trim();
    if (!target) return;
    this.busy.set(true);
    this.api
      .post<MigrationProject>('/api/v1/admin/migration-projects', {
        name: this.projectName.trim() || `migration-${Date.now()}`,
        source_kind: this.sourceKind,
        source_ref: this.sourceRef.trim() || null,
        target_entity: target,
        mapping_ref: this.mappingRef,
      })
      .subscribe({
        next: p => {
          this.project.set(p);
          this.busy.set(false);
        },
        error: () => this.busy.set(false),
      });
  }

  private parsedRecords(): unknown[] | null {
    try {
      const parsed: unknown = JSON.parse(this.recordsJson);
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  protected submit(mode: 'dry_run' | 'stage'): void {
    const project = this.project();
    if (!project) return;
    const records = this.parsedRecords();
    if (!records || records.length === 0) {
      this.stageError.set('records must be a non-empty JSON array');
      return;
    }
    this.stageError.set(null);
    this.lastMode.set(mode);
    this.busy.set(true);
    const body: Record<string, unknown> = { operation: this.operation, records, mode };
    if (project.mapping_ref) body['mapping_ref'] = project.mapping_ref;
    this.api
      .post<StagedImportResponse>(`/api/v1/${project.target_entity}/staged-import`, body)
      .subscribe({
        next: staged => {
          this.stagedImport.set(staged);
          this.busy.set(false);
        },
        error: err => {
          this.stageError.set(String((err as { message?: string })?.message ?? err));
          this.busy.set(false);
        },
      });
  }

  protected resetSubmission(): void {
    this.stagedImport.set(null);
    this.stageError.set(null);
  }

  protected linkAndApprove(): void {
    const project = this.project();
    const staged = this.stagedImport();
    if (!project || !staged) return;
    this.busy.set(true);
    this.api
      .post<{ id: string }>(`/api/v1/admin/migration-projects/${project.id}/runs`, {
        staged_import_id: staged.id,
      })
      .subscribe({
        next: created => {
          this.api
            .post(`/api/v1/${project.target_entity}/staged-import/${staged.id}/approve`, {})
            .subscribe({
              next: () => this.refreshRun(project.id, created.id),
              error: () => this.busy.set(false),
            });
        },
        error: () => this.busy.set(false),
      });
  }

  private refreshRun(projectId: string, runId: string): void {
    this.api
      .get<MigrationRunDetail>(`/api/v1/admin/migration-projects/${projectId}/runs/${runId}`)
      .subscribe({
        next: r => {
          this.run.set(r);
          this.busy.set(false);
        },
        error: () => this.busy.set(false),
      });
  }

  protected refresh(): void {
    const project = this.project();
    const r = this.run();
    if (!project || !r) return;
    this.busy.set(true);
    this.refreshRun(project.id, r.id);
  }

  protected rollback(): void {
    const project = this.project();
    const r = this.run();
    if (!project || !r) return;
    this.busy.set(true);
    this.api
      .post(`/api/v1/admin/migration-projects/${project.id}/runs/${r.id}/rollback`, {})
      .subscribe({
        next: () => this.refreshRun(project.id, r.id),
        error: () => this.busy.set(false),
      });
  }

  protected errorsUrl(): string | null {
    const project = this.project();
    const r = this.run();
    if (!project || !r) return null;
    return `${this.config.apiUrl}/api/v1/admin/migration-projects/${project.id}/runs/${r.id}/errors`;
  }
}
