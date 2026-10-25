import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';

/** A template name: not blank, at most 100 characters. */
export function templateNameOk(name: string): boolean {
  const n = name.trim().length;
  return n > 0 && n <= 100;
}

/**
 * B8-T3 — "Save as template" on a record's form, for administrators: the
 * record's settable values become a new draft record template
 * (`POST /api/v1/record-templates/from-record`), published later like any
 * metadata. Renders nothing for anyone else.
 */
@Component({
  selector: 'xrm-save-as-template',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    @if (allowed()) {
      <button type="button" class="xf-btn xf-btn-secondary" data-testid="sat-open" (click)="openDialog()">
        {{ 'recordTemplates.saveAs' | translate }}
      </button>
      @if (open()) {
        <div class="sat-dialog" role="dialog" aria-modal="true" [attr.aria-label]="'recordTemplates.saveAs' | translate" data-testid="sat-dialog">
          <label>{{ 'recordTemplates.name' | translate }}
            <input type="text" dir="ltr" name="name" [(ngModel)]="name" data-testid="sat-name" />
          </label>
          <label>{{ 'recordTemplates.labelEn' | translate }}
            <input type="text" dir="ltr" name="labelEn" [(ngModel)]="labelEn" />
          </label>
          <label>{{ 'recordTemplates.labelAr' | translate }}
            <input type="text" dir="rtl" name="labelAr" [(ngModel)]="labelAr" />
          </label>
          @if (message(); as text) {
            <p role="status" data-testid="sat-message">{{ text }}</p>
          }
          <div class="sat-buttons">
            <button type="button" class="xf-btn xf-btn-primary" data-testid="sat-save" [disabled]="busy()" (click)="save()">
              {{ 'recordTemplates.save' | translate }}
            </button>
            <button type="button" class="xf-btn xf-btn-secondary" (click)="open.set(false)">{{ 'recordTemplates.cancel' | translate }}</button>
          </div>
        </div>
      }
    }
  `,
  styles: [`
    .sat-dialog { display: flex; flex-direction: column; gap: 0.75rem; margin-block: 0.75rem; padding: 1rem; border: 1px solid var(--color-border); border-radius: 0.5rem; max-inline-size: 28rem; background: var(--color-surface); }
    .sat-dialog label { display: flex; flex-direction: column; gap: 0.25rem; }
    .sat-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  `],
})
export class SaveAsTemplateComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly access = inject(AccessService);
  private readonly lang = inject(LangService);

  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();

  readonly allowed = signal(false);
  readonly open = signal(false);
  readonly busy = signal(false);
  readonly message = signal<string | null>(null);
  name = '';
  labelEn = '';
  labelAr = '';

  ngOnInit(): void {
    this.access.ready().subscribe(() => this.allowed.set(this.access.hasPrivilege('system.admin')));
  }

  openDialog(): void {
    this.name = '';
    this.labelEn = '';
    this.labelAr = '';
    this.message.set(null);
    this.open.set(true);
  }

  save(): void {
    if (!templateNameOk(this.name.trim()) || this.labelEn.trim() === '') {
      this.message.set(this.lang.translate('recordTemplates.nameRule'));
      return;
    }
    this.busy.set(true);
    const body = {
      entity: this.entity(),
      id: this.recordId(),
      name: this.name.trim(),
      label_en: this.labelEn.trim(),
      ...(this.labelAr.trim() ? { label_ar: this.labelAr.trim() } : {}),
    };
    this.api.post<{ id: string; name: string; values: number }>('/api/v1/record-templates/from-record', body).subscribe({
      next: saved => {
        this.busy.set(false);
        this.message.set(this.lang.translate('recordTemplates.saved', { name: saved.name, values: saved.values }));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.message.set(this.lang.errorText(e));
      },
    });
  }
}
