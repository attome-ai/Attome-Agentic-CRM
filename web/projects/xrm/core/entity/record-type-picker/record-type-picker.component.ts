import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { Page } from '@attome/base';

/** A27-T4: one record type the caller may create (`GET /api/v1/{entity}/record-types`). */
export interface RecordTypeOption {
  code: string;
  label_en: string;
  label_ar: string | null;
  form: string | null;
  is_default: boolean;
}

/**
 * A27-T4 — the new-record button of an entity with record types. With none
 * (or one) it is the plain New button; with several it is a split button:
 * New for the caller's default type, and a menu of the other types the
 * caller's roles may create. Answers `create` with the chosen type's code,
 * or `null` when the entity has no types (the server then applies the
 * caller's default, if any).
 */
@Component({
  selector: 'xrm-record-type-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./record-type-picker.component.css'],
  template: `
    @if (types().length <= 1) {
      <button type="button" class="btn btn-primary" data-record-type-new (click)="pick(types().at(0)?.code ?? null)">
        {{ 'entityList.newRecord' | translate }}
      </button>
    } @else {
      <span class="type-picker">
        <button type="button" class="btn btn-primary" data-record-type-new (click)="pick(first()?.code ?? null)">
          {{ 'recordTypePicker.newOf' | translate: { type: label(first()) } }}
        </button>
        <button type="button" class="btn btn-primary type-toggle" data-record-type-toggle
                [attr.aria-expanded]="open()" [attr.aria-label]="'recordTypePicker.more' | translate"
                (click)="open.set(!open())">
          <i class="las la-angle-down" aria-hidden="true"></i>
        </button>
        @if (open()) {
          <ul class="type-menu" role="menu">
            @for (type of types(); track type.code) {
              <li role="none">
                <button type="button" role="menuitem" [attr.data-record-type]="type.code" (click)="pick(type.code)">
                  {{ label(type) }}
                </button>
              </li>
            }
          </ul>
        }
      </span>
    }
  `,
})
export class RecordTypePickerComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  /** The entity's logical name. */
  readonly entity = input.required<string>();
  /** The chosen type's code; `null` for an entity without types. */
  readonly create = output<string | null>();

  readonly types = signal<RecordTypeOption[]>([]);
  readonly open = signal(false);
  /** The caller's default type, else the first one listed. */
  readonly first = computed<RecordTypeOption | null>(
    () => this.types().find(t => t.is_default) ?? this.types().at(0) ?? null,
  );

  constructor() {
    effect(onCleanup => {
      const entity = this.entity();
      this.types.set([]);
      const sub = this.api.get<Page<RecordTypeOption>>(`/api/v1/${entity}/record-types`).subscribe({
        next: page => this.types.set(page.items),
        // No types to offer (or no right to list them): the plain New button.
        error: () => this.types.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  label(type: RecordTypeOption | null): string {
    if (!type) return '';
    return this.lang.current() === 'ar' && type.label_ar ? type.label_ar : type.label_en;
  }

  pick(code: string | null): void {
    this.open.set(false);
    this.create.emit(code);
  }
}
