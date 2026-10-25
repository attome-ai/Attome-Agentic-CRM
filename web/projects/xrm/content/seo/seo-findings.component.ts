import {
  ChangeDetectionStrategy, Component, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { SeoFinding, SeoService } from './seo.service';

/**
 * E13-T12: a page's audit findings, errors first, each with "go to block"
 * when it names one. Reloads when `refresh` changes (after an audit run).
 */
@Component({
  selector: 'attome-seo-findings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sf">
      <h5>{{ 'e13.findings' | translate }}</h5>
      @if (error(); as message) { <p class="sf-error" role="alert">{{ message }}</p> }
      @if (findings().length === 0) {
        <p class="sf-muted">{{ 'e13.noFindings' | translate }}</p>
      } @else {
        <ul class="sf-list">
          @for (f of findings(); track f.id) {
            <li [attr.data-severity]="f.severity" [attr.data-rule]="f.rule">
              <span class="sf-severity">{{ ('e13.severity.' + f.severity) | translate }}</span>
              <span>{{ message(f) }}</span>
              @if (f.block_ref; as block) {
                <button type="button" class="btn-ghost" (click)="goToBlock.emit(block)">
                  {{ 'e13.goToBlock' | translate }}
                </button>
              }
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .sf-list { list-style: none; padding-inline-start: 0; display: grid; gap: 0.4rem; }
    .sf-list li { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }
    .sf-severity { font-weight: 600; min-inline-size: 5rem; }
    li[data-severity='error'] .sf-severity { color: var(--danger, #b91c1c); }
    li[data-severity='warning'] .sf-severity { color: var(--warning, #b45309); }
    .sf-muted { color: var(--text-muted, #6b7280); }
    .sf-error { color: var(--danger, #b91c1c); }
  `],
})
export class SeoFindingsComponent {
  private readonly seo = inject(SeoService);
  private readonly lang = inject(LangService);

  readonly pageId = input.required<string>();
  /** Any change reloads the list. */
  readonly refresh = input<number>(0);
  readonly goToBlock = output<string>();

  readonly findings = signal<SeoFinding[]>([]);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const page = this.pageId();
      this.refresh();
      untracked(() => this.load(page));
    });
  }

  private load(page: string): void {
    this.seo.findings(page).subscribe({
      next: result => this.findings.set(result.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** The finding's catalogue message, else its rule name made readable. */
  message(f: SeoFinding): string {
    const key = f.message_key;
    if (key) {
      const text = this.lang.translate(key);
      if (text && text !== key) return text;
    }
    return f.rule.replace(/_/g, ' ');
  }
}
