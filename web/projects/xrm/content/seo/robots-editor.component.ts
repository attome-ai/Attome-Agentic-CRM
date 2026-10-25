import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import { SeoService } from './seo.service';
import { lineChanges } from './seo-text';

/**
 * E13-T12: a site's robots.txt for site administrators. Saving shows how
 * many lines change and asks once more, since crawlers act on it. The
 * portal and preview paths are always closed by the server, whatever the
 * body says; "what crawlers get" shows the served file.
 */
@Component({
  selector: 'attome-robots-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="re" data-testid="robots-editor">
      <h3>{{ 'e13.robotsTitle' | translate }}</h3>
      <div class="re-row">
        <label class="re-field">
          <span>{{ 'e13.siteKey' | translate }}</span>
          <input type="text" dir="ltr" [(ngModel)]="siteKey" name="reSite" />
        </label>
        <button type="button" class="btn-ghost" (click)="load()" [disabled]="!siteKey.trim()">
          {{ 'e13.load' | translate }}
        </button>
      </div>
      @if (error(); as message) { <p class="re-error" role="alert">{{ message }}</p> }
      @if (loaded()) {
        <label class="re-field">
          <span>{{ 'e13.robotsBody' | translate }}</span>
          <textarea rows="10" dir="ltr" class="re-body" [(ngModel)]="body" name="reBody"></textarea>
        </label>
        @if (confirming()) {
          <div class="re-confirm" role="alertdialog" data-testid="robots-confirm">
            <p>{{ 'e13.robotsConfirm' | translate: { added: changes().added, removed: changes().removed } }}</p>
            <button type="button" class="btn-primary" (click)="confirm()" [disabled]="saving()">
              {{ 'e13.confirm' | translate }}
            </button>
            <button type="button" class="btn-ghost" (click)="confirming.set(false)">
              {{ 'e13.cancel' | translate }}
            </button>
          </div>
        } @else {
          <button type="button" class="btn-primary" (click)="askToSave()">{{ 'e13.save' | translate }}</button>
        }
        <h4>{{ 'e13.served' | translate }}</h4>
        <pre class="re-served" dir="ltr">{{ served() }}</pre>
      }
    </section>
  `,
  styles: [`
    .re { display: grid; gap: 0.6rem; }
    .re-row { display: flex; gap: 0.6rem; align-items: end; flex-wrap: wrap; }
    .re-field { display: grid; gap: 0.25rem; }
    .re-body, .re-served { font-family: monospace; }
    .re-served { background: var(--surface-muted, #f9fafb); padding-block: 0.6rem; padding-inline: 0.8rem; }
    .re-confirm { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }
    .re-error { color: var(--danger, #b91c1c); }
  `],
})
export class RobotsEditorComponent {
  private readonly seo = inject(SeoService);

  siteKey = '';
  body = '';
  private stored = '';

  readonly loaded = signal(false);
  readonly served = signal('');
  readonly confirming = signal(false);
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);
  readonly changes = signal({ added: 0, removed: 0 });

  load(): void {
    this.error.set(null);
    this.seo.robots(this.siteKey.trim().toLowerCase()).subscribe({
      next: view => {
        this.stored = view.body ?? '';
        this.body = this.stored;
        this.served.set(view.served);
        this.loaded.set(true);
        this.confirming.set(false);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  askToSave(): void {
    this.changes.set(lineChanges(this.stored, this.body));
    this.confirming.set(true);
  }

  confirm(): void {
    this.saving.set(true);
    this.seo.saveRobots(this.siteKey.trim().toLowerCase(), this.body).subscribe({
      next: view => {
        this.stored = view.body ?? '';
        this.body = this.stored;
        this.served.set(view.served);
        this.saving.set(false);
        this.confirming.set(false);
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(e.message);
      },
    });
  }
}
