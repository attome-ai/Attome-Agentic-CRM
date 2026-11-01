import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import {
  CrawlChange, CrawlRun, TargetListItem, TargetSettings, WebcrawlAdminService,
} from '../services/webcrawl-admin.service';

type Tab = 'settings' | 'runs' | 'changes';

/** The settings form, as the inputs hold them. */
interface SettingsDraft {
  include_patterns: string;
  exclude_patterns: string;
  ar: boolean;
  en: boolean;
  audience: string;
  import_mode: string;
  schedule: string;
  sitemap_url: string;
  watch_only: boolean;
  max_depth: number;
}

/** The form's draft for `t`. Pure. */
export function draftOf(t: TargetListItem): SettingsDraft {
  const languages = t.languages ?? [];
  return {
    include_patterns: t.include_patterns ?? '',
    exclude_patterns: t.exclude_patterns ?? '',
    ar: languages.includes('ar'),
    en: languages.includes('en'),
    audience: t.audience ?? 'internal',
    import_mode: t.import_mode ?? 'review',
    schedule: t.schedule ?? 'manual',
    sitemap_url: t.sitemap_url ?? '',
    watch_only: t.watch_only ?? false,
    max_depth: t.max_depth,
  };
}

/** The PATCH body for a draft. Pure. */
export function settingsOf(d: SettingsDraft): TargetSettings {
  return {
    include_patterns: d.include_patterns,
    exclude_patterns: d.exclude_patterns,
    languages: [...(d.ar ? ['ar'] : []), ...(d.en ? ['en'] : [])],
    audience: d.audience,
    import_mode: d.import_mode,
    schedule: d.schedule,
    sitemap_url: d.sitemap_url.trim(),
    watch_only: d.watch_only,
    max_depth: d.max_depth,
  };
}

/**
 * K6-T11 — a website source's own panel on its page list.
 *
 * - Settings: include and exclude patterns (one per line), languages,
 *   audience, import mode, schedule, sitemap, depth and watch only, saved
 *   with the source's row version (`PATCH /api/v1/webcrawl/targets/{id}`);
 *   a stale version says the source changed and reloads it.
 * - Runs: each crawl with its pages and what it did to the items.
 * - Changes to review: items a recrawl changed after an editor published
 *   them; Take the site's version imports the page again, Keep ours clears
 *   the flag.
 *
 * The intranet host and the credential are an administrator's settings and
 * are not edited here.
 */
@Component({
  selector: 'attome-webcrawl-source-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, FormsModule, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../webcrawl.css'],
  styles: [`
    .wsp-tabs { display: flex; gap: .25rem; margin-block-end: .75rem; }
    .wsp-tabs button[aria-selected='true'] { font-weight: 600; border-block-end: 2px solid var(--color-accent); }
    .wsp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: .75rem; }
    .wsp-grid textarea { inline-size: 100%; min-block-size: 5rem; }
    .wsp-actions { display: flex; gap: .5rem; align-items: center; margin-block-start: .75rem; }
    table { inline-size: 100%; }
    td, th { text-align: start; padding-inline: .4rem; padding-block: .25rem; }
  `],
  template: `
    <section class="card" data-testid="wsp">
      <div class="wsp-tabs" role="tablist">
        @for (t of tabs; track t) {
          <button type="button" role="tab" class="btn-ghost" [attr.aria-selected]="tab() === t"
                  [attr.data-testid]="'wsp-tab-' + t" (click)="open(t)">{{ tabKey(t) | translate }}</button>
        }
      </div>
      @if (error(); as e) { <p class="error-msg" role="alert">{{ e }}</p> }

      @if (tab() === 'settings') {
        @if (draft(); as d) {
          <form class="wsp-grid" (ngSubmit)="save()">
            <label>{{ 'webcrawl.source.include' | translate }}
              <textarea name="include" dir="ltr" [(ngModel)]="d.include_patterns"
                        [placeholder]="'webcrawl.source.patternHelp' | translate"></textarea></label>
            <label>{{ 'webcrawl.source.exclude' | translate }}
              <textarea name="exclude" dir="ltr" [(ngModel)]="d.exclude_patterns"></textarea></label>
            <fieldset>
              <legend>{{ 'webcrawl.source.languages' | translate }}</legend>
              <label><input type="checkbox" name="ar" [(ngModel)]="d.ar" /> {{ 'webcrawl.source.arabic' | translate }}</label>
              <label><input type="checkbox" name="en" [(ngModel)]="d.en" /> {{ 'webcrawl.source.english' | translate }}</label>
            </fieldset>
            <label>{{ 'webcrawl.source.audience' | translate }}
              <select name="audience" [(ngModel)]="d.audience">
                <option value="internal">{{ 'webcrawl.source.audience_internal' | translate }}</option>
                <option value="partner">{{ 'webcrawl.source.audience_partner' | translate }}</option>
                <option value="customer">{{ 'webcrawl.source.audience_customer' | translate }}</option>
              </select></label>
            <label>{{ 'webcrawl.source.importMode' | translate }}
              <select name="import_mode" [(ngModel)]="d.import_mode">
                <option value="review">{{ 'webcrawl.source.mode_review' | translate }}</option>
                <option value="automatic">{{ 'webcrawl.source.mode_automatic' | translate }}</option>
              </select></label>
            <label>{{ 'webcrawl.source.schedule' | translate }}
              <select name="schedule" data-testid="wsp-schedule" [(ngModel)]="d.schedule">
                <option value="manual">{{ 'webcrawl.source.schedule_manual' | translate }}</option>
                <option value="daily">{{ 'webcrawl.source.schedule_daily' | translate }}</option>
                <option value="weekly">{{ 'webcrawl.source.schedule_weekly' | translate }}</option>
              </select></label>
            <label>{{ 'webcrawl.source.sitemap' | translate }}
              <input type="url" name="sitemap" dir="ltr" [(ngModel)]="d.sitemap_url" /></label>
            <label>{{ 'webcrawl.depth' | translate }}
              <input type="number" name="depth" min="1" max="20" [(ngModel)]="d.max_depth" /></label>
            <label><input type="checkbox" name="watch_only" data-testid="wsp-watch" [(ngModel)]="d.watch_only" />
              {{ 'webcrawl.source.watchOnly' | translate }}</label>
            <div class="wsp-actions">
              <button type="submit" class="btn-primary" data-testid="wsp-save" [disabled]="saving()">
                {{ 'webcrawl.source.save' | translate }}</button>
              @if (saved()) { <span role="status">{{ 'webcrawl.source.saved' | translate }}</span> }
            </div>
          </form>
        }
      }

      @if (tab() === 'runs') {
        @if (runs().length === 0) {
          <p class="state-msg">{{ 'webcrawl.source.noRuns' | translate }}</p>
        } @else {
          <table data-testid="wsp-runs">
            <thead><tr>
              <th>{{ 'webcrawl.source.started' | translate }}</th><th>{{ 'webcrawl.colStatus' | translate }}</th>
              <th>{{ 'webcrawl.source.pages' | translate }}</th><th>{{ 'webcrawl.source.imported' | translate }}</th>
              <th>{{ 'webcrawl.source.updated' | translate }}</th><th>{{ 'webcrawl.source.flagged' | translate }}</th>
            </tr></thead>
            <tbody>
              @for (r of runs(); track r.id) {
                <tr>
                  <td>{{ r.started_at | date: 'short' }}</td>
                  <td><span class="badge" [class]="'status-' + r.status">{{ r.status }}</span>
                    @if (r.error) { <span class="error-msg">{{ r.error }}</span> }</td>
                  <td>{{ r.pages_found }}</td><td>{{ r.items_imported }}</td>
                  <td>{{ r.items_updated }}</td><td>{{ r.items_flagged }}</td>
                </tr>
              }
            </tbody>
          </table>
        }
      }

      @if (tab() === 'changes') {
        @if (changes().length === 0) {
          <p class="state-msg">{{ 'webcrawl.source.noChanges' | translate }}</p>
        } @else {
          <ul data-testid="wsp-changes">
            @for (c of changes(); track c.item_id) {
              <li>
                <bdi dir="auto">{{ c.title ?? c.url_path }}</bdi> <bdi dir="ltr" class="cell-muted">{{ c.url_path }}</bdi>
                <button type="button" class="btn-sm" data-testid="wsp-take" (click)="takeSite(c)">
                  {{ 'webcrawl.source.takeSite' | translate }}</button>
                <button type="button" class="btn-sm" data-testid="wsp-keep" (click)="keepOurs(c)">
                  {{ 'webcrawl.source.keepOurs' | translate }}</button>
              </li>
            }
          </ul>
        }
      }
    </section>
  `,
})
export class WebcrawlSourcePanelComponent {
  private readonly svc = inject(WebcrawlAdminService);

  readonly target = input.required<TargetListItem>();
  /** The source as saved, so the page list keeps the new row version. */
  readonly targetSaved = output<TargetListItem>();

  readonly tabs: readonly Tab[] = ['settings', 'runs', 'changes'];
  readonly tab = signal<Tab>('settings');
  readonly draft = signal<SettingsDraft | null>(null);
  readonly runs = signal<CrawlRun[]>([]);
  readonly changes = signal<CrawlChange[]>([]);
  readonly saving = signal(false);
  readonly saved = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      this.draft.set(draftOf(this.target()));
      this.saved.set(false);
    });
  }

  tabKey(t: Tab): string {
    return t === 'settings' ? 'webcrawl.source.tab_settings'
      : t === 'runs' ? 'webcrawl.source.tab_runs' : 'webcrawl.source.tab_changes';
  }

  open(t: Tab): void {
    this.tab.set(t);
    this.error.set(null);
    const id = this.target().id;
    if (t === 'runs') {
      this.svc.listRuns(id).subscribe({ next: r => this.runs.set(r), error: (e: ApiError) => this.error.set(e.message) });
    } else if (t === 'changes') {
      this.loadChanges();
    }
  }

  save(): void {
    const d = this.draft();
    const t = this.target();
    if (!d) return;
    this.saving.set(true);
    this.saved.set(false);
    this.error.set(null);
    this.svc.updateTarget(t.id, t.row_version ?? 0, settingsOf(d)).subscribe({
      next: updated => { this.saving.set(false); this.saved.set(true); this.targetSaved.emit(updated); },
      error: (e: ApiError) => { this.saving.set(false); this.error.set(e.message); },
    });
  }

  takeSite(c: CrawlChange): void {
    this.svc.importPages(this.target().id, [c.page_id]).subscribe({
      next: () => this.loadChanges(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  keepOurs(c: CrawlChange): void {
    this.svc.keepItem(c.item_id).subscribe({
      next: () => this.loadChanges(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private loadChanges(): void {
    this.svc.listChanges(this.target().id).subscribe({
      next: c => this.changes.set(c),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
