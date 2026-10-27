import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import {
  AccessExplanation,
  EXPLAIN_ACTIONS,
  ExplainAction,
  PrincipalKind,
  PrincipalOption,
  RecordShare,
  SharingPanelService,
} from './sharing-panel.service';

interface ShareRow {
  share: RecordShare;
  label: string;
}

/**
 * Q14-T6 — a record's Sharing tab: who owns it and in which unit, the
 * record's shares (added and removed by anyone holding `{entity}.share`, who
 * can give no more than they hold — Q14-T1), and an Explain action that asks
 * the explainer (Q14-T4) why a chosen person can or cannot see or change the
 * record: their role level, unit, ownership, shares, default shares, sharing
 * rules and denies, with the deciding one marked.
 *
 * The server decides every answer; a 403 shows that the person cannot manage
 * sharing here, never a guess.
 */
@Component({
  selector: 'xrm-sharing-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styleUrl: './sharing-panel.component.css',
  template: `
    <section class="sp" aria-labelledby="sp-title">
      <h3 id="sp-title">{{ 'sharingPanel.title' | translate }}</h3>

      @if (error()) { <p class="sp-error" role="alert">{{ error() }}</p> }

      <dl class="sp-facts">
        <dt>{{ 'sharingPanel.owner' | translate }}</dt>
        <dd>{{ owner() ?? ('sharingPanel.none' | translate) }}</dd>
        <dt>{{ 'sharingPanel.unit' | translate }}</dt>
        <dd>{{ unit() ?? ('sharingPanel.none' | translate) }}</dd>
      </dl>

      <h4>{{ 'sharingPanel.shares' | translate }}</h4>
      @if (forbidden()) {
        <p class="sp-hint">{{ 'sharingPanel.forbidden' | translate }}</p>
      } @else if (loading()) {
        <p class="sp-hint">{{ 'sharingPanel.loading' | translate }}</p>
      } @else if (shares().length === 0) {
        <p class="sp-hint">{{ 'sharingPanel.noShares' | translate }}</p>
      } @else {
        <ul class="sp-list">
          @for (row of shares(); track row.share.id) {
            <li>
              <span class="sp-who">
                <i [class]="row.share.principal_type === 'team' ? 'las la-users' : 'las la-user'" aria-hidden="true"></i>
                {{ row.label }}
              </span>
              <span class="sp-cap">{{ ('sharingPanel.capability.' + row.share.capability) | translate }}</span>
              <span class="sp-when">{{ row.share.granted_at | localDate }}</span>
              @if (row.share.capability !== 'deny') {
                <button type="button" class="sp-remove" (click)="unshare(row.share)" [disabled]="busy()"
                        [attr.aria-label]="'sharingPanel.removeFor' | translate: { name: row.label }">
                  {{ 'sharingPanel.remove' | translate }}
                </button>
              }
            </li>
          }
        </ul>
      }

      @if (!forbidden()) {
        <fieldset class="sp-add">
          <legend>{{ 'sharingPanel.add' | translate }}</legend>
          <label for="sp-kind">{{ 'sharingPanel.kind' | translate }}</label>
          <select id="sp-kind" [ngModel]="kind()" (ngModelChange)="setKind($event)">
            <option value="user">{{ 'sharingPanel.user' | translate }}</option>
            <option value="team">{{ 'sharingPanel.team' | translate }}</option>
          </select>
          <label for="sp-search">{{ 'sharingPanel.search' | translate }}</label>
          <input id="sp-search" type="search" [ngModel]="term()" (ngModelChange)="find($event)">
          <label for="sp-who">{{ 'sharingPanel.who' | translate }}</label>
          <select id="sp-who" [ngModel]="pickedId()" (ngModelChange)="pickedId.set($event)">
            <option value="" disabled>{{ 'sharingPanel.choose' | translate }}</option>
            @for (o of options(); track o.id) { <option [value]="o.id">{{ o.label }}</option> }
          </select>
          <label for="sp-cap">{{ 'sharingPanel.access' | translate }}</label>
          <select id="sp-cap" [ngModel]="capability()" (ngModelChange)="capability.set($event)">
            <option value="view">{{ 'sharingPanel.capability.view' | translate }}</option>
            <option value="action">{{ 'sharingPanel.capability.action' | translate }}</option>
          </select>
          <button type="button" (click)="share()" [disabled]="busy() || !pickedId()">
            {{ 'sharingPanel.share' | translate }}
          </button>
        </fieldset>
      }

      <fieldset class="sp-explain">
        <legend>{{ 'sharingPanel.explain' | translate }}</legend>
        <label for="sp-explain-who">{{ 'sharingPanel.person' | translate }}</label>
        <input id="sp-explain-who" type="search" [ngModel]="explainTerm()" (ngModelChange)="findPerson($event)">
        <select [attr.aria-label]="'sharingPanel.person' | translate" [ngModel]="explainUser()"
                (ngModelChange)="explainUser.set($event)">
          <option value="" disabled>{{ 'sharingPanel.choose' | translate }}</option>
          @for (o of people(); track o.id) { <option [value]="o.id">{{ o.label }}</option> }
        </select>
        <label for="sp-explain-action">{{ 'sharingPanel.operation' | translate }}</label>
        <select id="sp-explain-action" [ngModel]="explainAction()" (ngModelChange)="explainAction.set($event)">
          @for (a of actions; track a) { <option [value]="a">{{ ('sharingPanel.action.' + a) | translate }}</option> }
        </select>
        <button type="button" (click)="explain()" [disabled]="busy() || !explainUser()">
          {{ 'sharingPanel.explainButton' | translate }}
        </button>
      </fieldset>

      @if (explanation(); as e) {
        <p class="sp-verdict" role="status">
          {{ (e.allowed ? 'sharingPanel.allowed' : 'sharingPanel.denied') | translate }}
        </p>
        <ul class="sp-sources">
          @for (s of e.sources; track $index) {
            <li [class.sp-winning]="s.winning" [class.sp-off]="s.effect === 'not_applicable'">
              <strong>{{ ('sharingPanel.source.' + s.source) | translate }}</strong>
              <span>{{ ('sharingPanel.effect.' + s.effect) | translate }}</span>
              @if (s.winning) { <span class="sp-badge">{{ 'sharingPanel.deciding' | translate }}</span> }
              <span class="sp-detail" dir="auto">{{ s.detail }}</span>
            </li>
          }
        </ul>
      }
    </section>
  `,
})
export class SharingPanelComponent implements OnInit {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();

  private readonly svc  = inject(SharingPanelService);
  private readonly lang = inject(LangService);

  readonly actions = EXPLAIN_ACTIONS;

  readonly owner     = signal<string | null>(null);
  readonly unit      = signal<string | null>(null);
  readonly shares    = signal<ShareRow[]>([]);
  readonly loading   = signal(true);
  readonly forbidden = signal(false);
  readonly busy      = signal(false);
  readonly error     = signal<string | null>(null);

  readonly kind       = signal<PrincipalKind>('user');
  readonly term       = signal('');
  readonly options    = signal<PrincipalOption[]>([]);
  readonly pickedId   = signal('');
  readonly capability = signal<'view' | 'action'>('view');

  readonly explainTerm   = signal('');
  readonly people        = signal<PrincipalOption[]>([]);
  readonly explainUser   = signal('');
  readonly explainAction = signal<ExplainAction>('read');
  readonly explanation   = signal<AccessExplanation | null>(null);

  ngOnInit(): void {
    this.loadFacts();
    this.loadShares();
    this.find('');
    this.findPerson('');
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e));
  }

  private loadFacts(): void {
    this.svc.record(this.entityName(), this.recordId()).subscribe({
      next: r => {
        const data = r.data as Record<string, unknown>;
        const owner = typeof data['owner_ref'] === 'string' ? data['owner_ref'] : null;
        if (owner) {
          // owner_type 1 is a team, 0 (or absent) a user.
          const kind: PrincipalKind = data['owner_type'] === 1 ? 'team' : 'user';
          this.svc.name(kind, owner).pipe(catchError(() => of(owner))).subscribe(n => this.owner.set(n));
        }
        const unit = typeof data['organization_ref'] === 'string' ? data['organization_ref'] : null;
        if (unit) {
          this.svc.record('organization', unit).pipe(catchError(() => of(null))).subscribe(o => {
            const name = o ? (o.data as Record<string, unknown>)['name'] : null;
            this.unit.set(typeof name === 'string' && name ? name : unit);
          });
        }
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  loadShares(): void {
    this.loading.set(true);
    this.svc.shares(this.entityName(), this.recordId()).subscribe({
      next: shares => {
        this.forbidden.set(false);
        if (shares.length === 0) {
          this.shares.set([]);
          this.loading.set(false);
          return;
        }
        forkJoin(shares.map(share => this.svc
          .name(share.principal_type === 'team' ? 'team' : 'user', share.principal_id)
          .pipe(catchError(() => of(share.principal_id))),
        )).subscribe(labels => {
          this.shares.set(shares.map((share, i) => ({ share, label: labels[i] })));
          this.loading.set(false);
        });
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        if (e.status === 403) this.forbidden.set(true);
        else this.error.set(this.lang.errorText(e));
      },
    });
  }

  setKind(kind: PrincipalKind): void {
    this.kind.set(kind);
    this.pickedId.set('');
    this.find(this.term());
  }

  find(term: string): void {
    this.term.set(term);
    const kind = this.kind();
    this.svc.search(kind, term).pipe(catchError(() => of([]))).subscribe(o => {
      if (this.kind() === kind) this.options.set(o);
    });
  }

  findPerson(term: string): void {
    this.explainTerm.set(term);
    this.svc.search('user', term).pipe(catchError(() => of([]))).subscribe(o => this.people.set(o));
  }

  share(): void {
    const who = this.options().find(o => o.id === this.pickedId());
    if (!who) return;
    this.busy.set(true);
    this.error.set(null);
    this.svc.share(this.entityName(), this.recordId(), who, this.capability()).subscribe({
      next: share => {
        this.busy.set(false);
        this.pickedId.set('');
        this.shares.update(rows => [{ share, label: who.label }, ...rows]);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  unshare(share: RecordShare): void {
    this.busy.set(true);
    this.error.set(null);
    this.svc.unshare(this.entityName(), this.recordId(), share.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.shares.update(rows => rows.filter(r => r.share.id !== share.id));
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  explain(): void {
    const user = this.explainUser();
    if (!user) return;
    this.busy.set(true);
    this.error.set(null);
    this.explanation.set(null);
    this.svc.explain(this.entityName(), this.recordId(), user, this.explainAction()).subscribe({
      next: e => { this.busy.set(false); this.explanation.set(e); },
      error: (e: ApiError) => this.fail(e),
    });
  }
}
