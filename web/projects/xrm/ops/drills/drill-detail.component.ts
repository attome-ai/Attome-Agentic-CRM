import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** One check of `attome_ops::evidence::Evidence`. */
export interface DrillCheck {
  name: string;
  result: 'pass' | 'fail' | 'skipped';
  detail: string | null;
}

/** `attome_ops::evidence::SignedEvidence`, without the `extra` map. */
export interface SignedDrillEvidence {
  key_id: string;
  signature: string;
  evidence: {
    kind: string;
    drill_id: string;
    started_at: string;
    finished_at: string;
    platform_version: string;
    image_digest: string | null;
    rpo_seconds: number | null;
    rto_seconds: number | null;
    data_size_bytes: number | null;
    restore_ok: boolean;
    provenance_ok: boolean;
    overall_ok: boolean;
    checks: DrillCheck[];
  };
}

/**
 * One recovery drill (roadmap AB4-T11): every check with its result and
 * detail, the numbers, and the key that signed it. The signature was
 * checked when the evidence was uploaded; the kind-specific `extra` data is
 * not shown.
 */
@Component({
  selector: 'attome-ops-drill-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe, LocalDatePipe],
  template: `
    <section class="dd-page">
      <a routerLink="..">{{ 'ops.drills.back' | translate }}</a>
      @if (error(); as message) {
        <p class="dd-error" role="alert">{{ message }}</p>
      }
      @if (signed(); as s) {
        <h2>{{ 'ops.drills.kind.' + s.evidence.kind | translate }} · {{ s.evidence.finished_at | localDate }}</h2>
        <p data-testid="dd-result">
          {{ (s.evidence.overall_ok ? 'ops.drills.passed' : 'ops.drills.failed') | translate }}
        </p>
        <dl class="dd-facts">
          <dt>{{ 'ops.drills.rpo' | translate }}</dt><dd dir="ltr">{{ s.evidence.rpo_seconds ?? '—' }}</dd>
          <dt>{{ 'ops.drills.rto' | translate }}</dt><dd dir="ltr">{{ s.evidence.rto_seconds ?? '—' }}</dd>
          <dt>{{ 'ops.drills.version' | translate }}</dt><dd dir="ltr">{{ s.evidence.platform_version }}</dd>
          <dt>{{ 'ops.drills.keyId' | translate }}</dt><dd dir="ltr"><code>{{ s.key_id }}</code></dd>
        </dl>
        <p class="dd-note">{{ 'ops.drills.signatureNote' | translate }}</p>
        <ul class="dd-checks" data-testid="dd-checks">
          @for (c of s.evidence.checks; track c.name) {
            <li [attr.data-result]="c.result">
              <strong dir="ltr">{{ c.name }}</strong>
              {{ 'ops.drills.check.' + c.result | translate }}
              @if (c.detail) { <span class="dd-detail" dir="auto">{{ c.detail }}</span> }
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .dd-page { padding-inline: 1rem; max-inline-size: 48rem; }
    .dd-facts { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
    .dd-facts dd { margin: 0; }
    .dd-note { font-size: 0.8125rem; color: var(--color-text-secondary); }
    .dd-checks { padding-inline-start: 1.25rem; }
    .dd-checks li[data-result='fail'] strong { color: var(--color-danger); }
    .dd-detail { display: block; font-size: 0.8125rem; }
    .dd-error { color: var(--color-danger); }
  `],
})
export class DrillDetailComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly id = input.required<string>();
  readonly signed = signal<SignedDrillEvidence | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<SignedDrillEvidence>(`/api/v1/ops/drills/${encodeURIComponent(this.id())}`).subscribe({
      next: s => this.signed.set(s),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
