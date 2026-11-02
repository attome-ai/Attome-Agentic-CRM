import { ChangeDetectionStrategy, Component, inject, input, output, signal } from '@angular/core';
import { ApiError, SdkService, TranslatePipe } from '@attome/base';

/** One step of an `integration.rpa` node, as the browser service runs it. */
export interface RpaStep {
  kind: string;
  url?: string;
  selector?: string;
  value?: string;
  key?: string;
}

/** What a recorder call answers. */
export interface RecordFrame {
  session: string | null;
  step: RpaStep;
  password: boolean;
  png_base64: string;
}

/** The recorder's view, in the browser service's pixels. */
export const RECORD_VIEW = { width: 1280, height: 800 };

/** A step in one line, for the list. Pure. */
export function describeStep(step: RpaStep): string {
  switch (step.kind) {
    case 'goto': return `goto ${step.url ?? ''}`;
    case 'fill': return `fill ${step.selector ?? ''} = ${step.value ?? ''}`;
    case 'press': return `press ${step.key ?? ''} in ${step.selector ?? ''}`;
    case 'screenshot': return 'screenshot';
    default: return `${step.kind} ${step.selector ?? ''}`.trim();
  }
}

/** Where a click on the shown frame lands in the recorded page. Pure. */
export function framePoint(
  clientX: number, clientY: number, box: { left: number; top: number; width: number; height: number },
): { x: number; y: number } | null {
  if (box.width <= 0 || box.height <= 0) return null;
  const x = Math.round((clientX - box.left) * RECORD_VIEW.width / box.width);
  const y = Math.round((clientY - box.top) * RECORD_VIEW.height / box.height);
  if (x < 0 || y < 0 || x >= RECORD_VIEW.width || y >= RECORD_VIEW.height) return null;
  return { x, y };
}

/**
 * M16-T3: the step list of an `integration.rpa` node, edited by hand or
 * recorded by showing. The recorder opens a live page in the node's browser
 * service (`/api/v1/admin/integrations/rpa/{system}/record`), shows its
 * screenshot, and turns each click on it, text typed for the last clicked
 * field, and Enter into a step appended to the list. A password field's
 * text is typed into the page but recorded as the secret named `password`.
 * Logical CSS only.
 */
@Component({
  selector: 'xrm-rpa-editor',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="rpa" data-testid="rpa-editor">
      <h5>{{ 'rpaEditor.title' | translate }}</h5>
      @if (steps().length === 0) {
        <p class="rpa-hint">{{ 'rpaEditor.none' | translate }}</p>
      } @else {
        <ol class="rpa-steps">
          @for (s of steps(); track $index; let i = $index; let last = $last) {
            <li data-testid="rpa-step">
              <code dir="ltr">{{ describe(s) }}</code>
              @if (!readonly()) {
                <span class="rpa-step-actions">
                  <button type="button" (click)="move(i, -1)" [disabled]="i === 0">{{ 'rpaEditor.up' | translate }}</button>
                  <button type="button" (click)="move(i, 1)" [disabled]="last">{{ 'rpaEditor.down' | translate }}</button>
                  <button type="button" (click)="remove(i)">{{ 'rpaEditor.remove' | translate }}</button>
                </span>
              }
            </li>
          }
        </ol>
      }

      @if (!readonly()) {
        <h6>{{ 'rpaEditor.record' | translate }}</h6>
        @if (!system()) {
          <p class="rpa-hint">{{ 'rpaEditor.noSystem' | translate }}</p>
        } @else if (!session()) {
          <form class="rpa-row" (submit)="$event.preventDefault(); start(url.value)">
            <input #url type="url" dir="ltr" [attr.aria-label]="'rpaEditor.url' | translate"
                   [placeholder]="'rpaEditor.url' | translate" />
            <button type="submit" [disabled]="busy()">{{ 'rpaEditor.start' | translate }}</button>
          </form>
        } @else {
          @if (frame(); as src) {
            <button type="button" class="rpa-view" [attr.aria-label]="'rpaEditor.view' | translate"
                    [disabled]="busy()" (click)="clickFrame($event)">
              <img [src]="src" alt="" width="1280" height="800" />
            </button>
            <p class="rpa-hint">{{ 'rpaEditor.clickHint' | translate }}</p>
          }
          @if (password()) {
            <p class="rpa-hint" data-testid="rpa-password">{{ 'rpaEditor.passwordNote' | translate }}</p>
          }
          <form class="rpa-row" (submit)="$event.preventDefault(); typeText(text.value); text.value = ''">
            <input #text dir="auto" [type]="password() ? 'password' : 'text'"
                   [attr.aria-label]="'rpaEditor.typeLabel' | translate"
                   [placeholder]="'rpaEditor.typeLabel' | translate" />
            <button type="submit" [disabled]="busy()">{{ 'rpaEditor.type' | translate }}</button>
            <button type="button" (click)="press('Enter')" [disabled]="busy()">{{ 'rpaEditor.pressEnter' | translate }}</button>
            <button type="button" (click)="addScreenshot()">{{ 'rpaEditor.screenshot' | translate }}</button>
            <button type="button" (click)="stop()">{{ 'rpaEditor.stop' | translate }}</button>
          </form>
        }
        @if (error(); as e) { <p class="error-msg" role="alert">{{ e }}</p> }
      }
    </section>
  `,
  styles: [`
    .rpa { display: grid; gap: 0.5rem; margin-block-start: 0.75rem; }
    .rpa-steps { margin: 0; padding-inline-start: 1.25rem; display: grid; gap: 0.25rem; }
    .rpa-steps li { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .rpa-step-actions { display: inline-flex; gap: 0.25rem; }
    .rpa-row { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .rpa-view { padding: 0; border: 1px solid var(--color-border); background: none; cursor: crosshair; inline-size: 100%; }
    .rpa-view img { display: block; inline-size: 100%; block-size: auto; }
    .rpa-hint { margin: 0; color: var(--color-text-secondary); }
  `],
})
export class RpaEditorComponent {
  private readonly sdk = inject(SdkService);

  /** The integration system of the node's browser service. */
  readonly system = input('');
  readonly allowedHosts = input<string[]>([]);
  readonly steps = input<RpaStep[]>([]);
  readonly readonly = input(false);
  readonly stepsChange = output<RpaStep[]>();

  readonly session = signal<string | null>(null);
  /** The recorded page's last screenshot, as a data URL. */
  readonly frame = signal<string | null>(null);
  readonly password = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  describe(step: RpaStep): string {
    return describeStep(step);
  }

  private base(): string {
    return `/api/v1/admin/integrations/rpa/${encodeURIComponent(this.system())}/record`;
  }

  private show(frame: RecordFrame): void {
    this.frame.set(`data:image/png;base64,${frame.png_base64}`);
    this.password.set(frame.password);
    this.stepsChange.emit([...this.steps(), frame.step]);
  }

  start(url: string): void {
    if (!url.trim()) return;
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<RecordFrame>(this.base(), { body: { url: url.trim(), allowed_hosts: this.allowedHosts() } })
      .subscribe({
        next: f => { this.busy.set(false); this.session.set(f.session); this.show(f); },
        error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
      });
  }

  /** A click on the shown page (keyboard activations carry no point). */
  clickFrame(event: MouseEvent): void {
    if (event.detail === 0) return;
    const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const point = framePoint(event.clientX, event.clientY, box);
    if (point) this.act({ action: 'click', ...point });
  }

  typeText(text: string): void {
    if (text === '') return;
    this.act({ action: 'type', text });
  }

  press(key: string): void {
    this.act({ action: 'press', key });
  }

  addScreenshot(): void {
    this.stepsChange.emit([...this.steps(), { kind: 'screenshot' }]);
  }

  stop(): void {
    const session = this.session();
    this.session.set(null);
    this.frame.set(null);
    this.password.set(false);
    if (!session) return;
    this.sdk.delete(`${this.base()}/${session}`).subscribe({
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  remove(index: number): void {
    this.stepsChange.emit(this.steps().filter((_, i) => i !== index));
  }

  move(index: number, delta: number): void {
    const steps = [...this.steps()];
    const to = index + delta;
    if (to < 0 || to >= steps.length) return;
    [steps[index], steps[to]] = [steps[to], steps[index]];
    this.stepsChange.emit(steps);
  }

  private act(body: Record<string, unknown>): void {
    const session = this.session();
    if (!session) return;
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<RecordFrame>(`${this.base()}/${session}`, { body }).subscribe({
      next: f => { this.busy.set(false); this.show(f); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
