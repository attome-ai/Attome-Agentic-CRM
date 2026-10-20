import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';

/** One form field and the lead or contact attribute it fills. */
export interface FormFieldRow {
  name: string;
  attribute: string;
}

/** The wording the embed snippet shows on the customer's site. */
export interface SnippetTexts {
  submit: string;
  thanks: string;
  failed: string;
}

const NAME = /^[a-z][a-z0-9_]{0,62}$/;
const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];

/** The rows of a form's `field_map` text (`{"form field": "attribute"}`). Pure. */
export function parseFieldMap(raw: unknown): FormFieldRow[] {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
    return Object.entries(parsed as Record<string, unknown>)
      .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
      .map(([name, attribute]) => ({ name, attribute }));
  } catch {
    return [];
  }
}

/** The `field_map` text for `rows`, blank rows left out. Pure. */
export function serializeFieldMap(rows: readonly FormFieldRow[]): string {
  const map: Record<string, string> = {};
  for (const r of rows) {
    const name = r.name.trim();
    if (name) map[name] = r.attribute.trim();
  }
  return JSON.stringify(map);
}

/** The purposes in a comma-separated list. Pure. */
export function parsePurposes(raw: string): string[] {
  return raw.split(',').map(p => p.trim()).filter(Boolean);
}

/**
 * What stops the form from working, as i18n keys (empty when it can be
 * saved). The submission needs an email (a field mapped to `email`, or one
 * named `email`); names are lower-case identifiers; `consent_*`, the UTM
 * keys and `page_url` are the form's own. Pure.
 */
export function formProblems(rows: readonly FormFieldRow[], purposes: readonly string[]): string[] {
  const problems: string[] = [];
  const live = rows.filter(r => r.name.trim() || r.attribute.trim());
  const names = live.map(r => r.name.trim());
  if (!live.some(r => r.attribute.trim() === 'email' || r.name.trim() === 'email')) {
    problems.push('marketingForm.problem.noEmail');
  }
  if (live.some(r => !NAME.test(r.name.trim()) || !NAME.test(r.attribute.trim()))) {
    problems.push('marketingForm.problem.badName');
  }
  if (new Set(names).size !== names.length) problems.push('marketingForm.problem.duplicate');
  if (names.some(n => n.startsWith('consent_') || n === 'page_url' || UTM_KEYS.includes(n))) {
    problems.push('marketingForm.problem.reservedName');
  }
  if (purposes.some(p => !NAME.test(p))) problems.push('marketingForm.problem.badPurpose');
  return problems;
}

const escapeHtml = (s: string): string => s
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
/** A JS string literal that is safe inside a `<script>` element. */
const jsString = (s: string): string => JSON.stringify(s).replace(/</g, '\\u003c');

/**
 * The HTML a marketer pastes into a page: a plain form with one input per
 * field and one checkbox per consent purpose, and a small script that posts
 * it to the deployment as JSON (with the page's URL and, when the form
 * keeps them, its UTM tags) and shows the thank-you message or follows the
 * redirect. A site on another origin must be in the deployment's
 * `cors.allowed_origins`. Pure.
 */
export function embedSnippet(
  origin: string,
  formId: string,
  rows: readonly FormFieldRow[],
  purposes: readonly string[],
  captureUtm: boolean,
  texts: SnippetTexts,
): string {
  const elementId = `attome-form-${formId}`;
  const fields = rows.filter(r => r.name.trim()).map(r => {
    const name = escapeHtml(r.name.trim());
    const type = r.attribute.trim() === 'email' || r.name.trim() === 'email' ? 'email' : 'text';
    const required = type === 'email' ? ' required' : '';
    return `  <label>${name} <input name="${name}" type="${type}"${required}></label>`;
  });
  const consents = purposes.map(p => {
    const purpose = escapeHtml(p);
    return `  <label><input type="checkbox" name="consent_${purpose}" value="on"> ${purpose}</label>`;
  });
  const utm = captureUtm
    ? `    var q = new URLSearchParams(location.search);\n` +
      `    ${JSON.stringify(UTM_KEYS)}.forEach(function (k) { if (q.get(k)) fields[k] = q.get(k); });\n`
    : '';
  return [
    `<form id="${elementId}">`,
    ...fields,
    ...consents,
    `  <button type="submit">${escapeHtml(texts.submit)}</button>`,
    `  <p data-attome-message hidden></p>`,
    `</form>`,
    `<script>`,
    `(function () {`,
    `  var form = document.getElementById(${jsString(elementId)});`,
    `  var message = form.querySelector('[data-attome-message]');`,
    `  form.addEventListener('submit', function (event) {`,
    `    event.preventDefault();`,
    `    var fields = {};`,
    `    new FormData(form).forEach(function (value, key) { fields[key] = value; });`,
    utm + `    fields.page_url = location.href;`,
    `    fetch(${jsString(`${origin}/api/v1/marketing/forms/${formId}/submit`)}, {`,
    `      method: 'POST', headers: { 'Content-Type': 'application/json' },`,
    `      body: JSON.stringify({ fields: fields })`,
    `    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r); })`,
    `      .then(function (a) {`,
    `        if (a.redirect_url) { location.href = a.redirect_url; return; }`,
    `        message.textContent = a.thank_you || ${jsString(texts.thanks)};`,
    `        message.hidden = false; form.reset();`,
    `      })`,
    `      .catch(function () { message.textContent = ${jsString(texts.failed)}; message.hidden = false; });`,
    `  });`,
    `})();`,
    `</script>`,
  ].join('\n');
}

/**
 * The marketing form builder (roadmap E10-T2): which form fields fill which
 * lead or contact attributes, the consent purposes it asks for, whether it
 * keeps UTM tags, what the visitor sees after sending, and whether it is
 * published — saved to the `marketing_form` record through the generic API
 * at its row version — and the snippet that embeds it on a website.
 */
@Component({
  selector: 'xrm-marketing-form-builder',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="fb" aria-labelledby="fb-title">
      <h2 id="fb-title">{{ 'marketingForm.title' | translate }} <span class="fb-name">{{ name() }}</span></h2>
      @if (error(); as message) { <p class="fb-error" role="alert">{{ message }}</p> }

      <fieldset class="fb-group">
        <legend>{{ 'marketingForm.fields' | translate }}</legend>
        <p class="fb-muted">{{ 'marketingForm.fieldsHelp' | translate }} {{ 'marketingForm.target.' + target() | translate }}</p>
        <table class="fb-rows">
          <thead>
            <tr>
              <th scope="col">{{ 'marketingForm.fieldName' | translate }}</th>
              <th scope="col">{{ 'marketingForm.attribute' | translate }}</th>
              <th scope="col"><span class="fb-sr">{{ 'marketingForm.remove' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (row of rows(); track $index; let i = $index) {
              <tr data-testid="fb-row">
                <td><input [value]="row.name" (input)="setRow(i, 'name', $event)"
                  [attr.aria-label]="'marketingForm.fieldName' | translate" data-testid="fb-name"></td>
                <td><input [value]="row.attribute" (input)="setRow(i, 'attribute', $event)"
                  [attr.aria-label]="'marketingForm.attribute' | translate" data-testid="fb-attribute"></td>
                <td><button type="button" (click)="removeRow(i)">{{ 'marketingForm.remove' | translate }}</button></td>
              </tr>
            }
          </tbody>
        </table>
        <button type="button" data-testid="fb-add" (click)="addRow()">{{ 'marketingForm.addField' | translate }}</button>
      </fieldset>

      <fieldset class="fb-group">
        <legend>{{ 'marketingForm.settings' | translate }}</legend>
        <label>{{ 'marketingForm.purposes' | translate }}
          <input [value]="purposes()" (input)="purposes.set(text($event))" data-testid="fb-purposes"></label>
        <label><input type="checkbox" [checked]="captureUtm()" (change)="captureUtm.set(checked($event))">
          {{ 'marketingForm.captureUtm' | translate }}</label>
        <label>{{ 'marketingForm.thankYou' | translate }}
          <input [value]="thankYou()" (input)="thankYou.set(text($event))"></label>
        <label>{{ 'marketingForm.redirectUrl' | translate }}
          <input type="url" [value]="redirectUrl()" (input)="redirectUrl.set(text($event))"></label>
        <label><input type="checkbox" [checked]="published()" (change)="published.set(checked($event))"
          data-testid="fb-published"> {{ 'marketingForm.published' | translate }}</label>
      </fieldset>

      @if (problems().length) {
        <ul class="fb-problems" role="status">
          @for (p of problems(); track p) { <li>{{ p | translate }}</li> }
        </ul>
      }
      <div class="fb-actions">
        <button type="button" data-testid="fb-save" [disabled]="saving() || problems().length > 0" (click)="save()">
          {{ 'marketingForm.save' | translate }}</button>
        @if (saved()) { <span role="status">{{ 'marketingForm.saved' | translate }}</span> }
      </div>

      <h3>{{ 'marketingForm.embed' | translate }}</h3>
      <p class="fb-muted">{{ 'marketingForm.embedHelp' | translate }}</p>
      <textarea class="fb-snippet" readonly rows="14" dir="ltr" data-testid="fb-snippet"
        [attr.aria-label]="'marketingForm.embed' | translate" [value]="snippet()"></textarea>
      <button type="button" data-testid="fb-copy" (click)="copy()">{{ 'marketingForm.copy' | translate }}</button>
      @if (copied()) { <span role="status">{{ 'marketingForm.copied' | translate }}</span> }
    </section>
  `,
  styles: [`
    .fb { display: flex; flex-direction: column; gap: var(--space-3, 12px); }
    .fb-group { display: flex; flex-direction: column; gap: var(--space-2, 8px); border: 1px solid var(--color-border); padding: var(--space-3, 12px); }
    .fb-group label { display: flex; flex-direction: column; gap: var(--space-1, 4px); }
    .fb-rows { border-collapse: collapse; inline-size: 100%; }
    .fb-rows th, .fb-rows td { padding: var(--space-1, 4px); text-align: start; }
    .fb-rows input { inline-size: 100%; }
    .fb-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
    .fb-problems { color: var(--color-danger); margin: 0; padding-inline-start: var(--space-4, 16px); }
    .fb-actions { display: flex; align-items: center; gap: var(--space-2, 8px); }
    .fb-snippet { inline-size: 100%; font-family: var(--font-mono, monospace); }
    .fb-muted { color: var(--color-text-secondary); margin: 0; }
    .fb-error { color: var(--color-danger); margin: 0; }
  `],
})
export class FormBuilderComponent {
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  /** The `marketing_form` record (route parameter). */
  readonly id = input.required<string>();

  readonly name = signal('');
  readonly target = signal('lead');
  readonly rows = signal<FormFieldRow[]>([]);
  readonly purposes = signal('');
  readonly captureUtm = signal(true);
  readonly thankYou = signal('');
  readonly redirectUrl = signal('');
  readonly published = signal(false);
  readonly rowVersion = signal<number | undefined>(undefined);
  readonly saving = signal(false);
  readonly saved = signal(false);
  readonly copied = signal(false);
  readonly error = signal<string | null>(null);

  readonly problems = computed(() => formProblems(this.rows(), parsePurposes(this.purposes())));

  readonly snippet = computed(() => embedSnippet(
    globalThis.location?.origin ?? '',
    this.id(),
    this.rows(),
    parsePurposes(this.purposes()),
    this.captureUtm(),
    {
      submit: this.lang.translate('marketingForm.snippetSubmit'),
      thanks: this.lang.translate('marketingForm.snippetThanks'),
      failed: this.lang.translate('marketingForm.snippetFailed'),
    },
  ));

  constructor() {
    effect(() => this.load(this.id()));
  }

  text(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  checked(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }

  setRow(index: number, key: keyof FormFieldRow, event: Event): void {
    const value = this.text(event);
    this.rows.update(rows => rows.map((r, i) => (i === index ? { ...r, [key]: value } : r)));
    this.saved.set(false);
  }

  addRow(): void {
    this.rows.update(rows => [...rows, { name: '', attribute: '' }]);
  }

  removeRow(index: number): void {
    this.rows.update(rows => rows.filter((_, i) => i !== index));
    this.saved.set(false);
  }

  save(): void {
    if (this.problems().length) return;
    this.saving.set(true);
    this.error.set(null);
    this.entities.update('marketing_form', this.id(), {
      field_map: serializeFieldMap(this.rows()),
      consent_purposes: parsePurposes(this.purposes()).join(','),
      capture_utm: this.captureUtm(),
      thank_you_message: this.thankYou().trim() || null,
      redirect_url: this.redirectUrl().trim() || null,
      is_published: this.published(),
    }, this.rowVersion()).subscribe({
      next: r => {
        this.rowVersion.set(r.row_version);
        this.saving.set(false);
        this.saved.set(true);
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(e.message);
      },
    });
  }

  copy(): void {
    void globalThis.navigator?.clipboard?.writeText(this.snippet()).then(() => this.copied.set(true));
  }

  private load(id: string): void {
    this.error.set(null);
    this.entities.get('marketing_form', id).subscribe({
      next: r => {
        const d = r.data;
        this.name.set(String(d['name'] ?? ''));
        this.target.set(d['target_entity'] === 'contact' ? 'contact' : 'lead');
        this.rows.set(parseFieldMap(d['field_map']));
        this.purposes.set(String(d['consent_purposes'] ?? ''));
        this.captureUtm.set(d['capture_utm'] !== false);
        this.thankYou.set(String(d['thank_you_message'] ?? ''));
        this.redirectUrl.set(String(d['redirect_url'] ?? ''));
        this.published.set(d['is_published'] === true);
        this.rowVersion.set(r.row_version);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
