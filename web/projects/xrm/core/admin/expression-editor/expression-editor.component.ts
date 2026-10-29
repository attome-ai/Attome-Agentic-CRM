import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, model, signal,
} from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiService, LangService, RulesEvaluatorService, TranslatePipe } from '@attome/base';
import type { RulesAnswer, RulesDiagnostic, RulesSchema } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import {
  dottedPaths, errorKey, indexOfByte, lookupTarget, pathAt, replaceWord, rulesSchemaOf, withPaths, wordAt,
} from './expression-text';

/** One built-in function, as `GET /api/v1/admin/expressions/spec` lists it. */
interface FunctionSpec {
  name: string;
  params: { name: string; type: string }[];
  returns: string;
  description_en: string;
  description_ar: string;
  example: string;
}

/** `POST /api/v1/admin/expressions/validate`'s answer. */
interface ExpressionCheck {
  ok: boolean;
  result_type: string | null;
  diagnostics: RulesDiagnostic[];
  sql_translatable: boolean;
  sql_reason: string | null;
  value: unknown;
  trace: { expr: string; value: unknown }[] | null;
}

let nextId = 0;

interface Suggestion {
  insert: string;
  label: string;
  detail: string;
}

/**
 * Z11-T14: the one editor for a rule-language expression. It checks as you
 * type with the server's own evaluator running in the browser
 * (`RulesEvaluatorService`), underlines the part an error points at and
 * explains it in the reader's language, completes field and function names,
 * and previews the value on a sample record through
 * `POST /api/v1/admin/expressions/validate`, which also says whether the
 * expression runs in the database. The code itself is always left-to-right.
 *
 * A9-T4: with `lookupHops` above 0 (a formula read when its record is read),
 * a field path through lookups (`parent_ref.owner_ref.region`) completes
 * field by field, each lookup's target schema read once, and the in-browser
 * check declares the paths the text uses, as the server does.
 */
@Component({
  selector: 'xrm-expression-editor',
  imports: [TranslatePipe],
  templateUrl: './expression-editor.component.html',
  styleUrl: './expression-editor.component.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ExpressionEditorComponent {
  private readonly api = inject(ApiService);
  private readonly rules = inject(RulesEvaluatorService);
  private readonly lang = inject(LangService);

  /** The expression text. */
  readonly value = model('');
  /** The entity whose fields the expression reads. */
  readonly entity = input.required<string>();
  /** `v1` or `v2`. */
  readonly version = input('v2');
  readonly rows = input(3);
  readonly placeholder = input('');
  readonly disabled = input(false);
  /** Shows the sample-record preview. */
  readonly preview = input(true);
  /** The accessible name of the code input. */
  readonly label = input('');
  /** A9-T4: how many lookups a field path may follow; 0 reads only the record's own fields. */
  readonly lookupHops = input(0);

  /** The suggestion list's id, unique per editor, for `aria-controls`. */
  protected readonly listId = `xee-list-${nextId++}`;
  protected readonly errorId = `${this.listId}-error`;

  private readonly schema = signal<RulesSchema | null>(null);
  private readonly functions = signal<FunctionSpec[]>([]);
  protected readonly answer = signal<RulesAnswer | null>(null);
  protected readonly suggestions = signal<Suggestion[]>([]);
  protected readonly active = signal(0);
  private readonly caret = signal(0);
  protected readonly sampleId = signal('');
  protected readonly check = signal<ExpressionCheck | null>(null);
  protected readonly checking = signal(false);
  protected readonly previewError = signal(false);

  protected readonly diagnostic = computed(() => this.answer()?.diagnostics[0] ?? null);

  /** The text split around the error span, for the underline layer. */
  protected readonly marked = computed(() => {
    const text = this.value();
    const d = this.diagnostic();
    if (!d || d.start === null || d.end === null) return null;
    const start = indexOfByte(text, d.start);
    const end = Math.max(indexOfByte(text, d.end), start + 1);
    return { before: text.slice(0, start), bad: text.slice(start, end) || ' ', after: text.slice(end) };
  });

  /** The error in the reader's language, else the evaluator's own words. */
  protected readonly message = computed(() => {
    const d = this.diagnostic();
    if (!d) return null;
    const key = errorKey(d.code);
    const text = this.lang.translate(key);
    return text && text !== key ? text : d.message;
  });

  private timer: ReturnType<typeof setTimeout> | undefined;
  /** A9-T4: entity schemas by logical name, each read once. */
  private readonly schemas = new Map<string, Promise<EntitySchema | null>>();

  constructor() {
    inject(DestroyRef).onDestroy(() => clearTimeout(this.timer));
    effect(() => {
      const entity = this.entity();
      this.schema.set(null);
      void this.schemaOf(entity).then(s => {
        if (entity !== this.entity()) return;
        this.schema.set(s ? rulesSchemaOf(s) : { fields: {} });
        if (s) this.scheduleValidate();
      });
    });
    effect(() => {
      this.api.get<{ functions: FunctionSpec[] }>('/api/v1/admin/expressions/spec', { version: this.version() })
        .subscribe({ next: spec => this.functions.set(spec.functions), error: () => this.functions.set([]) });
    });
  }

  protected onInput(event: Event): void {
    const el = event.target as HTMLTextAreaElement;
    this.value.set(el.value);
    this.caret.set(el.selectionStart ?? el.value.length);
    this.check.set(null);
    this.suggest();
    this.scheduleValidate();
  }

  protected onKeydown(event: KeyboardEvent): void {
    const items = this.suggestions();
    if (!items.length) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      this.active.set((this.active() + step + items.length) % items.length);
    } else if (event.key === 'Enter' || event.key === 'Tab') {
      event.preventDefault();
      this.accept(items[this.active()], event.target as HTMLTextAreaElement);
    } else if (event.key === 'Escape') {
      this.suggestions.set([]);
    }
  }

  protected accept(item: Suggestion, el: HTMLTextAreaElement): void {
    const caret = this.caret();
    const { start } = wordAt(this.value(), caret);
    const next = replaceWord(this.value(), start, caret, item.insert);
    this.value.set(next.text);
    el.value = next.text;
    el.setSelectionRange(next.caret, next.caret);
    el.focus();
    this.caret.set(next.caret);
    this.suggestions.set([]);
    this.scheduleValidate();
  }

  /** An entity's schema, read once; `null` when it cannot be read. */
  private schemaOf(entity: string): Promise<EntitySchema | null> {
    let cached = this.schemas.get(entity);
    if (!cached) {
      cached = firstValueFrom(this.api.get<EntitySchema>(`/api/v1/schema/${encodeURIComponent(entity)}`))
        .catch(() => null);
      this.schemas.set(entity, cached);
    }
    return cached;
  }

  /** A9-T4: the schema at the end of `lookups` from the editor's entity, or `null`. */
  private async schemaAt(lookups: string[]): Promise<EntitySchema | null> {
    if (lookups.length > this.lookupHops()) return null;
    let schema = await this.schemaOf(this.entity());
    for (const lookup of lookups) {
      const target = schema ? lookupTarget(schema, lookup) : null;
      schema = target ? await this.schemaOf(target) : null;
    }
    return schema;
  }

  /** A9-T4: the fields of the entity a typed path reaches. */
  private async suggestPath(segments: string[], word: string, text: string, caret: number): Promise<void> {
    const schema = await this.schemaAt(segments);
    if (this.value() !== text || this.caret() !== caret) return;
    const lower = word.toLowerCase();
    const types = schema ? rulesSchemaOf(schema).fields ?? {} : {};
    this.suggestions.set(Object.entries(types)
      .filter(([name]) => name.toLowerCase().startsWith(lower) && name !== word)
      .map(([name, ty]) => {
        const target = schema && ty === 'lookup' ? lookupTarget(schema, name) : null;
        return { insert: name, label: name, detail: target ? `${ty} → ${target}` : ty };
      })
      .slice(0, 8));
    this.active.set(0);
  }

  private suggest(): void {
    if (this.lookupHops() > 0) {
      const path = pathAt(this.value(), this.caret());
      if (path.segments.length > 0) {
        void this.suggestPath(path.segments, path.word, this.value(), this.caret());
        return;
      }
    }
    const { word } = wordAt(this.value(), this.caret());
    if (!word) { this.suggestions.set([]); return; }
    const lower = word.toLowerCase();
    const arabic = this.lang.current() === 'ar';
    const fields = Object.entries(this.schema()?.fields ?? {})
      .filter(([name]) => name.toLowerCase().startsWith(lower) && name !== word)
      .map(([name, ty]) => ({ insert: name, label: name, detail: ty }));
    const functions = this.functions()
      .filter(f => f.name.startsWith(lower))
      .map(f => ({
        insert: `${f.name}(`,
        label: `${f.name}(${f.params.map(p => p.name).join(', ')})`,
        detail: arabic ? f.description_ar : f.description_en,
      }));
    this.suggestions.set([...fields, ...functions].slice(0, 8));
    this.active.set(0);
  }

  private scheduleValidate(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.validate(), 150);
  }

  private async validate(): Promise<void> {
    const schema = this.schema();
    const src = this.value();
    if (!schema || !src.trim()) { this.answer.set(null); return; }
    try {
      const declared = this.lookupHops() > 0 ? withPaths(schema, await this.resolvePaths(src)) : schema;
      if (src !== this.value()) return;
      this.answer.set(await this.rules.validate(src, declared, this.version()));
    } catch {
      // The browser module did not load: the preview and the server still check.
      this.answer.set(null);
    }
  }

  /** A9-T4: the type of each field path `src` reads that resolves; one
   * that does not is left out, so the check names it. */
  private async resolvePaths(src: string): Promise<{ segments: string[]; type: string }[]> {
    const out: { segments: string[]; type: string }[] = [];
    for (const segments of dottedPaths(src)) {
      const schema = await this.schemaAt(segments.slice(0, -1));
      const type = schema ? rulesSchemaOf(schema).fields?.[segments[segments.length - 1]] : undefined;
      if (type) out.push({ segments, type });
    }
    return out;
  }

  protected async runPreview(): Promise<void> {
    this.checking.set(true);
    this.previewError.set(false);
    try {
      const sample = this.sampleId().trim();
      this.check.set(await firstValueFrom(this.api.post<ExpressionCheck>('/api/v1/admin/expressions/validate', {
        expression: this.value(),
        entity: this.entity(),
        language_version: this.version(),
        ...(sample ? { sample_record_id: sample } : {}),
      })));
    } catch {
      this.previewError.set(true);
    } finally {
      this.checking.set(false);
    }
  }

  protected show(value: unknown): string {
    return value === null || value === undefined ? 'null' : typeof value === 'string' ? `"${value}"` : JSON.stringify(value);
  }

}
