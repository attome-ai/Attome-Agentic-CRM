import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { Router, RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { CanvasComponent, EditCommand, valueAt } from '@attome/xrm/canvas';
import {
  DesignDoc, DesignNode, Direction, EmailDesign, PALETTE, PaletteType, fromCanvas, newNode, problems, toCanvas,
} from './email-design.model';

/** The entity saved designs live in (marketing pack changeset 0012). */
export const DESIGN_ENTITY = 'marketing_email_design';

/** One saved design as the generic list returns it. */
export interface SavedDesign {
  id: string;
  name: string;
}

interface DesignRecord {
  id: string;
  row_version: number;
  data: Record<string, unknown>;
}

/** Each palette block's catalog key. */
const BLOCK_KEYS: Record<PaletteType, string> = {
  heading: 'emailDesigner.blocks.heading', text: 'emailDesigner.blocks.text', image: 'emailDesigner.blocks.image',
  button: 'emailDesigner.blocks.button', divider: 'emailDesigner.blocks.divider', spacer: 'emailDesigner.blocks.spacer',
  columns: 'emailDesigner.blocks.columns',
};
const PROBLEM_KEYS = {
  missingAlt: 'emailDesigner.problems.missingAlt',
  badLink: 'emailDesigner.problems.badLink',
  empty: 'emailDesigner.problems.empty',
} as const;

function textOf(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/**
 * E2-T1: the email designer, on the shared canvas (Y14-T1). A palette adds
 * headings, text, images, buttons, dividers, spacers and two-column rows into
 * the selected column or the email; the canvas moves, edits (the selected
 * block's fields in its property panel), undoes and redoes them. The design
 * reads right to left in Arabic. Preview renders it on the server
 * (`POST /api/v1/marketing/emails/preview`, the same renderer a send uses)
 * for a chosen person, at desktop or phone width, in a sandboxed frame that
 * runs nothing. Save keeps the design, its name, subject and language as a
 * `marketing_email_design` record; a campaign send takes the same JSON.
 * What the renderer would refuse (an image without its alt text, a link
 * that is not https, mailto, tel or a placeholder) is listed before it is.
 */
@Component({
  selector: 'xrm-email-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CanvasComponent, RouterLink, TranslatePipe],
  templateUrl: './email-designer.component.html',
  styleUrl: './email-designer.component.css',
})
export class EmailDesignerComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly router = inject(Router);
  private readonly canvas = viewChild(CanvasComponent);

  /** The design to edit (route parameter); none lists the saved ones. */
  readonly id = input<string | null>(null);

  readonly palette = PALETTE;
  readonly blockKeys = BLOCK_KEYS;
  readonly problemKeys = PROBLEM_KEYS;

  readonly saved = signal<SavedDesign[]>([]);
  readonly initial = signal<DesignDoc | null>(null);
  readonly current = signal<DesignDoc | null>(null);
  readonly selectedPath = signal<string | null>(null);
  readonly name = signal('');
  readonly subject = signal('');
  readonly locale = signal<'en' | 'ar'>('en');
  readonly width = signal(600);
  readonly colour = signal('');
  readonly rowVersion = signal<number | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly previewEntity = signal('contact');
  readonly previewPerson = signal('');
  readonly previewHtml = signal<SafeHtml | null>(null);
  readonly phone = signal(false);

  readonly dir = computed<Direction>(() => (this.locale() === 'ar' ? 'rtl' : 'ltr'));
  readonly design = computed<EmailDesign | null>(() => {
    const doc = this.current();
    return doc ? fromCanvas(doc, { dir: this.dir(), width: this.width(), colour: this.colour() }) : null;
  });
  readonly issues = computed(() => {
    const d = this.design();
    return d ? problems(d) : [];
  });

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => (id && id !== 'new' ? this.load(id) : this.start(id === 'new')));
    });
  }

  valueOf(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  setLocale(event: Event): void {
    this.locale.set(this.valueOf(event) === 'ar' ? 'ar' : 'en');
  }

  setWidth(event: Event): void {
    this.width.set(Number(this.valueOf(event)) || 600);
  }

  onChanged(doc: unknown): void {
    this.current.set(doc as DesignDoc);
  }

  onSelect(paths: string[]): void {
    this.selectedPath.set(paths.at(-1) ?? null);
  }

  /** Adds a block into the selected column, else after the email's blocks. */
  add(type: PaletteType): void {
    const doc = this.current();
    if (!doc) return;
    const list = this.targetList(doc, type);
    const length = (valueAt(doc, list) as unknown[]).length;
    this.canvas()?.exec({ op: 'add', path: `${list}/-`, value: newNode(type) }, `${list}/${length}`);
  }

  /** Save: the whole design as the record (the canvas's commands only mark it saved). */
  save(_commands: EditCommand[] = []): void {
    const design = this.design();
    if (!design || !this.name().trim() || this.busy()) {
      if (!this.name().trim()) this.error.set(this.lang.translate('emailDesigner.nameNeeded'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    const body = {
      name: this.name().trim(), subject: this.subject().trim() || null, locale: this.locale(), design: JSON.stringify(design),
    };
    const id = this.id();
    const request = id && id !== 'new' && this.rowVersion() !== null
      ? this.api.patch<DesignRecord>(`/api/v1/${DESIGN_ENTITY}/${encodeURIComponent(id)}`, body, this.rowVersion() ?? undefined)
      : this.api.post<DesignRecord>(`/api/v1/${DESIGN_ENTITY}`, body);
    request.subscribe({
      next: record => {
        this.busy.set(false);
        this.rowVersion.set(Number(record.row_version ?? 0));
        this.notice.set(this.lang.translate('emailDesigner.saved'));
        if (!id || id === 'new') this.router.navigate(['/xrm', 'marketing', 'email-designer', record.id]);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 409 ? this.lang.translate('emailDesigner.conflict') : this.lang.errorText(e));
      },
    });
  }

  /** Renders the design for the chosen person, as the send would. */
  preview(): void {
    const design = this.design();
    const person = this.previewPerson().trim();
    if (!design || !person) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.post<{ html: string }>('/api/v1/marketing/emails/preview', {
      design, entity: this.previewEntity().trim() || 'contact', person_id: person,
    }).subscribe({
      next: r => {
        this.busy.set(false);
        // Shown in a frame with an empty sandbox: no script, form or same-origin access.
        this.previewHtml.set(this.sanitizer.bypassSecurityTrustHtml(r.html));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  private start(fresh: boolean): void {
    this.rowVersion.set(null);
    this.initial.set(fresh ? toCanvas({ blocks: [] }) : null);
    this.current.set(this.initial());
    if (!fresh) {
      this.api.get<{ items: Record<string, unknown>[] }>(`/api/v1/${DESIGN_ENTITY}`, { page_size: '100', sort: 'name' })
        .subscribe({
          next: page => this.saved.set((page.items ?? []).map(r => {
            const data = (r['data'] ?? r) as Record<string, unknown>;
            return { id: String(r['id']), name: textOf(data['name']) || String(r['id']) };
          })),
          error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
        });
    }
  }

  private load(id: string): void {
    this.error.set(null);
    this.api.get<DesignRecord>(`/api/v1/${DESIGN_ENTITY}/${encodeURIComponent(id)}`).subscribe({
      next: record => {
        const data = record.data ?? {};
        let design: EmailDesign = { blocks: [] };
        try {
          design = JSON.parse(textOf(data['design']) || '{"blocks":[]}') as EmailDesign;
        } catch {
          this.error.set(this.lang.translate('emailDesigner.unreadable'));
        }
        this.name.set(textOf(data['name']));
        this.subject.set(textOf(data['subject']));
        this.locale.set(data['locale'] === 'ar' || design.dir === 'rtl' ? 'ar' : 'en');
        this.width.set(design.width ?? 600);
        this.colour.set(design.primary_colour ?? '');
        this.rowVersion.set(Number(record.row_version ?? 0));
        const doc = toCanvas({ blocks: Array.isArray(design.blocks) ? design.blocks : [] });
        this.initial.set(doc);
        this.current.set(doc);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  /** Where a new block goes: into the selected column, into the selected columns row's first column, or the email. */
  private targetList(doc: DesignDoc, type: PaletteType): string {
    const path = this.selectedPath();
    let node: DesignNode | null;
    try {
      node = path ? (valueAt(doc, path) as DesignNode) : null;
    } catch {
      node = null;
    }
    // A columns row never goes inside a column: the renderer nests one level.
    if (type !== 'columns' && path && node?.type === 'column') return `${path}/children`;
    if (type !== 'columns' && path && node?.type === 'columns' && node.children?.length) return `${path}/children/0/children`;
    return '/root/children';
  }
}
