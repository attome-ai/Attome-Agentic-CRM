import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, InjectionToken, effect, inject, input, signal,
  untracked, viewChild,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { AuthService, ThemeService, TranslatePipe } from '@attome/base';

import { PageContext } from './page-context';
import { ComponentView, PageDataService } from './page-data.service';

/** How long a module may take to define its element before the box says it failed. */
export const DEFINE_TIMEOUT_MS = 10_000;

/** Loads a module by URL, checked against its Subresource Integrity value. */
export type ModuleLoader = (url: string, integrity: string) => Promise<void>;

/** One load per module URL in this page, shared by every host that uses it. */
const loaded = new Map<string, Promise<void>>();

/**
 * T3-T2: a module from a package, as a `<script type="module">` with its
 * `integrity`: the browser refuses it unless its bytes hash to what the
 * package was signed with. The same origin serves it, so the page's CSP
 * (`script-src 'self'`) admits it and no inline script is ever made.
 */
export function scriptModuleLoader(doc: Document): ModuleLoader {
  return (url, integrity) => {
    const key = `${url}#${integrity}`;
    let load = loaded.get(key);
    if (!load) {
      load = new Promise<void>((resolve, reject) => {
        const script = doc.createElement('script');
        script.type = 'module';
        script.src = url;
        script.integrity = integrity;
        script.addEventListener('load', () => resolve());
        script.addEventListener('error', () => {
          loaded.delete(key);
          reject(new Error('the component module did not load'));
        });
        doc.head.appendChild(script);
      });
      loaded.set(key, load);
    }
    return load;
  };
}

/** The loader a host uses; a test provides its own. */
export const COMPONENT_MODULE_LOADER = new InjectionToken<ModuleLoader>('COMPONENT_MODULE_LOADER', {
  factory: () => scriptModuleLoader(inject(DOCUMENT)),
});

/**
 * What one manifest property receives: its binding when it has one (the
 * record's id, the bound field's value, the entity's name, the signed-in
 * user's id, the theme), otherwise the builder's value from the page node,
 * otherwise the manifest's default. Pure.
 */
export function propertyValue(
  property: Record<string, unknown>,
  props: Readonly<Record<string, unknown>> | undefined,
  bound: { recordId: string | null; record: Readonly<Record<string, unknown>> | null; entity: string | null; userId: string | null; theme: 'light' | 'dark' },
): unknown {
  const name = String(property['name'] ?? '');
  switch (property['bind']) {
    case 'record_id': return bound.recordId;
    case 'entity_name': return bound.entity;
    case 'user_id': return bound.userId;
    case 'theme': return bound.theme;
    case 'field_value': {
      // The field the builder chose for this property, or the field of the same name.
      const fields = props?.['fields'];
      const field = fields && typeof fields === 'object' && !Array.isArray(fields)
        ? String((fields as Record<string, unknown>)[name] ?? name)
        : name;
      return bound.record?.[field] ?? null;
    }
    default:
      if (props && name in props) return props[name];
      return property['default'] ?? null;
  }
}

/**
 * T3-T2: hosts a published custom component (T3-T3's component kind) on a
 * page. Its module is loaded only from the package that carried it, with
 * its integrity checked; the element lives in this host's shadow root, so
 * its styles and DOM stay apart from the page's; and anything that goes
 * wrong (no installed package, a module that does not load or never
 * defines its element, a constructor or setter that throws, an error the
 * module raises) shows this component's error box and leaves the rest of
 * the page as it was.
 */
@Component({
  selector: 'xrm-custom-component-host',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="cch-mount" #mount [attr.data-component]="componentId()" [hidden]="failed()"></div>
    @if (failed()) {
      <p class="pn-error" role="alert" data-component-error>{{ 'pageRuntime.componentFailed' | translate }}</p>
    }
  `,
  styles: [`:host { display: block; } .cch-mount { display: block; }`],
})
export class CustomComponentHostComponent {
  private readonly data = inject(PageDataService);
  private readonly ctx = inject(PageContext);
  private readonly auth = inject(AuthService);
  private readonly theme = inject(ThemeService);
  private readonly loader = inject(COMPONENT_MODULE_LOADER);
  private readonly doc = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);

  /** The component's model object id (the page node's `component`). */
  readonly componentId = input.required<string>();
  /** The page node's props: the builder's values, and `fields` for bound fields. */
  readonly props = input<Readonly<Record<string, unknown>>>({});

  protected readonly failed = signal(false);
  private readonly mount = viewChild.required<ElementRef<HTMLElement>>('mount');
  private element: HTMLElement | null = null;
  private view: ComponentView | null = null;

  constructor() {
    effect(() => {
      const id = this.componentId();
      untracked(() => this.load(id));
    });
    // Bound values follow the page: a new record, its fields, the theme.
    effect(() => {
      const bound = {
        recordId: this.ctx.recordId(),
        record: this.ctx.record(),
        entity: this.ctx.entity(),
        userId: this.auth.userId(),
        theme: (this.theme.isDark() ? 'dark' : 'light') as 'light' | 'dark',
      };
      const props = this.props();
      untracked(() => this.apply(bound, props));
    });
    const onError = (event: ErrorEvent) => {
      const url = this.view?.module_url;
      if (url && event.filename && new URL(url, this.doc.baseURI).href === event.filename) this.failed.set(true);
    };
    this.doc.defaultView?.addEventListener('error', onError);
    this.destroyRef.onDestroy(() => this.doc.defaultView?.removeEventListener('error', onError));
  }

  private load(id: string): void {
    this.failed.set(false);
    this.view = null;
    this.element = null;
    this.data.component(id).subscribe({
      next: view => void this.host(view),
      error: () => this.failed.set(true),
    });
  }

  private async host(view: ComponentView): Promise<void> {
    if (!view.module_url || !view.integrity || !view.tag) {
      this.failed.set(true);
      return;
    }
    this.view = view;
    try {
      await this.loader(view.module_url, view.integrity);
      await withTimeout(customElements.whenDefined(view.tag), DEFINE_TIMEOUT_MS);
      const mount = this.mount().nativeElement;
      const root = mount.shadowRoot ?? mount.attachShadow({ mode: 'open' });
      const element = this.doc.createElement(view.tag);
      root.replaceChildren(element);
      this.element = element;
      this.apply({
        recordId: this.ctx.recordId(),
        record: this.ctx.record(),
        entity: this.ctx.entity(),
        userId: this.auth.userId(),
        theme: this.theme.isDark() ? 'dark' : 'light',
      }, this.props());
    } catch {
      this.failed.set(true);
    }
  }

  private apply(bound: Parameters<typeof propertyValue>[2], props: Readonly<Record<string, unknown>>): void {
    const element = this.element;
    const view = this.view;
    if (!element || !view) return;
    try {
      for (const property of view.properties) {
        const name = String(property['name'] ?? '');
        if (name) (element as unknown as Record<string, unknown>)[name] = propertyValue(property, props, bound);
      }
    } catch {
      this.failed.set(true);
    }
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), ms);
    promise.then(
      value => { clearTimeout(timer); resolve(value); },
      error => { clearTimeout(timer); reject(error); },
    );
  });
}
