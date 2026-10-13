import { inject, Injector, runInInjectionContext, signal } from '@angular/core';
import { DefaultTranspiler, TranslocoTranspiler, TranspileParams } from '@jsverse/transloco';
import type { MessageformatConfig } from '@jsverse/transloco-messageformat';

/**
 * P-i18n-a11y §4.1's ICU support, moved off the initial bundle.
 *
 * `provideTranslocoMessageformat()` pulls `@messageformat/core` (plus
 * `make-plural` and the skeleton parsers) into whatever chunk references it.
 * Because the i18n providers are part of `provideAttomeBase()`, that chunk was
 * the eager one — and since `@messageformat/core` is CommonJS, esbuild reports
 * an optimization bailout for it and cannot tree-shake the parts we never use.
 * Every visitor paid for it on first paint, including on the public landing and
 * login pages, which render no ICU message at all.
 *
 * This transpiler keeps the same public behaviour while deferring that cost:
 *
 * - It extends `DefaultTranspiler`, so `{{param}}` interpolation — which is
 *   what the overwhelming majority of catalog keys use — works synchronously
 *   from the first render, with no plugin loaded.
 * - It starts the dynamic `import()` in its own constructor, i.e. as soon as
 *   `TranslocoService` first resolves a transpiler, so the chunk downloads in
 *   parallel with the app's own route chunks rather than on the critical path.
 * - `transpile()` reads the `delegate` signal. Any view that renders a
 *   translation therefore becomes a consumer of it, and swapping the real
 *   transpiler in marks those views dirty — which is what makes this correct
 *   under `ChangeDetectionStrategy.OnPush`, where nothing else would prompt a
 *   re-render once the chunk lands.
 *
 * The only observable difference is the window between first paint and the
 * chunk resolving: an ICU message rendered in that window falls back to
 * `DefaultTranspiler` and shows its raw `{count, plural, …}` source, then
 * corrects itself on the swap. Every ICU key in the catalogs today
 * (`resetPassword.minLength`, `entityList.*`, `usersList.*` — see
 * en.catalog.ts) sits behind a lazy route and a user interaction, so none of
 * them can render during that window in practice.
 */
// No `@Injectable()`: `MessageformatConfig` is an interface, so it is not a
// usable injection token. provide.ts constructs this through a `useFactory`,
// which already runs inside an injection context — which is what the `inject()`
// call below and `DefaultTranspiler`'s own `inject(TRANSLOCO_CONFIG)` need.
export class LazyMessageFormatTranspiler extends DefaultTranspiler implements TranslocoTranspiler {
  private readonly injector = inject(Injector);
  private readonly delegate = signal<TranslocoTranspiler | null>(null);

  /**
   * The active language, mirrored so the delegate can be put on the right
   * locale the moment it arrives. `TranslocoService.setActiveLang()` fires
   * `onLangChanged` once at bootstrap, long before the chunk resolves, so
   * without this the plugin would stay on its constructor-time locale.
   */
  private lang: string | null = null;

  /** Named `mfConfig`, not `config` — `DefaultTranspiler.config` is Transloco's own. */
  private readonly mfConfig: MessageformatConfig;

  /**
   * Resolves once the plugin chunk has landed and been swapped in. Application
   * code should not await this — the whole point is that rendering does not
   * block on it — but a test asserting ICU output has to, since before it
   * settles `transpile()` deliberately returns the raw `{count, plural, …}`
   * source. Rejections are surfaced rather than swallowed so a broken chunk
   * shows up as a failing test rather than as silently un-formatted messages.
   */
  readonly ready: Promise<void>;

  constructor(config: MessageformatConfig) {
    super();
    this.mfConfig = config;
    this.ready = this.loadPlugin();
    // A failed chunk load leaves every ICU message stuck showing its raw
    // source, which is worth a console signal rather than silent degradation.
    // Attaching a handler here also stops it surfacing as an unhandled
    // rejection; `ready` still rejects for anyone who awaits it.
    this.ready.catch((error: unknown) => {
      console.warn(
        '[attome] ICU message formatting is unavailable: the transloco-messageformat chunk failed to load.',
        error,
      );
    });
  }

  private async loadPlugin(): Promise<void> {
    const { MessageFormatTranspiler } = await import('@jsverse/transloco-messageformat');
    // `MessageFormatTranspiler`'s own `super()` calls `inject(TRANSLOCO_CONFIG)`,
    // and this runs in a microtask well outside the original injection context.
    const plugin = runInInjectionContext(
      this.injector,
      () => new MessageFormatTranspiler(this.mfConfig),
    );
    if (this.lang !== null) plugin.onLangChanged(this.lang);
    this.delegate.set(plugin);
  }

  override transpile(params: TranspileParams): unknown {
    const plugin = this.delegate();
    return plugin ? plugin.transpile(params) : super.transpile(params);
  }

  onLangChanged(lang: string): void {
    this.lang = lang;
    (this.delegate() as { onLangChanged?(l: string): void } | null)?.onLangChanged?.(lang);
  }
}
