import {
  ChangeDetectionStrategy, Component, ComponentRef, DestroyRef, ElementRef, ViewContainerRef,
  inject, signal, viewChild,
} from '@angular/core';
import { TranslatePipe } from '@attome/base';
import type { CopilotPanelComponent } from '@attome/xrm/ai/chat';

/**
 * The shell's copilot button (C7). The panel lives in its own entry point,
 * `@attome/xrm/ai/chat`, loaded with a dynamic `import()` the first time the
 * button is pressed — the `DashboardComponent` pattern — so the shell carries
 * only this button and the panel's type.
 *
 * Closing hides the panel rather than destroying it, so the conversation
 * survives navigation between records (the shell outlives every route). The
 * panel re-reads the record context from the URL on each message.
 */
@Component({
  selector: 'xrm-copilot-launcher',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./copilot-launcher.component.css'],
  templateUrl: './copilot-launcher.component.html',
})
export class CopilotLauncherComponent {
  private readonly host = viewChild.required('panelHost', { read: ViewContainerRef });
  private readonly trigger = viewChild<ElementRef<HTMLButtonElement>>('trigger');
  private panel: ComponentRef<CopilotPanelComponent> | null = null;
  private loading = false;

  readonly open = signal(false);
  /** An i18n key when the panel's chunk could not be loaded. */
  readonly loadError = signal<string | null>(null);

  constructor() {
    inject(DestroyRef).onDestroy(() => this.panel?.destroy());
  }

  toggle(): void {
    if (this.open()) {
      this.close();
    } else {
      void this.show();
    }
  }

  /** B10-T3: opens the panel and asks it `text`. */
  async ask(text: string): Promise<void> {
    await this.show();
    this.panel?.instance.ask(text);
  }

  private show(): Promise<void> {
    this.loadError.set(null);
    if (this.panel) {
      this.setHidden(false);
      this.open.set(true);
      return Promise.resolve();
    }
    if (this.loading) return Promise.resolve();
    this.loading = true;
    return import('@attome/xrm/ai/chat')
      .then((m) => {
        this.loading = false;
        this.panel = this.host().createComponent(m.CopilotPanelComponent);
        this.panel.instance.closed.subscribe(() => this.close());
        this.open.set(true);
      })
      .catch(() => {
        this.loading = false;
        this.loadError.set('aiChat.launcher.loadFailed');
      });
  }

  close(): void {
    this.setHidden(true);
    this.open.set(false);
    queueMicrotask(() => this.trigger()?.nativeElement.focus());
  }

  private setHidden(hidden: boolean): void {
    const el = this.panel?.location.nativeElement as HTMLElement | undefined;
    if (el) el.hidden = hidden;
  }
}
