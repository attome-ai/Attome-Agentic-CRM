import {
  ChangeDetectionStrategy, Component, ComponentRef, DestroyRef, OnInit, ViewContainerRef, inject,
} from '@angular/core';
import { ApiService } from '@attome/base';
import type { SoftphoneComponent, SoftphoneConfig } from '@attome/xrm/service/softphone';

/**
 * J6-T2: the shell's softphone slot. It asks the server whether a browser
 * softphone is set up and, only then, loads `@attome/xrm/service/softphone`
 * (and through it the provider's SDK) with a dynamic `import()` — the
 * copilot launcher's pattern — so a deployment without one carries nothing
 * but this request.
 */
@Component({
  selector: 'xrm-softphone-launcher',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '',
})
export class SoftphoneLauncherComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly host = inject(ViewContainerRef);
  private readonly destroyRef = inject(DestroyRef);
  private ref: ComponentRef<SoftphoneComponent> | null = null;

  ngOnInit(): void {
    const sub = this.api.get<SoftphoneConfig>('/api/v1/voice/softphone').subscribe({
      next: config => {
        if (config.available) void this.mount(config);
      },
      // No voice module or no access: no softphone, nothing to show.
      error: () => undefined,
    });
    this.destroyRef.onDestroy(() => {
      sub.unsubscribe();
      this.ref?.destroy();
    });
  }

  private async mount(config: SoftphoneConfig): Promise<void> {
    const { SoftphoneComponent } = await import('@attome/xrm/service/softphone');
    this.ref = this.host.createComponent(SoftphoneComponent);
    this.ref.setInput('config', config);
  }
}
