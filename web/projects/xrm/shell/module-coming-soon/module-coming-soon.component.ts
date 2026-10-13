import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';

/**
 * Shared landing page for a licensable module (`attome_modules::MODULE_MAP`)
 * that has no engine crate or route built yet. One generic, param-driven
 * component instead of ten near-duplicate stub pages, keyed by the route's
 * `:module` segment (the same string `sidebar_seed.rs` uses as `module_key`
 * and Module Management's own toggle list) — adding the next module here
 * later never means touching this component, only the sidebar seed row and
 * this route's still-generic template.
 */
@Component({
  selector:   'xrm-module-coming-soon',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./module-coming-soon.component.css'],
  templateUrl: './module-coming-soon.component.html',
})
export class ModuleComingSoonComponent {
  private readonly route = inject(ActivatedRoute);

  private readonly moduleKey = toSignal(
    this.route.paramMap.pipe(map(params => params.get('module') ?? '')),
    { initialValue: '' },
  );

  readonly label = computed(() => this.moduleKey());
}
