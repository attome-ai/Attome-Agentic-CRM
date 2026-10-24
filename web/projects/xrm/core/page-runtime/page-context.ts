import { Injectable, computed, signal } from '@angular/core';
import type { ConditionTree, EntitySchema } from '@attome/xrm';
import { evaluateBusinessRuleCondition, fieldKindResolver } from '@attome/xrm/core/entity';

import { Device, VisibilityContext } from './page-model';

/**
 * T2-T2: what every component of one rendered page shares: its record (on
 * a record page), the caller's roles, the screen size and the language. One
 * per `<xrm-page-runtime>`, provided by it.
 */
@Injectable()
export class PageContext {
  readonly entity = signal<string | null>(null);
  readonly recordId = signal<string | null>(null);
  readonly record = signal<Readonly<Record<string, unknown>> | null>(null);
  readonly schema = signal<EntitySchema | null>(null);
  readonly roles = signal<readonly string[]>([]);
  readonly device = signal<Device>('desktop');
  readonly arabic = signal(false);

  private readonly kinds = computed(() => fieldKindResolver(this.schema()?.fields ?? []));

  /** The visibility check's inputs, as they stand now. */
  readonly visibility = computed<VisibilityContext>(() => {
    const record = this.record();
    const kinds = this.kinds();
    return {
      roles: this.roles(),
      device: this.device(),
      holds: (when: ConditionTree) => (record ? evaluateBusinessRuleCondition(when, record, kinds) : null),
    };
  });
}
