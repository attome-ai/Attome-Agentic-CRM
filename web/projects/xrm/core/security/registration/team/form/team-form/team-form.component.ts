import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, RelatedGridComponent, TeamRolesPanelComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';

/**
 * Dedicated form for `team`. Users (via the `user_account_mm_team`
 * junction, many-to-many picker) and Roles (`TeamRolesPanelComponent`, D-133's
 * bespoke admin endpoints — the junction backing it is infrastructure-only,
 * never registered as a generic entity) are this entity's own relationships,
 * carried over unchanged from the generic dispatcher this form replaces.
 */
@Component({
  selector:   'xrm-team-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmTabDirective, XrmBaseFormComponent, FieldInputComponent, RelatedGridComponent, TeamRolesPanelComponent],
  styleUrls:  ['../../../../../../styles/xrm-form.css', './team-form.component.css'],
  templateUrl: './team-form.component.html',
})
export class TeamFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      { id: 'users', label: 'Users', icon: 'las la-user-friends' },
      { id: 'roles', label: 'Roles', icon: 'las la-shield-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }
}
