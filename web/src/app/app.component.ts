import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { DialogHostComponent } from '@attome/base/dialog';
import { StepUpPromptComponent } from '@attome/base/step-up';
import { AuthModalComponent } from './components/auth-modal/auth-modal.component';
import { UpdateReadyComponent } from './components/update-ready/update-ready.component';

@Component({
  selector:   'app-root',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterOutlet, AuthModalComponent, DialogHostComponent, StepUpPromptComponent, UpdateReadyComponent],
  template:   `<router-outlet /><app-auth-modal /><base-dialog-host /><base-step-up-prompt /><app-update-ready />`,
})
export class AppComponent {}
