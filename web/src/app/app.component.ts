import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { DialogHostComponent } from '@attome/base/dialog';
import { StepUpPromptComponent } from '@attome/base/step-up';
import { AuthModalComponent } from './components/auth-modal/auth-modal.component';

@Component({
  selector:   'app-root',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterOutlet, AuthModalComponent, DialogHostComponent, StepUpPromptComponent],
  template:   `<router-outlet /><app-auth-modal /><base-dialog-host /><base-step-up-prompt />`,
})
export class AppComponent {}
