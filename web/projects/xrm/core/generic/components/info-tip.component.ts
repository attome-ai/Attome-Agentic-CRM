import { ChangeDetectionStrategy, Component, ElementRef, HostListener, inject, input, signal } from '@angular/core';

let nextId = 0;

/**
 * The small "ⓘ" glyph that sits after a field label — replaces the
 * always-visible `.xf-helper` paragraph under a field with the same copy on
 * demand, so a dense form reads as labels and inputs, not labels, inputs, and
 * a caption under every one of them.
 *
 *   <span class="xf-label-inline">
 *     <label for="user_name">Username</label>
 *     <xrm-info-tip text="Unique login handle. Lowercase letters, digits, and
 *                          underscores only. Cannot be changed after creation."
 *                   label="Username" />
 *   </span>
 *
 * Opens on hover and on keyboard focus, and closes on the matching
 * mouseleave/blur or Escape — the same pair of triggers a native `title`
 * responds to, which is what makes it work for both a mouse and a tab-through
 * without any extra wiring. A touch tap focuses the button first, so the same
 * focus/blur pair opens and closes it there too; no separate click handling
 * is needed.
 */
@Component({
  selector: 'xrm-info-tip',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'xf-info-tip-host' },
  styleUrls: ['./info-tip.component.css'],
  templateUrl: './info-tip.component.html',
})
export class InfoTipComponent {
  /** The copy shown in the panel — what `.xf-helper` used to carry under the field. */
  readonly text = input.required<string>();
  /** Field name, read into the trigger's accessible name — "More info: Username". */
  readonly label = input('');
  /** Flip to 'end' for a field near the right edge of its row, so the panel doesn't clip. */
  readonly align = input<'start' | 'end'>('start');

  readonly tipId = `xf-info-tip-${nextId++}`;
  readonly open = signal(false);

  private readonly host = inject(ElementRef<HTMLElement>);

  show(): void { this.open.set(true); }
  hide(): void { this.open.set(false); }

  @HostListener('keydown.escape')
  onEscape(): void {
    this.open.set(false);
    (this.host.nativeElement.querySelector('button') as HTMLButtonElement | null)?.blur();
  }
}
