import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';

import { MenuItem, MenuView, ModelService } from '../model.service';

/** Where an item opens, as an app route or an outside link. */
export type MenuLink = { route: string } | { href: string } | null;

/**
 * The app route an item opens. Forms open in the generic renderer; links
 * open as links; the other kinds get their routes as their screens join the
 * renderer (Y14), and until then show without a link.
 */
export function linkFor(item: MenuItem): MenuLink {
  switch (item.kind) {
    case 'form':
      return item.target ? { route: `/model/forms/${item.target}` } : null;
    case 'url':
      if (!item.url) return null;
      return item.url.startsWith('/') ? { route: item.url } : { href: item.url };
    default:
      return null;
  }
}

/**
 * An app's menu (roadmap A21-T2): draws a published navigation object as
 * the server filtered it for this user, groups of links in order. Layout
 * uses logical CSS properties only, so Arabic needs nothing extra.
 */
@Component({
  selector:        'xrm-app-menu',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [RouterLink, TranslatePipe],
  templateUrl:     './app-menu.component.html',
  styleUrls:       ['./app-menu.component.css'],
})
export class AppMenuComponent {
  private readonly model = inject(ModelService);

  /** The navigation object to draw. */
  readonly menuId = input.required<string>();

  readonly menu  = signal<MenuView | null>(null);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const id = this.menuId();
      untracked(() => this.load(id));
    });
  }

  private load(id: string): void {
    this.error.set(null);
    this.model.menu(id).subscribe({
      next: menu => this.menu.set(menu),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  link(item: MenuItem): MenuLink {
    return linkFor(item);
  }

  route(link: MenuLink): string | null {
    return link && 'route' in link ? link.route : null;
  }

  href(link: MenuLink): string | null {
    return link && 'href' in link ? link.href : null;
  }

  /** A21-T5: counts the open; a failure is of no concern to the person. */
  opened(group: string, item: string): void {
    this.model.menuItemOpened(this.menuId(), `${group}/${item}`).subscribe({ error: () => undefined });
  }
}
