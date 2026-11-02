import { DOCUMENT } from '@angular/common';
import { Injectable, inject, signal } from '@angular/core';

import { ATTOME_CONFIG } from './config';
import { SdkService } from './sdk.service';
import { ThemeService } from './theme.service';

/** `settings_admin::PublicBranding`. */
export interface Branding {
  variables: Record<string, string>;
  hide_vendor_name: boolean;
  app_name?: string | null;
  font_latin?: string | null;
  font_arabic?: string | null;
  logo_url?: string | null;
  logo_dark_url?: string | null;
  favicon_url?: string | null;
}

/**
 * B13-T8: fetches the published brand and hands its colours to
 * `ThemeService`. Before sign-in it asks `/api/v1/branding/public` (the
 * deployment's and the domain's theme); once signed in, `/api/v1/branding/me`
 * adds the caller's app and business unit. A failure leaves the product's own
 * colours in place.
 */
@Injectable({ providedIn: 'root' })
export class BrandService {
  private readonly sdk = inject(SdkService);
  private readonly theme = inject(ThemeService);
  private readonly doc = inject(DOCUMENT);
  private readonly config = inject(ATTOME_CONFIG);
  /** The last brand applied, for the shell's logo. */
  readonly current = signal<Branding | null>(null);

  loadPublic(): void {
    this.load('/api/v1/branding/public');
  }

  /** `app` is the app being shown, when it has its own theme. */
  loadMine(app?: string): void {
    this.load('/api/v1/branding/me', app ? { app } : undefined);
  }

  private load(path: string, query?: Record<string, string>): void {
    (query ? this.sdk.get<Branding>(path, { query }) : this.sdk.get<Branding>(path)).subscribe({
      next: brand => {
        this.current.set(brand);
        this.theme.setBrand(brand.variables);
        if (brand.favicon_url) this.setFavicon(`${this.config.apiUrl}${brand.favicon_url}`);
        if (brand.app_name) this.doc.title = brand.app_name;
      },
      error: () => undefined,
    });
  }

  private setFavicon(href: string): void {
    let link = this.doc.head.querySelector<HTMLLinkElement>('link[rel="icon"]');
    if (!link) {
      link = this.doc.createElement('link');
      link.rel = 'icon';
      this.doc.head.appendChild(link);
    }
    link.href = href;
  }
}
