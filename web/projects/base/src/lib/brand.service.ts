import { Injectable, inject } from '@angular/core';

import { ApiService } from './api.service';
import { ThemeService } from './theme.service';

/** `settings_admin::PublicBranding`. */
export interface Branding {
  variables: Record<string, string>;
  hide_vendor_name: boolean;
  font_latin?: string | null;
  font_arabic?: string | null;
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
  private readonly api = inject(ApiService);
  private readonly theme = inject(ThemeService);

  loadPublic(): void {
    this.load('/api/v1/branding/public');
  }

  /** `app` is the app being shown, when it has its own theme. */
  loadMine(app?: string): void {
    this.load(app ? `/api/v1/branding/me?app=${encodeURIComponent(app)}` : '/api/v1/branding/me');
  }

  private load(path: string): void {
    this.api.get<Branding>(path).subscribe({
      next: brand => this.theme.setBrand(brand.variables),
      error: () => undefined,
    });
  }
}
