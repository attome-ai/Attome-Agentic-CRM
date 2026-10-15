import { InjectionToken } from '@angular/core';
import type { LanguageDef } from './i18n/languages';

export interface AttomeBaseConfig {
  apiUrl:      string;  // e.g. 'http://localhost:8080'
  portalKey?:  string;  // namespace for localStorage/theme keys (default: 'attome')
  loginRoute?: string;  // where authGuard redirects unauthenticated users (default: '/login')
  /** B20-T1: the interface languages (default English and Arabic). */
  languages?: readonly LanguageDef[];
}

export const ATTOME_CONFIG = new InjectionToken<AttomeBaseConfig>('ATTOME_CONFIG');
