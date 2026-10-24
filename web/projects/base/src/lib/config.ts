import type { HttpInterceptorFn } from '@angular/common/http';
import { InjectionToken } from '@angular/core';
import type { LanguageDef } from './i18n/languages';

export interface AttomeBaseConfig {
  apiUrl:      string;  // e.g. 'http://localhost:8080'
  portalKey?:  string;  // namespace for localStorage/theme keys (default: 'attome')
  loginRoute?: string;  // where authGuard redirects unauthenticated users (default: '/login')
  /** B20-T1: the interface languages (default English and Arabic). */
  languages?: readonly LanguageDef[];
  /** B18-T8: interceptors that run before the auth interceptor (the host's offline data path). */
  interceptors?: readonly HttpInterceptorFn[];
}

export const ATTOME_CONFIG = new InjectionToken<AttomeBaseConfig>('ATTOME_CONFIG');
