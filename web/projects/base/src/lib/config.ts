import { InjectionToken } from '@angular/core';

export interface AttomeBaseConfig {
  apiUrl:      string;  // e.g. 'http://localhost:8080'
  portalKey?:  string;  // namespace for localStorage/theme keys (default: 'attome')
  loginRoute?: string;  // where authGuard redirects unauthenticated users (default: '/login')
}

export const ATTOME_CONFIG = new InjectionToken<AttomeBaseConfig>('ATTOME_CONFIG');
