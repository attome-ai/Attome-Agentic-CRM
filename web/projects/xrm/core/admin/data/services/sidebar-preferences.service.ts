import { Injectable, signal } from '@angular/core';

export type SidebarStyle = 'classic' | 'rail';

const STORAGE_KEY = 'attome-xrm-sidebar-style';

@Injectable({ providedIn: 'root' })
export class SidebarPreferencesService {
  readonly style = signal<SidebarStyle>(this.readStoredStyle());

  setStyle(style: SidebarStyle): void {
    this.style.set(style);
    try { localStorage.setItem(STORAGE_KEY, style); } catch { /* storage may be unavailable */ }
  }

  private readStoredStyle(): SidebarStyle {
    try { return localStorage.getItem(STORAGE_KEY) === 'rail' ? 'rail' : 'classic'; }
    catch { return 'classic'; }
  }
}
