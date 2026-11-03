import { HttpInterceptorFn } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { ATTOME_CONFIG } from './config';

/**
 * T5-T3: the request header naming the Develop workspace a request runs in
 * (`attome_api::workspace::proxy::WORKSPACE_HEADER`).
 */
export const WORKSPACE_HEADER = 'x-attome-workspace';

/**
 * The workspace routes. They always run on live: a workspace is made, listed,
 * refreshed and published from there.
 */
export const WORKSPACE_ROUTES = '/api/v1/admin/workspaces';

/** Sign-in and the session stay on live too. */
const AUTH_ROUTES = '/api/v1/auth/';

/** The workspace this tab works in. */
export interface ChosenWorkspace {
  id: string;
  /** Shown in the banner and the picker. */
  name: string;
}

const STORAGE_KEY = 'attome-workspace';

/**
 * T5-T7 — the Develop workspace this browser tab works in, if any, beside
 * `ChangesetState`. Kept in `sessionStorage` so a reload stays in it and a
 * new tab starts on live. The server decides everything; this only names the
 * workspace on each request ([`workspaceInterceptor`]).
 */
@Injectable({ providedIn: 'root' })
export class WorkspaceState {
  private readonly current = signal<ChosenWorkspace | null>(read());

  readonly active = this.current.asReadonly();
  readonly inside = computed(() => this.current() !== null);

  /** Works in `workspace` from the next request; a blank id leaves instead. */
  enter(workspace: ChosenWorkspace): void {
    const id = workspace.id.trim();
    if (!id) {
      this.leave();
      return;
    }
    const chosen = { id, name: workspace.name };
    this.current.set(chosen);
    write(chosen);
  }

  /** Back to live from the next request. */
  leave(): void {
    this.current.set(null);
    write(null);
  }
}

/**
 * Whether a request to `path` runs inside the chosen workspace: every API
 * request but the workspace and sign-in routes. Pure.
 */
export function workspaceHeaderApplies(path: string): boolean {
  return path.startsWith('/api/v1/')
    && !path.startsWith(WORKSPACE_ROUTES)
    && !path.startsWith(AUTH_ROUTES);
}

function read(): ChosenWorkspace | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<ChosenWorkspace>;
    return typeof parsed.id === 'string' && parsed.id
      ? { id: parsed.id, name: typeof parsed.name === 'string' ? parsed.name : parsed.id }
      : null;
  } catch {
    return null;
  }
}

function write(chosen: ChosenWorkspace | null): void {
  try {
    if (chosen) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(chosen));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked: the choice lasts until the page reloads.
  }
}

/**
 * T5-T7: names the chosen workspace on every API request it applies to
 * ([`workspaceHeaderApplies`]), whichever client sends it (the SDK goes
 * through `HttpClient` too).
 */
export const workspaceInterceptor: HttpInterceptorFn = (req, next) => {
  const config = inject(ATTOME_CONFIG);
  const chosen = inject(WorkspaceState).active();
  const path = req.url.startsWith(config.apiUrl) ? req.url.slice(config.apiUrl.length) : req.url;
  if (!chosen || !workspaceHeaderApplies(path)) return next(req);
  return next(req.clone({ setHeaders: { [WORKSPACE_HEADER]: chosen.id } }));
};
