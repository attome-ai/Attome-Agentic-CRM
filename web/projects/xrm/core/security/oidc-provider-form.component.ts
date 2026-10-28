import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import {
  CreateOidcProviderBody, OidcDomainItem, OidcGroupMappingItem, OidcPresetItem, OidcProviderHealthItem,
  OidcProviderItem, RoleItem, SecurityAdminService, UpdateOidcProviderBody,
} from './security-admin.service';

export type OidcTab = 'settings' | 'domains' | 'groups' | 'health';

/** The editable settings of a provider, as the form holds them. */
export interface OidcDraft {
  preset: string;
  key: string;
  display_name: string;
  display_name_ar: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  /** Space-separated. */
  scopes: string;
  /** Comma-separated tenant ids. */
  tenant_allowlist: string;
  link_mode: 'link_only' | 'create' | string;
  default_role_ref: string;
  trusted_for_mfa: boolean;
  enabled: boolean;
  /** The claim map as JSON text. */
  claim_map: string;
}

export const LINK_MODES = ['link_only', 'create'] as const;

/** An empty draft. Pure. */
export function emptyDraft(): OidcDraft {
  return {
    preset: '', key: '', display_name: '', display_name_ar: '', issuer: '', client_id: '',
    client_secret: '', scopes: 'openid email profile', tenant_allowlist: '', link_mode: 'link_only',
    default_role_ref: '', trusted_for_mfa: false, enabled: true, claim_map: '{}',
  };
}

/** A saved provider as a draft; the secret is never read back. Pure. */
export function draftOf(p: OidcProviderItem): OidcDraft {
  return {
    preset: p.preset ?? '', key: p.key, display_name: p.display_name, display_name_ar: p.display_name_ar ?? '',
    issuer: p.issuer, client_id: p.client_id, client_secret: '', scopes: (p.scopes ?? []).join(' '),
    tenant_allowlist: (p.tenant_allowlist ?? []).join(', '), link_mode: p.link_mode,
    default_role_ref: p.default_role_ref ?? '', trusted_for_mfa: p.trusted_for_mfa, enabled: p.enabled,
    claim_map: JSON.stringify(p.claim_map ?? {}, null, 2),
  };
}

/** A preset applied to `draft`: its scopes and claim map, and the issuer
 *  template when the issuer is still empty. Pure. */
export function applyPreset(draft: OidcDraft, preset: OidcPresetItem): OidcDraft {
  return {
    ...draft,
    preset: preset.key,
    display_name: draft.display_name || preset.display_name,
    issuer: draft.issuer || preset.issuer_template,
    scopes: (preset.scopes ?? []).join(' '),
    claim_map: JSON.stringify(preset.claim_map ?? {}, null, 2),
  };
}

function words(text: string, separator: RegExp): string[] {
  return text.split(separator).map(w => w.trim()).filter(Boolean);
}

/** The request body for `draft`, or the key of what is wrong with it. A
 *  blank secret on an edit keeps the stored one. Pure. */
export function bodyOf(draft: OidcDraft, creating: boolean): { body: Record<string, unknown> } | { invalid: string } {
  let claimMap: unknown;
  try {
    claimMap = JSON.parse(draft.claim_map || '{}');
  } catch {
    return { invalid: 'oidcAdmin.invalidClaimMap' };
  }
  if (typeof claimMap !== 'object' || claimMap === null || Array.isArray(claimMap)) {
    return { invalid: 'oidcAdmin.invalidClaimMap' };
  }
  if (!draft.display_name.trim() || !draft.issuer.trim() || !draft.client_id.trim()) {
    return { invalid: 'oidcAdmin.required' };
  }
  if (creating && (!draft.key.trim() || !draft.client_secret)) {
    return { invalid: 'oidcAdmin.required' };
  }
  const body: Record<string, unknown> = {
    display_name: draft.display_name.trim(),
    display_name_ar: draft.display_name_ar.trim() || null,
    issuer: draft.issuer.trim(),
    client_id: draft.client_id.trim(),
    scopes: words(draft.scopes, /\s+/),
    tenant_allowlist: words(draft.tenant_allowlist, /,/),
    link_mode: draft.link_mode,
    default_role_ref: draft.default_role_ref || null,
    trusted_for_mfa: draft.trusted_for_mfa,
    enabled: draft.enabled,
    claim_map: claimMap,
  };
  if (creating) {
    body['key'] = draft.key.trim();
    body['preset'] = draft.preset || null;
  }
  if (draft.client_secret) body['client_secret'] = draft.client_secret;
  return { body };
}

/**
 * Q1-T14: one sign-in provider (`admin/security/oidc-providers/:id`, or
 * `new`). Settings with presets and a test sign-in; once saved, its email
 * domains (with the TXT record to publish and a verify button), its group
 * mappings, and its health on this node. A provider from `config.json` is
 * shown read-only.
 */
@Component({
  selector: 'xrm-oidc-provider-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  templateUrl: './oidc-provider-form.component.html',
})
export class OidcProviderFormComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  private readonly lang = inject(LangService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  readonly linkModes = LINK_MODES;
  readonly provider = signal<OidcProviderItem | null>(null);
  readonly presets = signal<OidcPresetItem[]>([]);
  readonly roles = signal<RoleItem[]>([]);
  readonly domains = signal<OidcDomainItem[]>([]);
  readonly mappings = signal<OidcGroupMappingItem[]>([]);
  readonly health = signal<OidcProviderHealthItem | null>(null);
  readonly tab = signal<OidcTab>('settings');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly creating = computed(() => this.provider() === null);
  readonly readOnly = computed(() => this.provider()?.read_only === true);
  draft: OidcDraft = emptyDraft();
  newDomain = '';
  newDomainSsoOnly = false;
  newClaimValue = '';
  newRoleId = '';
  newTeamId = '';

  ngOnInit(): void {
    this.svc.listOidcPresets().subscribe({ next: p => this.presets.set(p), error: () => this.presets.set([]) });
    this.svc.listRoles().subscribe({ next: r => this.roles.set(r), error: () => this.roles.set([]) });
    const id = this.route.snapshot.paramMap.get('id');
    if (id && id !== 'new') this.loadProvider(id);
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e));
  }

  private loadProvider(id: string): void {
    this.svc.listOidcProviders().subscribe({
      next: providers => {
        const found = providers.find(p => p.id === id) ?? null;
        if (!found) { this.error.set(this.lang.translate('oidcAdmin.notFound')); return; }
        this.provider.set(found);
        this.draft = draftOf(found);
        this.loadDomains();
        this.loadMappings();
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  back(): void {
    void this.router.navigate(['..'], { relativeTo: this.route });
  }

  onPreset(key: string): void {
    const preset = this.presets().find(p => p.key === key);
    this.draft = preset ? applyPreset(this.draft, preset) : { ...this.draft, preset: '' };
  }

  save(): void {
    const result = bodyOf(this.draft, this.creating());
    if ('invalid' in result) { this.error.set(this.lang.translate(result.invalid)); return; }
    this.busy.set(true);
    this.error.set(null);
    const existing = this.provider();
    const saved = existing?.id
      ? this.svc.updateOidcProvider(existing.id, result.body as UpdateOidcProviderBody, existing.row_version ?? 0)
      : this.svc.createOidcProvider(result.body as unknown as CreateOidcProviderBody);
    saved.subscribe({
      next: p => {
        this.busy.set(false);
        this.provider.set(p);
        this.draft = draftOf(p);
        this.notice.set(this.lang.translate('oidcAdmin.saved'));
        if (!existing && p.id) void this.router.navigate(['..', p.id], { relativeTo: this.route, replaceUrl: true });
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  remove(): void {
    const id = this.provider()?.id;
    if (!id) return;
    this.busy.set(true);
    this.svc.deleteOidcProvider(id).subscribe({
      next: () => { this.busy.set(false); this.back(); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  /** Opens the provider's sign-in in a new tab; the result comes back there. */
  test(): void {
    const id = this.provider()?.id;
    if (!id) return;
    this.svc.testOidcProvider(id).subscribe({
      next: start => window.open(start.authorize_url, '_blank', 'noopener'),
      error: (e: ApiError) => this.fail(e),
    });
  }

  show(tab: OidcTab): void {
    this.tab.set(tab);
    if (tab === 'health') this.loadHealth();
  }

  private loadDomains(): void {
    const id = this.provider()?.id;
    this.svc.listOidcDomains().subscribe({
      next: domains => this.domains.set(domains.filter(d => d.provider_id === id)),
      error: (e: ApiError) => this.fail(e),
    });
  }

  addDomain(): void {
    const id = this.provider()?.id;
    const domain = this.newDomain.trim();
    if (!id || !domain) return;
    this.svc.createOidcDomain({ provider_id: id, domain, sso_only: this.newDomainSsoOnly }).subscribe({
      next: () => { this.newDomain = ''; this.newDomainSsoOnly = false; this.loadDomains(); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  verifyDomain(domain: OidcDomainItem): void {
    this.svc.verifyOidcDomain(domain.id).subscribe({
      next: updated => this.domains.update(all => all.map(d => (d.id === updated.id ? updated : d))),
      error: (e: ApiError) => this.fail(e),
    });
  }

  removeDomain(domain: OidcDomainItem): void {
    this.svc.deleteOidcDomain(domain.id).subscribe({
      next: () => this.domains.update(all => all.filter(d => d.id !== domain.id)),
      error: (e: ApiError) => this.fail(e),
    });
  }

  private loadMappings(): void {
    const id = this.provider()?.id;
    if (!id) return;
    this.svc.listOidcGroupMappings(id).subscribe({
      next: m => this.mappings.set(m),
      error: (e: ApiError) => this.fail(e),
    });
  }

  addMapping(): void {
    const id = this.provider()?.id;
    const claim = this.newClaimValue.trim();
    if (!id || !claim || (!this.newRoleId && !this.newTeamId.trim())) return;
    this.svc.createOidcGroupMapping(id, {
      claim_value: claim,
      role_id: this.newRoleId || null,
      team_id: this.newTeamId.trim() || null,
    }).subscribe({
      next: () => { this.newClaimValue = ''; this.newRoleId = ''; this.newTeamId = ''; this.loadMappings(); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  removeMapping(mapping: OidcGroupMappingItem): void {
    const id = this.provider()?.id;
    if (!id) return;
    this.svc.deleteOidcGroupMapping(id, mapping.id).subscribe({
      next: () => this.mappings.update(all => all.filter(m => m.id !== mapping.id)),
      error: (e: ApiError) => this.fail(e),
    });
  }

  private loadHealth(): void {
    const id = this.provider()?.id;
    if (!id) return;
    this.svc.oidcProviderHealth(id).subscribe({
      next: h => this.health.set(h),
      error: (e: ApiError) => this.fail(e),
    });
  }

  /** The DNS record to publish, as a zone file line. */
  txtRecord(d: OidcDomainItem): string {
    return `${d.verification_record_name} TXT "${d.verification_record_value}"`;
  }

  roleName(id: string | null | undefined): string {
    if (!id) return '';
    return this.roles().find(r => r.id === id)?.name ?? id;
  }

  failures(h: OidcProviderHealthItem): { kind: string; count: number }[] {
    return Object.entries((h.failures ?? {}) as Record<string, number>)
      .map(([kind, count]) => ({ kind, count: Number(count) }))
      .sort((a, b) => a.kind.localeCompare(b.kind));
  }
}
