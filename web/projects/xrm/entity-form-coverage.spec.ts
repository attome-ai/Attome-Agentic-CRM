import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import type { EntityRouteOverride, EntityRouteRegistry } from '@attome/xrm/core/entity';
import { registerSecurityEntityForms } from '@attome/xrm/core/security/registration';
import { registerCoreEntityForms } from '@attome/xrm/core/entity/registration';
import { registerWorkflowEntityForms } from '@attome/xrm/workflow/registration';
import { registerDashboardEntityForms } from '@attome/xrm/dashboard/registration';
import { registerDashboardLayoutForms } from '@attome/xrm/dashboard/layout-forms';
import { registerDashboardModelingForms } from '@attome/xrm/dashboard/modeling-forms';
import { registerProjectEntityForms } from '@attome/xrm/project/registration';
import { registerNotificationEntityForms } from '@attome/xrm/notification';
import { registerAuditEntityForms } from '@attome/xrm/audit';
import { registerWebcrawlEntityForms } from '@attome/xrm/webcrawl/registration';
import { registerIntegrationEntityForms } from '@attome/xrm/integration';
import { registerGrcEntityForms } from '@attome/xrm/grc';
import { registerAiEntityForms } from '@attome/xrm/ai';
import { registerReportEntityForms } from '@attome/xrm/report';
import { registerS2sEntityForms } from '@attome/xrm/s2s';
import { registerSearchEntityForms } from '@attome/xrm/search';
import { registerServiceEntityForms } from '@attome/xrm/service';
import { registerPortalEntityForms } from '@attome/xrm/portal';
import { registerAssetManagementEntityForms } from '@attome/xrm/verticals/asset-management';
import { registerContractManagementEntityForms } from '@attome/xrm/verticals/contract-management';
import { registerCrmEntityForms } from '@attome/xrm/verticals/crm';
import { registerCustomerServiceEntityForms } from '@attome/xrm/verticals/customer-service';
import { registerEnterpriseArchitectureEntityForms } from '@attome/xrm/verticals/enterprise-architecture';
import { registerFinanceEntityForms } from '@attome/xrm/verticals/finance';
import { registerGameOpsEntityForms } from '@attome/xrm/verticals/game-ops';
import { registerHumanResourcesEntityForms } from '@attome/xrm/verticals/human-resources';
import { registerSalesEntityForms } from '@attome/xrm/verticals/sales';
import { registerVendorSupplierEntityForms } from '@attome/xrm/verticals/vendor-supplier';
import { registerTrdMarketEntityForms } from '@attome/xrm/trd/registration/market';
import { registerTrdBrokerEntityForms } from '@attome/xrm/trd/registration/broker';
import { registerTrdStrategyEntityForms } from '@attome/xrm/trd/registration/strategy';
import { registerTrdResearchEntityForms } from '@attome/xrm/trd/registration/research';
import { registerTrdJournalEntityForms } from '@attome/xrm/trd/registration/journal';

/**
 * SYSTEM-CHANGES.md Topic 14 ("Forms"): every entity has its own form in code,
 * as three separate files (`.ts`, `.html`, `.css`) on the shared base form
 * (D-773). This spec is that rule's enforcement:
 *
 *  1. every entity declared in `platform-bundles/*.json` or
 *     `verticals/*\/bundle.json`, and every code-created `trd_*` entity
 *     (`TrdModel::owned_entities` in `crates/trd/trd-engine/src/model.rs`,
 *     Topic 15 #8), gets a `formComponent` from one of the module
 *     registration functions below;
 *  2. every such entity is named in the host app's loader table
 *     (`angular/src/app/attome-metadata-form-loaders.ts`) — `ensureLoaded` only runs
 *     a module's registration for a logicalname listed there, so an entity
 *     missing from it gets the "no form registered" page (there is no
 *     generic form fallback);
 *  3. every `extends EngineFormBase` component has sibling `.ts`, `.html` and
 *     `.css` files and points `templateUrl`/`styleUrls` at them.
 *
 * A new module's registration function must be added to REGISTRATIONS below;
 * until it is, check 1 fails for that module's entities.
 */
const REGISTRATIONS: ((r: EntityRouteRegistry) => void)[] = [
  registerSecurityEntityForms, registerCoreEntityForms, registerWorkflowEntityForms,
  registerDashboardEntityForms, registerDashboardLayoutForms, registerDashboardModelingForms,
  registerProjectEntityForms, registerNotificationEntityForms, registerAuditEntityForms,
  registerWebcrawlEntityForms, registerIntegrationEntityForms, registerGrcEntityForms,
  registerAiEntityForms, registerReportEntityForms, registerS2sEntityForms,
  registerSearchEntityForms, registerServiceEntityForms, registerPortalEntityForms,
  registerAssetManagementEntityForms, registerContractManagementEntityForms, registerCrmEntityForms,
  registerCustomerServiceEntityForms, registerEnterpriseArchitectureEntityForms, registerFinanceEntityForms,
  registerGameOpsEntityForms, registerHumanResourcesEntityForms, registerSalesEntityForms,
  registerVendorSupplierEntityForms,
  registerTrdMarketEntityForms, registerTrdBrokerEntityForms, registerTrdStrategyEntityForms,
  registerTrdResearchEntityForms, registerTrdJournalEntityForms,
];

/** The repository root: the nearest ancestor of the test's cwd holding `platform-bundles/`. */
function repoRoot(): string {
  let dir = process.cwd();
  while (!existsSync(join(dir, 'platform-bundles'))) {
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`no platform-bundles/ above ${process.cwd()}`);
    dir = parent;
  }
  return dir;
}

interface BundleEntity { bundle: string; logicalname: string }

function bundleEntities(root: string): BundleEntity[] {
  const files = readdirSync(join(root, 'platform-bundles'))
    .filter(f => f.endsWith('.json'))
    .map(f => join('platform-bundles', f));
  for (const v of readdirSync(join(root, 'verticals'), { withFileTypes: true })) {
    const file = join('verticals', v.name, 'bundle.json');
    if (v.isDirectory() && existsSync(join(root, file))) files.push(file);
  }
  const out: BundleEntity[] = [];
  for (const file of files) {
    const bundle = JSON.parse(readFileSync(join(root, file), 'utf8')) as { entities?: { logicalname: string }[] };
    for (const e of bundle.entities ?? []) out.push({ bundle: file, logicalname: e.logicalname });
  }
  return out;
}

/**
 * The code-created trading entities: the logical names in
 * `TrdModel::owned_entities()` (the list `entity_module_gate.rs` holds equal
 * to what `crates/trd/trd-engine/src/entities/*` provisions). Read from the
 * one `&[ "trd_…", … ]` array literal, not by parsing Rust generally.
 */
function trdEntities(root: string): BundleEntity[] {
  const file = join('crates', 'trd', 'trd-engine', 'src', 'model.rs');
  const source = readFileSync(join(root, file), 'utf8');
  const body = /fn owned_entities\(&self\)[^{]*\{\s*&\[([^\]]*)\]/.exec(source);
  if (!body) throw new Error(`no owned_entities() array in ${file}`);
  return [...body[1].matchAll(/"(trd_[a-z0-9_]+)"/g)].map(m => ({ bundle: file, logicalname: m[1] }));
}

function componentFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) componentFiles(p, out);
    else if (e.name.endsWith('.component.ts')) out.push(p);
  }
  return out;
}

describe('entity form coverage (SYSTEM-CHANGES.md Topic 14)', () => {
  const root = repoRoot();
  const entities = [...bundleEntities(root), ...trdEntities(root)];

  it('reads the bundles and the trd entity list', () => {
    expect(entities.length).toBeGreaterThan(100);
    expect(entities.filter(e => e.logicalname.startsWith('trd_')).length).toBeGreaterThanOrEqual(30);
  });

  it('registers a form component for every entity', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(), provideHttpClientTesting(), provideRouter([]),
        provideAttomeI18n(), provideXrmI18n(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      ],
    });
    const withForm = new Set<string>();
    const registry = {
      register(logicalname: string, override: EntityRouteOverride): void {
        if (override.formComponent) withForm.add(logicalname);
      },
    } as unknown as EntityRouteRegistry;
    TestBed.runInInjectionContext(() => {
      for (const register of REGISTRATIONS) register(registry);
    });

    const missing = entities.filter(e => !withForm.has(e.logicalname)).map(e => `${e.logicalname} (${e.bundle})`);
    expect(missing).toEqual([]);
  });

  it('lists every entity in the host app loader table', () => {
    const loaders = readFileSync(join(root, 'angular', 'src', 'app', 'attome-metadata-form-loaders.ts'), 'utf8');
    const missing = entities.filter(e => !loaders.includes(`'${e.logicalname}'`)).map(e => `${e.logicalname} (${e.bundle})`);
    expect(missing).toEqual([]);
  });

  it('gives every EngineFormBase component its own .ts, .html and .css', () => {
    const xrmRoot = join(root, 'angular', 'projects', 'xrm');
    const forms = componentFiles(xrmRoot).filter(f => /\bextends EngineFormBase\b/.test(readFileSync(f, 'utf8')));
    expect(forms.length).toBeGreaterThan(100);

    const problems: string[] = [];
    for (const ts of forms) {
      const source = readFileSync(ts, 'utf8');
      const stem = basename(ts, '.ts');
      const rel = ts.slice(xrmRoot.length + 1).split('\\').join('/');
      for (const ext of ['html', 'css']) {
        if (!existsSync(join(dirname(ts), `${stem}.${ext}`))) problems.push(`${rel}: no ${stem}.${ext}`);
      }
      if (!source.includes(`templateUrl: './${stem}.html'`)) problems.push(`${rel}: templateUrl is not './${stem}.html'`);
      if (!source.includes(`'./${stem}.css'`)) problems.push(`${rel}: styleUrls does not include './${stem}.css'`);
    }
    expect(problems).toEqual([]);
  });
});
