import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fixtureDeployment, fixtureRollout } from '../data/fleet-fixtures';
import type { ChangesetFile } from '../data/fleet.types';
import { FleetPublishComponent, previewWaves } from './fleet-publish.component';

function changeset(id: string, seq: number, ok = true): ChangesetFile {
  return {
    id, layer: 'platform', scope: 'platform', seq, name: `cs-${seq}`, title: `Changeset ${seq}`,
    checksum: 'abc', path: `platform/${seq}.json`, checksum_ok: ok,
  };
}

describe('FleetPublishComponent', () => {
  let fixture: ComponentFixture<FleetPublishComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FleetPublishComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetPublishComponent);
    fixture.detectChanges();
  }

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      allChangesets: vi.fn().mockReturnValue(of([changeset('c1', 1), changeset('c2', 2), changeset('c3', 3, false)])),
      allDeployments: vi.fn().mockReturnValue(of([
        fixtureDeployment('d1', { ring: 'broad', maintenance_window: 'Fri 22:00' }),
        fixtureDeployment('d2', { ring: 'canary', environment: 'test' }),
        fixtureDeployment('d3', { has_credential: false }),
      ])),
      startRollout: vi.fn().mockReturnValue(of(fixtureRollout('in_progress'))),
    };
  });

  it('groups customers into waves canary first, skipping empty rings', () => {
    const waves = previewWaves([
      fixtureDeployment('a', { ring: 'broad' }), fixtureDeployment('b', { ring: 'canary' }),
    ]);
    expect(waves.map(w => w.ring)).toEqual(['canary', 'broad']);
  });

  it('chooses only changesets whose checksum matches, and only customers with a credential', async () => {
    await render();
    const c = fixture.componentInstance;
    c.chooseAllChangesets();
    expect(c.selectedChangesets().map(x => x.id)).toEqual(['c1', 'c2']);
    expect(c.selectable(c.deployments()[2])).toBe(false);
    const boxes = (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLInputElement>('input[type="checkbox"]');
    expect(Array.from(boxes).filter(b => b.disabled).length).toBe(2);
  });

  it('asks for a title, a changeset and a customer before the review', async () => {
    await render();
    const c = fixture.componentInstance;
    expect(c.validationKey()).toBe('fleet.publish.needTitle');
    c.setTitle('October');
    expect(c.validationKey()).toBe('fleet.publish.needChangeset');
    c.toggleChangeset('c1', true);
    expect(c.validationKey()).toBe('fleet.publish.needCustomer');
    c.toggleDeployment('d1', true);
    expect(c.validationKey()).toBeNull();
  });

  it('reviews the plan, then starts the rollout and opens it', async () => {
    await render();
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const c = fixture.componentInstance;
    c.setTitle(' October ');
    c.toggleChangeset('c2', true);
    c.toggleChangeset('c1', true);
    c.toggleDeployment('d1', true);
    c.toggleDeployment('d2', true);
    c.start();
    expect(svc['startRollout']).not.toHaveBeenCalled();
    c.review();
    fixture.detectChanges();
    expect(c.waves().map(w => w.ring)).toEqual(['canary', 'broad']);
    expect(c.prodTargets().length).toBe(1);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('fleet.publish.prodBackup');
    c.start();
    expect(svc['startRollout']).toHaveBeenCalledWith({
      title: 'October', changeset_ids: ['c1', 'c2'], deployment_ids: ['d1', 'd2'],
    });
    expect(navigate).toHaveBeenCalledWith(['/xrm/fleet/rollouts', 'ro1']);
  });

  it('shows "another rollout is active" in plain words', async () => {
    svc['startRollout'].mockReturnValue(throwError(() => ({
      kind: 'conflict', status: 409, code: 'conflict', message: 'conflict: fleet_rollout_active: another rollout is planned',
    })));
    await render();
    const c = fixture.componentInstance;
    c.setTitle('x');
    c.toggleChangeset('c1', true);
    c.toggleDeployment('d1', true);
    c.review();
    c.start();
    expect(c.startError()).toBe('fleet.errors.fleet_rollout_active');
    expect(c.reviewing()).toBe(true);
  });
});
