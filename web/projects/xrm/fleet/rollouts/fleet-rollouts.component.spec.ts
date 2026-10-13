import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fixtureRollout } from '../data/fleet-fixtures';
import { FleetRolloutsComponent, rolloutTone } from './fleet-rollouts.component';

describe('FleetRolloutsComponent', () => {
  let fixture: ComponentFixture<FleetRolloutsComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;
  const translate = vi.fn((key: string) => key);

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FleetRolloutsComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        { provide: LangService, useValue: { translate, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetRolloutsComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    translate.mockClear();
    svc = {
      listRollouts: vi.fn().mockReturnValue(of({ items: [fixtureRollout().rollout], total: 30, page: 1, page_size: 25 })),
    };
  });

  it('lists rollouts one-based and links to each', async () => {
    await render();
    expect(svc['listRollouts']).toHaveBeenCalledWith(1, 25);
    const link = el().querySelector('tbody a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/xrm/fleet/rollouts/ro1');
    expect(el().textContent).toContain('fleet.rolloutStatus.in_progress');
    fixture.componentInstance.next();
    expect(svc['listRollouts']).toHaveBeenLastCalledWith(2, 25);
  });

  it('names the current wave', async () => {
    await render();
    fixture.componentInstance.waveText(fixtureRollout().rollout);
    expect(translate).toHaveBeenCalledWith('fleet.rollouts.waveOf', { wave: 1, waves: 1, name: 'fleet.ring.canary' });
  });

  it('colours finished and stopped rollouts apart (with the status word beside it)', () => {
    expect(rolloutTone('completed')).toBe('fleet-pill--ok');
    expect(rolloutTone('halted')).toBe('fleet-pill--bad');
    expect(rolloutTone('in_progress')).toBe('fleet-pill--warn');
  });

  it('shows a load failure', async () => {
    svc['listRollouts'].mockReturnValue(throwError(() => ({ kind: 'forbidden', status: 403, message: '' })));
    await render();
    expect(el().querySelector('[role="alert"]')?.textContent).toContain('errors.unknown');
  });
});
