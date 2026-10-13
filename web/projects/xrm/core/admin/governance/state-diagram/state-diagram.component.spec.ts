import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import { StateDiagramComponent } from './state-diagram.component';

describe('StateDiagramComponent', () => {
  let fixture: ComponentFixture<StateDiagramComponent>;

  async function render(states: string[], transitions: { from_state: string; to_state: string; name: string }[], initial = '') {
    await TestBed.configureTestingModule({
      imports: [StateDiagramComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } }],
    }).compileComponents();
    fixture = TestBed.createComponent(StateDiagramComponent);
    fixture.componentRef.setInput('states', states);
    fixture.componentRef.setInput('transitions', transitions);
    fixture.componentRef.setInput('initial', initial);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => TestBed.resetTestingModule());

  it('says so when there is nothing to draw', async () => {
    await render([], []);
    expect(el().querySelector('svg')).toBeNull();
    expect(el().textContent).toContain('governance.stateModels.diagramEmpty');
  });

  it('draws one node per state and one edge per transition, ringing the initial state', async () => {
    await render(['new', 'open', 'closed'], [
      { from_state: 'new', to_state: 'open', name: 'Open' },
      { from_state: 'open', to_state: 'closed', name: 'Close' },
      { from_state: 'closed', to_state: 'open', name: 'Reopen' },
    ], 'new');
    expect(el().querySelectorAll('.sd-node').length).toBe(3);
    expect(el().querySelectorAll('.sd-edge').length).toBe(3);
    expect(el().querySelectorAll('.sd-node__ring').length).toBe(1);
  });

  it('adds states that only a transition names, and skips self-loops', async () => {
    await render(['a'], [
      { from_state: 'a', to_state: 'b', name: 'AB' },
      { from_state: 'a', to_state: 'a', name: 'loop' },
    ]);
    expect(fixture.componentInstance.allStates()).toEqual(['a', 'b']);
    expect(fixture.componentInstance.edges().length).toBe(1);
  });

  it('bows opposite edges apart so A->B and B->A do not overlap', async () => {
    await render(['a', 'b'], [
      { from_state: 'a', to_state: 'b', name: 'AB' },
      { from_state: 'b', to_state: 'a', name: 'BA' },
    ]);
    const [ab, ba] = fixture.componentInstance.edges();
    expect(ab.d).not.toBe(ba.d);
  });
});
