import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SequenceBuilderComponent, logicalNameOf, starterGraph } from './sequence-builder.component';
import type { SequenceSummary } from './sequence-builder.component';

const LIST = '01900000-0000-7000-8000-0000000000c1';

const SEQUENCES: SequenceSummary[] = [
  { logicalname: 'intro', name: 'Introduction', published_version: 2, exit_on: ['reply'], active: 4 },
  { logicalname: 'renewal', name: 'Renewal', published_version: 1, exit_on: ['reply', 'meeting'], active: 0 },
];

describe('sequence builder (D17-T2)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
  let entities: { list: ReturnType<typeof vi.fn> };
  let router: { navigate: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = { get: vi.fn(() => of({ items: SEQUENCES })), post: vi.fn() };
    entities = {
      list: vi.fn(() => of({ data: [{ id: LIST, data: { name: 'Riyadh leads' } }], meta: { total: 1 } })),
    };
    router = { navigate: vi.fn(() => Promise.resolve(true)) };
    TestBed.configureTestingModule({
      imports: [SequenceBuilderComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: EntityService, useValue: entities },
        { provide: Router, useValue: router },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (key: string) => key } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(SequenceBuilderComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement>(sel: string) => el.querySelector<T>(sel);
    return { fixture, el, q };
  }

  it('builds a logical name and a starter graph', () => {
    expect(logicalNameOf('  Q4 Renewal — Gulf ')).toBe('q4_renewal_gulf');
    const graph = starterGraph(['reply', 'meeting']) as {
      nodes: { type: string; config: Record<string, unknown> }[];
      settings: { sequence: { exit_on: string[] } };
    };
    expect(graph.nodes.map(n => n.type)).toEqual(['trigger', 'module_step']);
    expect(graph.nodes[1].config['handler']).toBe('sequence.send_window');
    expect(graph.settings.sequence.exit_on).toEqual(['reply', 'meeting']);
  });

  it('lists the published sequences and enrols a list in the chosen one', () => {
    api.post.mockReturnValue(of({ enrolled: 12, skipped_active: 1, skipped_missing: 0 }));
    const { fixture, q } = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/workflow/sequences', { page_size: '200' });
    expect(q('[data-testid="sequence-enrol"]')).toBeNull();

    q<HTMLButtonElement>('[data-sequence="intro"]')!.click();
    fixture.detectChanges();
    const enrol = q<HTMLButtonElement>('[data-testid="sequence-enrol"]')!;
    expect(enrol.disabled).toBe(true);

    fixture.componentInstance.listId.set(LIST);
    fixture.detectChanges();
    enrol.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/workflow/sequences/intro/enrolments', { list_id: LIST });
    expect(q('[data-testid="sequence-outcome"]')).not.toBeNull();
    expect(api.get).toHaveBeenCalledTimes(2);
  });

  it('starts a new sequence and opens its first version in the editor', () => {
    api.post
      .mockReturnValueOnce(of({ id: 'def-1' }))
      .mockReturnValueOnce(of({ id: 'ver-1', definition_id: 'def-1' }));
    const { fixture, q } = render();
    fixture.componentInstance.newName.set('Intro Gulf');
    fixture.detectChanges();
    q<HTMLInputElement>('[data-exit="stage_change"]')!.click();
    fixture.detectChanges();
    q<HTMLButtonElement>('[data-testid="sequence-create"]')!.click();

    expect(api.post).toHaveBeenNthCalledWith(1, '/api/v1/workflow/definitions', {
      logicalname: 'intro_gulf', name: 'Intro Gulf', kind: 'sequence',
    });
    const [path, body] = api.post.mock.calls[1];
    expect(path).toBe('/api/v1/workflow/definitions/def-1/versions');
    expect(body.graph.settings.sequence.exit_on).toEqual(['reply', 'meeting']);
    expect(router.navigate).toHaveBeenCalledWith(['/xrm/workflow/definitions', 'def-1', 'versions', 'ver-1']);
  });

  it('cannot start a sequence without a name or an exit', () => {
    const { fixture } = render();
    const c = fixture.componentInstance;
    expect(c.canCreate()).toBe(false);
    c.newName.set('Intro');
    expect(c.canCreate()).toBe(true);
    for (const e of ['reply', 'meeting', 'stage_change'] as const) c.toggleExit(e);
    expect(c.canCreate()).toBe(false);
  });
});
