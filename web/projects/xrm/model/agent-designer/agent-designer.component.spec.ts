import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { AgentDesignerComponent, commandsFor, draftFromDoc, emptyAgent } from './agent-designer.component';

const page = <T>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 50 });

describe('agent drafts', () => {
  it('reads a document and writes it back as one set per property', () => {
    const draft = draftFromDoc({
      role: 'Triage', instructions: 'Route cases.', tools: ['records.read'],
      identity: { run_as: 'service' },
      limits: { max_steps: 5, max_tool_calls: 9, max_tokens: 1000 },
      channels: ['web'],
    });
    expect(draft).toEqual({
      role: 'Triage', instructions: 'Route cases.', tools: ['records.read'], runAs: 'service',
      maxSteps: 5, maxToolCalls: 9, maxTokens: 1000, channels: ['web'],
    });
    const commands = commandsFor(draft);
    expect(commands.map(c => c.op === 'set' ? c.path : '')).toEqual(
      ['/role', '/instructions', '/tools', '/identity', '/limits', '/channels'],
    );
    expect(commands[4]).toEqual({ op: 'set', path: '/limits', value: { max_steps: 5, max_tool_calls: 9, max_tokens: 1000 } });
  });

  it('fills defaults for a missing document', () => {
    expect(draftFromDoc(null)).toEqual(emptyAgent());
  });
});

describe('AgentDesignerComponent', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    svc = {
      objects: vi.fn().mockReturnValue(of(page([
        { id: 'a1', name: 'triage', app: 'customer', owner_layer: 'customer', version_no: 1, state: 'draft', content_hash: 'h1' },
      ]))),
      actions: vi.fn().mockReturnValue(of({ items: [{ id: 'records.read', description: 'Read', risk: 'read' }] })),
      object: vi.fn().mockReturnValue(of({
        id: 'a1', kind: 'agent', name: 'triage', version_no: 1, kind_schema_version: 1, state: 'draft',
        doc: { role: 'Triage', instructions: 'Route.', tools: [], limits: { max_steps: 3, max_tool_calls: 3, max_tokens: 300 } },
        content_hash: 'h1', created_at: '2026-10-14T00:00:00Z',
      })),
      saveDraft: vi.fn().mockReturnValue(of({ id: 'a1', version_no: 2, content_hash: 'h2', issues: [] })),
      publish: vi.fn().mockReturnValue(of({ id: 'a1', version_no: 2 })),
    };
    TestBed.configureTestingModule({
      imports: [AgentDesignerComponent],
      providers: [
        { provide: ModelService, useValue: svc },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  it('lists agents and saves an edited one against its content hash', () => {
    const fixture = TestBed.createComponent(AgentDesignerComponent);
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    expect(fixture.nativeElement.querySelectorAll('[data-agent]').length).toBe(1);

    cmp.open(cmp.agents()[0]);
    cmp.toggle('tools', 'records.read', true);
    cmp.save();
    expect(svc['saveDraft']).toHaveBeenCalledWith('agent', 'a1', 'h1', null, expect.any(Array));
    const commands = svc['saveDraft'].mock.calls[0][4];
    expect(commands[2]).toEqual({ op: 'set', path: '/tools', value: ['records.read'] });
    expect(cmp.baseHash()).toBe('h2');
    expect(cmp.status()).toBe('saved');

    cmp.publish();
    expect(svc['publish']).toHaveBeenCalledWith('agent', 'a1');
    expect(cmp.status()).toBe('published');
  });

  it('creates a new agent with its name and an empty base hash', () => {
    const fixture = TestBed.createComponent(AgentDesignerComponent);
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    cmp.create();
    cmp.newName.set('helper');
    cmp.update({ role: 'Helper', instructions: 'Help.' });
    cmp.save();
    const [kind, id, base, name] = svc['saveDraft'].mock.calls[0];
    expect([kind, base, name]).toEqual(['agent', '', 'helper']);
    expect(typeof id).toBe('string');
  });
});
