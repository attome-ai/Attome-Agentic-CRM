import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';

import { CanvasComponent, flatten, moveCommand } from './canvas.component';
import { CommandStack } from './command-stack';
import { EditCommand, applyCommand, inverseOf } from './commands';

const DOC = {
  page_type: 'custom',
  root: {
    id: 'main', type: 'container', children: [
      { id: 'a', type: 'text', props: { text_en: 'A' } },
      { id: 'b', type: 'text', props: { text_en: 'B', size: 2 } },
      { id: 'box', type: 'container', children: [{ id: 'c', type: 'text', props: { text_en: 'C' } }] },
    ],
  },
};

const ids = (doc: unknown) => flatten(doc, '/root', 'children').map(p => p.node['id']);

describe('edit commands (Y14-T1)', () => {
  it('every command undoes back to where it started', () => {
    const commands: EditCommand[] = [
      { op: 'add', path: '/root/children/-', value: { id: 'd', type: 'text' } },
      { op: 'remove', path: '/root/children/0' },
      { op: 'set', path: '/root/children/1/props/text_en', value: 'Bee' },
      { op: 'set', path: '/root/children/1/props/new_prop', value: true },
      { op: 'move', from: '/root/children/0', to: '/root/children/1/children/0' },
      { op: 'move', from: '/root/children/2', to: '/root/children/0' },
    ];
    for (const c of commands) {
      const after = applyCommand(DOC, c);
      expect(applyCommand(after, inverseOf(DOC, c))).toEqual(DOC);
    }
    expect(DOC.root.children).toHaveLength(3);
  });
});

describe('moveCommand (Y14-T1)', () => {
  it('names the destination as it reads after the removal', () => {
    // Into a later sibling container: the container moves up by one.
    expect(moveCommand('/root/children/0', '/root/children', 0, '/root/children/2/children', 1))
      .toEqual({ op: 'move', from: '/root/children/0', to: '/root/children/1/children/1' });
    // Down within the same list.
    expect(moveCommand('/root/children/0', '/root/children', 0, '/root/children', 2))
      .toEqual({ op: 'move', from: '/root/children/0', to: '/root/children/1' });
    // Into an earlier container: nothing shifts.
    expect(moveCommand('/root/children/2/children/0', '/root/children/2/children', 0, '/root/children', 0))
      .toEqual({ op: 'move', from: '/root/children/2/children/0', to: '/root/children/0' });
  });
});

describe('CommandStack (Y14-T1)', () => {
  it('records what to send, including undos as their inverses', () => {
    const stack = new CommandStack(DOC);
    expect(stack.exec({ op: 'remove', path: '/root/children/0' })).toBe(true);
    expect(stack.exec({ op: 'remove', path: '/root/children/9' })).toBe(false);
    stack.undo();
    expect(stack.doc()).toEqual(DOC);
    stack.redo();
    expect(ids(stack.doc())).toEqual(['main', 'b', 'box', 'c']);
    const sent = stack.takeUnsaved();
    expect(sent.map(c => c.op)).toEqual(['remove', 'add', 'remove']);
    expect(stack.dirty()).toBe(false);
    expect(stack.canUndo()).toBe(true);
  });
});

describe('CanvasComponent (Y14-T1)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [CanvasComponent],
      providers: [{ provide: LangService, useValue: { translate: (k: string) => k } }],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(CanvasComponent);
    fixture.componentRef.setInput('doc', DOC);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const node = (root: HTMLElement, path: string) => root.querySelector(`[data-path="${path}"]`) as HTMLElement;
  const key = (root: HTMLElement, k: string, init: KeyboardEventInit = {}) =>
    (root.querySelector('[data-testid="canvas-tree"]') as HTMLElement).dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, ...init }));

  it('selects with a click and the keyboard, and shows the properties', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    node(root, '/root/children/1').click();
    fixture.detectChanges();
    expect(node(root, '/root/children/1').getAttribute('aria-selected')).toBe('true');
    expect(root.querySelector('[data-prop="text_en"]')).not.toBeNull();
    key(root, 'ArrowDown');
    fixture.detectChanges();
    expect(fixture.componentInstance.selected()).toEqual(['/root/children/2']);
    node(root, '/root/children/0').dispatchEvent(new MouseEvent('click', { ctrlKey: true, bubbles: true }));
    expect(fixture.componentInstance.selected()).toEqual(['/root/children/2', '/root/children/0']);
  });

  it('moves by drag and drop and by the keyboard', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    // Drop "a" into the container "box".
    node(root, '/root/children/0').dispatchEvent(new Event('dragstart'));
    node(root, '/root/children/2').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(ids(fixture.componentInstance.stack().doc())).toEqual(['main', 'b', 'box', 'c', 'a']);
    // Alt+ArrowUp moves "box" above "b".
    node(root, '/root/children/1').click();
    key(root, 'ArrowUp', { altKey: true });
    fixture.detectChanges();
    expect(ids(fixture.componentInstance.stack().doc())).toEqual(['main', 'box', 'c', 'a', 'b']);
    expect(fixture.componentInstance.selected()).toEqual(['/root/children/0']);
  });

  it('undoes and redoes, and saves the commands', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const saved: EditCommand[][] = [];
    fixture.componentInstance.save.subscribe(c => saved.push(c));
    node(root, '/root/children/0').click();
    key(root, 'Delete');
    fixture.detectChanges();
    expect(ids(fixture.componentInstance.stack().doc())).toEqual(['main', 'b', 'box', 'c']);
    key(root, 'z', { ctrlKey: true });
    fixture.detectChanges();
    expect(fixture.componentInstance.stack().doc()).toEqual(DOC);
    key(root, 'y', { ctrlKey: true });
    fixture.detectChanges();
    expect(ids(fixture.componentInstance.stack().doc())).toEqual(['main', 'b', 'box', 'c']);
    (root.querySelector('[data-testid="canvas-save"]') as HTMLButtonElement).click();
    expect(saved).toHaveLength(1);
    expect(saved[0].map(c => c.op)).toEqual(['remove', 'add', 'remove']);
  });

  it('shows where other editors are', () => {
    const fixture = TestBed.createComponent(CanvasComponent);
    fixture.componentRef.setInput('doc', DOC);
    fixture.componentRef.setInput('presence', [{ name: 'Huda', path: '/root/children/2' }]);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    const badge = (fixture.nativeElement as HTMLElement).querySelector('[data-path="/root/children/2"] [data-testid="canvas-presence"]');
    expect(badge?.textContent).toContain('Huda');
  });
});
