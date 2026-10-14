import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { Observable, of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { RecordTag, RecordTagsComponent } from './record-tags.component';

const VIP: RecordTag = { id: 't1', name: 'VIP', colour: '#aa3300', group_id: null, personal: false };

class StubApi {
  tags: RecordTag[] = [VIP];
  posts: { path: string; body: unknown }[] = [];
  deletes: string[] = [];
  get(path: string): Observable<unknown> {
    return of({ items: path.endsWith('/tags') ? this.tags : [] });
  }
  post(path: string, body: unknown): Observable<unknown> {
    this.posts.push({ path, body });
    return of({ items: [...this.tags, { id: 't2', name: 'متابعة', colour: null, group_id: null, personal: true }] });
  }
  delete(path: string): Observable<void> {
    this.deletes.push(path);
    return of(undefined);
  }
}

function setup() {
  const api = new StubApi();
  TestBed.configureTestingModule({
    imports: [RecordTagsComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { current: signal('en'), translate: (k: string) => k, errorText: () => 'error' } },
    ],
  });
  const fixture = TestBed.createComponent(RecordTagsComponent);
  fixture.componentRef.setInput('entity', 'account');
  fixture.componentRef.setInput('recordId', 'r1');
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, api };
}

describe('RecordTagsComponent', () => {
  it('shows the record\'s tags', () => {
    const { fixture } = setup();
    fixture.detectChanges();
    const chips = (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="record-tag"]');
    expect(chips.length).toBe(1);
    expect(chips[0].textContent).toContain('VIP');
  });

  it('creates a personal tag from what was typed on Enter', () => {
    const { component, api } = setup();
    component.onInput('متابعة');
    component.personal.set(true);
    component.onKeydown(new KeyboardEvent('keydown', { key: 'Enter' }));
    expect(api.posts[0]).toEqual({ path: '/api/v1/account/r1/tags', body: { name: 'متابعة', personal: true } });
    expect(component.tags().length).toBe(2);
    expect(component.typed()).toBe('');
  });

  it('adds a suggested tag by id and removes a tag', () => {
    const { component, api } = setup();
    component.add({ id: 't9', name: 'Gold', colour: null, personal: false, uses: 3 });
    expect(api.posts[0].body).toEqual({ tag_id: 't9' });
    component.remove(VIP);
    expect(api.deletes).toEqual(['/api/v1/account/r1/tags/t1']);
  });

  it('ignores an empty add', () => {
    const { component, api } = setup();
    const post = vi.spyOn(api, 'post');
    component.add();
    expect(post).not.toHaveBeenCalled();
  });
});
