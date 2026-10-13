import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { EMPTY } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { QueryAdminService } from '@attome/xrm/core/query/data';
import { QueryEditorComponent } from './query-editor.component';
import { QueryService } from '@attome/xrm/core/query/data';

describe('QueryEditorComponent route input', () => {
  const getQuery = vi.fn(() => EMPTY);

  beforeEach(() => {
    getQuery.mockClear();
    TestBed.configureTestingModule({
      imports: [QueryEditorComponent],
      providers: [
        { provide: QueryAdminService, useValue: { getQuery } },
        { provide: QueryService, useValue: {} },
        { provide: Router, useValue: { navigate: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(QueryEditorComponent, { set: { template: '' } });
  });

  it('loads the query identified by the route-bound id input', () => {
    const fixture = TestBed.createComponent(QueryEditorComponent);
    fixture.componentRef.setInput('id', 'query-1');

    fixture.detectChanges();

    expect(getQuery).toHaveBeenCalledWith('query-1');
  });
});
