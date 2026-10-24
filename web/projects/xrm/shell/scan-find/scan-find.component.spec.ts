import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { ScanService } from '@attome/base/scan';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ScanFindComponent, type ScanHit } from './scan-find.component';

describe('ScanFindComponent (B16-T6)', () => {
  let get: ReturnType<typeof vi.fn>;
  let navigate: ReturnType<typeof vi.fn>;

  const page = (items: ScanHit[]) => of({ items, total: items.length, page: 1, page_size: 50 });

  beforeEach(() => {
    get = vi.fn();
    navigate = vi.fn(() => Promise.resolve(true));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ScanFindComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: Router, useValue: { navigate } },
        { provide: ScanService, useValue: { startCamera: vi.fn(), stop: vi.fn() } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'failed' } },
      ],
    });
  });

  async function render() {
    const fixture = TestBed.createComponent(ScanFindComponent);
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="scan-find"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    // ngModel writes its first value in a microtask; let it settle before typing.
    await fixture.whenStable();
    return fixture;
  }

  /** A keyboard-wedge scanner: the code typed into the field, then Enter. */
  async function scanIn(fixture: Awaited<ReturnType<typeof render>>, value: string) {
    const input = fixture.nativeElement.querySelector('[data-testid="scan-value"]') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
    (input.form as HTMLFormElement).dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('one hit navigates', async () => {
    get.mockReturnValue(page([{ entity: 'product', id: 'p1', name: 'Dates 1kg', attribute: 'barcode' }]));
    const fixture = await render();
    const done = vi.fn();
    fixture.componentInstance.done.subscribe(done);
    await scanIn(fixture, '6281000000017');
    expect(get).toHaveBeenCalledWith('/api/v1/scan/find', { value: '6281000000017' });
    expect(navigate).toHaveBeenCalledWith(expect.arrayContaining([]), { queryParams: { id: 'p1' } });
    expect(done).toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('[data-testid="scan-panel"]')).toBeNull();
  });

  it('many hits show list', async () => {
    get.mockReturnValue(page([
      { entity: 'product', id: 'p1', name: 'Dates 1kg', attribute: 'barcode' },
      { entity: 'asset', id: 'a1', name: 'Shelf scanner', attribute: 'tag' },
    ]));
    const fixture = await render();
    await scanIn(fixture, 'X-1');
    const items = fixture.nativeElement.querySelectorAll('[data-testid="scan-hits"] button');
    expect(items.length).toBe(2);
    expect(navigate).not.toHaveBeenCalled();
    (items[1] as HTMLButtonElement).click();
    expect(navigate).toHaveBeenCalledWith(expect.anything(), { queryParams: { id: 'a1' } });
  });

  it('no hit shows message', async () => {
    get.mockReturnValue(page([]));
    const fixture = await render();
    await scanIn(fixture, 'nothing');
    expect(fixture.nativeElement.querySelector('[data-testid="scan-message"]')?.textContent).toContain('shell.scan.noMatch');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('says when scanning is switched off', async () => {
    get.mockReturnValue(throwError(() => ({ status: 404, kind: 'not_found' })));
    const fixture = await render();
    await scanIn(fixture, 'x');
    expect(fixture.nativeElement.querySelector('[data-testid="scan-message"]')?.textContent).toContain('shell.scan.off');
  });
});
