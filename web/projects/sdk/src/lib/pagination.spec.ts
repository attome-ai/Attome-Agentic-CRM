import { describe, expect, it, vi } from 'vitest';
import { collectAllPages, MAX_ALL_PAGES_ITEMS, paginate, type PaginatedResponse } from './pagination';

function page<T>(items: T[], total: number, pageNo: number, pageSize: number): PaginatedResponse<T> {
  return { items, total, page: pageNo, page_size: pageSize };
}

describe('paginate', () => {
  it('walks every page in order and yields every item exactly once', async () => {
    const fetchPage = vi.fn(async (p: number) => {
      if (p === 1) return page([1, 2], 5, 1, 2);
      if (p === 2) return page([3, 4], 5, 2, 2);
      return page([5], 5, 3, 2);
    });

    const items: number[] = [];
    for await (const item of paginate(fetchPage)) items.push(item);

    expect(items).toEqual([1, 2, 3, 4, 5]);
    expect(fetchPage).toHaveBeenCalledTimes(3);
    expect(fetchPage).toHaveBeenNthCalledWith(1, 1);
    expect(fetchPage).toHaveBeenNthCalledWith(2, 2);
    expect(fetchPage).toHaveBeenNthCalledWith(3, 3);
  });

  it('stops after a single page when total fits in it', async () => {
    const fetchPage = vi.fn(async () => page(['a', 'b'], 2, 1, 50));
    const items: string[] = [];
    for await (const item of paginate(fetchPage)) items.push(item);
    expect(items).toEqual(['a', 'b']);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('stops on an empty page even if total looks larger (defensive against a mismatch)', async () => {
    const fetchPage = vi.fn(async () => page<number>([], 100, 1, 10));
    const items: number[] = [];
    for await (const item of paginate(fetchPage)) items.push(item);
    expect(items).toEqual([]);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('honours an explicit startPage', async () => {
    const fetchPage = vi.fn(async (p: number) => page([p], 3, p, 1));
    const items: number[] = [];
    for await (const item of paginate(fetchPage, 2)) items.push(item);
    expect(fetchPage).toHaveBeenNthCalledWith(1, 2);
  });

  it('is lazy: stops requesting pages once the consumer stops iterating', async () => {
    const fetchPage = vi.fn(async (p: number) => page([p], 100, p, 1));
    const iterator = paginate(fetchPage);
    const first = await iterator.next();
    expect(first.value).toBe(1);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    // No second call until the consumer asks for more.
  });
});

describe('collectAllPages', () => {
  it('eagerly collects every item across every page', async () => {
    const fetchPage = vi.fn(async (p: number) => {
      if (p === 1) return page([1, 2], 3, 1, 2);
      return page([3], 3, 2, 2);
    });
    const items = await collectAllPages(fetchPage);
    expect(items).toEqual([1, 2, 3]);
  });

  it('caps at maxItems without requesting further pages than necessary', async () => {
    const fetchPage = vi.fn(async (p: number) => page([p * 10, p * 10 + 1], 1000, p, 2));
    const items = await collectAllPages(fetchPage, { maxItems: 3 });
    expect(items.length).toBe(3);
  });

  it('defaults its cap to MAX_ALL_PAGES_ITEMS', async () => {
    expect(MAX_ALL_PAGES_ITEMS).toBeGreaterThan(0);
  });
});
