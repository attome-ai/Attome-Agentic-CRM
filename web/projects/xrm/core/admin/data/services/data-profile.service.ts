import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

/**
 * M12 / L6 data profiles — `GET /api/v1/admin/data/profile` (one-based,
 * newest first) over `crates/engine/attome-api/src/data_profile_admin.rs`.
 * A holder of `metadata.read` sees the profiles of entities they may read,
 * without the attributes field security hides (L6-T6).
 */
export type DataProfileRow = ApiComponents['schemas']['DataProfileRow'];

/** One field's statistics in a profile's `fields` list (`scan.rs`'s `finish`). */
export interface FieldProfile {
  field: string;
  rows: number;
  null_pct: number;
  nulls: number;
  blanks: number;
  distinct_count: number;
  distinct_is_lower_bound: boolean;
  /** Masked to shapes when the field carries a sensitive label. */
  top_values: { value: string; count: number }[];
  masked: boolean;
  number?: {
    min: number; max: number; mean: number; median: number;
    percentiles: { p5: number; p25: number; p75: number; p95: number };
    histogram: { from: number; bucket_width: number; counts: number[] };
    outliers: number;
  };
  length?: { min: number; max: number; mean: number; median: number };
  min?: string | null;
  max?: string | null;
  date_range?: { earliest?: string | null; latest?: string | null };
  patterns?: {
    values: number;
    top_shapes: { shape: string; count: number; share_pct: number }[];
    format_match_pct?: number | null;
    arabic: {
      script: { arabic: number; latin: number; mixed: number };
      digits: { eastern: number; western: number };
      with_diacritics: number;
      dates: { hijri: number; gregorian: number };
      name_parts?: Record<string, number>;
    };
  };
}

/** The fields of a profile row, typed. */
export function profileFields(row: DataProfileRow): FieldProfile[] {
  return Array.isArray(row.fields) ? (row.fields as FieldProfile[]) : [];
}

/** The share of rows with a value (neither null nor blank), 0–100. Pure. */
export function fillRate(field: FieldProfile): number {
  if (field.rows <= 0) return 0;
  return Math.max(0, Math.min(100, ((field.rows - field.nulls - field.blanks) * 100) / field.rows));
}

/** Fill rate per field name. Pure. */
export function fillRates(row: DataProfileRow | null): Map<string, number> {
  return new Map(row ? profileFields(row).map(f => [f.field, fillRate(f)]) : []);
}

/** The newest completed profiles looked at for one entity. */
const LATEST_WINDOW = 10;

@Injectable({ providedIn: 'root' })
export class DataProfileService {
  private readonly api = inject(ApiService);

  list(entity: string | undefined, page = 1, pageSize = 50): Observable<Page<DataProfileRow>> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (entity) params['entity'] = entity;
    return this.api.get<Page<DataProfileRow>>('/api/v1/admin/data/profile', params);
  }

  /** The entity's newest completed profile of its own records (not of a
   * staged import), or `null` when it has none yet. */
  latest(entity: string): Observable<DataProfileRow | null> {
    return this.list(entity, 1, LATEST_WINDOW).pipe(
      map(page => page.items.find(p => p.status === 'completed' && !p.import_job_ref) ?? null),
    );
  }
}
