import { inject, Injectable } from '@angular/core';
import { HttpClient, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

// Mirrors the wire shapes of crates/engine/attome-api/src/files.rs's
// upload-session/finalize/status/download-url handlers (P-file-upload-pipeline, D-144).

export interface UploadSessionRequest {
  filename: string;
  content_type: string;
  declared_size_bytes: number;
  checksum_sha256?: string | null;
}

export interface UploadSessionResponse {
  session_id: string;
  upload_url: string;
  expires_in_secs: number;
}

export interface FinalizeResponse {
  session_id: string;
  status: 'uploaded' | 'rejected';
}

// `status` also takes the transient 'pending'/'scanning' values while the
// async scan job (files_scan.rs) hasn't settled it yet — callers poll until
// it reaches 'clean' or 'rejected'.
export interface SessionStatusResponse {
  status: string;
  reject_reason: string | null;
  actual_size_bytes: number | null;
  actual_content_type: string | null;
  final_key: string | null;
}

// Z6-T2 / AB7-T6: a multipart upload (crates/engine/attome-document/src/
// multipart_routes.rs). The status lists the parts that arrived, so a client
// interrupted mid-way sends only the missing ones.
export interface MultipartStarted {
  session_id: string;
  part_size:  number;
  part_count: number;
}

export interface PartUpload {
  part:            number;
  upload_url:      string;
  expires_in_secs: number;
}

export interface MultipartStatus {
  session_id: string;
  status:     'open' | 'assembled' | 'aborted' | string;
  part_size:  number;
  part_count: number;
  received:   number[];
}

export interface MultipartAssembled {
  session_id:      string;
  size:            number;
  checksum_sha256: string;
}

export interface DownloadUrlResponse {
  download_url: string;
  expires_in_secs: number;
}

// M55 P2 (U18) — file version history, straight from the generated contract
// (`crates/engine/attome-document/src/files.rs`'s version routes).
export type FileVersion = ApiComponents['schemas']['FileVersionResponse'];
export type FileVersionPage = ApiComponents['schemas']['PaginatedResponse_FileVersionResponse'];
export type RestoreVersionResponse = ApiComponents['schemas']['RestoreVersionResponse'];

/** Which object `getDownloadUrl` resolves: the live value (default), one key
 * of a multi-file field, or one recorded version. */
export interface DownloadTarget {
  key?:     string;
  version?: number;
}

@Injectable({ providedIn: 'root' })
export class FileUploadService {
  private readonly api  = inject(ApiService);
  private readonly http = inject(HttpClient);

  createSession(
    entityName: string,
    recordId:   string,
    fieldName:  string,
    req:        UploadSessionRequest,
  ): Observable<UploadSessionResponse> {
    return this.api.post<UploadSessionResponse>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/upload-session`,
      req,
    );
  }

  // Goes straight to the object store's own presigned URL, never through
  // ApiService: it targets a different origin than this app's API and must
  // not carry `withCredentials`/an extra unsigned header — the presign only
  // signs (method, path, expiry) (attome-storage/src/presign.rs), so anything
  // this client adds beyond the raw PUT body is outside what was signed.
  //
  // Staying uncredentialed is not this method's to enforce: `authInterceptor`
  // sees every HttpClient request and used to clone `withCredentials: true`
  // onto all of them, which made the browser reject RustFS's wildcard CORS
  // response and failed every upload at the preflight. It now exempts
  // non-app origins (`isAppRequest`) — keep that exemption if either side
  // moves.
  putToStorage(uploadUrl: string, file: File): Observable<HttpEvent<unknown>> {
    return this.http.request('PUT', uploadUrl, {
      body: file,
      reportProgress: true,
      observe: 'events',
    });
  }

  // ── Multipart uploads (Z6-T2, AB7-T6) ────────────────────────────────────

  startMultipart(
    entityName: string,
    recordId:   string,
    fieldName:  string,
    req:        UploadSessionRequest,
  ): Observable<MultipartStarted> {
    return this.api.post<MultipartStarted>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/multipart`,
      req,
    );
  }

  /** A presigned PUT for part `n` (1-based). */
  partUrl(sessionId: string, n: number): Observable<PartUpload> {
    return this.api.put<PartUpload>(`/api/v1/files/uploads/${sessionId}/parts/${n}`, {});
  }

  /** The upload's state and the parts that arrived — ask before resuming. */
  multipartStatus(sessionId: string): Observable<MultipartStatus> {
    return this.api.get<MultipartStatus>(`/api/v1/files/uploads/${sessionId}`);
  }

  completeMultipart(sessionId: string): Observable<MultipartAssembled> {
    return this.api.post<MultipartAssembled>(`/api/v1/files/uploads/${sessionId}/complete`, {});
  }

  /** Same uncredentialed presigned PUT as {@link putToStorage}, for one part. */
  putPart(uploadUrl: string, part: Blob): Observable<HttpEvent<unknown>> {
    return this.http.request('PUT', uploadUrl, {
      body: part,
      reportProgress: true,
      observe: 'events',
    });
  }

  finalize(
    entityName: string,
    recordId:   string,
    fieldName:  string,
    sessionId:  string,
  ): Observable<FinalizeResponse> {
    return this.api.post<FinalizeResponse>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/upload-session/${sessionId}/finalize`,
      {},
    );
  }

  getStatus(
    entityName: string,
    recordId:   string,
    fieldName:  string,
    sessionId:  string,
  ): Observable<SessionStatusResponse> {
    return this.api.get<SessionStatusResponse>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/upload-session/${sessionId}`,
    );
  }

  /**
   * `key` is required for a multi-file field (the field no longer names a
   * single object) and ignored for a single-file one — mirrors
   * `files.rs::get_download_url`'s own `?key=` contract. Passing
   * `{ version }` instead resolves one recorded version (`?version=N`, which
   * the server lets take precedence over `key`).
   */
  getDownloadUrl(
    entityName: string,
    recordId:   string,
    fieldName:  string,
    target?:    string | DownloadTarget,
  ): Observable<DownloadUrlResponse> {
    const { key, version } = typeof target === 'string' ? { key: target, version: undefined } : (target ?? {});
    const params: string[] = [];
    if (version !== undefined && version !== null) params.push(`version=${encodeURIComponent(String(version))}`);
    else if (key) params.push(`key=${encodeURIComponent(key)}`);
    const suffix = params.length ? `?${params.join('&')}` : '';
    return this.api.get<DownloadUrlResponse>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/download-url${suffix}`,
    );
  }

  // ── Version history (M55 P2, U18) ────────────────────────────────────────
  // All three are authorized by record access server-side (Read for the
  // list, Update for restore/purge) — nothing here decides who may act.

  /** Every version recorded for this field, newest first, in one page. */
  listVersions(entityName: string, recordId: string, fieldName: string): Observable<FileVersionPage> {
    return this.api.get<FileVersionPage>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/versions`,
    );
  }

  /** Makes a prior version current again and writes its key back to the
   * record's field (which bumps the record's `row_version`). 409 when the
   * version is already current or another version change is in flight. */
  restoreVersion(
    entityName: string, recordId: string, fieldName: string, versionNo: number,
  ): Observable<RestoreVersionResponse> {
    return this.api.post<RestoreVersionResponse>(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/versions/${versionNo}/restore`,
      {},
    );
  }

  /** Permanently removes a non-current version. 409 when it is current,
   * under legal hold or inside its retention period. */
  purgeVersion(
    entityName: string, recordId: string, fieldName: string, versionNo: number,
  ): Observable<void> {
    return this.api.delete(
      `/api/v1/${entityName}/${recordId}/files/${fieldName}/versions/${versionNo}`,
    );
  }
}
