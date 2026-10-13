import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

/** A record was changed on the server by something other than the form's own
 * save — e.g. a file version restore, which writes the field and bumps the
 * record's `row_version` behind the form's back. */
export interface RecordChange {
  entityName: string;
  recordId:   string;
  /** The fields that changed; the form re-reads only these. */
  fields:     string[];
}

/**
 * U18 — lets a field widget tell the form that hosts it that the record moved
 * on the server. `EngineFormBase` listens and re-GETs the record so its next save
 * carries the new `row_version` (otherwise it would 409 as an edit conflict)
 * and the changed fields show the server's value.
 *
 * In-process and page-local by design: it only ever connects a widget to the
 * form in the same view, never another tab or node (those learn about the
 * change through the ordinary `row_version` conflict path).
 */
@Injectable({ providedIn: 'root' })
export class RecordChangeNotifier {
  private readonly subject = new Subject<RecordChange>();

  readonly changes: Observable<RecordChange> = this.subject.asObservable();

  notify(change: RecordChange): void {
    this.subject.next(change);
  }
}
