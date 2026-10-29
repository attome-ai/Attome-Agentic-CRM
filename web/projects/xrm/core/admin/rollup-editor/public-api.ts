// A10-T6: the rollup field editor, its own entry point so the entity editor
// loads it without the rule screens (D-314).
export {
  BACKFILL_BATCH, ROLLUP_FUNCTIONS, RollupEditorComponent, backfillRuns, exactAllowed, fits, resultType,
} from './rollup-editor.component';
export type { RollupFunction } from './rollup-editor.component';
