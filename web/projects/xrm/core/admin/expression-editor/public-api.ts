// Z11-T14: the rule-language expression editor, its own entry point so the
// rule screens and the governance screens share it without pulling in each
// other (D-314).
export { ExpressionEditorComponent } from './expression-editor.component';
export {
  dottedPaths, errorKey, indexOfByte, lookupTarget, pathAt, rulesSchemaOf, withPaths, wordAt,
} from './expression-text';
