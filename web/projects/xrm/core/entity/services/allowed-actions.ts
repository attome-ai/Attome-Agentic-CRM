/**
 * Q10-T11: whether a screen offers `action`, from the schema's
 * `allowed_actions`. Unknown (no schema yet, or a server that does not send
 * it) offers it, and the API still decides.
 */
export function actionAllowed(allowed: readonly string[] | null | undefined, action: string): boolean {
  return allowed == null || allowed.includes(action);
}
