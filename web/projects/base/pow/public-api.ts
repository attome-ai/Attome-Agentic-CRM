/*
 * @attome/base/pow — the browser half of the proof-of-work challenge
 * (Q20-T3). Its own entry point with no Angular in it, so a Web Worker can
 * import it without the rest of @attome/base.
 */
export { leadingZeroBits, solvePow } from './pow';
