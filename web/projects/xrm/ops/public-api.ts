/*
 * @attome/xrm/ops — the reliability engine's screens (AB4-T1): cluster
 * status and switchover, recovery drills, incidents and upgrades, as the
 * AB2, AB3, AB8, AB9, AB11 and U8 tasks add them. Every one is opt-in
 * (V2-D100): the server mounts the `ops` module's routes only when the
 * module is on.
 *
 * Only the host imports this entry point, lazily (D-314).
 */
export { OPS_ROUTES } from './ops.routes';
