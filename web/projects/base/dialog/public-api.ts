/*
 * @attome/base/dialog — the confirm/prompt/error dialog service, its types and
 * the host component that renders it (NGB-5.1b, D-760). The host is also the
 * library's accessibility reference for a modal (NGB-3.1/3.2).
 */
export { DialogService, ConfirmService } from './dialog.service';
export { DialogHostComponent }           from './dialog-host.component';
export type { ConfirmOptions, PromptOptions, ErrorDialogOptions, DialogState } from './dialog.types';
