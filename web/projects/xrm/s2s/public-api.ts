export { S2sAdminService }            from './services/s2s-admin.service';
export { S2sClientListComponent }     from './s2s-client/list/s2s-client-list/s2s-client-list.component';
export { S2sClientEditorComponent }   from './s2s-client/editor/s2s-client-editor/s2s-client-editor.component';
export type {
  ClientListItem, ClientDetail, KeySummary, PermissionItem,
  AccessLogItem, AccessLogPage, KeyCreatedResponse,
  CreateClientBody, UpdateClientBody, GenerateKeyBody, SetPermissionBody,
} from './services/s2s-admin.service';

// Hand-coded forms (moving off the generic metadata-driven EntityFormComponent
// for the platform's own built-in entities — see xrm/audit and xrm/notification
// for the established pattern).
export { registerS2sEntityForms } from './provide-s2s-entity-forms';
