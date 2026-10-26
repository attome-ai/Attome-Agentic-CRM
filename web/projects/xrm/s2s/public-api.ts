export { S2sAdminService }            from './services/s2s-admin.service';
export { S2sClientListComponent }     from './clients/clients.component';
export { S2sClientEditorComponent }   from './s2s-client/editor/s2s-client-editor/s2s-client-editor.component';
export type {
  ClientListItem, ClientDetail, KeySummary, PermissionItem,
  AccessLogItem, AccessLogPage, KeyCreatedResponse,
  CreateClientBody, UpdateClientBody, GenerateKeyBody, SetPermissionBody,
  TrustItem, CreateTrustBody, S2sEnvironment, S2sMethod,
} from './services/s2s-admin.service';
export { S2S_ENVIRONMENTS } from './services/s2s-admin.service';

// Hand-coded forms (moving off the generic metadata-driven EntityFormComponent
// for the platform's own built-in entities — see xrm/audit and xrm/notification
// for the established pattern).
export { registerS2sEntityForms } from './provide-s2s-entity-forms';
