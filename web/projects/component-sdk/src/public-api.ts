// Public API surface of @attome/component-sdk (roadmap T3-T1): the `attome`
// object a custom component is given by its host page.
export { createAttome, ComponentSdkError, MAX_PAGE_SIZE } from './lib/attome';
export type {
  Attome,
  ComponentContext,
  ComponentRecord,
  HostRequestOptions,
  HostTransport,
  ListOptions,
  RecordPage,
} from './lib/attome';
