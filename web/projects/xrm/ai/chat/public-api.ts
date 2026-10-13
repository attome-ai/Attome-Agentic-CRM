// @attome/xrm/ai/chat — the copilot panel (C7, `document/chatbot/04-channels-and-ui.md`).
//
// Its own secondary entry point, loaded by the shell's launcher on first open
// through a dynamic `import()`: a user who never opens the panel never
// downloads it, and a deployment with AI switched off ships none of it to the
// people who never ask. The shell imports only the component's type.
export { CopilotPanelComponent } from './copilot-panel/copilot-panel.component';
export { ChatService } from './services/chat.service';
export type {
  AgentOption,
  CitationView,
  ConfirmResult,
  ConversationDetail,
  Grounding,
  MessageView,
  RecordContext,
  RiskCeiling,
  ToolCallView,
  TurnResponse,
} from './services/chat.service';
export { recordContextFromUrl } from './record-context';
