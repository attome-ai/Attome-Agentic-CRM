import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AiAgentFormComponent } from './forms/ai-agent-form/ai-agent-form.component';
import { AiAgentPolicyFormComponent } from './forms/ai-agent-policy-form/ai-agent-policy-form.component';
import { AiCapabilityPackFormComponent } from './forms/ai-capability-pack-form/ai-capability-pack-form.component';
import { AiModelFormComponent } from './forms/ai-model-form/ai-model-form.component';
import { AiPersonalityFormComponent } from './forms/ai-personality-form/ai-personality-form.component';
import { AiProviderFormComponent } from './forms/ai-provider-form/ai-provider-form.component';
import { AiToneFormComponent } from './forms/ai-tone-form/ai-tone-form.component';

// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerAiEntityForms(registry: EntityRouteRegistry): void {
  registry.register('ai_agent', { formComponent: AiAgentFormComponent });
  // C6 (D-556) — the grant surface itself: a policy's ceiling, budgets and
  // grants, and the reusable capability packs a policy may reference. Both are
  // ordinary metadata entities; these forms only give the columns a picker.
  registry.register('ai_agent_policy', { formComponent: AiAgentPolicyFormComponent });
  registry.register('ai_capability_pack', { formComponent: AiCapabilityPackFormComponent });
  registry.register('ai_model', { formComponent: AiModelFormComponent });
  registry.register('ai_personality', { formComponent: AiPersonalityFormComponent });
  registry.register('ai_provider', { formComponent: AiProviderFormComponent });
  registry.register('ai_tone', { formComponent: AiToneFormComponent });
}
