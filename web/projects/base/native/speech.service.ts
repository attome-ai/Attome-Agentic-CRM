import { Injectable } from '@angular/core';

/** The parts of the shell's speech recognition plugin the service uses. */
interface SpeechPlugin {
  available(): Promise<{ available: boolean }>;
  requestPermissions?(): Promise<unknown>;
  start(options: Record<string, unknown>): Promise<{ matches?: string[] }>;
}

/** The parts of the browser's Web Speech API the service uses. */
interface WebRecognition {
  lang: string;
  interimResults: boolean;
  maxAlternatives: number;
  onresult: ((event: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
  start(): void;
}
type WebRecognitionConstructor = new () => WebRecognition;

/** The recognition language for an app language. Pure. */
export function speechLanguage(lang: string): 'ar-SA' | 'en-US' {
  return lang.startsWith('ar') ? 'ar-SA' : 'en-US';
}

/**
 * B17-T10 — speech to text for the assistant: the shell's
 * `SpeechRecognition` plugin on a phone (through the native bridge, as
 * `NativeService`), the browser's Web Speech API elsewhere, nothing when
 * neither is there. Arabic is recognised as `ar-SA`, English as `en-US`.
 */
@Injectable({ providedIn: 'root' })
export class SpeechService {
  protected plugin(): SpeechPlugin | undefined {
    const bridge = (globalThis as {
      Capacitor?: { isNativePlatform?: () => boolean; Plugins?: { SpeechRecognition?: SpeechPlugin } };
    }).Capacitor;
    return bridge?.isNativePlatform?.() ? bridge.Plugins?.SpeechRecognition : undefined;
  }

  protected webRecognition(): WebRecognitionConstructor | undefined {
    const g = globalThis as { SpeechRecognition?: WebRecognitionConstructor; webkitSpeechRecognition?: WebRecognitionConstructor };
    return g.SpeechRecognition ?? g.webkitSpeechRecognition;
  }

  /** Whether any speech engine is there. */
  available(): boolean {
    return !!this.plugin() || !!this.webRecognition();
  }

  /** One spoken request as text, or `null` when nothing was understood. */
  async listen(lang: string): Promise<string | null> {
    const language = speechLanguage(lang);
    const plugin = this.plugin();
    if (plugin) {
      try {
        const { available } = await plugin.available();
        if (!available) return null;
        await plugin.requestPermissions?.();
        const result = await plugin.start({ language, maxResults: 1, partialResults: false, popup: true });
        return result.matches?.[0]?.trim() || null;
      } catch {
        return null;
      }
    }
    const Recognition = this.webRecognition();
    if (!Recognition) return null;
    return new Promise(resolve => {
      const recognition = new Recognition();
      let heard: string | null = null;
      recognition.lang = language;
      recognition.interimResults = false;
      recognition.maxAlternatives = 1;
      recognition.onresult = event => {
        heard = event.results[0]?.[0]?.transcript?.trim() || null;
      };
      recognition.onerror = () => resolve(null);
      recognition.onend = () => resolve(heard);
      recognition.start();
    });
  }
}
