import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { SpeechService } from '@attome/base/native';

import { CopilotLauncherComponent } from './copilot-launcher.component';

async function render(available: boolean, heard: string | null): Promise<ComponentFixture<CopilotLauncherComponent>> {
  await TestBed.configureTestingModule({
    imports: [CopilotLauncherComponent],
    providers: [
      {
        provide: SpeechService,
        useValue: { available: () => available, listen: vi.fn(async () => heard) },
      },
      {
        provide: LangService,
        useValue: { translate: (key: string) => key, current: signal('ar'), isRtl: signal(true) },
      },
    ],
  }).compileComponents();
  const fixture = TestBed.createComponent(CopilotLauncherComponent);
  fixture.detectChanges();
  return fixture;
}

describe('CopilotLauncherComponent (B17-T10)', () => {
  it('transcript sent as chat turn', async () => {
    const fixture = await render(true, 'سجل مكالمة مع الفيصل');
    const component = fixture.componentInstance;
    const ask = vi.spyOn(component, 'ask').mockResolvedValue(undefined);
    const speech = TestBed.inject(SpeechService) as unknown as { listen: ReturnType<typeof vi.fn> };

    (fixture.nativeElement.querySelector('[data-testid="copilot-speak"]') as HTMLButtonElement).click();
    await vi.waitFor(() => expect(component.transcript()).toBe('سجل مكالمة مع الفيصل'));
    expect(speech.listen).toHaveBeenCalledWith('ar');
    fixture.detectChanges();

    const box = fixture.nativeElement.querySelector('[data-testid="copilot-transcript"]') as HTMLTextAreaElement;
    box.value = 'سجل مكالمة مع الفيصل، يريدون عرض سعر الأسبوع القادم';
    (fixture.nativeElement.querySelector('[data-testid="copilot-transcript-send"]') as HTMLButtonElement).click();
    await vi.waitFor(() => expect(ask).toHaveBeenCalledWith('سجل مكالمة مع الفيصل، يريدون عرض سعر الأسبوع القادم'));
    expect(component.transcript()).toBeNull();
  });

  it('button hidden without engine', async () => {
    TestBed.resetTestingModule();
    const fixture = await render(false, null);
    expect(fixture.nativeElement.querySelector('[data-testid="copilot-speak"]')).toBeNull();
  });
});
