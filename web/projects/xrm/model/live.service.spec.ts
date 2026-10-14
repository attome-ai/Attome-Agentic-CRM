import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { LiveService } from './live.service';
import { ModelService } from './model.service';

describe('LiveService (Y14-T3)', () => {
  let model: { forgetPlans: ReturnType<typeof vi.fn> };
  let live: LiveService;

  beforeEach(() => {
    model = { forgetPlans: vi.fn() };
    TestBed.configureTestingModule({
      providers: [
        { provide: ModelService, useValue: model },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: '' } },
      ],
    });
    live = TestBed.inject(LiveService);
  });

  it('remembers the first version without dropping plans', () => {
    live.receive('{"model_version":"a/1"}');
    expect(live.modelVersion()).toBe('a/1');
    expect(model.forgetPlans).not.toHaveBeenCalled();
  });

  it('drops cached plans when the version changes', () => {
    live.receive('{"model_version":"a/1"}');
    live.receive('{"model_version":"b/2"}');
    expect(model.forgetPlans).toHaveBeenCalledTimes(1);
    expect(live.modelVersion()).toBe('b/2');
    live.receive('{"model_version":"b/2"}');
    expect(model.forgetPlans).toHaveBeenCalledTimes(1);
  });

  it('ignores a malformed frame', () => {
    live.receive('not json');
    live.receive('{"other":1}');
    expect(live.modelVersion()).toBeNull();
  });
});
