import { describe, expect, it } from 'vitest';
import { AuthModalService } from './auth-modal.service';

describe('AuthModalService', () => {
  it('starts closed', () => {
    expect(new AuthModalService().isOpen()).toBe(false);
  });

  it('open() / close() toggle the signal', () => {
    const svc = new AuthModalService();
    svc.open();
    expect(svc.isOpen()).toBe(true);
    svc.close();
    expect(svc.isOpen()).toBe(false);
  });
});
