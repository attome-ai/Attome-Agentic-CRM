import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { DialogService, ConfirmService } from './dialog.service';

describe('DialogService', () => {
  let service: DialogService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [DialogService, ConfirmService],
    });
    service = TestBed.inject(DialogService);
  });

  it('initializes with null state', () => {
    expect(service.state()).toBeNull();
  });

  it('opens and confirms a confirmation dialog', async () => {
    const promise = service.confirm({
      title: 'Confirm Delete',
      message: 'Are you sure?',
      variant: 'danger',
    });

    const state = service.state();
    expect(state).not.toBeNull();
    expect(state?.kind).toBe('confirm');
    if (state?.kind === 'confirm') {
      expect(state.options.title).toBe('Confirm Delete');
      expect(state.options.variant).toBe('danger');
      state.resolve(true);
    }

    const result = await promise;
    expect(result).toBe(true);
    expect(service.state()).toBeNull();
  });

  it('opens and cancels a confirmation dialog', async () => {
    const promise = service.confirm({
      message: 'Proceed?',
    });

    const state = service.state();
    expect(state?.kind).toBe('confirm');
    service.close();

    const result = await promise;
    expect(result).toBe(false);
    expect(service.state()).toBeNull();
  });

  it('opens and resolves a prompt dialog with stem selection option', async () => {
    const promise = service.prompt({
      title: 'Rename document',
      value: 'report.final.pdf',
      selectStem: true,
    });

    const state = service.state();
    expect(state?.kind).toBe('prompt');
    if (state?.kind === 'prompt') {
      expect(state.options.selectStem).toBe(true);
      expect(state.options.value).toBe('report.final.pdf');
      state.resolve('annual_report.pdf');
    }

    const result = await promise;
    expect(result).toBe('annual_report.pdf');
    expect(service.state()).toBeNull();
  });

  it('opens and resolves an error dialog', async () => {
    const promise = service.error({
      title: 'Failed',
      message: 'Network error occurred',
    });

    const state = service.state();
    expect(state?.kind).toBe('error');
    if (state?.kind === 'error') {
      expect(state.options.title).toBe('Failed');
      expect(state.options.message).toBe('Network error occurred');
      state.resolve();
    }

    await promise;
    expect(service.state()).toBeNull();
  });

  it('accepts a string message for error dialog', async () => {
    const promise = service.error('Simple error string');

    const state = service.state();
    expect(state?.kind).toBe('error');
    if (state?.kind === 'error') {
      expect(state.options.message).toBe('Simple error string');
      state.resolve();
    }

    await promise;
    expect(service.state()).toBeNull();
  });

  // NGB-P.2, flipped by NGB-1.7. `confirm`/`prompt`/`error` used to overwrite
  // `stateSignal` without settling the promise they displaced, so a guarded
  // action that awaited the first dialog waited forever.
  it('NGB-F14 a displaced confirm resolves false', async () => {
    const first = service.confirm({ message: 'first' });
    let firstSettled: boolean | undefined;
    void first.then(r => { firstSettled = r; });

    const second = service.confirm({ message: 'second' });
    service.close(); // cancels the *second* dialog
    expect(await second).toBe(false);

    await new Promise(resolve => setTimeout(resolve, 0));
    expect(firstSettled).toBe(false);
  });

  it('NGB-F14 a displaced prompt resolves null', async () => {
    const first = service.prompt({ title: 'first' });
    let firstSettled: string | null | undefined;
    void first.then(r => { firstSettled = r; });

    service.prompt({ title: 'second' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(firstSettled).toBeNull();
  });

  it('NGB-F14 a displaced error dialog resolves', async () => {
    let firstSettled = false;
    void service.error({ message: 'first' }).then(() => { firstSettled = true; });

    service.error({ message: 'second' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(firstSettled).toBe(true);
  });

  it('NGB-F14 opening a dialog does not settle the one that is already current', async () => {
    const only = service.confirm({ message: 'only' });
    let settled = false;
    void only.then(() => { settled = true; });
    expect(service.state()?.kind).toBe('confirm');

    await new Promise(resolve => setTimeout(resolve, 0));
    expect(settled).toBe(false);
    service.close();
    expect(await only).toBe(false);
  });

  it('ConfirmService alias resolves through the one dialog state', async () => {
    const confirmSvc = TestBed.inject(ConfirmService);

    const cPromise = confirmSvc.confirm({ message: 'Confirm via alias' });
    const state = service.state();
    expect(state?.kind).toBe('confirm');
    service.close();
    await expect(cPromise).resolves.toBe(false);
    expect(service.state()).toBeNull();
  });
});
