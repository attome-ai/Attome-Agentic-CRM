import { describe, expect, it } from 'vitest';

import { renderCode } from './code-render';

describe('renderCode (B16-T11)', () => {
  it('renders qr svg', async () => {
    const svg = await renderCode('qr', 'https://crm.example.com/r/contact/0192f0a0-0000-7000-8000-000000000001');
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('viewBox');
  });

  it('renders the linear codes and refuses text a symbology cannot hold', async () => {
    expect(await renderCode('ean13', '4006381333931')).toContain('<svg');
    expect(await renderCode('code128', 'LOT-7')).toContain('<svg');
    expect(await renderCode('datamatrix', 'A1')).toContain('<svg');
    await expect(renderCode('ean13', '12')).rejects.toThrow();
  });
});
