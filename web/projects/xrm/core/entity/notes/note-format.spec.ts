import { describe, expect, it } from 'vitest';

import { applyMark, isPreviewable, renderNoteText } from './note-format';

describe('note formatting (B3-T2)', () => {
  it('escapes markup before formatting the marks', () => {
    expect(renderNoteText('<img src=x onerror=alert(1)> **ok**')).toBe('&lt;img src=x onerror=alert(1)&gt; <strong>ok</strong>');
  });

  it('formats bold, italic, code, lists, quotes, links and mentions', () => {
    const html = renderNoteText('Call _today_ about `PO-7`\n- first\n- second\n> quoted\nsee https://example.com/a. @[user:42]');
    expect(html).toContain('<em>today</em>');
    expect(html).toContain('<code>PO-7</code>');
    expect(html).toContain('<ul><li>first</li><li>second</li></ul>');
    expect(html).toContain('<blockquote>quoted</blockquote>');
    expect(html).toContain('<a href="https://example.com/a" target="_blank" rel="noopener noreferrer">https://example.com/a</a>.');
    expect(html).toContain('<span class="xnp-mention xnp-mention-user" title="42">@user</span>');
    expect(renderNoteText('snake_case_name stays')).toBe('snake_case_name stays');
    expect(renderNoteText(null)).toBe('');
  });

  it('puts a mark around the selection or at the start of each line', () => {
    expect(applyMark('make this bold', 5, 9, 'bold')).toEqual({ text: 'make **this** bold', start: 7, end: 11 });
    expect(applyMark('one\ntwo', 1, 6, 'list').text).toBe('- one\n- two');
    expect(applyMark('- one', 0, 5, 'list').text).toBe('- one');
  });

  it('shows images as thumbnails', () => {
    expect(isPreviewable({ type: 'image/png', name: 'a.png' })).toBe(true);
    expect(isPreviewable({ type: 'application/pdf', name: 'a.pdf' })).toBe(false);
    expect(isPreviewable({ name: 'photo.JPG' })).toBe(true);
  });
});
