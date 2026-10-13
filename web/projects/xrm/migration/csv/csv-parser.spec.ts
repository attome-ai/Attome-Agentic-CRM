import { describe, expect, it } from 'vitest';
import { decodeCsvBytes, MAX_IMPORT_ROWS, parseCsv, sniffDelimiter } from './csv-parser';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('parseCsv (RFC 4180)', () => {
  it('reads quoted fields, escaped quotes and a multiline cell', () => {
    const text = 'name,notes,city\r\n"Smith, Jane","She said ""hi""\r\nand left",Riyadh\r\nBob,,Jeddah\r\n';
    const p = parseCsv(text);
    expect(p.delimiter).toBe(',');
    expect(p.headers).toEqual(['name', 'notes', 'city']);
    expect(p.rows).toEqual([
      ['Smith, Jane', 'She said "hi"\r\nand left', 'Riyadh'],
      ['Bob', '', 'Jeddah'],
    ]);
    // The multiline cell is one spreadsheet row: the second data row is row 3.
    expect(p.rowNumbers).toEqual([2, 3]);
    expect(p.ragged).toEqual([]);
  });

  it('sniffs and reads a semicolon file whose cells contain commas', () => {
    const text = 'name;amount;note\n"A";1,5;"x, y"\nB;2,25;z\n';
    expect(sniffDelimiter(text)).toBe(';');
    const p = parseCsv(text);
    expect(p.delimiter).toBe(';');
    expect(p.rows).toEqual([
      ['A', '1,5', 'x, y'],
      ['B', '2,25', 'z'],
    ]);
  });

  it('sniffs a tab-separated file', () => {
    expect(sniffDelimiter('a\tb\tc\n1\t2\t3\n')).toBe('\t');
  });

  it('honours an explicit delimiter over sniffing', () => {
    expect(parseCsv('a;b,c\n1;2,3\n', { delimiter: ',' }).headers).toEqual(['a;b', 'c']);
  });

  it('reports ragged rows with their spreadsheet row numbers', () => {
    const p = parseCsv('a,b,c\n1,2,3\n4,5\n\n6,7,8,9\n');
    expect(p.rows.length).toBe(3);
    expect(p.ragged).toEqual([
      { index: 1, rowNumber: 3, expected: 3, actual: 2 },
      // Row 4 is the blank line: skipped but still counted.
      { index: 2, rowNumber: 5, expected: 3, actual: 4 },
    ]);
  });

  it('reads the last record without a trailing newline, and a trailing empty cell', () => {
    expect(parseCsv('a,b\n1,').rows).toEqual([['1', '']]);
  });

  it('names blank headers and de-duplicates repeated ones', () => {
    expect(parseCsv(' Name ,,Name\n1,2,3\n').headers).toEqual(['Name', 'Column 2', 'Name (2)']);
  });

  it('flags a quote that is never closed', () => {
    const p = parseCsv('a,b\n1,"open\n2,3\n');
    expect(p.unterminatedQuoteRow).toBe(2);
  });

  it('keeps a quote that does not open a field as a literal character', () => {
    expect(parseCsv('a,b\n5" pipe,x\n').rows).toEqual([['5" pipe', 'x']]);
  });

  it('stops at the row cap and says so', () => {
    const lines = ['h'];
    for (let i = 0; i < 12; i++) lines.push(String(i));
    const over = parseCsv(lines.join('\n'), { maxRows: 10 });
    expect(over.tooManyRows).toBe(true);
    expect(over.rows.length).toBe(10);
    const exact = parseCsv(lines.slice(0, 11).join('\n'), { maxRows: 10 });
    expect(exact.tooManyRows).toBe(false);
    expect(exact.rows.length).toBe(10);
    expect(MAX_IMPORT_ROWS).toBe(50_000);
  });

  it('parses a 10,000-row file with a quoted multiline cell', () => {
    const lines = ['id,text'];
    for (let i = 0; i < 10_000; i++) lines.push(i === 5000 ? `${i},"line one\nline two"` : `${i},row ${i}`);
    const p = parseCsv(lines.join('\r\n'));
    expect(p.rows.length).toBe(10_000);
    expect(p.rows[5000][1]).toBe('line one\nline two');
    expect(p.ragged).toEqual([]);
  });
});

describe('decodeCsvBytes', () => {
  it('strips a UTF-8 BOM', () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...utf8('name\nأحمد\n')]);
    const d = decodeCsvBytes(bytes);
    expect(d).toMatchObject({ encoding: 'utf-8', bom: true });
    expect(parseCsv(d.text).headers).toEqual(['name']);
    expect(parseCsv(d.text).rows).toEqual([['أحمد']]);
  });

  it('reads UTF-16LE with a BOM', () => {
    const text = 'a,b\n1,2\n';
    const bytes = new Uint8Array(2 + text.length * 2);
    bytes[0] = 0xff;
    bytes[1] = 0xfe;
    for (let i = 0; i < text.length; i++) bytes[2 + i * 2] = text.charCodeAt(i);
    const d = decodeCsvBytes(bytes);
    expect(d.encoding).toBe('utf-16le');
    expect(d.text).toBe(text);
  });

  it('reads plain UTF-8 without a BOM', () => {
    expect(decodeCsvBytes(utf8('الاسم\n'))).toMatchObject({ encoding: 'utf-8', bom: false, text: 'الاسم\n' });
  });

  it('falls back to Windows-1256 for an Arabic Excel export', () => {
    // "name,الاسم\r\n1,محمد\r\n" as Windows-1256 bytes.
    const bytes = new Uint8Array([
      ...utf8('name,'), 0xc7, 0xe1, 0xc7, 0xd3, 0xe3, 0x0d, 0x0a,
      ...utf8('1,'), 0xe3, 0xcd, 0xe3, 0xcf, 0x0d, 0x0a,
    ]);
    const d = decodeCsvBytes(bytes);
    expect(d.encoding).toBe('windows-1256');
    const p = parseCsv(d.text);
    expect(p.headers).toEqual(['name', 'الاسم']);
    expect(p.rows).toEqual([['1', 'محمد']]);
  });

  it('falls back to Windows-1252 for a Western ANSI export', () => {
    // "café;naïve" in Windows-1252.
    const bytes = new Uint8Array([...utf8('caf'), 0xe9, 0x3b, ...utf8('na'), 0xef, ...utf8('ve\n')]);
    const d = decodeCsvBytes(bytes);
    expect(d.encoding).toBe('windows-1252');
    expect(d.text).toBe('café;naïve\n');
  });

  it('uses a forced encoding', () => {
    expect(decodeCsvBytes(new Uint8Array([0xc7]), 'windows-1256').text).toBe('ا');
  });
});
