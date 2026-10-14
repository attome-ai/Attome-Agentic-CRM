/**
 * AG1-T8 — Umm al-Qura Hijri dates in the browser, from the same table the
 * server embeds (`attome_calendar::hijri`, 1356 to 1500 AH), so a date
 * entered here and grouped there land on the same day. Not `Intl`'s
 * `islamic-umalqura`: browsers' ICU agrees with the published calendar only
 * for 1420 to 1450 AH and differs by a day elsewhere (1 Muharram 1400 was
 * 20 November 1979; ICU says the 21st).
 */

/** A Hijri date; `month` is 1 (Muharram) to 12 (Dhu al-Hijjah). */
export interface HijriParts {
  year: number;
  month: number;
  day: number;
}

export const HIJRI_FIRST_YEAR = 1356;
export const HIJRI_LAST_YEAR = 1500;

/** 1 Muharram of each year from 1356, as days since 1970-01-01. */
const YEAR_STARTS: readonly number[] = [
  -11982, -11627, -11273, -10919, -10565, -10211, -9856, -9501, -9147, -8793, -8439, -8085,
  -7730, -7376, -7021, -6666, -6312, -5958, -5604, -5250, -4895, -4540, -4186, -3831, -3477,
  -3123, -2769, -2414, -2060, -1705, -1351, -997, -643, -288, 66, 421, 776, 1130, 1484, 1838,
  2192, 2547, 2901, 3256, 3610, 3964, 4318, 4673, 5027, 5382, 5736, 6091, 6445, 6799, 7153,
  7508, 7862, 8217, 8572, 8926, 9280, 9634, 9988, 10343, 10698, 11053, 11407, 11761, 12115,
  12469, 12824, 13179, 13533, 13888, 14242, 14596, 14950, 15304, 15659, 16013, 16368, 16722,
  17076, 17430, 17785, 18139, 18494, 18848, 19203, 19557, 19911, 20265, 20620, 20975, 21329,
  21683, 22037, 22392, 22746, 23101, 23455, 23810, 24164, 24518, 24872, 25227, 25581, 25936,
  26290, 26645, 26999, 27353, 27707, 28062, 28416, 28771, 29125, 29479, 29833, 30188, 30542,
  30897, 31251, 31606, 31960, 32314, 32668, 33023, 33377, 33732, 34087, 34441, 34795, 35149,
  35503, 35858, 36213, 36567, 36921, 37275, 37629, 37984, 38338, 38693, 39047,
];

/** Per year, bit `m - 1` set when month `m` has 30 days. */
const MONTH_MASKS: readonly number[] = [
  3785, 3474, 3365, 2637, 685, 1389, 2922, 2898, 2725, 2635, 1175, 2359, 694, 1397, 3434, 3410,
  2710, 2349, 605, 1245, 2778, 1492, 3497, 3410, 2730, 1238, 2486, 884, 1897, 1874, 1701, 1355,
  2731, 1370, 2773, 3538, 3492, 3401, 2709, 1325, 2653, 1370, 2773, 1706, 1685, 1323, 2647,
  1198, 2422, 1388, 2901, 2730, 2645, 1197, 2397, 730, 1497, 3506, 2980, 2890, 2645, 693, 1397,
  2922, 3026, 3012, 2953, 2709, 1325, 1453, 2922, 1748, 3529, 3474, 2726, 2390, 686, 1389, 874,
  2901, 2730, 2381, 1181, 2397, 698, 1461, 1450, 3413, 2714, 2350, 622, 1373, 2778, 1748, 1701,
  1355, 2711, 1358, 2734, 1452, 2985, 3474, 2853, 1611, 3243, 1370, 2901, 1746, 3749, 3658,
  2709, 1325, 2733, 876, 1881, 1746, 1685, 1325, 2651, 1210, 2490, 948, 2921, 2898, 2726, 1206,
  2413, 748, 1753, 3762, 3412, 3370, 2646, 1198, 2413, 3434, 2900, 2857, 2707, 1323, 2647,
  1334, 2741, 1706, 3731,
];

export const HIJRI_MONTHS_EN = [
  'Muharram', 'Safar', 'Rabi al-Awwal', 'Rabi al-Thani', 'Jumada al-Ula', 'Jumada al-Akhirah',
  'Rajab', 'Shaban', 'Ramadan', 'Shawwal', 'Dhu al-Qadah', 'Dhu al-Hijjah',
] as const;

export const HIJRI_MONTHS_AR = [
  'محرم', 'صفر', 'ربيع الأول', 'ربيع الآخر', 'جمادى الأولى', 'جمادى الآخرة',
  'رجب', 'شعبان', 'رمضان', 'شوال', 'ذو القعدة', 'ذو الحجة',
] as const;

/** A month's name in `lang` (`ar`, or anything else for English). */
export function hijriMonthName(month: number, lang: string): string {
  const names = lang === 'ar' ? HIJRI_MONTHS_AR : HIJRI_MONTHS_EN;
  return names[month - 1] ?? '';
}

const DAY_MS = 86_400_000;

function monthLength(yearIndex: number, month: number): number {
  return (MONTH_MASKS[yearIndex] >> (month - 1)) & 1 ? 30 : 29;
}

function dayNumber(iso: string): number | null {
  const time = Date.parse(`${iso.slice(0, 10)}T00:00:00Z`);
  return Number.isNaN(time) ? null : Math.round(time / DAY_MS);
}

/** The Hijri date of a Gregorian day (`yyyy-mm-dd`), or null outside the table. */
export function toHijri(iso: string): HijriParts | null {
  const day = dayNumber(iso);
  if (day === null || day < YEAR_STARTS[0]) return null;
  // The last year starting on or before `day`.
  let lo = 0;
  let hi = YEAR_STARTS.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (YEAR_STARTS[mid] <= day) lo = mid; else hi = mid - 1;
  }
  let offset = day - YEAR_STARTS[lo];
  for (let month = 1; month <= 12; month++) {
    const length = monthLength(lo, month);
    if (offset < length) return { year: HIJRI_FIRST_YEAR + lo, month, day: offset + 1 };
    offset -= length;
  }
  return null; // past the last year of the table
}

/** The Gregorian day (`yyyy-mm-dd`) of a Hijri date, or null when it does not exist. */
export function fromHijri(hijri: HijriParts): string | null {
  const { year, month, day } = hijri;
  const yearIndex = year - HIJRI_FIRST_YEAR;
  if (!Number.isInteger(yearIndex) || yearIndex < 0 || yearIndex >= YEAR_STARTS.length) return null;
  if (!Number.isInteger(month) || month < 1 || month > 12) return null;
  if (!Number.isInteger(day) || day < 1 || day > monthLength(yearIndex, month)) return null;
  let days = YEAR_STARTS[yearIndex];
  for (let m = 1; m < month; m++) days += monthLength(yearIndex, m);
  return new Date((days + day - 1) * DAY_MS).toISOString().slice(0, 10);
}

/** `1 Ramadan 1447 AH` / `١ رمضان ١٤٤٧ هـ`, with `arab` digits when asked. */
export function formatHijri(hijri: HijriParts, lang: string, digits: 'latn' | 'arab' | null): string {
  const arabic = lang === 'ar';
  const text = `${hijri.day} ${hijriMonthName(hijri.month, lang)} ${hijri.year} ${arabic ? 'هـ' : 'AH'}`;
  const useArab = digits === 'arab' || (digits === null && arabic);
  return useArab ? text.replace(/[0-9]/g, d => String.fromCharCode(0x0660 + Number(d))) : text;
}
