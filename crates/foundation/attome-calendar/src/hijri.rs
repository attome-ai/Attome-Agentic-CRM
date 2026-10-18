//! The Umm al-Qura Hijri calendar (roadmap AG1-T1): the official calendar of
//! Saudi Arabia, from 1 Muharram 1356 AH (1937-03-13) to the end of 1500 AH
//! (2077-11-16).
//!
//! Umm al-Qura is a published table, not a formula: each month has 29 or 30
//! days as the table says, so this module embeds it rather than using the
//! arithmetic (tabular) Hijri calendar, which disagrees with it on many days.
//! Each year's row is the Gregorian day of 1 Muharram, as days since
//! 1970-01-01, and a 12-bit mask whose bit `m - 1` is set when month `m` has
//! 30 days.
//!
//! Source: the Umm al-Qura month starts published by the Saudi calendar
//! authority (King Abdulaziz City for Science and Technology), as compiled by
//! R. H. van Gent and shipped in .NET's `System.Globalization.UmAlQuraCalendar`,
//! from which these rows were generated. Checked against 1 Muharram 1447 =
//! 2025-06-26, 1 Ramadan 1447 = 2026-02-18 and 1 Shawwal 1446 = 2025-03-30.
//!
//! A month start announced differently after a moon sighting is an override
//! ([`HijriCalendar::with_overrides`]); the free functions use the published
//! table.

use std::sync::OnceLock;

use chrono::{Datelike, Days, NaiveDate};

use crate::CalendarError;

/// The first Hijri year the table covers.
pub const FIRST_YEAR: u16 = 1356;
/// The last Hijri year the table covers.
pub const LAST_YEAR: u16 = 1500;

/// `(hijri_year, 1 Muharram as days since 1970-01-01, 30-day month mask)`.
const UMM_AL_QURA: [(u16, i32, u16); 145] = [
    (1356, -11982, 0b111011001001), // 1 Muharram 1356 = 1937-03-13
    (1357, -11627, 0b110110010010), // 1 Muharram 1357 = 1938-03-03
    (1358, -11273, 0b110100100101), // 1 Muharram 1358 = 1939-02-20
    (1359, -10919, 0b101001001101), // 1 Muharram 1359 = 1940-02-09
    (1360, -10565, 0b001010101101), // 1 Muharram 1360 = 1941-01-28
    (1361, -10211, 0b010101101101), // 1 Muharram 1361 = 1942-01-17
    (1362, -9856, 0b101101101010),  // 1 Muharram 1362 = 1943-01-07
    (1363, -9501, 0b101101010010),  // 1 Muharram 1363 = 1943-12-28
    (1364, -9147, 0b101010100101),  // 1 Muharram 1364 = 1944-12-16
    (1365, -8793, 0b101001001011),  // 1 Muharram 1365 = 1945-12-05
    (1366, -8439, 0b010010010111),  // 1 Muharram 1366 = 1946-11-24
    (1367, -8085, 0b100100110111),  // 1 Muharram 1367 = 1947-11-13
    (1368, -7730, 0b001010110110),  // 1 Muharram 1368 = 1948-11-02
    (1369, -7376, 0b010101110101),  // 1 Muharram 1369 = 1949-10-22
    (1370, -7021, 0b110101101010),  // 1 Muharram 1370 = 1950-10-12
    (1371, -6666, 0b110101010010),  // 1 Muharram 1371 = 1951-10-02
    (1372, -6312, 0b101010010110),  // 1 Muharram 1372 = 1952-09-20
    (1373, -5958, 0b100100101101),  // 1 Muharram 1373 = 1953-09-09
    (1374, -5604, 0b001001011101),  // 1 Muharram 1374 = 1954-08-29
    (1375, -5250, 0b010011011101),  // 1 Muharram 1375 = 1955-08-18
    (1376, -4895, 0b101011011010),  // 1 Muharram 1376 = 1956-08-07
    (1377, -4540, 0b010111010100),  // 1 Muharram 1377 = 1957-07-28
    (1378, -4186, 0b110110101001),  // 1 Muharram 1378 = 1958-07-17
    (1379, -3831, 0b110101010010),  // 1 Muharram 1379 = 1959-07-07
    (1380, -3477, 0b101010101010),  // 1 Muharram 1380 = 1960-06-25
    (1381, -3123, 0b010011010110),  // 1 Muharram 1381 = 1961-06-14
    (1382, -2769, 0b100110110110),  // 1 Muharram 1382 = 1962-06-03
    (1383, -2414, 0b001101110100),  // 1 Muharram 1383 = 1963-05-24
    (1384, -2060, 0b011101101001),  // 1 Muharram 1384 = 1964-05-12
    (1385, -1705, 0b011101010010),  // 1 Muharram 1385 = 1965-05-02
    (1386, -1351, 0b011010100101),  // 1 Muharram 1386 = 1966-04-21
    (1387, -997, 0b010101001011),   // 1 Muharram 1387 = 1967-04-10
    (1388, -643, 0b101010101011),   // 1 Muharram 1388 = 1968-03-29
    (1389, -288, 0b010101011010),   // 1 Muharram 1389 = 1969-03-19
    (1390, 66, 0b101011010101),     // 1 Muharram 1390 = 1970-03-08
    (1391, 421, 0b110111010010),    // 1 Muharram 1391 = 1971-02-26
    (1392, 776, 0b110110100100),    // 1 Muharram 1392 = 1972-02-16
    (1393, 1130, 0b110101001001),   // 1 Muharram 1393 = 1973-02-04
    (1394, 1484, 0b101010010101),   // 1 Muharram 1394 = 1974-01-24
    (1395, 1838, 0b010100101101),   // 1 Muharram 1395 = 1975-01-13
    (1396, 2192, 0b101001011101),   // 1 Muharram 1396 = 1976-01-02
    (1397, 2547, 0b010101011010),   // 1 Muharram 1397 = 1976-12-22
    (1398, 2901, 0b101011010101),   // 1 Muharram 1398 = 1977-12-11
    (1399, 3256, 0b011010101010),   // 1 Muharram 1399 = 1978-12-01
    (1400, 3610, 0b011010010101),   // 1 Muharram 1400 = 1979-11-20
    (1401, 3964, 0b010100101011),   // 1 Muharram 1401 = 1980-11-08
    (1402, 4318, 0b101001010111),   // 1 Muharram 1402 = 1981-10-28
    (1403, 4673, 0b010010101110),   // 1 Muharram 1403 = 1982-10-18
    (1404, 5027, 0b100101110110),   // 1 Muharram 1404 = 1983-10-07
    (1405, 5382, 0b010101101100),   // 1 Muharram 1405 = 1984-09-26
    (1406, 5736, 0b101101010101),   // 1 Muharram 1406 = 1985-09-15
    (1407, 6091, 0b101010101010),   // 1 Muharram 1407 = 1986-09-05
    (1408, 6445, 0b101001010101),   // 1 Muharram 1408 = 1987-08-25
    (1409, 6799, 0b010010101101),   // 1 Muharram 1409 = 1988-08-13
    (1410, 7153, 0b100101011101),   // 1 Muharram 1410 = 1989-08-02
    (1411, 7508, 0b001011011010),   // 1 Muharram 1411 = 1990-07-23
    (1412, 7862, 0b010111011001),   // 1 Muharram 1412 = 1991-07-12
    (1413, 8217, 0b110110110010),   // 1 Muharram 1413 = 1992-07-01
    (1414, 8572, 0b101110100100),   // 1 Muharram 1414 = 1993-06-21
    (1415, 8926, 0b101101001010),   // 1 Muharram 1415 = 1994-06-10
    (1416, 9280, 0b101001010101),   // 1 Muharram 1416 = 1995-05-30
    (1417, 9634, 0b001010110101),   // 1 Muharram 1417 = 1996-05-18
    (1418, 9988, 0b010101110101),   // 1 Muharram 1418 = 1997-05-07
    (1419, 10343, 0b101101101010),  // 1 Muharram 1419 = 1998-04-27
    (1420, 10698, 0b101111010010),  // 1 Muharram 1420 = 1999-04-17
    (1421, 11053, 0b101111000100),  // 1 Muharram 1421 = 2000-04-06
    (1422, 11407, 0b101110001001),  // 1 Muharram 1422 = 2001-03-26
    (1423, 11761, 0b101010010101),  // 1 Muharram 1423 = 2002-03-15
    (1424, 12115, 0b010100101101),  // 1 Muharram 1424 = 2003-03-04
    (1425, 12469, 0b010110101101),  // 1 Muharram 1425 = 2004-02-21
    (1426, 12824, 0b101101101010),  // 1 Muharram 1426 = 2005-02-10
    (1427, 13179, 0b011011010100),  // 1 Muharram 1427 = 2006-01-31
    (1428, 13533, 0b110111001001),  // 1 Muharram 1428 = 2007-01-20
    (1429, 13888, 0b110110010010),  // 1 Muharram 1429 = 2008-01-10
    (1430, 14242, 0b101010100110),  // 1 Muharram 1430 = 2008-12-29
    (1431, 14596, 0b100101010110),  // 1 Muharram 1431 = 2009-12-18
    (1432, 14950, 0b001010101110),  // 1 Muharram 1432 = 2010-12-07
    (1433, 15304, 0b010101101101),  // 1 Muharram 1433 = 2011-11-26
    (1434, 15659, 0b001101101010),  // 1 Muharram 1434 = 2012-11-15
    (1435, 16013, 0b101101010101),  // 1 Muharram 1435 = 2013-11-04
    (1436, 16368, 0b101010101010),  // 1 Muharram 1436 = 2014-10-25
    (1437, 16722, 0b100101001101),  // 1 Muharram 1437 = 2015-10-14
    (1438, 17076, 0b010010011101),  // 1 Muharram 1438 = 2016-10-02
    (1439, 17430, 0b100101011101),  // 1 Muharram 1439 = 2017-09-21
    (1440, 17785, 0b001010111010),  // 1 Muharram 1440 = 2018-09-11
    (1441, 18139, 0b010110110101),  // 1 Muharram 1441 = 2019-08-31
    (1442, 18494, 0b010110101010),  // 1 Muharram 1442 = 2020-08-20
    (1443, 18848, 0b110101010101),  // 1 Muharram 1443 = 2021-08-09
    (1444, 19203, 0b101010011010),  // 1 Muharram 1444 = 2022-07-30
    (1445, 19557, 0b100100101110),  // 1 Muharram 1445 = 2023-07-19
    (1446, 19911, 0b001001101110),  // 1 Muharram 1446 = 2024-07-07
    (1447, 20265, 0b010101011101),  // 1 Muharram 1447 = 2025-06-26
    (1448, 20620, 0b101011011010),  // 1 Muharram 1448 = 2026-06-16
    (1449, 20975, 0b011011010100),  // 1 Muharram 1449 = 2027-06-06
    (1450, 21329, 0b011010100101),  // 1 Muharram 1450 = 2028-05-25
    (1451, 21683, 0b010101001011),  // 1 Muharram 1451 = 2029-05-14
    (1452, 22037, 0b101010010111),  // 1 Muharram 1452 = 2030-05-03
    (1453, 22392, 0b010101001110),  // 1 Muharram 1453 = 2031-04-23
    (1454, 22746, 0b101010101110),  // 1 Muharram 1454 = 2032-04-11
    (1455, 23101, 0b010110101100),  // 1 Muharram 1455 = 2033-04-01
    (1456, 23455, 0b101110101001),  // 1 Muharram 1456 = 2034-03-21
    (1457, 23810, 0b110110010010),  // 1 Muharram 1457 = 2035-03-11
    (1458, 24164, 0b101100100101),  // 1 Muharram 1458 = 2036-02-28
    (1459, 24518, 0b011001001011),  // 1 Muharram 1459 = 2037-02-16
    (1460, 24872, 0b110010101011),  // 1 Muharram 1460 = 2038-02-05
    (1461, 25227, 0b010101011010),  // 1 Muharram 1461 = 2039-01-26
    (1462, 25581, 0b101101010101),  // 1 Muharram 1462 = 2040-01-15
    (1463, 25936, 0b011011010010),  // 1 Muharram 1463 = 2041-01-04
    (1464, 26290, 0b111010100101),  // 1 Muharram 1464 = 2041-12-24
    (1465, 26645, 0b111001001010),  // 1 Muharram 1465 = 2042-12-14
    (1466, 26999, 0b101010010101),  // 1 Muharram 1466 = 2043-12-03
    (1467, 27353, 0b010100101101),  // 1 Muharram 1467 = 2044-11-21
    (1468, 27707, 0b101010101101),  // 1 Muharram 1468 = 2045-11-10
    (1469, 28062, 0b001101101100),  // 1 Muharram 1469 = 2046-10-31
    (1470, 28416, 0b011101011001),  // 1 Muharram 1470 = 2047-10-20
    (1471, 28771, 0b011011010010),  // 1 Muharram 1471 = 2048-10-09
    (1472, 29125, 0b011010010101),  // 1 Muharram 1472 = 2049-09-28
    (1473, 29479, 0b010100101101),  // 1 Muharram 1473 = 2050-09-17
    (1474, 29833, 0b101001011011),  // 1 Muharram 1474 = 2051-09-06
    (1475, 30188, 0b010010111010),  // 1 Muharram 1475 = 2052-08-26
    (1476, 30542, 0b100110111010),  // 1 Muharram 1476 = 2053-08-15
    (1477, 30897, 0b001110110100),  // 1 Muharram 1477 = 2054-08-05
    (1478, 31251, 0b101101101001),  // 1 Muharram 1478 = 2055-07-25
    (1479, 31606, 0b101101010010),  // 1 Muharram 1479 = 2056-07-14
    (1480, 31960, 0b101010100110),  // 1 Muharram 1480 = 2057-07-03
    (1481, 32314, 0b010010110110),  // 1 Muharram 1481 = 2058-06-22
    (1482, 32668, 0b100101101101),  // 1 Muharram 1482 = 2059-06-11
    (1483, 33023, 0b001011101100),  // 1 Muharram 1483 = 2060-05-31
    (1484, 33377, 0b011011011001),  // 1 Muharram 1484 = 2061-05-20
    (1485, 33732, 0b111010110010),  // 1 Muharram 1485 = 2062-05-10
    (1486, 34087, 0b110101010100),  // 1 Muharram 1486 = 2063-04-30
    (1487, 34441, 0b110100101010),  // 1 Muharram 1487 = 2064-04-18
    (1488, 34795, 0b101001010110),  // 1 Muharram 1488 = 2065-04-07
    (1489, 35149, 0b010010101110),  // 1 Muharram 1489 = 2066-03-27
    (1490, 35503, 0b100101101101),  // 1 Muharram 1490 = 2067-03-16
    (1491, 35858, 0b110101101010),  // 1 Muharram 1491 = 2068-03-05
    (1492, 36213, 0b101101010100),  // 1 Muharram 1492 = 2069-02-23
    (1493, 36567, 0b101100101001),  // 1 Muharram 1493 = 2070-02-12
    (1494, 36921, 0b101010010011),  // 1 Muharram 1494 = 2071-02-01
    (1495, 37275, 0b010100101011),  // 1 Muharram 1495 = 2072-01-21
    (1496, 37629, 0b101001010111),  // 1 Muharram 1496 = 2073-01-09
    (1497, 37984, 0b010100110110),  // 1 Muharram 1497 = 2073-12-30
    (1498, 38338, 0b101010110101),  // 1 Muharram 1498 = 2074-12-19
    (1499, 38693, 0b011010101010),  // 1 Muharram 1499 = 2075-12-09
    (1500, 39047, 0b111010010011),  // 1 Muharram 1500 = 2076-11-27
];

/// A day in the Hijri calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HijriDate {
    pub year: u16,
    /// 1 (Muharram) to 12 (Dhu al-Hijjah).
    pub month: u8,
    /// 1 to 29 or 30.
    pub day: u8,
}

impl HijriDate {
    pub const fn new(year: u16, month: u8, day: u8) -> Self {
        Self { year, month, day }
    }
}

impl std::fmt::Display for HijriDate {
    /// `1447-09-01`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// A Hijri calendar: the Umm al-Qura table, possibly with sighting
/// corrections applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HijriCalendar {
    /// The first day of every month from 1 Muharram [`FIRST_YEAR`], as days
    /// since 1970-01-01, then the day after the last month ends.
    starts: Vec<i32>,
}

impl HijriCalendar {
    /// The published Umm al-Qura table.
    pub fn umm_al_qura() -> &'static HijriCalendar {
        static TABLE: OnceLock<HijriCalendar> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut starts = Vec::with_capacity(UMM_AL_QURA.len() * 12 + 1);
            let mut day = UMM_AL_QURA[0].1;
            for &(_, first, mask) in &UMM_AL_QURA {
                debug_assert_eq!(day, first, "the table's years are contiguous");
                day = first;
                for month in 0..12 {
                    starts.push(day);
                    day += if mask & (1 << month) != 0 { 30 } else { 29 };
                }
            }
            starts.push(day);
            HijriCalendar { starts }
        })
    }

    /// The published table with each `(year, month, gregorian_start)`
    /// moved: the month starts that day, and the month before it ends the
    /// day before. A move must keep every month 29 or 30 days long.
    pub fn with_overrides(overrides: &[(u16, u8, NaiveDate)]) -> Result<Self, CalendarError> {
        let mut calendar = Self::umm_al_qura().clone();
        for &(year, month, start) in overrides {
            let index = month_index(year, month)?;
            if index == 0 {
                return Err(CalendarError::InvalidCalendar(
                    "the first month of the table cannot be moved".into(),
                ));
            }
            calendar.starts[index] = day_number(start);
        }
        for pair in calendar.starts.windows(2) {
            let length = pair[1] - pair[0];
            if !(29..=30).contains(&length) {
                return Err(CalendarError::InvalidCalendar(
                    "a corrected month must have 29 or 30 days".into(),
                ));
            }
        }
        Ok(calendar)
    }

    /// The Hijri date of a Gregorian day.
    pub fn to_hijri(&self, date: NaiveDate) -> Result<HijriDate, CalendarError> {
        let day = day_number(date);
        let last = self.starts.len() - 1;
        if day < self.starts[0] || day >= self.starts[last] {
            return Err(CalendarError::OutOfHijriRange);
        }
        // The month whose start is the last one on or before `day`.
        let index = self.starts[..last].partition_point(|&start| start <= day) - 1;
        let year =
            FIRST_YEAR + u16::try_from(index / 12).map_err(|_| CalendarError::OutOfHijriRange)?;
        let month = u8::try_from(index % 12 + 1).map_err(|_| CalendarError::OutOfHijriRange)?;
        let offset = u8::try_from(day - self.starts[index] + 1)
            .map_err(|_| CalendarError::OutOfHijriRange)?;
        Ok(HijriDate::new(year, month, offset))
    }

    /// The Gregorian day of a Hijri date; a day past the month's end is an
    /// error.
    pub fn to_gregorian(&self, date: HijriDate) -> Result<NaiveDate, CalendarError> {
        let index = month_index(date.year, date.month)?;
        let length = self.starts[index + 1] - self.starts[index];
        if date.day == 0 || i32::from(date.day) > length {
            return Err(CalendarError::InvalidCalendar(format!(
                "{date} does not exist: the month has {length} days"
            )));
        }
        from_day_number(self.starts[index] + i32::from(date.day) - 1)
    }

    /// A month's first day and the day after its last.
    pub fn month_bounds(
        &self,
        year: u16,
        month: u8,
    ) -> Result<(NaiveDate, NaiveDate), CalendarError> {
        let index = month_index(year, month)?;
        Ok((
            from_day_number(self.starts[index])?,
            from_day_number(self.starts[index + 1])?,
        ))
    }

    /// A year's 1 Muharram and the day after its last day.
    pub fn year_bounds(&self, year: u16) -> Result<(NaiveDate, NaiveDate), CalendarError> {
        let first = month_index(year, 1)?;
        Ok((
            from_day_number(self.starts[first])?,
            from_day_number(self.starts[first + 12])?,
        ))
    }

    /// The number of days in a month: 29 or 30.
    pub fn month_length(&self, year: u16, month: u8) -> Result<u8, CalendarError> {
        let index = month_index(year, month)?;
        u8::try_from(self.starts[index + 1] - self.starts[index])
            .map_err(|_| CalendarError::OutOfHijriRange)
    }
}

/// The Hijri date of a Gregorian day, in the published table.
pub fn to_hijri(date: NaiveDate) -> Result<HijriDate, CalendarError> {
    HijriCalendar::umm_al_qura().to_hijri(date)
}

/// The Gregorian day of a Hijri date, in the published table.
pub fn from_hijri(date: HijriDate) -> Result<NaiveDate, CalendarError> {
    HijriCalendar::umm_al_qura().to_gregorian(date)
}

/// A month's first day and the day after its last, in the published table.
pub fn month_bounds(year: u16, month: u8) -> Result<(NaiveDate, NaiveDate), CalendarError> {
    HijriCalendar::umm_al_qura().month_bounds(year, month)
}

/// A year's 1 Muharram and the day after its last day, in the published table.
pub fn year_bounds(year: u16) -> Result<(NaiveDate, NaiveDate), CalendarError> {
    HijriCalendar::umm_al_qura().year_bounds(year)
}

/// A month's length, 29 or 30 days, in the published table (Z12-T1).
pub fn month_length(year: u16, month: u8) -> Result<u8, CalendarError> {
    HijriCalendar::umm_al_qura().month_length(year, month)
}

const MONTHS_AR: [&str; 12] = [
    "محرم",
    "صفر",
    "ربيع الأول",
    "ربيع الآخر",
    "جمادى الأولى",
    "جمادى الآخرة",
    "رجب",
    "شعبان",
    "رمضان",
    "شوال",
    "ذو القعدة",
    "ذو الحجة",
];

const MONTHS_EN: [&str; 12] = [
    "Muharram",
    "Safar",
    "Rabi al-Awwal",
    "Rabi al-Thani",
    "Jumada al-Ula",
    "Jumada al-Akhirah",
    "Rajab",
    "Shaban",
    "Ramadan",
    "Shawwal",
    "Dhu al-Qadah",
    "Dhu al-Hijjah",
];

/// A month's name: Arabic for `lang` "ar", English otherwise. `None` for a
/// month outside 1 to 12.
pub fn month_name(month: u8, lang: &str) -> Option<&'static str> {
    let names = if lang == "ar" { &MONTHS_AR } else { &MONTHS_EN };
    names.get(usize::from(month).checked_sub(1)?).copied()
}

/// Where a month sits in [`HijriCalendar::starts`].
fn month_index(year: u16, month: u8) -> Result<usize, CalendarError> {
    if !(FIRST_YEAR..=LAST_YEAR).contains(&year) || !(1..=12).contains(&month) {
        return Err(CalendarError::OutOfHijriRange);
    }
    Ok(usize::from(year - FIRST_YEAR) * 12 + usize::from(month - 1))
}

fn epoch() -> NaiveDate {
    NaiveDate::from_ymd_opt(1970, 1, 1).unwrap_or(NaiveDate::MIN)
}

fn day_number(date: NaiveDate) -> i32 {
    date.num_days_from_ce() - epoch().num_days_from_ce()
}

fn from_day_number(day: i32) -> Result<NaiveDate, CalendarError> {
    let base = epoch();
    let moved = if day >= 0 {
        base.checked_add_days(Days::new(u64::from(day.unsigned_abs())))
    } else {
        base.checked_sub_days(Days::new(u64::from(day.unsigned_abs())))
    };
    moved.ok_or(CalendarError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn known_dates_round_trip() {
        for (hijri, gregorian) in [
            (HijriDate::new(1447, 9, 1), d(2026, 2, 18)),
            (HijriDate::new(1447, 1, 1), d(2025, 6, 26)),
            (HijriDate::new(1446, 10, 1), d(2025, 3, 30)),
            // Z12-T1's reference dates.
            (HijriDate::new(1446, 9, 1), d(2025, 3, 1)),
            (HijriDate::new(1445, 10, 1), d(2024, 4, 10)),
            (HijriDate::new(1445, 1, 1), d(2023, 7, 19)),
            (HijriDate::new(FIRST_YEAR, 1, 1), d(1937, 3, 13)),
        ] {
            assert_eq!(from_hijri(hijri).unwrap(), gregorian, "{hijri}");
            assert_eq!(to_hijri(gregorian).unwrap(), hijri, "{gregorian}");
        }
    }

    #[test]
    fn every_table_month_round_trips() {
        let mut day = d(1937, 3, 13);
        let (_, end) = year_bounds(LAST_YEAR).unwrap();
        assert_eq!(end, d(2077, 11, 17));
        let mut previous: Option<HijriDate> = None;
        while day < end {
            let hijri = to_hijri(day).unwrap();
            assert_eq!(from_hijri(hijri).unwrap(), day, "{hijri}");
            if let Some(p) = previous {
                let next_day = p.day + 1 == hijri.day && p.month == hijri.month;
                let next_month = hijri.day == 1
                    && ((p.month + 1 == hijri.month && p.year == hijri.year)
                        || (p.month == 12 && hijri.month == 1 && p.year + 1 == hijri.year));
                assert!(next_day || next_month, "{p} then {hijri}");
            }
            previous = Some(hijri);
            day = day.succ_opt().unwrap();
        }
        for year in FIRST_YEAR..=LAST_YEAR {
            for month in 1..=12 {
                let length = month_length(year, month).unwrap();
                assert!((29..=30).contains(&length), "{year}-{month}");
            }
        }
    }

    #[test]
    fn out_of_range_is_error() {
        assert_eq!(
            to_hijri(d(1937, 3, 12)),
            Err(CalendarError::OutOfHijriRange)
        );
        assert_eq!(
            to_hijri(d(2077, 11, 17)),
            Err(CalendarError::OutOfHijriRange)
        );
        assert_eq!(
            from_hijri(HijriDate::new(1355, 12, 1)),
            Err(CalendarError::OutOfHijriRange)
        );
        assert_eq!(
            from_hijri(HijriDate::new(1501, 1, 1)),
            Err(CalendarError::OutOfHijriRange)
        );
        assert_eq!(month_bounds(1447, 13), Err(CalendarError::OutOfHijriRange));
        assert!(from_hijri(HijriDate::new(1447, 1, 31)).is_err());
        assert!(from_hijri(HijriDate::new(1447, 1, 0)).is_err());
    }

    #[test]
    fn month_names_in_both_languages() {
        assert_eq!(month_name(9, "ar"), Some("رمضان"));
        assert_eq!(month_name(9, "en"), Some("Ramadan"));
        assert_eq!(month_name(12, "en"), Some("Dhu al-Hijjah"));
        assert_eq!(month_name(0, "en"), None);
        assert_eq!(month_name(13, "ar"), None);
    }

    #[test]
    fn a_sighting_moves_one_month_start() {
        let table = HijriCalendar::umm_al_qura();
        let length = |m| table.month_length(1447, m).unwrap();
        // A one-day-later start is valid when the month before has 29 days
        // (it becomes 30) and the month itself has 30 (it becomes 29).
        let month = (2..=12)
            .find(|&m| length(m - 1) == 29 && length(m) == 30)
            .expect("1447 has a 29-day month followed by a 30-day one");
        let (start, end) = table.month_bounds(1447, month).unwrap();
        let moved = start.succ_opt().unwrap();
        let corrected = HijriCalendar::with_overrides(&[(1447, month, moved)]).unwrap();
        assert_eq!(corrected.month_bounds(1447, month).unwrap(), (moved, end));
        assert_eq!(
            corrected.to_hijri(start).unwrap(),
            HijriDate::new(1447, month - 1, 30)
        );
        assert_eq!(
            corrected
                .to_gregorian(HijriDate::new(1447, month, 1))
                .unwrap(),
            moved
        );

        // A move that would make a month 31 or 28 days long is refused.
        let two_days = moved.succ_opt().unwrap();
        assert!(HijriCalendar::with_overrides(&[(1447, month, two_days)]).is_err());
        // The table's first month has nothing before it to lengthen.
        assert!(HijriCalendar::with_overrides(&[(FIRST_YEAR, 1, start)]).is_err());
    }
}
