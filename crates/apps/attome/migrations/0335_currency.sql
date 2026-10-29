-- A19-T1: the currencies a money amount may carry, with the number of
-- decimals an amount in each is rounded to on write (ISO 4217 minor units:
-- KWD, BHD, OMR 3; JPY 0). Infrastructure data, seeded here and read by the
-- record write path (attome_records::money); a money attribute `x` keeps its
-- code in the companion attribute `x_currency`. Readable by attome_readonly:
-- it holds no customer data.
CREATE TABLE IF NOT EXISTS currency (
    code char(3) PRIMARY KEY CHECK (code ~ '^[A-Z]{3}$'),
    decimals smallint NOT NULL CHECK (decimals BETWEEN 0 AND 4),
    symbol text NOT NULL,
    name text NOT NULL
);

INSERT INTO currency (code, decimals, symbol, name) VALUES
    ('AED', 2, 'د.إ', 'UAE Dirham'),
    ('AUD', 2, 'A$', 'Australian Dollar'),
    ('BHD', 3, '.د.ب', 'Bahraini Dinar'),
    ('BRL', 2, 'R$', 'Brazilian Real'),
    ('CAD', 2, 'CA$', 'Canadian Dollar'),
    ('CHF', 2, 'CHF', 'Swiss Franc'),
    ('CLP', 0, 'CLP$', 'Chilean Peso'),
    ('CNY', 2, '¥', 'Chinese Yuan'),
    ('DKK', 2, 'kr', 'Danish Krone'),
    ('DZD', 2, 'د.ج', 'Algerian Dinar'),
    ('EGP', 2, 'ج.م', 'Egyptian Pound'),
    ('EUR', 2, '€', 'Euro'),
    ('GBP', 2, '£', 'Pound Sterling'),
    ('HKD', 2, 'HK$', 'Hong Kong Dollar'),
    ('IDR', 2, 'Rp', 'Indonesian Rupiah'),
    ('INR', 2, '₹', 'Indian Rupee'),
    ('IQD', 3, 'ع.د', 'Iraqi Dinar'),
    ('ISK', 0, 'kr', 'Icelandic Króna'),
    ('JOD', 3, 'د.ا', 'Jordanian Dinar'),
    ('JPY', 0, '¥', 'Japanese Yen'),
    ('KRW', 0, '₩', 'South Korean Won'),
    ('KWD', 3, 'د.ك', 'Kuwaiti Dinar'),
    ('LBP', 2, 'ل.ل', 'Lebanese Pound'),
    ('LYD', 3, 'ل.د', 'Libyan Dinar'),
    ('MAD', 2, 'د.م.', 'Moroccan Dirham'),
    ('MXN', 2, 'MX$', 'Mexican Peso'),
    ('MYR', 2, 'RM', 'Malaysian Ringgit'),
    ('NOK', 2, 'kr', 'Norwegian Krone'),
    ('NZD', 2, 'NZ$', 'New Zealand Dollar'),
    ('OMR', 3, 'ر.ع.', 'Omani Rial'),
    ('PKR', 2, '₨', 'Pakistani Rupee'),
    ('PHP', 2, '₱', 'Philippine Peso'),
    ('PLN', 2, 'zł', 'Polish Złoty'),
    ('QAR', 2, 'ر.ق', 'Qatari Riyal'),
    ('SAR', 2, 'ر.س', 'Saudi Riyal'),
    ('SEK', 2, 'kr', 'Swedish Krona'),
    ('SGD', 2, 'S$', 'Singapore Dollar'),
    ('THB', 2, '฿', 'Thai Baht'),
    ('TND', 3, 'د.ت', 'Tunisian Dinar'),
    ('TRY', 2, '₺', 'Turkish Lira'),
    ('UGX', 0, 'USh', 'Ugandan Shilling'),
    ('USD', 2, '$', 'US Dollar'),
    ('VND', 0, '₫', 'Vietnamese Dong'),
    ('ZAR', 2, 'R', 'South African Rand')
ON CONFLICT (code) DO NOTHING;

GRANT SELECT ON currency TO attome_runtime;
GRANT SELECT ON currency TO attome_readonly;
