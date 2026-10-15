-- A21-T5: how often each menu item is opened, per day, so administrators
-- see the items nobody uses.
CREATE TABLE IF NOT EXISTS menu_item_use (
    menu_id uuid NOT NULL,
    item text NOT NULL CHECK (char_length(item) BETWEEN 1 AND 300),
    day date NOT NULL,
    opens integer NOT NULL DEFAULT 0,
    PRIMARY KEY (menu_id, item, day)
);

GRANT SELECT, INSERT, UPDATE ON menu_item_use TO attome_runtime;
GRANT SELECT ON menu_item_use TO attome_readonly;
