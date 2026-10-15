-- B20-T3: a deployment rewords built-in interface text. An override is a
-- label of kind `ui_text`, keyed by the built-in text's catalogue key.
ALTER TABLE metadata_label DROP CONSTRAINT IF EXISTS metadata_label_object_kind_check;
ALTER TABLE metadata_label ADD CONSTRAINT metadata_label_object_kind_check CHECK (
    object_kind = ANY (ARRAY['entity', 'attribute', 'choice_option', 'view', 'sidebar', 'dashboard', 'ui_text'])
);
