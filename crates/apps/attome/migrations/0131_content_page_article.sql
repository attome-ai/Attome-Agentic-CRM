-- G11-T1: knowledge articles as a content page type. An `article` page names
-- the knowledge data source it is filed under (its permission anchor), a
-- category and products; publishing it projects it into one
-- `knowledge_data_item` record (`knowledge_item_id`), written as
-- `knowledge_author`, which the knowledge index chunks for retrieval.
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS page_type text NOT NULL DEFAULT 'page';
ALTER TABLE content_page DROP CONSTRAINT IF EXISTS content_page_page_type_check;
ALTER TABLE content_page ADD CONSTRAINT content_page_page_type_check
    CHECK (page_type = ANY (ARRAY['page', 'article']));
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS knowledge_source_id uuid;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS article_category text;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS article_products text[] NOT NULL DEFAULT ARRAY[]::text[];
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS knowledge_author uuid;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS knowledge_item_id uuid;
