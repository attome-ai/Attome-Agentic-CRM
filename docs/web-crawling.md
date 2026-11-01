# Web crawling into knowledge

A website becomes a knowledge source: the crawler (`crates/engine/attome-webcrawl`) walks the site,
keeps each page's text, and imports the pages into knowledge items (`knowledge_data_item`) under a
knowledge data source, where search and agents read them under the source's audience. Crawling is
off until `webcrawl.enabled` is set in the configuration; reading sources and pages works either way.

## Who manages sources

Administrators of the Integrations area, and knowledge managers: install the **Knowledge manager**
role template (`POST /api/v1/admin/security/role-templates/knowledge_manager/install`), which may
read and change knowledge data sources and items. Two settings stay with administrators: the intranet
host a source may reach and the credential it signs in with.

## A source and its settings

`POST /api/v1/webcrawl/targets` adds a source (or recrawls one already added for the same address);
`PATCH /api/v1/webcrawl/targets/{id}` changes its settings with the source's `row_version` as
`If-Match` (a stale one is `409 version_conflict`). The settings:

| Setting | Values | What it does |
|---|---|---|
| `include_patterns`, `exclude_patterns` | one path pattern per line, `*` any text, `?` one character | Which paths are crawled; empty includes everything. |
| `languages` | `ar`, `en` | Pages declaring another language are not imported; empty keeps every language, and a page that declares none is kept. |
| `audience` | `internal`, `partner`, `customer` | Who may read what the source imports. |
| `import_mode` | `review`, `automatic` | A person picks pages to import, or every new page is imported after each crawl. |
| `schedule` | `manual`, `daily`, `weekly` | Recrawl by hand or on a schedule. |
| `sitemap_url` | a URL on the same site | Seeds the crawl with the sitemap's pages. |
| `watch_only` | true or false | Report changes only; import nothing. |
| `max_depth` | 1 to 20 | How many links deep the crawl follows. |
| `allow_host` | one host name (administrators) | The one intranet host this source may reach. |
| `credential_ref` | an integration connection (administrators) | Signs the crawl's requests to the source's own host. |

The web app's website page list shows these settings in the source's panel, with its runs and the
changes waiting for review, in Arabic and English.

## A crawl

A crawl follows only the source's own site and its patterns, honours `robots.txt` and its crawl
delay, waits between requests to a host, and asks for each known page conditionally (ETag,
Last-Modified), so an unchanged page costs one short request; a page whose text hash did not change
is not touched. It keeps a page's main content: the `<main>` or `<article>` block, or the block
holding the most text, without navigation, headers, footers, side panels and cookie banners, with
headings, lists, tables and Arabic text kept; a page with no such block keeps its visible text. The
page's declared language is recorded and shown on the page list.

Every fetch is checked against private addresses: a private, loopback, link-local or metadata
address is refused before the request and again at connection time, redirects are never followed
blindly (each hop is checked again), and credentials never follow a redirect off the source's
host. One named intranet host per source is the only exception.

Linked PDF, Word and Excel files in scope are fetched by their own job (at most 20 MB, conditional
on their ETag), stored as documents through the upload pipeline's virus scan, and imported like
pages once their text is read.

Each crawl is a run (`GET /api/v1/webcrawl/targets/{id}/runs`): when it started and ended, how it
ended, the pages it recorded, and the items the sync after it imported, updated or flagged.

Scheduled sources are checked every hour; a source whose last crawl is older than its period is
queued, and one already pending or crawling is skipped. `POST /api/v1/webcrawl/targets/{id}/recrawl`
crawls by hand.

## From pages to knowledge

`review` sources: pick pages on the page list (`PATCH .../pages/selection`) and import them
(`POST .../import`). `automatic` sources import their new pages after every crawl.

After every crawl, a page whose text changed updates its knowledge item as the item's next
`version`. An item someone published from a `review` source keeps its text and is marked
`needs_review` instead; the source's changes to review (`GET /api/v1/webcrawl/targets/{id}/changes`)
list them, and the panel offers **Take the site's version** (import the page again) or **Keep ours**
(clear the flag). A page with the same text as an imported page becomes its alias rather than a
second item. A page missing from two complete crawls in a row has its item retired (`expired`: no
longer cited; the item and its history stay).

A `watch_only` source imports nothing. When a watched page's text changes, the change feed carries a
`webcrawl.page_changed` event with the lines added and removed (at most 50 each way), for flows and
notifications to act on.

## Agents

Two read-only tools: `webcrawl.propose_scope` proposes include and exclude patterns from the pages a
crawl found (main sections in; tags, search, sign-in and feeds out) for a person to put on the
source, and `webcrawl.summarise_changes` says in a few lines what one run changed. No tool starts a
crawl or opens an intranet host.

## Configuration

| Key | Default | What it does |
|---|---|---|
| `webcrawl.enabled` | false | Lets crawls start (adding, recrawling, schedules). |
| `webcrawl.max_depth` | 6 | The depth a new source gets when none is given. |
| `webcrawl.max_pages` | see `config.example.json` | The most pages one crawl records. |
| `webcrawl.max_page_bytes` | see `config.example.json` | The largest page body read. |
| `webcrawl.request_timeout_secs` | see `config.example.json` | Each request's timeout. |
