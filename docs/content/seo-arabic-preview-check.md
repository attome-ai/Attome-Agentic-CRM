# Arabic page paths: the link-preview check

`content.seo_arabic_paths` lets an Arabic translation have an Arabic `url_path` (for example
`/الأسعار`). The server sends such a path percent-encoded (`/%D8%A7%D9%84...`), and the redirect
from an old path does the same (`attome_content::redirect::encode_path`). Whether a shared link
shows its preview card depends on each app's link fetcher, which this repository cannot test.
So the flag stays **off** until a person has run this check and all three apps pass.

## How to run it

1. On a test deployment, switch on `content.seo_arabic_paths` for your own user only
   (a user override on the flag, not the deployment value).
2. Publish an Arabic translation of a public page with an Arabic path, a search title, a
   description and an Open Graph image. Open it in a browser and confirm it renders.
3. Copy the address from the browser bar (the browser shows it decoded; the copy is encoded).
4. Share that address, in a new message or post, in each app below. Wait up to a minute for the
   preview.
5. A pass is: the card shows the page's Arabic title and description, the image, and opening
   the card lands on the page (not a 404, not the home page). Record anything else as a fail,
   with a screenshot.
6. Switch the user override off again.

Run the check again after any change to `encode_path`, the page head (`render_html.rs`), or the
redirect route.

## Results

| App | Date | Deployment | Result | Notes |
|---|---|---|---|---|
| WhatsApp | not run | | pending | |
| X | not run | | pending | |
| LinkedIn | not run | | pending | |

The flag's deployment value stays off while any row is pending or failed. If one fails, record
it here and keep Arabic paths off; the page still works with its Latin path.

The automated part of the E13 checks is `crates/engine/attome-content/tests/seo_e2e.rs`.
