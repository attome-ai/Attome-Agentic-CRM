# Data enrichment

Enrichment asks outside sources about an account and turns each answer into a proposal, never a
write: an empty field gets a `fill` proposal, a field holding another value a `review` proposal a
person decides, and each proposal names its source and when it was fetched. Each provider has a
daily call budget, and an account already matched to another by its work-email domain is skipped
before any call is spent.

## Free sources

Three sources cost nothing per call (`attome_sales::enrichment::free_sources`); each call is
bounded to ten seconds:

| Source | Asked by | Proposes |
|---|---|---|
| `registry` | the account's `cr_number`, at the Saudi commercial register (Wathq) | `legal_name_ar`, `legal_name_en`, `cr_number`, `phone`, `website`, `hq_address`, `founded_year` |
| `national_address` | the account's `hq_address` (its short address when it holds one, else the text), at SPL's National Address | `hq_address`, standardised |
| `website` | the account's `website`: its home page only, and only when its `robots.txt` allows `/` | `logo_url` (`og:image`, else the organisation's logo), and from a schema.org organisation in JSON-LD `phone`, `hq_address` and `social_links` (`sameAs`, one per line) |

The website is fetched through the crawler's SSRF-safe client, so a private or internal address
is never read, and no AI model is called. The register's status and activities are not proposed:
the account has no field for the status, and the ISIC list the activities would map to is not
shipped yet.
