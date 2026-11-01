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

## Queueing a run, budgets and agent tools

A run enriches up to 500 records of one entity with one provider in the background (the
`enrich_records` job). Queueing it checks that the caller reads the entity and answers the cost
estimate: the calls it would make, the calls left in the provider's budget today, and how many
records the budget would not reach. Each provider's daily budget is the deployment setting
`enrichment.daily_limits` (`{"registry": 100, "website": 500}`; a provider not named gets 100).
Records already matched to an account by their work-email domain are skipped before any call.
The registry uses the API key of the integration connection named `wathq`, the National Address
that of `national_address`; the website needs none.

Agents have three tools: `sales.enrich.record` (one record), `sales.enrich.list` (up to 500
records; an agent always asks a person first, and the answer carries the estimate) and
`sales.account.brief`, a short brief of an account in which every line cites its source: the
account record (`record:account/<id>`), the registry (`registry:CR <number>`) or the website's
address, with when an enrichment value was fetched. The brief changes nothing and calls no model.

## Arabic names

`sales.suggest_arabic_names` (up to 100 accounts) asks the model for the Arabic form of each
account's Latin legal name, 20 names a call, and files each as a `review` proposal from the source
`model`: a suggestion a person accepts, never a fill. Sources rank as the registry, then any other
provider, then the model: an account whose Arabic legal name is filled, or has a pending value
from the registry or another provider, gets no suggestion.

An enrichment run over accounts does this on its own when it finishes: it asks for the Arabic
names of the run's accounts as an agent of the person who queued the run, so their record access,
the approved model and their AI budget apply, and the audit names them. Without AI, or with the
budget spent, the run ends as it did and no suggestion is made.
