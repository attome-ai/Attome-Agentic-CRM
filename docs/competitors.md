# Competitor tracking

Competitor tracking (roadmap D25) records who you compete with, which deals they are on, why deals
are won and lost against them, and what the buyer said. It ships in the sales pack
(`packs/sales/changesets/0008-sales-competitors.json` for the records,
`0017-sales-win-loss.json` for the reports). A deployment without those changesets has none of
it: every route below answers `404`, and the two background jobs find no tables and do nothing.

## The records

All of these are ordinary entities, read and written through the generic entity API
(`/api/v1/{entity}`) with the usual record rules and field grants.

| Entity | What it holds |
|---|---|
| `competitor` | Name (and `name_ar`), website, type, regions, strengths, weaknesses, price position, owner, `battlecard_ref` (a knowledge article) and `is_tracked`. |
| `opportunity_competitor` | A competitor on a deal, with `status` and `threat_level`. |
| `competitor_product` | A product of yours a competitor competes with. |
| `competitor_mention` | A competitor proposed for a deal from an email or note: source, snippet, `status` (`proposed`, `confirmed`, `rejected`) and who decided. |
| `win_loss_review` | The review of a won or lost deal: outcome, main and secondary reasons, what the winner did better, notes, `competitors_snapshot`, reviewer and `buyer_feedback_ref`. |

The pack also adds `opportunity.lost_to_competitor_ref`, `account.incumbent_competitor_ref`,
`lead.incumbent_supplier`, and two fields on `opportunity_stage`: `review_amount_threshold` and
`review_required_fields`.

## The switches, and what is off by default

Competitor tracking has no feature flags of its own. Each part is switched on by data, and each
starts doing nothing until someone sets it up:

| Part | Switched on by | Default |
|---|---|---|
| Battle cards | A competitor's `battlecard_ref` pointing at a knowledge article. | No card until one is linked. The panel on the opportunity form is hidden on a deal with no competitors. |
| Mention finding | A `competitor` record with `is_tracked` true (or unset). | On for every tracked competitor once one exists; set `is_tracked` false to stop proposals for one. |
| Win/loss reviews | A `review_amount_threshold` on the `closed_won` or `closed_lost` stage of a pipeline. | **Off**: a stage with no threshold creates no review. The threshold is per pipeline, because each pipeline has its own stages. |
| Buyer feedback | A published survey named `win_loss_buyer` (for the survey way) and contacts who consented to the `surveys` purpose. | Nothing is sent without both. The interview way (a task) needs neither. |
| Analysis | Installing `0017-sales-win-loss.json`. | The reports and the head-to-head route read whatever deals exist. |
| Competitor news | Not available. | **Not built.** Watching competitor news needs the news monitoring (K6) and web watch (E18) features, which do not exist yet. Nothing in this release reads competitor news. |

### Mention finding

A job runs every minute (`SalesMentionScan`). It reads new emails (`communication`) and notes
(`note`) off the change feed with its own cursor (`attome-sales/mention-scan`). When one is about a
deal, or about an account with open deals, and names a tracked competitor as a whole word, it
proposes that competitor on each such deal as a `competitor_mention` with a 200-character snippet.

- Names match after Arabic normalisation, so diacritics, letter variants and case do not hide a
  mention.
- A proposal is written as the deal's owner, and only when the owner can read the email or note.
- One proposal per source, competitor and deal, and none for a competitor already on the deal, so
  a retried run adds nothing twice.
- Nothing is linked until a person confirms.

`POST /api/v1/sales/competitor-mentions/{id}/confirm` puts the competitor on the deal as
`suspected` (unless it is already there) and marks the mention `confirmed`;
`POST /api/v1/sales/competitor-mentions/{id}/reject` marks it `rejected`. Both need update access on
the deal and the mention's current `row_version` in `If-Match`, so two people cannot decide one
mention twice.

### Win/loss reviews

A second minute job (`SalesDealCloseSweep`, cursor `attome-sales/deal-close`) watches deal changes.
When a deal moves to `closed_won` or `closed_lost` and its amount is at least that stage's
`review_amount_threshold`, it creates a draft `win_loss_review` as the deal's owner, with the
outcome and a snapshot of the competitors on the deal, plus a task for the owner due in seven days.
It never blocks or slows the close. There is one review per deal and outcome: reopening and closing
the deal again keeps the first review.

### Battle cards

- `GET /api/v1/sales/opportunities/{id}/battlecards` lists the competitors on a readable deal with
  their `battlecard_ref` (a `PaginatedResponse`, all on one page).
- `GET /api/v1/sales/competitors/{id}/card` returns the competitor fields the caller may read, and
  its battle card article when it is set and readable.

### Buyer feedback

`POST /api/v1/sales/win-loss-reviews/{id}/buyer-feedback` asks the buyer's contacts how the deal
went, and needs update access on the review. It works in one of two ways:

- `survey` sends the published survey `win_loss_buyer` to each named contact the caller may read
  who consented to surveys. Everyone else is listed with the reason they were skipped. The first
  answer links itself from `win_loss_review.buyer_feedback_ref`.
- `interview` creates one task regarding the review, for the caller, naming the contacts to
  interview.

At most 50 contacts can be named in one request.

### Analysis

- `GET /api/v1/sales/competitors/{id}/head-to-head` counts the won, lost and open deals against a
  competitor, with their amounts, the top loss reasons and the recent mentions. It counts only the
  deals the caller may read and needs `competitor.read`.
- The reports in `0017-sales-win-loss.json` run through `query/execute` and cover:
  - overall win rate;
  - win rate and reasons by competitor;
  - reasons by segment, region and size;
  - discount and sales cycle by competitor;
  - losses on price by discount band;
  - win rate by quarter.

  A deal counts against a competitor when it was lost to that competitor or the competitor is on the
  deal.

### Agent actions

These four actions are read only and run as the person:

- `sales.competitors.on_deal`
- `sales.battlecard.get`
- `sales.winloss.draft_review`
- `sales.battlecard.draft_update`

The two drafts are returned for a person to save or publish. Nothing is written.
