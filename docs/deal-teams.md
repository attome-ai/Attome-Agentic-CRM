# Deal teams and splits

A deal team is the people who work an opportunity with its owner: a sales engineer, an executive
sponsor, a bid manager, legal, or a partner's contact. Splits divide the deal's credit between
them. Both come from the sales pack (`packs/sales/changesets/0010`) and are off until switched on.

## Switches

| Flag | Turns on | Needs |
|---|---|---|
| `sales.deal_teams` | Team members on opportunities, with a role and read or edit access. | |
| `sales.splits` | Revenue and overlay splits between team members. | `sales.deal_teams` |
| `sales.line_splits` | Splits of one opportunity line rather than the whole deal. | `sales.splits`, `sales.opportunity_lines` |
| `sales.partner_members` | Partner contacts as team members, with partner split types. | `sales.deal_teams` |
| `sales.team_suggestions` | The owner's default team members added to each new deal. | `sales.deal_teams` |

## Team members

`opportunity_team_member` links a user (or a partner contact) to an opportunity with a role from
`sales_team_role` (Sales Engineer, Executive Sponsor, Bid Manager and Legal ship) and an access
level. Read access lets a member see a deal they do not own; edit access lets them change it.
`user_default_team_member` holds an owner's usual team, which `sales.team_suggestions` adds to
every new deal they own.

## Splits

A split gives a member a percent of a split type:

- **Revenue** (`must_total_100`): the percents of a deal, or of one line for a line split, add
  up to exactly 100. With no split, the owner has 100% revenue.
- **Overlay** and other types without `must_total_100` may add up to anything: a specialist can
  carry 100% overlay beside the owner's 100% revenue.

Each split's amount takes its type's basis (the total, the one-time or the recurring value, or
the line's total for a line split), is rounded once to the currency's minor units, and the
rounding remainder of a split type goes to the owner's split. Amounts are recalculated when the
lines, the splits or the owner change, in the same transaction, and within a few minutes of a change
to the deal's amount through an ordinary record update (the deal-close sweep reads it off the change
feed).

## Won deals

Changing the splits of a won deal needs approval and keeps the reason, because commission
(`attome-commission`) credits people from them.

## Leavers

When a member leaves, their open deals keep the team row until someone reassigns it; a manager
reassigns the member's splits before the next commission period closes. Splits on won deals stay
as they were: they are the record of who earned the deal.
