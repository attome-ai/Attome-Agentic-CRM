# Packs: manifests, levels and the quality bar

Every pack under `packs/<name>/` carries a manifest, `pack.json`:

```json
{
  "format": "attome-pack/v1",
  "name": "billing",
  "title": "Billing",
  "version": "1.25.0",
  "level": "standard",
  "depends": ["contract-management", "crm", "finance", "sales"],
  "contents": ["changesets"]
}
```

| Field | Meaning |
|---|---|
| `name` | The folder name, which is also the changesets' `scope` and the name `attome init --pack` takes. |
| `version` | `1.<changesets>.0`: the minor part is the number of changesets, so adding one bumps the version. |
| `level` | How far the pack meets the quality bar below: `starter`, `standard` or `complete`. |
| `depends` | The packs that must be installed first: the packs that define the entities this one extends or looks up, and the packs its golden workflows install. |
| `contents` | What the pack ships: `changesets` always, `model` (forms, pages and other model objects under `model/`) and `golden` (golden workflows under `golden/golden.json`) when present. |

Boot does not read the manifest: it installs the packs named at `attome init` from their changesets.
The manifest is what an operator, a reviewer and the test `every_pack_has_a_manifest`
(`crates/engine/attome-api/tests/pack_changesets.rs`) read: every pack has one, the version matches the
changesets, every dependency is a pack, dependencies form no cycle, and the contents exist.

## The quality bar

A pack is judged on seven things.

1. **Data model.** Entities and fields with English and Arabic labels, lookups to the shared entities
   (account, contact, product) rather than copies of them, and sensitive fields marked.
2. **Roles.** The people who use it as role templates, each at the narrowest level that does the job.
3. **Apps.** Forms and pages for its main entities (`model/`), built on the base form.
4. **Dashboards.** At least one view or dashboard per role that answers the role's first question.
5. **Sample data.** Bilingual records enough to show each screen and run each workflow.
6. **Golden workflows.** Customer tests that walk the pack's main journeys end to end
   (`golden/golden.json`), run in the release gate.
7. **Docs.** A section in `packs/README.md` saying what the pack holds, what it builds on and what to
   install with it.

| Level | Meets |
|---|---|
| `starter` | 1 and 7: a data model to build on. |
| `standard` | 1, 2 and 7, and usually 5 or 6: roles, or golden workflows over sample data. |
| `complete` | All seven; the test requires golden workflows and model objects for it. |

No pack is `complete` today: the packs with golden workflows ship no model objects yet, and the packs
with forms and pages have no golden workflows. Raising a pack's level is a change to its `pack.json`
in the same change that adds what the level needs.
