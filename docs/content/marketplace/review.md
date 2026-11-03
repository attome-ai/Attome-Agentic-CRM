# Reviewing a catalogue listing

A package version enters a deployment's catalogue as `pending`
(`POST /api/v1/admin/packages/catalogue`, see [packages](../../packages.md#catalogue)). Before it can be
installed, an administrator other than the one who added it reviews it and approves or rejects it
(`POST /api/v1/admin/packages/catalogue/{id}/review` with `decision` and a `note`). This page is what
that reviewer checks. Write the result of each section in the note, so the record says why the version
was approved.

## Process

1. **Read the entry.** `GET /api/v1/admin/packages/catalogue` shows the publisher, the source (`pushed`
   or `partner:<name>`) and what the package asks of the deployment: its mode, the components it
   carries, the entities it brings or extends with their field counts, its roles and the packages it
   depends on.
2. **Preview it on a copy first.** On a development or test deployment, add the same version and run
   `POST /api/v1/admin/packages/preview` with the document. The preview lists what installing would
   create, change and remove, the permissions it requests, its effects on records already there, and
   anything blocked. Do not approve on production what you have not previewed elsewhere.
3. **Go through the checklist below.** Each item is a yes or a reason.
4. **Decide.** Approve when every item holds; reject with the failing items in the note. A rejected
   version stays in the catalogue as rejected; the publisher fixes it and ships a new version.
5. **Install.** Only an approved version installs: `POST /api/v1/admin/packages/catalogue/{id}/install`
   returns the same preview and plan; applying the plan is the install, under the deployment's usual
   approval for metadata applies.

## Checklist

### Security

- [ ] The signature verifies against the publisher's key the deployment trusts (the catalogue refuses
      one that does not; for a partner package, the key is the partner catalogue's).
- [ ] The publisher is who you expect for this package id; a known package from a new publisher is a
      rejection until confirmed out of band.
- [ ] Nothing in the preview is `blocked`, and nothing is removed that the deployment still uses.
- [ ] No field holding personal, financial, health or secret data arrives unmarked: sensitive fields
      carry their sensitivity so field security applies.
- [ ] No rule, workflow or hook sends record data to an outside address you have not agreed to.

### Permissions

- [ ] Every role the package defines grants only what its job needs, at the narrowest access level;
      none grants administration.
- [ ] The entities it extends (fields added to entities it does not own) are ones you expect it to touch,
      and each added field carries the package's namespace.
- [ ] A managed package's extension points are the entities you will want to add your own fields to;
      everything else it owns will be locked to customer changes.
- [ ] Its dependencies are installed, at the versions it names or later.

### Tests

- [ ] The package ships golden workflows (`attome-pack-golden/v1`) for its main journeys, and they pass
      on a fresh test deployment (the release gate's `packs` step for packs in this repository).
- [ ] The preview on your test deployment applied cleanly, and the records already there behave as
      before: open a few, save a few.
- [ ] After installing on the test deployment, `GET /api/v1/admin/packages/{id}/drift` is clean.

### Documentation

- [ ] The package says what it is for, who uses it and how to start, in both languages.
- [ ] Each role and each main screen is explained.
- [ ] Its upgrade notes say what changed since the version installed here, and what an uninstall keeps,
      exports or retires.

### Arabic

- [ ] Every entity, field, choice, form, menu item and message has an Arabic label, written for the
      reader rather than translated word for word.
- [ ] Forms and pages read right to left without broken layout (check on a phone width too).
- [ ] Dates show in the deployment's calendar (Gregorian, Hijri or both) and numbers and currencies in
      the deployment's formats.
- [ ] Sample data, if any, has Arabic records as well as English ones.

## Recording the decision

The review writes a Configuration audit event naming the reviewer and the decision, and the entry keeps
the note, the reviewer and the time. Write the note so that someone reading the catalogue a year later
knows what was checked: for example, "Previewed on staging 2026-11-03; golden workflows pass; roles
checked against the sales team's access; Arabic labels reviewed by the support lead."
