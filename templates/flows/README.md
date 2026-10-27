# Starter flow templates

Twenty `flow_template` documents (M6-T1's kind, roadmap M6-T3) across sales,
service, back office and MENA (ZATCA invoice approval, Hijri renewal and iqama
expiry reminders). Each has English and Arabic descriptions and parameter
labels, and a default for every parameter, so it instantiates as it stands;
the defaults name the usual entity and attribute, which you change to your own.

Load one into a deployment as a `flow_template` object through the model admin
API, then instantiate it from the flow template gallery (M6-T4) into a draft
flow, where the workflow engine validates it again before you publish.

`crates/engine/attome-workflow/tests/flow_template_library.rs` checks that
every file is a valid template, instantiates with its defaults and passes the
engine's publish validation:

    cargo test -p attome-workflow --test flow_template_library
