## What and why

<!-- What changed and why. Link the issue: "Closes #123". -->

## How it was tested

<!-- The tests you added or ran, and the release gate result:
     cargo run -p attome-release --target-dir target/gate -- --check  (add --web for the web app) -->

## Checklist

- [ ] One change per pull request (refactoring and formatting go separately).
- [ ] Tests added or updated; a fixed bug has a test that failed before the fix.
- [ ] User-visible text is in both the English and the Arabic catalogue; layouts work right to left.
- [ ] A route or wire type change regenerated `openapi.json` and the web API types.
- [ ] A user-visible change has a `CHANGELOG.md` line; a breaking API change is under `### Breaking`.
- [ ] No secret, customer data or deployment configuration is committed.

## Anything you are unsure about

<!-- Optional. -->
