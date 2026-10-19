// English catalog for the runtime translation library (P-i18n-a11y §4.1).
// A TS module, not a JSON asset, so no resolveJsonModule/ng-packagr asset
// wiring is needed — it imports exactly like every other internal module
// this workspace already builds.
//
// Base-owned namespaces only (NGB-5.2, D-761). `@attome/xrm` and the host
// register their own catalogs with `provideLayerCatalog()` where they mount.

export const en = {
  // NGB-3.2/3.3 — the dialog host's own defaults. Every string the template
  // used to hardcode (title, buttons, the empty-value prompt error) resolves
  // here, in the active language.
  dialog: {
    confirmTitle: 'Confirm Action',
    cancel:       'Cancel',
    confirm:      'Confirm',
    save:         'Save',
    errorTitle:   'Action Failed',
    close:        'Close',
    emptyValue:   'Value cannot be empty.',
  },
// NGB-2.3 / OD-8 — one message per `ApiErrorKind`, rendered by
// `LangService.errorText`. The server's own English `message` is used only
// for `validation` and `rule_violation`; everything else is UI copy.
  errors: {
  validation:                   'Please check the highlighted fields.',
  not_found:                    'That item no longer exists.',
  unauthorized:                 'Your session has expired. Please sign in again.',
  forbidden:                    'You do not have permission to do that.',
  conflict:                     'Someone else changed this first. Reload and try again.',
  version_conflict:             'Someone else changed this record. Reload and try again.',
  internal:                     'Something went wrong on the server. Please try again.',
  reauth_required:              'Please confirm your identity to continue.',
  rate_limited:                 'Too many requests. Please wait a moment and try again.',
  unavailable:                  'The service is temporarily unavailable. Please try again shortly.',
  payload_too_large:            'That file or request is too large.',
  feature_hidden:               'That feature is not included in this deployment.',
  idempotency_conflict:         'This request was already sent with different content.',
  idempotency_outcome_unknown:  'The earlier attempt may have completed. Check the record before retrying.',
  idempotency_replay_unavailable: 'That request already completed.',
  rule_violation:               'A business rule rejected this change.',
  transition_not_allowed:       'That state change is not allowed.',
  authoring_locked:             'Configuration authoring is disabled on this deployment.',
  // AB5-T6 — a client code (`code`), not a kind: the system is read-only for now.
  read_only:                    'The system is read-only for now. You can still look things up; saving will work again soon.',
  unknown:                      'An unexpected error occurred.',
  // NGB-3.3 — the client-synthesised `getAllPages` ceiling error.
  too_many_pages:               'This list is too large to load in full. Narrow the search or use a filtered view.',
  // Solution 7 (D-785) — changeset refusals, lifted out of a 409 conflict's message.
  changeset_required:           'This change must be recorded in an open changeset. Open or pick a changeset, then try again.',
  changeset_ambiguous:          'You have more than one open changeset. Pick the one to record this change into, then try again.',
  changeset_not_open:           'The picked changeset is closed or no longer exists. Pick an open changeset, then try again.',
  layer_mismatch:               'This item is owned by another layer and cannot be changed here. Change it in a changeset of the layer that owns it.',
  hard_delete_not_recordable:   'A permanent delete cannot be recorded in a changeset. Retire the item instead.',
},
  auth: {
    back:       'Back',
    signingIn:  'Signing in…',
    signInWith: 'Sign in with',
    or:         'or',
    error:      'Sign-in failed. Please try again.',
  },
  forgotPassword: {
    back:      'Back to sign in',
    title:     'Forgot your password?',
    subtitle:  "Enter your account's email and we'll send you a reset link.",
    emailLabel:'Email',
    submit:    'Send reset link',
    sending:   'Sending…',
    sentTitle: 'Check your inbox',
    sentBody:  'If an account exists for that email, a reset link is on its way.',
    error:     'Something went wrong. Please try again.',
  },
  resetPassword: {
    back:          'Back to sign in',
    title:         'Set a new password',
    subtitle:      'Choose a new password for your account.',
    passwordLabel: 'New password',
    confirmLabel:  'Confirm password',
    // ICU plural (P-i18n-a11y §3/§4.2) — proves the messageformat plugin is
    // actually wired, not just installed. `count` is always the fixed
    // minimum length today, but the pattern is correct for any count.
    minLength:     '{count, plural, one {Minimum 1 character} other {Minimum # characters}}',
    submit:        'Reset password',
    submitting:    'Resetting…',
    mismatch:      'Passwords do not match.',
    invalidLink:   'This reset link is invalid, expired, or already used. Request a new one.',
    doneTitle:     'Password updated',
    doneBody:      'You can now sign in with your new password.',
    signInLink:    'Go to sign in',
    error:         'Something went wrong. Please try again.',
  },
  verifyEmail: {
    back:        'Back to sign in',
    verifying:   'Verifying your email…',
    doneTitle:   'Email verified',
    doneBody:    'Your email address has been verified.',
    signInLink:  'Go to sign in',
    invalidLink: 'This verification link is invalid, expired, or already used.',
  },
  // D-510 step-up prompt (attome-auth 2.1d) — `StepUpPromptComponent`. Failure
  // text is deliberately generic: the server answers every refusal alike, and
  // the prompt must never imply that another account or session exists.
  stepUp: {
    title: 'Confirm it is you',
    intro: 'To {operation}, confirm your identity again.',
    operation: {
      identity_link: 'link a sign-in method',
      api_key_create: 'create an API key',
      default: 'continue',
    },
    chooseFactor: 'Confirm with',
    factor: { password: 'Password', totp: 'Authenticator app code', recovery_code: 'Recovery code' },
    verify: 'Confirm', verifying: 'Confirming…', cancel: 'Cancel', close: 'Close',
    federatedIntro: 'Confirm with a sign-in provider linked to your account.',
    providersLoading: 'Loading your sign-in providers…',
    noProviders: 'No linked sign-in provider is available.',
    continueWith: 'Continue with {provider}',
    enrollmentRequired: 'Set up an authenticator app in your security settings first, then try again.',
    failed: 'That did not work. Check what you entered and try again.',
    tooManyAttempts: 'Too many attempts. Wait a few minutes and try again.',
  },
  // C4-T2: the mention picker in text editors.
  mentionPicker: {
    label: 'Mention a person, team or record',
    searching: 'Searching…',
    none: 'No matches',
    kind: {
      user: 'Person',
      team: 'Team',
      record: 'Record',
    },
  },
};
