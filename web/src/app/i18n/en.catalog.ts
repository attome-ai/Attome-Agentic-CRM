// English catalog for the host app's own screens (NGB-5.2b, D-761),
// registered in app.config.ts. Arabic mirrors it key-for-key in ar.catalog.ts.

export const hostEn = {
  authModal: {
    googleError: 'Google sign-in failed.',
    dialogAriaLabel: 'Sign in to Attome',
    closeAriaLabel:  'Close',
  },
  // The host app's XRM login page (src/app/pages/login/login.component.ts)
  // reaches for these three on a 401. They were referenced but never defined
  // in either catalog, so `translate()` fell through and the form rendered
  // the raw key ("xrmLogin.invalidCredentials") as its error text.
  //
  // Deliberately generic on the credential path: the backend is
  // enumeration-safe (it does not distinguish "no such account" from "wrong
  // password"), so this message must not either.
  xrmLogin: {
    invalidCredentials: 'Incorrect email or password.',
    invalidCode:        'That code is incorrect or has expired. Please try again.',
    googleError:        'Google sign-in failed. Please try again.',
    checkingBrowser:    'Checking your browser before signing in…',
  },
  // Host app's /settings/security page (src/app/pages/security-settings).
  securitySettings: {
    googleLinkConflict: 'This Google account is already linked to another user.',
    googleLinkError: 'Linking failed. Please try again.',
    stepUpComplete: 'Identity confirmed. You can continue now.',
    stepUpError: 'Your identity could not be confirmed. Nothing was changed.',
    stepUpExpired: 'Your identity confirmation is no longer valid. Please try again.',
    stepUpCheckFailed: 'Could not check your identity confirmation. Please try again.',
    apiKey: {
      title: 'API keys',
      subtitle: 'Create a key for scripts and integrations that call the API as you.',
      nameLabel: 'Key name',
      expiryLabel: 'Expires after (days, optional)',
      create: 'Create API key', creating: 'Creating…',
      nameRequired: 'Enter a name for the key.',
      expiryInvalid: 'Enter a whole number of days greater than zero, or leave it empty.',
      notCreated: 'The API key was not created.',
      ready: 'Identity confirmed. Create your API key now.',
      createdTitle: 'API key created',
      copyNow: 'Copy this secret now. It will not be shown again.',
      publicKeyLabel: 'Key ID', secretLabel: 'Secret',
      dismiss: 'I have copied it',
    },
  },
  // The hosted payment page (F5-T15, src/app/pages/pay).
  pay: {
    title: 'Pay securely',
    otherLanguage: 'العربية',
    loading: 'Loading the payment…',
    notFound: 'This payment link is not valid. It may have expired or been used. Ask the sender for a new link.',
    seller: 'Paying',
    invoice: 'Invoice',
    amount: 'Amount',
    pay: 'Pay',
    starting: 'Opening the payment page…',
    failed: 'The payment could not be started. Please try again.',
    secure: 'You enter your card details on the payment provider\'s secure page, not here.',
  },
  // Also recovered from the unimported en.json.
  register: {
    emailTaken: 'Email already registered.',
    invalidInvitation: 'This invitation code is invalid, expired, or already used.',
  },
};
