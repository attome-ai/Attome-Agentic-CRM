export const environment = {
  production: true,
  apiUrl:     '',  // same origin in production (nginx proxies /api → Rust)
  // Landing-page "Book a demo" destination: a mailto: or a booking URL.
  demoUrl:    'mailto:hello@attome.com?subject=Attome%20demo',
};
