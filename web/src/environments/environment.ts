export const environment = {
  production: false,
  // 127.0.0.1, not localhost: the backend binds 0.0.0.0 (IPv4 only), while
  // `ng serve` binds [::1], so a page loaded over IPv6 loopback resolves
  // `localhost` to [::1]:7865 and every API call fails with "Failed to fetch".
  apiUrl:     'http://127.0.0.1:7865',
  // Landing-page "Book a demo" destination: a mailto: or a booking URL.
  demoUrl:    'mailto:hello@attome.com?subject=Attome%20demo',
};
