# Branding

An administrator gives Attome the customer's colours, corner radius and name policy without a
rebuild. A theme is a set of optional tokens; each scope sets only what it changes.

## Scopes and the order they merge

A theme belongs to one scope. A request's brand is the published theme of each scope it falls
under, merged from the broadest outwards, so a later scope overrides only the tokens it sets:

1. `deployment`: everyone.
2. `app`: an app, by name (`?app=` on `/api/v1/branding/me`).
3. `unit`: a business unit, by id; the signed-in person's own unit.
4. `domain`: a host name, such as `crm.example.sa`.
5. `portal`: a web portal.

`GET /api/v1/branding/public` needs no session and uses the deployment and domain themes only;
the sign-in page uses it. `GET /api/v1/branding/me` adds the caller's app and business unit.
Both return the CSS variables to apply, the fonts and `hide_vendor_name`, with an ETag; a client
holding the current ETag gets `304`. The public answer may be cached for five minutes.

## Tokens

| Token | Meaning |
|---|---|
| `primary`, `accent` | Brand colours: buttons, links, highlights |
| `surface`, `text` | Page background and body text, light mode |
| `surface_dark`, `text_dark` | The same in dark mode |
| `success`, `warning`, `danger`, `info` | Status colours |
| `font_latin`, `font_arabic`, `arabic_line_height` | Font families and Arabic line height |
| `radius_px` | Corner radius, 0 to 24 |
| `density` | `comfortable` or `compact` |
| `hide_vendor_name` | Leave the Attome name out of the product |

Colours are `#RRGGBB`. Today the web app applies the light-mode colours `primary`, `accent`,
`surface`, `text`, `success` and `danger`, and the fonts and Arabic line height in both modes. A
font name may hold letters, digits, spaces and hyphens (at most 64 characters); the font itself
must be installed on the viewer's machine or served by the page, or the product's font shows. The
other tokens are stored, checked and returned, and the web app picks them up as it learns to use
them.

## The contrast check

A theme that would be hard to read cannot be published. Tokens a theme leaves out are checked at
the product's own colours. The rules (WCAG 2.2):

- `text` on `surface` and `text_dark` on `surface_dark`: at least 4.5:1.
- `primary` and each status colour on `surface`: at least 3:1.
- Any two status colours: at least ΔE 20 apart (CIE76), so success and danger never look alike.

`POST /api/v1/admin/themes/preview-check` with `{"tokens": {...}}` runs the check and saves
nothing. Each failure names the pair, the mode (`light`, `dark` or `distinct`), the measured value
and the required one.

## Draft, publish, roll back

Every save is a new version of its scope's theme; at most one version per scope is published.

```http
POST /api/v1/admin/themes
{"scope_kind": "deployment", "scope_ref": "", "tokens": {"primary": "#0b4f6c", "radius_px": 8}}

PATCH /api/v1/admin/themes/{id}          If-Match: "<row_version>"   (a draft only)
{"tokens": {"primary": "#0a3d55"}}

POST /api/v1/admin/themes/{id}/publish   If-Match: "<row_version>"
```

Publishing runs the contrast check again and retires the scope's previously published version.
To go back, publish an earlier version again:

```http
POST /api/v1/admin/themes/rollback
{"scope_kind": "deployment", "scope_ref": "", "version": 3}
```

`GET /api/v1/admin/themes/{id}/diff` lists each token a version changes against the scope's
published one. `GET /api/v1/admin/themes` lists every version. Each change writes a
`Configuration` audit event.

The Branding page (`/xrm/admin/branding`) does the same: colour pickers, a live contrast check,
a preview, save as draft, publish, and the version list with each version's changes.

## Logo, favicon and fonts

A draft takes one file per kind, sent as the raw request body with its `Content-Type`:

```http
POST /api/v1/admin/themes/{id}/assets?kind=logo
Content-Type: image/svg+xml

<svg ...>...</svg>
```

| Kind | Accepts |
|---|---|
| `logo`, `logo_dark` | PNG, SVG |
| `favicon` | PNG, SVG, ICO |
| `font_latin`, `font_arabic` | WOFF2 |
| `guidelines_pdf` | PDF |

A file is at most 2 MB and must start the way its type does. An SVG containing a script, an
event handler, a `javascript:` link, a foreign object or a reference to another site is refused.
A new draft keeps the previous version's files until it is given new ones; only a draft takes
uploads. `GET /api/v1/admin/themes/{id}/assets` lists a version's files.

Once published, the branding routes return `logo_url`, `logo_dark_url`, `favicon_url`,
`font_latin_url` and `font_arabic_url`, each pointing at `GET /api/v1/branding/asset?kind=...`.
That route needs no session, serves the most specific published file for the host, and sends
`nosniff` and a `sandbox` content security policy, so an SVG opened on its own runs nothing. The
guidelines PDF is never public. The web app sets the browser tab's icon from `favicon_url`.

## Hiding the vendor name

`hide_vendor_name: true` is an ordinary token: any administrator may publish it (V2-D490). There
is no separate white-label switch.

## A custom domain

To brand a host name, publish a theme with `scope_kind: "domain"` and the host as `scope_ref`
(lower case, no port). The server reads the request's `Host` header, so a reverse proxy in front
of Attome must pass the original host through. For nginx:

```nginx
server {
    listen 443 ssl;
    server_name crm.example.sa;
    ssl_certificate     /etc/ssl/crm.example.sa.crt;
    ssl_certificate_key /etc/ssl/crm.example.sa.key;

    location / {
        proxy_pass http://127.0.0.1:7865;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

If the deployment restricts staff host names (`deployment.staff_hosts`), add the new host there
too; a host outside that list gets `404`.
