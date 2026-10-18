# API versions

The HTTP API (`/api/v1/...`) has dated versions, named `YYYY-MM`. A version fixes the shape of every
request and response: once your integration works against a version, it keeps working when the
server is upgraded, for as long as that version is supported. This server answers **`2026-10`**,
which is today the only version.

## Choosing a version

Send the version your code was written against in the `Attome-Version` header:

```sh
curl https://crm.example.com/api/v1/account \
  -H "Authorization: Bearer $ATTOME_API_KEY" \
  -H "Attome-Version: 2026-10"
```

Every response says which version it was answered at, in the same header:

```
HTTP/1.1 200 OK
Attome-Version: 2026-10
```

The version a request is answered at is, in order:

1. the `Attome-Version` header, when the request sends one;
2. otherwise the version the API key or S2S client is **pinned** to;
3. otherwise the current version.

A browser session (the web app) always gets the current version: the web app is upgraded with the
server.

A version the server does not know is refused before anything runs:

```
HTTP/1.1 400 Bad Request

{"error": "unsupported_api_version",
 "message": "API version \"2025-02\" is not supported",
 "supported": ["2026-10"]}
```

## Pinning

Every API key and S2S client is pinned to the version that was current when it was created, so an
integration that never sends the header keeps getting the shape it was built against after the
server moves to a newer version. To move an integration to a newer version, send the newer
`Attome-Version` header from your code (and test it there), then create a new key or client, which
is pinned to the version current at that time, and retire the old one.

Sending the header on every request is the simplest way to be explicit; the pin is the safety net
for code that does not.

## How older versions keep working

When a newer version changes a request or response in a way an older caller would notice (a field
renamed or removed, a shape changed, a status code changed), the server carries an **adapter** for
that step. A request at the older version is rewritten up to the current version before it runs,
and its response is rewritten back down before it is sent, only for the operations the change
touched; everything else passes through unchanged. Adapters are pure translations: no data is
stored twice and no logic runs twice.

A release cannot change the API incompatibly without its adapter: the release gate compares the
API document with the previous release's and refuses the release when a break has no adapter from
the earlier version upward. Each release lists its API changes per version in
`docs/api-versions/v<release>.md`, generated from that comparison when the release is tagged.

## Support window

Each version is supported for **24 months after the next version is released**. During that window
its adapters are kept and its requests are answered as before.

When a version enters its last months, every response to a request at it carries two headers
(RFC 9745 and RFC 8594):

```
Deprecation: @1795000000
Sunset: Sat, 01 Jan 2028 00:00:00 GMT
```

`Deprecation` is the moment the version was deprecated (seconds since the Unix epoch) and `Sunset`
is when it stops being answered. After the sunset a request at that version is refused:

```
HTTP/1.1 410 Gone

{"error": "api_version_sunset",
 "message": "API version 2025-01 was retired on Sat, 01 Jan 2028 00:00:00 GMT",
 "supported": ["2026-10"]}
```

Watch for `Deprecation` in your integration's logs: it is the signal to move to a newer version
before the sunset date.

## Summary

| You want to | Do this |
|---|---|
| Know which version answered | Read the `Attome-Version` response header |
| Use a specific version | Send `Attome-Version: <version>` |
| Keep the shape your integration was built on | Nothing: your key or client is pinned |
| Move to a newer version | Send the newer header, test, then replace the key or client |
| Notice a version ending | Watch for `Deprecation` and `Sunset` response headers |

Versions of the platform itself (releases, their cadence and support) are described in
[versions-and-support.md](versions-and-support.md).
