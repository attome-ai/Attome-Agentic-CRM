// S3-T1: Attome's layer over the generated C# client. Copied into the
// generated project by the build (sdks/README.md). It adds API-key auth,
// retries of 429/502/503/504 (honouring Retry-After) and one
// x-idempotency-key per write, the same on every retry of that call, so the
// server applies it once; Records() follows next_cursor to the end.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Attome.Sdk.Api;
using Attome.Sdk.Client;
using Attome.Sdk.Model;

namespace Attome.Sdk
{
    /// <summary>Retries and the idempotency key, under the generated client.</summary>
    public sealed class AttomeHandler : DelegatingHandler
    {
        public const string IdempotencyHeader = "x-idempotency-key";
        private static readonly HttpStatusCode[] Retried =
        {
            (HttpStatusCode)429, HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable,
            HttpStatusCode.GatewayTimeout,
        };
        private readonly int _retries;

        public AttomeHandler(int retries) : base(new HttpClientHandler())
        {
            _retries = retries;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get && !request.Headers.Contains(IdempotencyHeader))
            {
                request.Headers.Add(IdempotencyHeader, Guid.NewGuid().ToString());
            }
            for (var attempt = 0; ; attempt++)
            {
                var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
                if (attempt >= _retries || !Retried.Contains(response.StatusCode))
                {
                    return response;
                }
                var wait = response.Headers.RetryAfter?.Delta
                    ?? TimeSpan.FromMilliseconds(500 * Math.Pow(2, attempt));
                response.Dispose();
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>One deployment, one API key.</summary>
    public sealed class AttomeClient
    {
        public EntityApi Entities { get; }
        public QueryApi Queries { get; }

        public AttomeClient(string baseUrl, string? publicKey = null, string? secret = null, int retries = 3)
        {
            var configuration = new Configuration { BasePath = baseUrl.TrimEnd('/') };
            if (publicKey != null && secret != null)
            {
                configuration.ApiKey["Authorization"] = $"ApiKey {publicKey}:{secret}";
            }
            var http = new HttpClient(new AttomeHandler(retries));
            Entities = new EntityApi(http, configuration);
            Queries = new QueryApi(http, configuration);
        }

        /// <summary>Every record of the entity the key may read, page after page.</summary>
        public async IAsyncEnumerable<object> Records(
            string entity, long pageSize = 200, int? maxPages = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            string? cursor = null;
            var pages = 0;
            while (true)
            {
                var page = await Entities.ListRecordsAsync(entity, pageSize: pageSize, cursor: cursor,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                foreach (var item in page.Items)
                {
                    yield return item;
                }
                pages++;
                cursor = page.NextCursor;
                if (string.IsNullOrEmpty(cursor) || (maxPages.HasValue && pages >= maxPages.Value))
                {
                    yield break;
                }
            }
        }

        public Task<EntityRecordResponse> CreateAsync(string entity, Dictionary<string, object> fields) =>
            Entities.CreateRecordAsync(entity, fields);

        /// <summary>Refused (409) when the record changed since rowVersion was read.</summary>
        public Task<EntityRecordResponse> UpdateAsync(
            string entity, Guid id, long rowVersion, Dictionary<string, object> fields) =>
            Entities.UpdateRecordAsync(entity, id, $"\"{rowVersion}\"", fields);
    }
}
