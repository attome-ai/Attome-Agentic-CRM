// S3-T1: Attome's layer over the generated Java client (native library).
// Copied into the generated sources by the build (sdks/README.md). It adds
// API-key auth, retries of 429/502/503/504 and one x-idempotency-key per
// write, the same on every retry of that call, so the server applies it
// once; records() follows next_cursor to the end.
package io.attome.sdk;

import io.attome.sdk.api.EntityApi;
import io.attome.sdk.api.QueryApi;
import io.attome.sdk.model.CursorPageValue;
import io.attome.sdk.model.EntityRecordResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;

/** One deployment, one API key. */
public final class AttomeClient {
    public static final String IDEMPOTENCY_HEADER = "x-idempotency-key";
    private static final Set<Integer> RETRIED = Set.of(429, 502, 503, 504);
    private static final ThreadLocal<String> WRITE_KEY = new ThreadLocal<>();

    private final EntityApi entities;
    private final QueryApi queries;
    private final int retries;

    public AttomeClient(String baseUrl, String publicKey, String secret, int retries) {
        ApiClient api = new ApiClient();
        api.updateBaseUri(baseUrl.replaceAll("/+$", ""));
        String authorization = publicKey == null || secret == null
            ? null
            : "ApiKey " + publicKey + ":" + secret;
        api.setRequestInterceptor(builder -> {
            if (authorization != null) {
                builder.header("Authorization", authorization);
            }
            String key = WRITE_KEY.get();
            if (key != null) {
                builder.header(IDEMPOTENCY_HEADER, key);
            }
        });
        this.entities = new EntityApi(api);
        this.queries = new QueryApi(api);
        this.retries = retries;
    }

    public EntityApi entities() {
        return entities;
    }

    public QueryApi queries() {
        return queries;
    }

    /** Runs one call, again on a retried status; a write keeps one key throughout. */
    private <T> T call(boolean write, Callable<T> request) throws ApiException {
        if (write) {
            WRITE_KEY.set(UUID.randomUUID().toString());
        }
        try {
            for (int attempt = 0; ; attempt++) {
                try {
                    return request.call();
                } catch (ApiException error) {
                    if (attempt >= retries || !RETRIED.contains(error.getCode())) {
                        throw error;
                    }
                    Thread.sleep((long) (500 * Math.pow(2, attempt)));
                }
            }
        } catch (ApiException error) {
            throw error;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new ApiException(error);
        } catch (Exception error) {
            throw new ApiException(error);
        } finally {
            WRITE_KEY.remove();
        }
    }

    /** Every record of the entity the key may read, up to maxPages pages (0: all). */
    public List<Object> records(String entity, long pageSize, int maxPages) throws ApiException {
        List<Object> out = new ArrayList<>();
        String cursor = null;
        int pages = 0;
        while (true) {
            final String at = cursor;
            CursorPageValue page =
                call(false, () -> entities.listRecords(entity, null, null, pageSize, at, null));
            out.addAll(page.getItems());
            pages++;
            cursor = page.getNextCursor();
            if (cursor == null || cursor.isEmpty() || (maxPages > 0 && pages >= maxPages)) {
                return out;
            }
        }
    }

    public EntityRecordResponse create(String entity, Map<String, Object> fields) throws ApiException {
        return call(true, () -> entities.createRecord(entity, fields, null));
    }

    /** Refused (409) when the record changed since rowVersion was read. */
    public EntityRecordResponse update(String entity, UUID id, long rowVersion, Map<String, Object> fields)
        throws ApiException {
        return call(true, () -> entities.updateRecord(entity, id, "\"" + rowVersion + "\"", fields));
    }

    public void delete(String entity, UUID id) throws ApiException {
        call(true, () -> {
            entities.deleteRecord(entity, id);
            return null;
        });
    }
}
