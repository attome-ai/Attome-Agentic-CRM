// S3-T1: the Java SDK against a Prism mock of the SDK document. Prism
// refuses a request the document does not allow, so a pass means the
// generated client and Attome's layer send what the API declares.
package io.attome.smoke;

import io.attome.sdk.ApiException;
import io.attome.sdk.AttomeClient;
import io.attome.sdk.model.EntityRecordResponse;
import io.attome.sdk.model.ExecResponse;
import io.attome.sdk.model.ExecuteQueryRequest;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class Smoke {
    public static void main(String[] args) throws Exception {
        String baseUrl = args.length > 0 ? args[0] : "http://127.0.0.1:4010";
        AttomeClient client = new AttomeClient(baseUrl, "pk_smoke", "secret", 0);
        UUID id = UUID.randomUUID();

        List<Object> listed = client.records("account", 10, 2);

        EntityRecordResponse created = client.create("account", Map.of("name", "Smoke"));
        check(created.getId() != null, "create returned no id");

        EntityRecordResponse updated = client.update("account", id, 1, Map.of("name", "Smoke 2"));
        check(updated.getData() != null, "update returned no data");

        client.delete("account", id);

        ExecResponse answer = client.queries().execute(new ExecuteQueryRequest().entity("account"));
        check(answer.getData() != null, "query returned no data");

        AttomeClient anonymous = new AttomeClient(baseUrl, null, null, 0);
        try {
            anonymous.records("account", 10, 1);
            throw new IllegalStateException("a call without an API key was accepted");
        } catch (ApiException error) {
            check(error.getCode() == 401, "expected 401, got " + error.getCode());
        }
        System.out.println("java sdk smoke: ok (" + listed.size() + " records listed)");
    }

    private static void check(boolean ok, String message) {
        if (!ok) {
            throw new IllegalStateException(message);
        }
    }
}
