// S3-T1: the C# SDK against a Prism mock of the SDK document. Prism refuses
// a request the document does not allow, so a pass means the generated
// client and Attome's layer send what the API declares.
using Attome.Sdk;
using Attome.Sdk.Client;
using Attome.Sdk.Model;

var baseUrl = args.Length > 0 ? args[0] : "http://127.0.0.1:4010";
var client = new AttomeClient(baseUrl, "pk_smoke", "secret", retries: 0);
var id = Guid.NewGuid();

var listed = 0;
await foreach (var _ in client.Records("account", pageSize: 10, maxPages: 2))
{
    listed++;
}

var created = await client.CreateAsync("account", new Dictionary<string, object> { ["name"] = "Smoke" });
if (created.Id == Guid.Empty) throw new Exception("create returned no id");

var updated = await client.UpdateAsync("account", id, 1, new Dictionary<string, object> { ["name"] = "Smoke 2" });
if (updated.Data == null) throw new Exception("update returned no data");

var answer = await client.Queries.ExecuteAsync(new ExecuteQueryRequest(entity: "account", pageSize: 5));
if (answer.Data == null) throw new Exception("query returned no data");

var anonymous = new AttomeClient(baseUrl, retries: 0);
try
{
    await foreach (var _ in anonymous.Records("account", maxPages: 1)) { }
    throw new Exception("a call without an API key was accepted");
}
catch (ApiException error) when (error.ErrorCode == 401)
{
}

Console.WriteLine($"csharp sdk smoke: ok ({listed} records listed)");
