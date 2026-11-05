// Attome pipeline starter (P12-T1) for Power BI or Excel Power Query.
// Paste into Home > Advanced Editor of a blank query, then set the two
// parameters below. It reads live records through the OData feed, so the
// report shows only what the API key's person may read.
let
    // The deployment's address, without a trailing slash.
    BaseUrl = "https://crm.example.com",
    // An API key for the person whose access the report should have:
    // "<public-key>:<secret>". Store it as a Power BI parameter or credential,
    // never in a shared file.
    ApiKey = "<public-key>:<secret>",

    Feed = OData.Feed(
        BaseUrl & "/api/v1/odata",
        null,
        [Headers = [Authorization = "Bearer " & ApiKey], Implementation = "2.0"]
    ),

    Opportunities = Feed{[Name = "opportunity", Signature = "table"]}[Data],
    Accounts = Feed{[Name = "account", Signature = "table"]}[Data],

    Deals = Table.SelectColumns(
        Opportunities,
        {"id", "name", "stage", "amount", "currency", "close_date", "account_ref"}
    ),
    AccountNames = Table.RenameColumns(
        Table.SelectColumns(Accounts, {"id", "name"}),
        {{"id", "account_id"}, {"name", "account_name"}}
    ),
    Joined = Table.NestedJoin(
        Deals, {"account_ref"}, AccountNames, {"account_id"}, "account", JoinKind.LeftOuter
    ),
    WithAccount = Table.ExpandTableColumn(Joined, "account", {"account_name"}),
    Typed = Table.TransformColumnTypes(
        WithAccount,
        {{"amount", type number}, {"close_date", type datetimezone}}
    ),
    WithMonth = Table.AddColumn(
        Typed, "close_month", each Date.StartOfMonth(DateTime.Date([close_date])), type date
    )
in
    WithMonth
