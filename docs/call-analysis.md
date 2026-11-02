# Call analysis

When a recorded call's transcript is ready (calls through the voice integration are transcribed by the
deployment's speech endpoint), call analysis can work out how the conversation went: how much each side
talked, the longest stretches, interruptions, questions, and which **trackers** (things to listen for,
such as a competitor or a pricing question) were heard. It belongs to the call intelligence module and
is off until you turn on the setting `callintel.enabled`.

## What it reads

Analysis never reads the raw transcript. When a call's transcript is final, a **redacted copy** is kept
for the analysis: email addresses, phone numbers and IBANs are replaced by tokens. Every figure and every
tracker hit comes from that copy.

Talk patterns need to know who is staff and who is the customer. The analysis uses the speaker labels
the speech endpoint returns: `staff` (or `agent`) and `customer` (or `caller`), as a dual-channel
recording gives them. A call with no labels, or with other labels such as `SPEAKER_00` from a
diariser that cannot tell roles apart, is marked **skipped**.

## Once per transcript

Each call is analysed once per transcript version: transcribing the same recording again makes a new
version and a new analysis; anything else is ignored. The analysis runs in the background after the
call, never during it. Its record (`call_analysis`) moves from `queued` to `done`, `skipped` or `failed`,
and holds the staff talk share, the longest staff monologue and customer story, interruptions, both
sides' questions and the staff's words per minute. Tracker hits are `call_finding` records of kind
`tracker_hit` with the redacted words and their time in the call; a rerun replaces them.

Trackers match by their **exact terms** (Arabic and English, compared after normalisation). Matching by
example phrases needs embeddings, which this analysis does not compute yet.

## Trends

Every night the analysed calls of the day before are summed up per team (the team of the call's activity
owner) into `call_daily_aggregate`: the number of calls, the average staff talk share, the average
questions per call, the share of scorecard answers that are yes, and each tracker's hits. A day's rows are
rebuilt whole, so running it again gives the same rows. Three stored queries read them: **Call trackers by
week**, **Call talk share by team** and **Call scorecard results by team** (`call_daily_aggregate.read`).
