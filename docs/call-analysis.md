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

## Questions, objections and scorecards

After a call is analysed, the redacted transcript goes once to the deployment's generation model (the
self-hosted one unless your AI provider settings say otherwise; the task is `callintel.extract`), within
the call owner's AI budget. It answers with the questions asked, objections, next steps and price
mentions, each tied to the moment in the call it comes from, and a proposed answer to each question of the
latest scorecard. Anything placed at a moment the transcript does not have is dropped. Scorecard answers
are only **proposed**: a person confirms them. Nobody's mood or tone is scored. When the budget is spent or
no model answers, the analysis stays as it is.

## Trends

Every night the analysed calls of the day before are summed up per team (the team of the call's activity
owner) into `call_daily_aggregate`: the number of calls, the average staff talk share, the average
questions per call, the share of scorecard answers that are yes, and each tracker's hits. A day's rows are
rebuilt whole, so running it again gives the same rows. Three stored queries read them: **Call trackers by
week**, **Call talk share by team** and **Call scorecard results by team** (`call_daily_aggregate.read`).

## Competitors and other engines

Every competitor in the sales pack (`competitor`) that is tracked becomes a call tracker of its own, its
English and Arabic names as the exact terms; renaming the competitor updates the tracker (a new tracker
version), and deleting it or turning off `is_tracked` turns the tracker off while keeping its hits. This
runs every five minutes from the change feed. When an analysis is done it writes the event
`callintel.analysis_done` on the `call_analysis` record, which deal health, competitive intelligence and
conversation signals read; the event carries no transcript text.

## Coaching

- **Next steps to tasks.** A finding (a next step, most often) becomes a task on the call's deal (else on the
  call) owned by the call's owner; the finding remembers it, so asking again gives the same task.
- **Confirmed scores.** Only a manager of the call's owner (anyone holding a position above the owner's)
  confirms a scorecard answer as yes, no or unclear.
- **Comments.** The owner, their managers and peers holding `call_comment.create` comment at a moment of the
  call; the owner is notified of others' comments. The owner and their managers read all comments; anyone
  else reads only their own.

## Routes

- `GET /api/v1/callintel/calls/{activity_id}`: the call's latest analysis, findings and scorecard answers;
  the talk patterns only for the call's owner and their managers. You must be able to read the call.
- `GET /api/v1/callintel/calls/{activity_id}/recording`: a short-lived link to the recording. Every
  playback is written to the audit log.
- `POST /api/v1/callintel/findings/{id}/task`, `POST /api/v1/callintel/scorecard-answers/{id}/confirm`
  (`{value, row_version}`) and `POST /api/v1/callintel/calls/{activity_id}/comments`
  (`{at_ms, body, parent_id}`): the coaching steps above.

All need `call_analysis.read` and are hidden while the call analysis module is off.

## Staff privacy

`GET /api/v1/callintel/my-analyses` lists every analysis of the caller's own calls, newest first, so staff
see all that is analysed about them. The notice staff are shown is the setting
`callintel.staff_notice_text` (English and Arabic). No analysis scores staff sentiment.

## The call page

`/xrm/calls/{activity_id}` shows a call: the recording player (each play is audited), the highlights as a
timeline that jumps the player to their second, the redacted transcript with each line right to left when
it is Arabic, the scorecard (confirming is for managers), the talk patterns as a coaching aid when you may
see them, and comments at the current moment.

## Settings and what is off by default

| Setting | Default | What it does |
|---|---|---|
| `callintel.enabled` | off | Turns analysis on. Until then nothing is analysed and nothing is kept beyond the transcript. |
| `callintel.staff_notice_text` | a short notice in English and Arabic | What staff are told about the analysis of their calls. |

With the module on, still off until set up: the extraction (questions, objections, next steps, proposed
scorecard answers) runs only where a generation model answers within the call owner's AI budget;
trackers exist only as administrators (or the competitor sync) create them; scorecards exist only as
administrators write them. Talk patterns are shown only to the call's owner and their managers, scores
are confirmed only by managers, and no staff sentiment is ever scored.

## Agent tools

Three read-only tools, all as the caller (`call_analysis.read`, and read access to each call):
`callintel.search_calls` (`tracker`, optional `from` and `to`: the calls that hit a tracker, with their
moments), `callintel.deal_highlights` (`opportunity_id`: a deal's calls and their findings, each linked to
its second in the call) and `callintel.coaching_brief` (`user_id`, optional `from` and `to`: one person's
calls with talk patterns and scorecard answers, for that person or a manager above them; anyone else gets
not found).

## Open points

- **Notice or consent.** Staff are told through `callintel.staff_notice_text`; nobody is asked to consent.
  Whether a notice is enough for analysing staff calls under the laws of Saudi Arabia, the United Arab
  Emirates and Egypt has **not** been checked by a lawyer. Have it checked before turning analysis on in
  those countries, and ask customers' consent to record where the law requires it.
- **Arabic dialects.** Trackers match exact terms after normalisation. How well that finds Gulf, Egyptian,
  Levantine or Maghrebi phrasings has **not** been measured; list the dialect forms you expect as extra terms.

