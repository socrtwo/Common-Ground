# Moderation Policy

## Rules (the only grounds for removal)
1. No doxxing: never post names, photos, addresses, or identifying details of anyone.
2. No operational information: no planned actions, locations, or case specifics.
3. No threats, harassment, or slurs.
4. Argue with ideas, not people. Good-faith disagreement is welcome.
5. Do not claim to be an agent without the verified badge.

## Principles
- Remove for rule violations only; viewpoint is never grounds for removal.
- Every removal cites a rule; removed posts leave a visible placeholder.
- Mutes are time-limited, not permanent bans.
- Every action appears in the public mod log (/modlog).
- Staff the moderator team from both sides (at least one verified agent
  and one community member).

## How the software applies them
- A post, or a thread title, cannot be removed without selecting one of the
  five rules; the server rejects the request otherwise. The rule is written
  to the public log with the action.
- A removed post is replaced by "[removed by moderator — see mod log]" and a
  removed title by "[title removed by moderator]". The thread itself stays.
- A mute is a whole number of days, capped at 365. A new mute never shortens
  one already running.
- Mistakes are reversible. Moderators can restore a post or title and lift a
  mute; each of those is logged too.
- A removed post or title can then be purged, which erases the text for
  good. This is for doxxing and similar material that must not linger. It
  is logged, cannot be undone, and leaves the placeholder in place.
- Members report a post by choosing the rule they believe it breaks. One
  report per member per post. Dismissing reports without removal is logged.
- The log shows the action, the target (post number and handle), the rule or
  reason, the time, and the acting moderator's label. It never shows who
  filed a report.
- Each moderator can be given their own key (`CG_MOD_KEYS`) with a public
  label and a side, `agent` or `community`. The log shows both, so readers
  can see which side acted. Labels should be roles, never names.
- An agent-side key works only from a forum account whose agent badge is
  currently valid. "Agent side" in the log therefore means a verified
  employee acted, without revealing which one.
- With `CG_REQUIRE_BOTH_SIDES=1` the site has no moderation at all unless
  both an agent-side and a community-side key are configured.
- Purging erases the text from the live database file and its journal.

## What the software does not do
- It cannot verify who holds a community-side key or stop moderators
  sharing keys.
- It does not require both sides to agree on an individual action; either
  side's moderator can act alone, and the log shows which did.
- It does not purge automatically, and a purge cannot reach backups or
  other copies of the database made earlier.
