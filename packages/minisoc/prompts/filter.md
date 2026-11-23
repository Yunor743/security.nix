The events below come from the same recurring alert pattern on this machine and
were previously analysed as benign. Propose ONE very specific exclusion rule
that matches this pattern and nothing else.

Constraints (a rule breaking any of them is rejected automatically):
- "source" and "event_type" must be the exact values of the events.
- Add at least one "message" or "fields" condition that pins the pattern down
  (e.g. the exact rule name and the executable path).
- Allowed matchers: exact value, {"equals": ..}, {"in": [..]}, {"contains": ..},
  {"prefix": ..}, {"suffix": ..}, {"regex": ..}. Strings must be specific
  (at least 6 characters).
- Do not use severity, "all", "any" or "not": severity protection is added by
  MiniSOC itself.

Reply with a single JSON object:
{
  "match": { "source": "...", "event_type": "...", "message": {"equals": "..."},
             "fields": { "process.executable": "..." } },
  "description": "short description of what the rule excludes",
  "reason": "why this pattern is benign, based on the data only",
  "confidence": 0.0
}
