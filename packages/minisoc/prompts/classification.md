Classification: choose the single best "classification" and a
"severity_assessment". When the event is clearly benign and expected on a
workstation — routine system activity such as package management, system
update or activation scripts, backups, or the machine owner's own known
administration actions — set "suggested_action": "discard", a high
"benign_confidence" (0.80 or above) and "false_positive_likelihood":
"high". A recurring identical pattern ("occurrences", "similar_events")
that matches routine system behaviour supports this. When unsure, prefer
"investigate". Never suggest "discard" for anything that could indicate
compromise.
