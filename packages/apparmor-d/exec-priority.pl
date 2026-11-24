#!/usr/bin/env perl
# Give priority to exec rules on a specific program over wildcard exec rules.
# On FHS systems "@{bin}/foo Px" is an exact path and wins over "@{bin}/* ix";
# once @{bin} also covers /nix/store/*/bin both are globs, which the parser
# rejects as "conflicting x modifiers". AppArmor >= 4.1 rule priority restores
# the intended precedence.
#
# Upstream's own priorities are kept in order (scaled by 10) and ties are
# broken by specificity: + AA_PRIORITY (3 in profiles, 2 in abstractions) for
# a rule whose last path component has no wildcard.
use strict; use warnings;
my $bonus = $ENV{AA_PRIORITY} // 1;
while (my $line = <>) {
  if ($line =~ /^(\s*)(?:priority=(-?\d+)\s+)?((?:audit\s+)?(?:owner\s+)?)([@\/]\S+)(\s+)([a-zA-Z]*x)(\b.*)$/s
      && $line !~ /^\s*(?:priority=\S+\s+)?deny\b/) {
    my ($ind, $up, $q, $path, $sp, $mode, $rest) = ($1, $2 // 0, $3, $4, $5, $6, $7);
    my $last = $path; $last =~ s{.*/}{};
    my $specific = $path !~ /\*\*/ && $last !~ /\*/ && $last ne '';
    my $prio = $up * 10 + ($specific ? $bonus : 0);
    $line = $prio == 0
      ? "${ind}${q}${path}${sp}${mode}${rest}"
      : "${ind}priority=$prio ${q}${path}${sp}${mode}${rest}";
  }
  print $line;
}
