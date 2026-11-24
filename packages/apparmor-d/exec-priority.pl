#!/usr/bin/env perl
# Give priority to exec rules on a specific program over wildcard exec rules.
# On FHS systems "@{bin}/foo Px" is an exact path and wins over "@{bin}/* ix";
# once @{bin} also covers /nix/store/*/bin both are globs, which the parser
# rejects as "conflicting x modifiers". AppArmor >= 4.1 rule priority restores
# the intended precedence.
use strict; use warnings;
my $prio = $ENV{AA_PRIORITY} // 1;
while (my $line = <>) {
  if ($line =~ /^(\s*)((?:audit\s+)?(?:owner\s+)?)([@\/]\S+)(\s+)([a-zA-Z]*x)(\b.*)$/s
      && $line !~ /^\s*(?:deny|priority=)/) {
    my ($ind, $q, $path, $sp, $mode, $rest) = ($1, $2, $3, $4, $5, $6);
    my $last = $path; $last =~ s{.*/}{};
    if ($path !~ /\*\*/ && $last !~ /\*/ && $last ne '') {
      $line = "${ind}priority=$prio ${q}${path}${sp}${mode}${rest}";
    }
  }
  print $line;
}
