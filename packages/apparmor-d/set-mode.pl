#!/usr/bin/env perl
# Put every profile of a file in complain mode through its flags, in place.
#
# `apparmor_parser --complain` would do the same at load time, but disables
# the policy cache for those profiles, so a whole apparmor.d set in complain
# mode would be recompiled at every boot.
use strict; use warnings;
my $file = shift or die "usage: set-mode.pl FILE\n";
open(my $in, '<', $file) or die "$file: $!";
my @lines = <$in>;
close $in;
for (@lines) {
  # Profile and hat declarations: "profile name ... {", "/path {", "^hat {".
  next unless /^\s*(?:profile\s|hat\s|\^|\/|@\{)/ && /\{\s*$/;
  next if /^\s*(?:include|if\s|else)/;
  if (/flags=\(([^)]*)\)/) {
    my $flags = $1;
    next if $flags =~ /\b(?:complain|unconfined|kill|prompt|enforce)\b/;
    s/flags=\(\Q$flags\E\)/flags=($flags,complain)/;
  } else {
    s/\s*\{\s*$/ flags=(complain) {\n/;
  }
}
open(my $out, '>', $file) or die "$file: $!";
print $out @lines;
close $out;
