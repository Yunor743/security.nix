#!/usr/bin/env perl
# NixOS layout: helper programs that FHS distributions install in a
# package sub-directory of lib/ (`@{lib}/openssh/sshd-session`) live
# directly in the package's libexec/ (`/nix/store/<hash>-openssh/libexec/
# sshd-session`).
#
# For exec rules and `@{exec_path}` definitions on `@{lib}/DIR/NAME`, a
# second line with `/nix/store/*/libexec/NAME` is added (prebuild's parser
# does not accept a rule starting with an alternation). Run on the sources,
# before prebuild resolves profile attachments from @{exec_path}.
use strict; use warnings;
my $seg = qr/(?:\{[^{}\/]*\}|[A-Za-z0-9_.+-]+)/;     # one directory, maybe {a,b}
my $name = qr/[A-Za-z0-9_.+\@\{\}-]*[A-Za-z0-9_.+-]/;  # program name, no glob
for my $file (@ARGV) {
  open(my $in, '<', $file) or die "$file: $!";
  my @lines = <$in>;
  close $in;
  my @out;
  my $changed = 0;
  for my $line (@lines) {
    push @out, $line;
    if ($line =~ /^(\s*)\@\{exec_path\}\s*\+?=\s*\@\{lib\}\/$seg\/($name)\s*$/) {
      push @out, "$1\@{exec_path} += /nix/store/*/libexec/$2\n";
      $changed++;
    } elsif ($line =~ /^(\s*(?:priority=\S+\s+)?(?:audit\s+)?(?:owner\s+)?)\@\{lib\}\/$seg\/($name)(\s+[a-zA-Z]*x\b.*)$/s) {
      push @out, "$1/nix/store/*/libexec/$2$3";
      $changed++;
    }
  }
  next unless $changed;
  open(my $out, '>', $file) or die "$file: $!";
  print $out @out;
  close $out;
}
