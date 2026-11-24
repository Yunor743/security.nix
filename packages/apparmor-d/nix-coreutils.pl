#!/usr/bin/env perl
# NixOS builds coreutils as a single multi-call binary: `@{bin}/cat` resolves
# to `/nix/store/<hash>-coreutils-<ver>/bin/coreutils`. Where a profile (or
# child profile) inherits a coreutils program (`ix`), it also gets the
# multi-call binary, once per profile block, with the same priority.
use strict; use warnings;
my $prog = join '|', qw(
  basename cat chgrp chmod chown cp cut date dd df dirname du echo env expr
  false head id install ln ls md5sum mkdir mkfifo mknod mktemp mv nice nohup
  numfmt od printenv printf readlink realpath rm rmdir seq sha1sum sha256sum
  sleep sort stat stty sync tail tee test timeout touch tr true tty uname
  uniq wc whoami yes);
for my $file (@ARGV) {
  open(my $in, '<', $file) or die "$file: $!";
  my @lines = <$in>;
  close $in;
  my (@out, $done, $changed);
  for my $line (@lines) {
    push @out, $line;
    $done = 0 if $line =~ /^\s*(?:profile|hat|\^)\S*.*\{\s*$/;
    next if $done;
    my ($ind, $prio) = $line =~ /^(\s*)((?:priority=\S+\s+)?)(?:audit\s+)?(?:owner\s+)?\@\{bin\}\/(?:\{[^}]*\}|$prog)\s+r?m?ix,/ or next;
    if ($line =~ /\@\{bin\}\/(?:$prog)\s/ || $line =~ /\@\{bin\}\/\{(?:[^}]*,)?(?:$prog)(?:,[^}]*)?\}/) {
      push @out, "$ind$prio/nix/store/*-coreutils-*/bin/coreutils rix,\n";
      $done = $changed = 1;
    }
  }
  next unless $changed;
  open(my $out, '>', $file) or die "$file: $!";
  print $out @out;
  close $out;
}
