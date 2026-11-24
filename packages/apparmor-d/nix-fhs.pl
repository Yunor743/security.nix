#!/usr/bin/env perl
# Literal FHS paths in exec rules and `@{exec_path}` definitions (the ones
# not written with @{bin}/@{lib}, which the tunables already extend) get a
# Nix store equivalent on an added line:
#   /usr/bin/NAME, /bin/NAME, /usr/sbin/NAME  -> /nix/store/*/{bin,sbin}/NAME
#   /usr/share/PATH                           -> /nix/store/*/share/PATH
#   /usr/lib.../NAME (literal last component) -> /nix/store/*/lib{,exec}/**/NAME
# Run on the sources, before prebuild resolves attachments from @{exec_path}
# (prebuild's parser does not accept a rule starting with an alternation,
# hence one added line per rule).
use strict; use warnings;
my $q = qr/(?:priority=\S+\s+)?(?:audit\s+)?(?:owner\s+)?/;

sub store {
  my ($p) = @_;
  return "/nix/store/*/{bin,sbin}/$1"
    if $p =~ m{^/(?:\{,usr/\}|usr/)?\{?,?s?bin\}?/([^/\s]+)$};
  return "/nix/store/*/share/$1" if $p =~ m{^/usr/share/(\S+)$};
  if ($p =~ m{^/usr/lib[^/]*/(?:\S*/)?([^/\s]+)$}) {
    my $last = $1;
    return undef if $last =~ /[*?\[]/ && $last !~ /[A-Za-z0-9]{3}/;
    return "/nix/store/*/lib{,exec}/**/$last";
  }
  return undef;
}

for my $file (@ARGV) {
  open(my $in, '<', $file) or die "$file: $!";
  my @lines = <$in>;
  close $in;
  my (@out, $changed);
  my %have = map { (s/^\s+|\s+$//gr) => 1 } @lines;   # idempotent
  for my $line (@lines) {
    push @out, $line;
    my $new;
    if ($line =~ /^(\s*)\@\{exec_path\}\s*\+?=\s*(.*?)\s*$/) {
      my ($ind, @alt) = ($1, map { store($_) } grep { m{^/} } split /\s+/, $2);
      @alt = grep { defined } @alt;
      $new = join '', map { "$ind\@{exec_path} += $_\n" } @alt if @alt;
    } elsif ($line =~ /^(\s*$q)(\/\S+)(\s+[a-zA-Z]*x\b.*)$/s) {
      my ($pre, $path, $rest) = ($1, $2, $3);
      my $s = store($path);
      $new = "$pre$s$rest" if defined $s;
    }
    $new = join "", grep { !$have{s/^\s+|\s+$//gr} } split /^/m, $new if defined $new;
    if (defined $new && length $new) { push @out, $new; $changed = 1; }
  }
  next unless $changed;
  open(my $out, '>', $file) or die "$file: $!";
  print $out @out;
  close $out;
}
