# Loads the SELinux policy if none is loaded yet, and labels the filesystem.
#
# Runs in two places:
#   - in the initrd, chrooted into the new root, before NixOS activation, so
#     that everything activation creates is labelled correctly;
#   - from the activation script on `nixos-rebuild switch`, to label store
#     paths that arrived since the last run.
#
# Nix is not involved. Nix leaves `security.selinux` attributes alone
# (its `ignored-acls` default), so labels set here stay in place.

set -euo pipefail

store=/nix/store
marker=trusted.nixos-selinux
stateDir=/var/lib/selinux-nixos

saved_args=("$@")

policy=
spec=
rev=
mutable_rev=
exact_rev=
exact_file=
remounted=
relabel_mutable=
exact=()
relabel=()

while [ $# -gt 0 ]; do
  case "$1" in
    --policy) policy=$2; shift 2 ;;
    --spec) spec=$2; shift 2 ;;
    --rev) rev=$2; shift 2 ;;
    --mutable-rev) mutable_rev=$2; shift 2 ;;
    --exact-rev) exact_rev=$2; shift 2 ;;
    --exact) exact+=("$2"); shift 2 ;;
    --exact-file) exact_file=$2; shift 2 ;;
    --relabel) relabel+=("$2"); shift 2 ;;
    --remounted) remounted=1; shift ;;
    --relabel-mutable) relabel_mutable=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

: "${mutable_rev:=$rev}"

log() { echo "selinux-setup: $*"; }

if [ -n "$remounted" ]; then
  mount -o remount,bind,rw "$store"
fi

if [ ! -e /sys/fs/selinux/load ]; then
  log "SELinux is not active in the running kernel, nothing to do"
  exit 0
fi

# --- Policy -------------------------------------------------------------------

# Before the first policy load every process runs in the context "kernel".
current=$(tr -d '\0' < /proc/self/attr/current)
if [ "$current" = kernel ]; then
  # The kernel takes the whole policy in a single write.
  dd if="$policy" of=/sys/fs/selinux/load bs=256M status=none
  log "loaded policy $policy"
fi

label_one() {
  # Label a single path without descending into it.
  local path=$1 context
  context=$(selabel_lookup -b file -f "$spec" -k "$path" 2>/dev/null \
    | sed -n 's/^Default context: //p')
  if [ -n "$context" ]; then
    setfilecon "$context" "$path" 2>/dev/null || true
  fi
}

# --- Mutable paths ------------------------------------------------------------

# Top-level directories, every time. New files take their parent
# directory's type, so this alone gets most of what activation creates
# right. On a fresh root some of them do not exist yet. Stage 2 and
# activation would create them a moment later, with these same modes, but
# then they would inherit the root directory's type.
[ -d /etc ] || install -d -m 0755 /etc
[ -d /var ] || install -d -m 0755 /var
[ -d /home ] || install -d -m 0755 /home
[ -d /root ] || install -d -m 0700 /root
[ -d /tmp ] || install -d -m 1777 /tmp
[ -d /var/lib ] || install -d -m 0755 /var/lib
[ -d /var/log ] || install -d -m 0755 /var/log
for dir in / /etc /var /var/lib /var/log /nix /nix/var "$store" /home /root /tmp /boot /bin /usr /usr/bin; do
  if [ -d "$dir" ]; then label_one "$dir"; fi
done

# Symlinks that activation creates under /run and every domain follows.
for link in /run/current-system /run/booted-system; do
  if [ -L "$link" ]; then setfiles -F "$spec" "$link" 2>/dev/null || true; fi
done

# A full pass over the mutable paths, when asked to and only if the
# labelling rules changed since the last one. This runs after activation,
# so it also corrects what inheritance alone got wrong.
if [ -n "$relabel_mutable" ] \
  && [ "$(cat "$stateDir/relabelled" 2>/dev/null || true)" != "$mutable_rev" ]; then
  existing=()
  for path in "${relabel[@]}"; do
    if [ -e "$path" ]; then existing+=("$path"); fi
  done
  if [ ${#existing[@]} -gt 0 ]; then
    log "relabelling ${existing[*]}"
    setfiles -F "$spec" "${existing[@]}"
  fi
  mkdir -p "$stateDir"
  echo "$mutable_rev" > "$stateDir/relabelled.tmp"
  mv "$stateDir/relabelled.tmp" "$stateDir/relabelled"
fi

# --- Nix store ----------------------------------------------------------------

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Every top-level store path. Names starting with a dot are not store
# paths: the hard-link farm of the optimiser and its short-lived temporary
# links, which can vanish while this runs.
find "$store" -mindepth 1 -maxdepth 1 ! -name '.*' -print | sort > "$work/all"

# Store paths that hold a file with an exact rule. Their labels depend on
# those rules as well as on the generic ones.
: > "$work/exact"
: > "$work/exact-files"
{
  if [ ${#exact[@]} -gt 0 ]; then printf '%s\n' "${exact[@]}"; fi
  if [ -n "$exact_file" ] && [ -e "$exact_file" ]; then cat "$exact_file"; fi
} | while IFS= read -r path; do
  root=$(echo "$path" | cut -d/ -f1-4)
  if [ -e "$root" ]; then echo "$root" >> "$work/exact"; fi
  if [ -e "$path" ]; then echo "$path" >> "$work/exact-files"; fi
done
sort -u -o "$work/exact" "$work/exact"

# Store paths already labelled under the current rules carry a marker on
# their top-level inode. A path that is garbage collected and fetched again
# is a new inode without a marker, so it is picked up again by itself.
{
  xargs -a "$work/all" -d '\n' -r \
    getfattr -h --absolute-names -n "$marker" -e text 2>/dev/null || true
} | awk -v plain="$marker=\"$rev\"" -v full="$marker=\"$rev+$exact_rev\"" '
    /^# file: / { file = substr($0, 9) }
    $0 == plain { print file > "'"$work/plain"'" }
    $0 == full { print file > "'"$work/full"'" }
  '
touch "$work/plain" "$work/full"
sort -o "$work/plain" "$work/plain"
sort -o "$work/full" "$work/full"

# Done: marked under the generic rules and without exact rules, or marked
# under both.
{
  comm -23 "$work/plain" "$work/exact"
  comm -12 "$work/full" "$work/exact"
} | sort > "$work/done"

comm -23 "$work/all" "$work/done" > "$work/todo"

# Files with exact rules are checked on every run, whatever the markers
# say. With store optimisation, a file of identical content in another
# store path is the same inode, and labelling that other path under the
# generic rules takes the exact label away. Exact rules are applied last
# so that they win.
drift=
if [ -s "$work/exact-files" ]; then
  drift=$(xargs -a "$work/exact-files" -d '\n' -r setfiles -n -v -F "$spec" 2>/dev/null \
    | grep -c '^Would relabel' || true)
  if [ "$drift" = 0 ]; then drift=; fi
fi

count=$(wc -l < "$work/todo")
if [ "$count" -eq 0 ] && [ -z "$drift" ]; then
  log "store labels are up to date"
  exit 0
fi

# The store is normally mounted read-only. Make it writable in a private
# mount namespace, the same way the Nix daemon does, and start over there.
if [ ! -w "$store" ]; then
  if [ -n "$remounted" ]; then
    echo "selinux-setup: cannot make $store writable" >&2
    exit 1
  fi
  exec unshare --mount -- "$0" --remounted "${saved_args[@]}"
fi

start=$(date +%s)
if [ "$count" -gt 0 ]; then
  log "labelling $count store paths"
  setfiles -F -f "$work/todo" "$spec"
fi
if [ -s "$work/exact-files" ]; then
  if [ -n "$drift" ]; then log "restoring $drift exact labels"; fi
  xargs -a "$work/exact-files" -d '\n' -r setfiles -F "$spec"
fi

# Mark the paths only once all of them are labelled, so an interrupted run
# is repeated in full.
comm -23 "$work/todo" "$work/exact" > "$work/mark-plain"
comm -12 "$work/todo" "$work/exact" > "$work/mark-full"
xargs -a "$work/mark-plain" -d '\n' -r \
  setfattr -h -n "$marker" -v "$rev" 2>/dev/null || true
xargs -a "$work/mark-full" -d '\n' -r \
  setfattr -h -n "$marker" -v "$rev+$exact_rev" 2>/dev/null || true

log "labelled $count store paths in $(( $(date +%s) - start ))s"
