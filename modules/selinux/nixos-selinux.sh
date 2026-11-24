# nixos-selinux: what SELinux is doing on this NixOS system, in plain terms.
#
# The module fills in: @type@, @mode@, @units@ (a file of "unit domain"
# lines) and @setup@ (the labelling tool of the running system).

usage() {
  cat <<'USAGE'
Usage: nixos-selinux <command>

  status            Is SELinux on, in which mode, and is every confined
                    service running in its domain?
  denials           What the policy denied since boot, grouped.
  denials --rules   The same, as allow rules to review and paste into
                    security.selinux.services.<name>.rules.
  denials --all     Since the journal began, not only this boot.
  relabel           Restore every label: the Nix store and the system's
                    mutable paths. Rarely needed; the system does this
                    itself at boot, at switch and after optimisation.
  help              This text.

Locked out of an enforcing system? In the boot loader, pick the previous
generation, or add enforcing=0 to the kernel command line.
USAGE
}

need_root() {
  if [ "$(id -u)" != 0 ]; then
    echo "nixos-selinux $1 needs root. Try: sudo nixos-selinux $1" >&2
    exit 1
  fi
}

# Prints "count|source|target|class|permissions|program|mode" per group.
denial_groups() {
  local boot=(-b)
  if [ "${1:-}" = all ]; then boot=(); fi
  journalctl "${boot[@]}" --no-pager -o cat 2>/dev/null \
    | awk '
        /avc: +denied/ {
          perms = ""; source = ""; target = ""; class = ""; comm = "-"; mode = "blocked"
          if (match($0, /\{[^}]*\}/)) perms = substr($0, RSTART + 2, RLENGTH - 4)
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^scontext=/) { split($i, a, ":"); source = a[3] }
            else if ($i ~ /^tcontext=/) { split($i, a, ":"); target = a[3] }
            else if ($i ~ /^tclass=/) { class = substr($i, 8) }
            else if ($i ~ /^comm=/) { comm = substr($i, 6); gsub(/"/, "", comm) }
            else if ($i == "permissive=1") { mode = "logged" }
          }
          if (source == "" || target == "" || class == "") next
          key = source "|" target "|" class "|" mode
          count[key]++
          if (!((key, "comm", comm) in seen)) {
            seen[key, "comm", comm] = 1
            comms[key] = comms[key] (comms[key] == "" ? "" : ",") comm
          }
          n = split(perms, p, " ")
          for (j = 1; j <= n; j++) if (!((key, p[j]) in seen)) {
            seen[key, p[j]] = 1
            all[key] = all[key] (all[key] == "" ? "" : " ") p[j]
          }
        }
        END {
          for (key in count) {
            split(key, k, "|")
            print count[key] "|" k[1] "|" k[2] "|" k[3] "|" all[key] "|" comms[key] "|" k[4]
          }
        }' \
    | sort -t'|' -k2,2 -k1,1nr
}

cmd_status() {
  local problems=0
  if [ ! -e /sys/fs/selinux/enforce ]; then
    echo "SELinux:  not active in this boot (configured: @type@ policy, @mode@)"
    echo "          The kernel was started without it. Reboot into this generation."
    exit 1
  fi
  local current=permissive
  if [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then current=enforcing; fi
  echo "SELinux:  active, $current"
  if [ "$current" != "@mode@" ]; then
    echo "          The configuration says @mode@. It applies at the next boot or switch."
  fi
  if [ "$current" = enforcing ]; then
    echo "          Rescue, from the boot loader: the previous generation, or add enforcing=0."
  fi
  if [ "$current" = permissive ]; then
    echo "          Nothing is blocked. What would be blocked is logged: nixos-selinux denials"
  fi
  echo "Policy:   @type@"
  echo
  if [ -s "@units@" ]; then
    printf '%-28s %-22s %s\n' "Confined service" "Domain" "State"
    while read -r unit domain; do
      local pid actual state
      pid=$(systemctl show -P MainPID "$unit.service" 2>/dev/null || echo 0)
      if [ -z "$pid" ] || [ "$pid" = 0 ]; then
        state="not running"
      else
        actual=$(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null | cut -d: -f3)
        if [ "$actual" = "$domain" ]; then
          state="ok"
        else
          state="WRONG: runs as ${actual:-unknown}"
          problems=1
        fi
      fi
      printf '%-28s %-22s %s\n' "$unit" "$domain" "$state"
    done < "@units@"
    echo
    echo "Every other service runs unconfined. security.selinux.services confines more."
  else
    echo "No service is confined on this system."
  fi
  if [ "$problems" = 1 ]; then
    echo
    echo "A service in the wrong domain usually means its program lost its label."
    echo "Run: sudo nixos-selinux relabel, then restart the service."
    exit 2
  fi
}

cmd_denials() {
  local rules=0 scope=boot
  for arg in "$@"; do
    case "$arg" in
      --rules) rules=1 ;;
      --all) scope=all ;;
      *) usage >&2; exit 64 ;;
    esac
  done
  if [ "$(id -u)" != 0 ] && ! id -nG | grep -qw -e systemd-journal -e wheel; then
    echo "Reading the system journal needs root or the systemd-journal group." >&2
    exit 1
  fi
  local groups
  groups=$(denial_groups "$scope")
  if [ -z "$groups" ]; then
    echo "No denials logged."
    echo "If something still fails with 'Permission denied', the policy may be hiding"
    echo "the denial. Build once with security.selinux.logAllDenials = true."
    return 0
  fi
  if [ "$rules" = 1 ]; then
    echo "# Rules that would allow what was denied. Read each one before using it:"
    echo "# a denial can also mean a file has the wrong label, and then the label"
    echo "# is what to fix. Paste what you want into"
    echo "# security.selinux.services.<name>.rules."
    local last=""
    while IFS='|' read -r _ source target class perms _ _; do
      if [ "$source" != "$last" ]; then
        echo
        echo "# $source"
        last=$source
      fi
      if [ "$source" = "$target" ]; then target=self; fi
      echo "allow $source $target:$class { $perms };"
    done <<< "$groups" | awk '!seen[$0]++ || $0 == ""'
  else
    printf '%5s  %-24s %-24s %-14s %-9s %-14s %s\n' Times Domain "Target type" Class Result Programs Permissions
    while IFS='|' read -r count source target class perms comm mode; do
      printf '%5s  %-24s %-24s %-14s %-9s %-14s %s\n' "$count" "$source" "$target" "$class" "$mode" "$comm" "$perms"
    done <<< "$groups"
    echo
    echo "'blocked' was refused. 'logged' was allowed because the system or that"
    echo "domain is permissive. For rules: nixos-selinux denials --rules"
  fi
}

cmd_relabel() {
  need_root relabel
  # Forget that the mutable paths were done, so they are done again.
  rm -f /var/lib/selinux-nixos/relabelled
  exec "@setup@" --relabel-mutable
}

case "${1:-help}" in
  status) cmd_status ;;
  denials) shift; cmd_denials "$@" ;;
  relabel) cmd_relabel ;;
  help | --help | -h) usage ;;
  *) usage >&2; exit 64 ;;
esac
