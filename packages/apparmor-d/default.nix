{
  lib,
  buildGoModule,
  fetchFromGitHub,
  apparmor-profiles,
  apparmor-parser,
  perl,
}:

# apparmor.d (https://github.com/roddhjav/apparmor.d), built with its own
# preprocessor for a "nixos" distribution and adapted to the Nix store.
#
# nixpkgs' roddhjav-apparmor-rules only copies the raw sources, which do not
# load on NixOS (unresolved directives, FHS-only paths). Here:
#
# 1. `prebuild` generates the profiles (ABI 4, AppArmor 4.1) for a "nixos"
#    distribution added by a small patch.
# 2. The result is laid over the stock AppArmor abi/abstractions/tunables.
# 3. NixOS adaptations:
#    - @{bin}, @{sbin} and @{lib} also cover /nix/store/*/..., since AppArmor
#      matches the resolved path of an executable;
#    - every profile may read the store and map its programs and libraries
#      (abstractions/base{,-strict}.d/nixos), the store being world-readable;
#    - exec rules on a specific program get a rule priority over wildcard
#      exec rules (see exec-priority.pl), profiles over abstractions.
# 4. Every profile is compiled with apparmor_parser. The few that still fail
#    are moved to share/apparmor.d/nixos/incompatible/ with the error, so the
#    loaded set always compiles.
# 5. `complain` flags are removed so the NixOS module decides each profile's
#    mode at load time; upstream's own complain list is kept in
#    share/apparmor.d/nixos/upstream-complain.
buildGoModule (finalAttrs: {
  pname = "apparmor-d";
  version = "0-unstable-2026-11-23";

  src = fetchFromGitHub {
    owner = "roddhjav";
    repo = "apparmor.d";
    rev = "4c4fec70fcd19307a871b3ecc7f117a9ad989c9f";
    hash = "sha256-ghkY/jstSYSYxxOkgd2Cub2MZIFfpJj4vCgJDIe0jYU=";
  };

  vendorHash = "sha256-aGqnmqCnp3uhbO93P2iFU5BEQMZAFnWfnwpGUM9pF/0=";

  subPackages = [
    "cmd/prebuild"
    "cmd/aa-log"
  ];

  nativeBuildInputs = [
    apparmor-parser
    perl
  ];

  postPatch = ''
    # NixOS as a distribution of its own (no package-manager family).
    substituteInPlace pkg/tasks/os.go \
      --replace-fail '"arch":     {},' '"arch":     {},
    		"nixos":    {},'
    substituteInPlace cmd/prebuild/configure.go \
      --replace-fail 'case "arch", "opensuse":' 'case "arch", "opensuse", "nixos":'
    # Same exclusions as Arch, plus the pacman group.
    { cat dists/ignore.d/arch.conf
      printf '\n# Arch package manager\napparmor.d/groups/pacman\n'
    } > dists/ignore.d/nixos.conf

    # (3) Store paths. prebuild resolves @{bin}/@{lib}/@{sbin} in profile
    # attachments ("profile ls /{,usr/}bin/ls") from values built into it,
    # and the tunables give them to the rules: both must cover the store.
    # prebuild also drops @{sbin} for distributions without a package-manager
    # family, so it is defined here.
    substituteInPlace pkg/aa/apparmor.go \
      --replace-fail '"bin", Values: []string{"/{,usr/}bin"}' \
        '"bin", Values: []string{"/{,usr/}bin", "/nix/store/*/bin", "/run/wrappers/wrappers.*"}' \
      --replace-fail '"lib", Values: []string{"/{,usr/}lib{,exec,32,64}"}' \
        '"lib", Values: []string{"/{,usr/}lib{,exec,32,64}", "/nix/store/*/lib{,exec,32,64}"}'
    substituteInPlace pkg/builder/userspace.go \
      --replace-fail 'tasks.Distribution == "arch" || tasks.Distribution == "fedora"' \
        'tasks.Distribution == "arch" || tasks.Distribution == "fedora" || tasks.Distribution == "nixos"' \
      --replace-fail 'Values: []string{"/{,usr/}{,s}bin"}' \
        'Values: []string{"/{,usr/}{,s}bin", "/nix/store/*/{,s}bin", "/run/wrappers/wrappers.*"}'
    # Helpers FHS distributions put in lib/<package>/ are in libexec/ on
    # NixOS (sshd-session, ...): see nix-libexec.pl.
    find apparmor.d -type f -not -path 'apparmor.d/tunables/*' -print0 \
      | xargs -0 perl ${./nix-libexec.pl}
    # Literal FHS paths (/usr/bin/foo, /usr/share/...): see nix-fhs.pl.
    find apparmor.d -type f -not -path 'apparmor.d/tunables/*' -print0 \
      | xargs -0 perl ${./nix-fhs.pl}
    substituteInPlace apparmor.d/tunables/multiarch.d/system \
      --replace-fail '@{bin}=/{,usr/}bin' \
        '@{bin}=/{,usr/}bin /nix/store/*/bin /run/wrappers/wrappers.*' \
      --replace-fail '@{lib}=/{,usr/}lib{,exec,32,64}' \
        '@{lib}=/{,usr/}lib{,exec,32,64} /nix/store/*/lib{,exec,32,64}
    @{sbin}=/{,usr/}{,s}bin /nix/store/*/{,s}bin /run/wrappers/wrappers.*'
  '';

  postBuild = ''
    DISTRIBUTION=nixos "$GOPATH/bin/prebuild" --buildir .build --abi 4 --version 4.1

    tree=$PWD/tree
    mkdir -p $tree
    for d in abi abstractions tunables; do
      cp -r ${apparmor-profiles}/etc/apparmor.d/$d $tree/
    done
    chmod -R u+w $tree
    cp -r .build/apparmor.d/. $tree/

    # apparmor.d transitions to some profiles it expects from the stock
    # AppArmor package (runc, crun, podman...: `flags=(unconfined)` stubs
    # allowing user namespaces). Without them a `px` to these programs is
    # denied once enforced (Docker cannot start containers). Add the stock
    # unconfined profiles apparmor.d does not define, attached in the store
    # too.
    mkdir -p $tree/stock
    for f in ${apparmor-profiles}/etc/apparmor.d/*; do
      [ -f "$f" ] || continue
      grep -q 'flags=(unconfined)' "$f" || continue
      name=$(perl -ne 'print $1 and exit if /^profile\s+(\S+)/' "$f")
      [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || continue
      grep -rqE "^profile $name( |$)" .build/apparmor.d && continue
      perl -pe 's{^(profile\s+\S+\s+)/(\S+?)/([^/\s{}]+)(\s)}{$1/\{$2/$3,nix/store/*/\{bin,sbin,libexec\}/$3\}$4}' \
        "$f" > $tree/stock/$name
    done

    find $tree -type f -not -path "$tree/abi/*" -not -path "$tree/tunables/*" \
      | while read -r f; do
          case "$f" in
            "$tree"/abstractions/*) p=2 ;;
            *) p=3 ;;
          esac
          AA_PRIORITY=$p perl ${./exec-priority.pl} "$f" > "$f.tmp"
          mv "$f.tmp" "$f"
        done

    # NixOS packaging specifics, inserted before each profile's local hook
    # (users keep local/<profile> for themselves).
    fix() {
      f=$(grep -rl "^  include if exists <local/$1>" $tree --include='*' | head -1)
      [ -n "$f" ] || { echo "nixos fix: no profile $1" >&2; exit 1; }
      R="$2" perl -0pi -e "s|(  include if exists <local/$1>)|  # NixOS\n\$ENV{R}\n\$1|" "$f"
    }
    # bin/dockerd is a wrapper running libexec/docker/dockerd.
    fix dockerd '  priority=3 /nix/store/*/libexec/docker/dockerd rix,'
    # bin/docker is a wrapper running libexec/docker/docker.
    fix docker '  priority=3 /nix/store/*/libexec/docker/docker rix,'
    # The Wayland greeter of sddm runs on weston; it reads the input
    # devices from sysfs and udev.
    fix sddm '  priority=3 @{bin}/weston rix,
      @{sys}/bus/ r,
      @{sys}/devices/**/uevent r,
      @{run}/udev/data/* r,
      @{run}/systemd/sessions/* r,'
    # Polkit agent for interactive authentication.
    fix loginctl '  @{bin}/pkttyagent Px,
      signal send set=(cont term winch) peer=pkttyagent,'
    # NixOS openresolv notifies the resolvers it updates.
    fix resolvconf '  capability kill,
      capability sys_resource,
      signal send,
      @{run}/*/pid r,'
    # NixOS keeps the CUPS configuration in /var/lib/cups (ServerRoot).
    fix cupsd '  /var/lib/cups/{,**} rw,'
    # NixOS tmpfiles rules for the Nix daemon.
    fix systemd-tmpfiles '  /nix/var/{,**} r,
      /lib64/ r,'
    # systemd --user stops the session bus.
    fix dbus-session '  signal receive peer=systemd-user,'
    # systemd >= 258: logind serves a varlink socket (without it, logind
    # exits at start: no user session).
    fix systemd-logind '  @{run}/systemd/io.systemd.Login rw,'
    # The NixOS service creates the agent socket itself.
    fix spice-vdagentd '  owner @{run}/spice-vdagentd/spice-vdagent-sock rw,'
    # NixOS runs qemu-ga with its state in /run/qemu-ga.
    fix qemu-ga '  owner @{run}/qemu-ga/{,qga.state,qga.state.@{rand6}} rw,'
    # Qt fallback runtime directory of the greeter, cgroup lookup.
    fix sddm '  owner /tmp/runtime-sddm/{,**} rw,
      @{PROC}/@{pid}/cgroup r,
      # The DRM device of the greeter (weston), passed by logind: a
      # disconnected path. Without it the greeter exits at once.
      @{att}/dev/dri/card@{int} rw,
      @{att}/dev/input/event@{int} rw,
      @{sys}/class/{backlight,input}/ r,
      owner @{run}/user/@{uid}/wayland-@{int}.lock rwk,'
    # Session launcher: inherits the session tty and log from sddm.
    fix start-hyprland '  /dev/tty@{int} rw,
      owner @{user_share_dirs}/sddm/wayland-session.log w,'
    # Input devices (PS/2 too), realtime priority of the compositor.
    fix hyprland '  @{run}/udev/data/+serio:* r,
      capability sys_nice,'
    # nscd socket inherited from the caller.
    fix resolvconf '  @{run}/nscd/socket rw,'
    # tailscaled runs resolvconf under its own profile (ix): on NixOS it is
    # a wrapper script around openresolv, a shell script running coreutils,
    # all denied there (tailscaled then loops on stop). The resolvconf
    # profile has the NixOS adaptations: switch to it, above the ix rule.
    fix tailscaled '  priority=4 @{sbin}/resolvconf rPx -> resolvconf,'
    fix containerd '  @{sys}/fs/cgroup/**/cpu.max r,'
    # NixOS keeps the USBGuard rules and IPC ACLs in /var/lib/usbguard.
    fix usbguard-daemon '  /var/lib/usbguard/{,**} r,
      /var/lib/usbguard/*.conf rw,
      /var/lib/usbguard/IPCAccessControl.d/{,**} rw,'
    # The stock authentication abstraction names unix_chkpwd by FHS path:
    # add the store and the setuid wrapper.
    sed -i 's|^\(\s*\)\(priority=[0-9]* \)\?/{,usr/}{,s}bin/unix_chkpwd Px,|&\n\1\2/nix/store/*/{,s}bin/unix_chkpwd Px,\n\1\2/run/wrappers/wrappers.*/unix_chkpwd Px,|' \
      $tree/abstractions/authentication
    grep -q 'run/wrappers/wrappers.\*/unix_chkpwd' $tree/abstractions/authentication
    # Same for the stock AppArmor abstractions (idempotent on the rest).
    find $tree -type f -not -path "$tree/abi/*" -not -path "$tree/tunables/*" -print0 \
      | xargs -0 perl ${./nix-fhs.pl}
    # The fusermount setuid wrapper runs the real program from the store
    # (fusermount children of gvfsd-fuse, flatpak...).
    printf '\n  # NixOS: setuid wrapper, then the store program\n  /nix/store/*/bin/fusermount{,3} rix,\n' >> $tree/abstractions/app/fusermount
    # coreutils is a multi-call binary: see nix-coreutils.pl.
    find $tree -type f -not -path "$tree/abi/*" -not -path "$tree/tunables/*" -print0 \
      | xargs -0 perl ${./nix-coreutils.pl}

    # Written after the priority pass, with explicit priorities: wrapped
    # programs above every rule, the wrapper rule just above wildcards.
    for base in base base-strict; do
      mkdir -p $tree/abstractions/$base.d
      cat > $tree/abstractions/$base.d/nixos <<'EOF'
      # NixOS: the store is world-readable and holds every program, library
      # and configuration file (/etc and /run/current-system are symlinks
      # into it).
      /nix/store/ r,
      /nix/store/*/ r,
      /nix/store/** r,
      /nix/store/*/{bin,sbin,lib,lib32,lib64,libexec}/** mr,
      /run/current-system/sw/** r,
      /etc/static/** r,
      # Nix wrappers: bin/foo is a script running bin/.foo-wrapped, which
      # keeps the wrapper's profile.
      priority=1000 /nix/store/*/{bin,sbin,libexec}/.*-wrapped* rix,
      # Wrapper packages: bin/foo of a wrapper runs bin/foo of the unwrapped
      # package, another store path with the same name. A rule of the
      # profile itself on @{exec_path} has a higher priority.
      if defined @{exec_path} {
        priority=1 @{exec_path} rix,
      }
    EOF
    done

    # (5) Modes are decided at load time.
    nixos=$PWD/nixos
    mkdir -p $nixos/incompatible
    profiles() {
      find $tree -type f -not -path "$tree/abstractions/*" -not -path "$tree/tunables/*" \
        -not -path "$tree/abi/*" -not -path "$tree/mappings/*" -not -name '*.md'
    }
    profiles | xargs grep -lE 'flags=\([^)]*complain' | xargs -r -n1 basename | sort > $nixos/upstream-complain
    profiles | xargs sed -i -E \
      -e 's/flags=\(complain\)//' \
      -e 's/flags=\(([^)]*),complain\)/flags=(\1)/' \
      -e 's/flags=\(complain,([^)]*)\)/flags=(\1)/'

    # (4) Compile everything; set aside what does not compile.
    compile() {
      apparmor_parser -Q -K --config-file /dev/null -I "$tree" -b "$tree" \
        -M "$tree/abi/4.0" "$1" >/dev/null 2>"$1.err" || echo "$1"
    }
    export -f compile
    export tree
    profiles | xargs -P "$NIX_BUILD_CORES" -I{} bash -c 'compile "$1"' _ {} | sort > failed
    while read -r f; do
      name=$(basename "$f")
      { printf '%s\t' "$name"; head -1 "$f.err"; } >> $nixos/incompatible.tsv
      mv "$f" $nixos/incompatible/$name
    done < failed
    find $tree -name '*.err' -delete
    profiles | xargs -n1 basename | sort > $nixos/profiles
    profiles | sed "s|^$tree/||" | sort > $nixos/profile-paths
    echo "apparmor.d: $(wc -l < $nixos/profiles) profiles compile," \
      "$(wc -l < failed) set aside (share/apparmor.d/nixos/incompatible.tsv)"
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 $GOPATH/bin/aa-log $out/bin/aa-log
    mkdir -p $out/etc $out/share/apparmor.d
    cp -r tree $out/etc/apparmor.d
    cp -r nixos $out/share/apparmor.d/nixos
    touch $out/share/apparmor.d/nixos/incompatible.tsv
    # systemd drop-ins (AppArmorProfile= for D-Bus services).
    cp -r .build/systemd $out/share/apparmor.d/systemd
    runHook postInstall
  '';

  meta = {
    description = "Full set of AppArmor profiles (apparmor.d), prebuilt and adapted for NixOS";
    homepage = "https://github.com/roddhjav/apparmor.d";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
    mainProgram = "aa-log";
  };
})
