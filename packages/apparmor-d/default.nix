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
      priority=3 /nix/store/*/{bin,sbin,libexec}/.*-wrapped* rix,
    EOF
    done

    find $tree -type f -not -path "$tree/abi/*" -not -path "$tree/tunables/*" \
      | while read -r f; do
          case "$f" in
            "$tree"/abstractions/*) p=1 ;;
            *) p=2 ;;
          esac
          AA_PRIORITY=$p perl ${./exec-priority.pl} "$f" > "$f.tmp"
          mv "$f.tmp" "$f"
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
