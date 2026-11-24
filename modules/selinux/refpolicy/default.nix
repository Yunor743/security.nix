# The SELinux reference policy built as one monolithic binary policy, in
# the layout of /etc/selinux/<name>, with a NixOS module added.
{
  lib,
  selinux-refpolicy,
  policycoreutils,
  libselinux,
  name ? "refpolicy",
  policyVersion ? 33,
  extraFileContexts ? "",
  # A directory with `rules` (file context rules for exact store paths)
  # and `paths` (the files they name), or null.
  exactRules ? null,
  # Packages whose programs get the types the reference policy gives the
  # same programs at their usual FHS locations.
  fhsPackages ? [ ],
  # Modules of the system's own, by name: { te, if } as text.
  localModules ? { },
  # false removes the policy's dontaudit rules, so that every denial is
  # logged. For policy development.
  dontaudit ? true,
  # Default values of policy booleans and tunables, by name.
  booleans ? { },
  # Contents of the seusers file; null keeps the reference policy's own.
  seusers ? null,
}:
(selinux-refpolicy.override { inherit policyVersion; }).overrideAttrs (old: {
  pname = "selinux-policy-${name}";

  postPatch =
    (old.postPatch or "")
    + ''
      mkdir -p policy/modules/nixos
      cp ${./nixos.te} policy/modules/nixos/nixos.te
      cp ${./nixos.fc} policy/modules/nixos/nixos.fc
      cp ${./nixos.if} policy/modules/nixos/nixos.if
      echo '<summary>NixOS-specific policy.</summary>' > policy/modules/nixos/metadata.xml
    ''
    + lib.optionalString (localModules != { }) (
      ''
        mkdir -p policy/modules/local
        echo '<summary>Policy of this system.</summary>' > policy/modules/local/metadata.xml
      ''
      + lib.concatStrings (
        lib.mapAttrsToList (
          module: text:
          let
            te = builtins.toFile "${module}.te" "policy_module(${module})\n${text.te}";
            interfaces = builtins.toFile "${module}.if" "## <summary>${module}</summary>\n${text."if"}";
          in
          ''
            cp ${te} policy/modules/local/${module}.te
            cp ${interfaces} policy/modules/local/${module}.if
            : > policy/modules/local/${module}.fc
          ''
        ) localModules
      )
    );

  # `make conf` writes the defaults; change the ones asked for, and fail
  # on a name the policy does not have.
  postConfigure =
    (old.postConfigure or "")
    + lib.concatStrings (
      lib.mapAttrsToList (boolean: value: ''
        grep -q '^${boolean} = ' policy/booleans.conf \
          || { echo "unknown SELinux boolean: ${boolean}" >&2; exit 1; }
        sed -i 's/^${boolean} = .*/${boolean} = ${lib.boolToString value}/' policy/booleans.conf
      '') booleans
    );

  makeFlags = old.makeFlags ++ [
    "MONOLITHIC=y"
    "NAME=${name}"
    "TYPE=mcs"
    "UNK_PERMS=allow"
    # No separation between SELinux users beyond what types give, as in
    # other targeted-style distributions.
    "UBAC=n"
    "SETFILES=${lib.getExe' policycoreutils "setfiles"}"
  ];

  preInstall = lib.optionalString (!dontaudit) ''
    make enableaudit ''${makeFlags[@]}
  '';

  installTargets = "install";

  inherit extraFileContexts;
  passAsFile = [ "extraFileContexts" ];

  # Flatten to the layout the NixOS module expects, and append the rules
  # the system configuration adds. Later rules win over earlier ones.
  postInstall = ''
    mv $out/etc/selinux/${name}/* $out/
    rm -r $out/etc
    # Home directory rules are generated from the accounts in the build
    # sandbox, where root's home is /build.
    sed -i -E 's|^/build([/[:space:]])|/root\1|' $out/contexts/files/file_contexts.homedirs
    # For each program in fhsPackages, ask the policy what type it gives
    # the same file under /usr. Where that is more specific than the
    # generic type the store rules give, write a rule for the exact
    # store path. The hash in the path cannot be chosen by whoever
    # builds another package, so these types cannot be forged.
    mkdir -p $out/nixos
    : > $out/nixos/exact-paths
    lookup() {
      ${lib.getExe' libselinux "selabel_lookup"} -b file \
        -f $out/contexts/files/file_contexts -k "$1" -t file 2>/dev/null \
        | sed -n 's/^Default context: //p'
    }
    for package in ${lib.escapeShellArgs (map toString fhsPackages)}; do
      for dir in bin sbin libexec lib/systemd lib/udev; do
        [ -d "$package/$dir" ] || continue
        find "$package/$dir" -type f -perm -0100 ! -name '*.so*' -print
      done
    done | sort -u > fhs-candidates
    : > fhs-rules
    while IFS= read -r file; do
      relative=''${file#/nix/store/*/}
      wanted=$(lookup "/usr/$relative")
      generic=$(lookup "$file")
      if [ -n "$wanted" ] && [ "$wanted" != "<<none>>" ] && [ "$wanted" != "$generic" ]; then
        printf '%s\t--\t%s\n' "$(printf '%s' "$file" | sed 's/[][\.*+?(){}|^$]/\\&/g')" "$wanted" >> fhs-rules
        echo "$file" >> $out/nixos/exact-paths
      fi
    done < fhs-candidates
    echo "FHS-derived rules: $(wc -l < fhs-rules)"
    cat fhs-rules
    # A rule the system configuration gives for the same path wins.
    cp "$extraFileContextsPath" given-rules
    ${lib.optionalString (exactRules != null) ''
      cat ${exactRules}/rules >> given-rules
      cat ${exactRules}/paths >> $out/nixos/exact-paths
    ''}
    awk -F'\t' 'NR == FNR { given[$1] = 1; next } !($1 in given)' \
      given-rules fhs-rules >> $out/contexts/files/file_contexts
    cat given-rules >> $out/contexts/files/file_contexts
    ${lib.optionalString (seusers != null) ''
      cat ${builtins.toFile "seusers" seusers} > $out/seusers
    ''}
    ${lib.getExe' policycoreutils "setfiles"} -c $out/policy/policy.${toString policyVersion} \
      $out/contexts/files/file_contexts
  '';

  passthru = (old.passthru or { }) // {
    inherit policyVersion;
    policyName = name;
  };
})
