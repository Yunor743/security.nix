# Builds the minimal policy into the layout libselinux expects under
# /etc/selinux/<name>.
{
  lib,
  runCommand,
  python3,
  secilc,
  policycoreutils,
  selinux-refpolicy,

  # Policy name, as used for SELINUXTYPE.
  name ? "minimal",
  # Kernel policy format version. 33 is accepted by every kernel since 5.8.
  policyVersion ? 33,
  # Extra CIL files compiled into the policy.
  extraCil ? [ ],
  # Extra file context lines, appended after the base rules.
  extraFileContexts ? "",
  # A directory with `rules` (file context rules for exact store paths)
  # and `paths` (the files they name), or null.
  exactRules ? null,
}:

runCommand "selinux-policy-${name}"
  {
    nativeBuildInputs = [
      python3
      secilc
      policycoreutils
    ];
    flask = "${selinux-refpolicy.src}/policy/flask";
    inherit extraCil extraFileContexts;
    passAsFile = [ "extraFileContexts" ];
    passthru = {
      inherit policyVersion;
      policyName = name;
      # The generic labelling rules, for the NixOS module to hash.
      fileContexts = ./file_contexts;
    };
    meta = {
      description = "Minimal SELinux policy for NixOS";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
    };
  }
  ''
    python3 ${./gen-flask.py} "$flask" > flask.cil

    mkdir -p $out/policy $out/contexts/files
    policy=$out/policy/policy.${toString policyVersion}

    # A failure here names the file and line of the offending fragment.
    secilc -c ${toString policyVersion} -o "$policy" -f /dev/null \
      flask.cil ${./base.cil} $extraCil

    mkdir -p $out/nixos
    cat ${./file_contexts} "$extraFileContextsPath" \
      ${lib.optionalString (exactRules != null) "${exactRules}/rules"} \
      > $out/contexts/files/file_contexts
    cat ${if exactRules != null then "${exactRules}/paths" else "/dev/null"} > $out/nixos/exact-paths

    # Reject file contexts that name types the policy does not define.
    setfiles -c "$policy" $out/contexts/files/file_contexts
  ''
