# Vector for the checks. Vector 0.59 does not build with the rustc of recent
# nixpkgs: it denies warnings (.cargo/config.toml and crate attributes) and a
# std method it calls is now deprecated. Lint levels only, the behaviour under
# test is unchanged. One of its unit tests compares the text of a std error
# message, which that rustc words differently: it is skipped. Hosts pin a
# buildable Vector with `services.minisoc.collector.package`.
{ vector }:

vector.overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    sed -i 's/"-D", "warnings",/"-A", "deprecated",/' .cargo/config.toml
    grep -rlF '#![deny(warnings)]' --include=*.rs . | xargs -r sed -i '/^#!\[deny(warnings)\]/d'
  '';
  checkFlags = (old.checkFlags or [ ]) ++ [
    "--skip=sinks::util::buffer::compression::test::deserialization_json"
  ];
})
