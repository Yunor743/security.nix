# nixpkgs' sbomnix, fixed: it does not build on nixos-unstable at the locked
# revision.
# - SimpleSQLite 1.5.4 and sqliteschema 2.0.1 (pulled by df-diskcache) pin
#   typepy < 2, nixpkgs has typepy 2.0 and pythonRuntimeDepsCheck fails.
#   SimpleSQLite's own test suite passes with typepy 2.0.
# - reuse's Sphinx `man` builder produces nothing with Sphinx 9.1 (missing
#   `man` output): sbomnix only needs the library, keep the HTML docs.
# - makeWrapperArgs is one "--prefix PATH : …" string, which makeWrapper now
#   rejects: split it.
# `grype` and `vulnix` are arguments so that they can be overridden (NVD
# mirror of security.sbomnix, stub of the VM test).
{
  lib,
  sbomnix,
  python3,
  git,
  grype,
  nix,
  nix-visualize,
  vulnix,
}:

let
  python = python3.override {
    self = python;
    packageOverrides =
      _: super:
      let
        relax =
          p:
          p.overridePythonAttrs (old: {
            pythonRelaxDeps = (old.pythonRelaxDeps or [ ]) ++ [ "typepy" ];
          });
      in
      {
        sqliteschema = relax super.sqliteschema;
        simplesqlite = relax super.simplesqlite;
        reuse = super.reuse.overridePythonAttrs {
          outputs = [
            "out"
            "doc"
          ];
          sphinxBuilders = [ "html" ];
        };
      };
  };
in
(sbomnix.override { python3 = python; }).overridePythonAttrs {
  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath [
      git
      nix
      python.pkgs.graphviz
      nix-visualize
      vulnix
      grype
    ])
  ];
}
