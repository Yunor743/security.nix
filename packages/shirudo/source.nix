# shirudo sources, pinned (pre-release: no tagged version yet).
{ fetchFromGitHub }:
{
  version = "0-unstable-2026-11-24";
  src = fetchFromGitHub {
    owner = "shirudo-dev";
    repo = "shirudo";
    rev = "0132734bb2ef04cde6f73f85aedac776a4e60a6c";
    hash = "sha256-IkqsmDgVUaUBrwVGHNU7DexaECD9C5WQ1RWPmW5C0pk=";
  };
}
