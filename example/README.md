
Commands to use with a QEMU VM to test your configuration

## Complete (re)install

```bash
ssh -p 3333 root@localhost "systemctl stop fapolicyd"
SSHPASS='passwd' nix run github:nix-community/nixos-anywhere -- \
  --flake .#from-local \
  --ssh-port 3333 \
  --env-password \
  --ssh-option StrictHostKeyChecking=no \
  root@localhost
```

## Push a new configuration

```bash
nix shell nixpkgs#sshpass -c bash -c 'sshpass -p "passwd" env NIX_SSHOPTS="-o PreferredAuthentications=password -p 3333" nixos-rebuild switch --flake .#from-local --target-host user@localhost --build-host user@localhost --sudo'
```
