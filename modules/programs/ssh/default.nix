{ config, lib, ... }:

with lib;

let
  cfg = config.programs.ssh;

  knownHosts = map (h: getAttr h cfg.knownHosts) (attrNames cfg.knownHosts);

  host =
    { name, ... }:
    {
      options = {
        hostNames = mkOption {
          type = types.listOf types.str;
          default = [];
          description = ''
            A list of host names and/or IP numbers used for accessing
            the host's ssh service.
          '';
        };
        publicKey = mkOption {
          default = null;
          type = types.nullOr types.str;
          example = "ecdsa-sha2-nistp521 AAAAE2VjZHN...UEPg==";
          description = ''
            The public key data for the host. You can fetch a public key
            from a running SSH server with the {command}`ssh-keyscan`
            command. The public key should not include any host names, only
            the key type and the key itself.
          '';
        };
        publicKeyFile = mkOption {
          default = null;
          type = types.nullOr types.path;
          description = ''
            The path to the public key file for the host. The public
            key file is read at build time and saved in the Nix store.
            You can fetch a public key file from a running SSH server
            with the {command}`ssh-keyscan` command. The content
            of the file should follow the same format as described for
            the `publicKey` option.
          '';
        };
      };
      config = {
        hostNames = mkDefault [ name ];
      };
    };
  # Taken from: https://github.com/NixOS/nixpkgs/blob/f4aa6afa5f934ece2d1eb3157e392d056be01617/nixos/modules/services/networking/ssh/sshd.nix#L46-L93
  userOptions = {

    options.openssh.authorizedKeys = {
      keys = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          A list of verbatim OpenSSH public keys that should be added to the
          user's authorized keys. The keys are added to a file that the SSH
          daemon reads in addition to the the user's authorized_keys file.
          You can combine the `keys` and
          `keyFiles` options.
          Warning: If you are using `NixOps` then don't use this
          option since it will replace the key required for deployment via ssh.
        '';
      };

      keyFiles = mkOption {
        type = types.listOf types.path;
        default = [];
        description = ''
          A list of files each containing one OpenSSH public key that should be
          added to the user's authorized keys. The contents of the files are
          read at build time and added to a file that the SSH daemon reads in
          addition to the the user's authorized_keys file. You can combine the
          `keyFiles` and `keys` options.
        '';
      };
    };

  };

  authKeysFiles = let
    mkAuthKeyFile = u: nameValuePair "ssh/nix_authorized_keys.d/${u.name}" {
      text = ''
        ${concatStringsSep "\n" u.openssh.authorizedKeys.keys}
        ${concatMapStrings (f: readFile f + "\n") u.openssh.authorizedKeys.keyFiles}
      '';
    };
    usersWithKeys = attrValues (flip filterAttrs config.users.users (n: u:
      length u.openssh.authorizedKeys.keys != 0 || length u.openssh.authorizedKeys.keyFiles != 0
    ));
  in listToAttrs (map mkAuthKeyFile usersWithKeys);

  oldAuthorizedKeysHash = "5a5dc1e20e8abc162ad1cc0259bfd1dbb77981013d87625f97d9bd215175fc0a";
in

{
  imports = [
    (mkRemovedOptionModule [ "services" "openssh" "authorizedKeysFiles" ] "No `nix-darwin` equivalent to this NixOS option.")
  ];

  options = {

    users.users = mkOption {
      type = with types; attrsOf (submodule userOptions);
    };

    /*programs.ssh.knownHosts = mkOption {
      default = {};
      type = types.attrsOf (types.submodule host);
      description = ''
        The set of system-wide known SSH hosts.
      '';
      example = literalExpression ''
        [
          {
            hostNames = [ "myhost" "myhost.mydomain.com" "10.10.1.4" ];
            publicKeyFile = ./pubkeys/myhost_ssh_host_dsa_key.pub;
          }
          {
            hostNames = [ "myhost2" ];
            publicKeyFile = ./pubkeys/myhost2_ssh_host_dsa_key.pub;
          }
        ]
      '';
    };*/
    /*services.openssh.authorizedKeysFiles = mkOption {
      type = types.listOf types.str;
      default = [];
      description = ''
        Specify the rules for which files to read on the host.

        This is an advanced option. If you're looking to configure user
        keys, you can generally use [](#opt-users.users._name_.openssh.authorizedKeys.keys)
        or [](#opt-users.users._name_.openssh.authorizedKeys.keyFiles).

        These are paths relative to the host root file system or home
        directories and they are subject to certain token expansion rules.
        See AuthorizedKeysFile in man sshd_config for details.
      '';
    };*/

    programs.ssh = {
      knownHosts = mkOption {
        default = {};
        type = types.attrsOf (types.submodule host);
        description = lib.mdDoc ''
          The set of system-wide known SSH hosts.
        '';
        example = literalExpression ''
          [
            {
              hostNames = [ "myhost" "myhost.mydomain.com" "10.10.1.4" ];
              publicKeyFile = ./pubkeys/myhost_ssh_host_dsa_key.pub;
            }
            {
              hostNames = [ "myhost2" ];
              publicKeyFile = ./pubkeys/myhost2_ssh_host_dsa_key.pub;
            }
          ]
        '';
      };

      pubkeyAcceptedKeyTypes = mkOption {
        type = types.listOf types.str;
        default = [];
        example = [ "ssh-ed25519" "ssh-rsa" ];
        description = lib.mdDoc ''
          Specifies the key types that will be used for public key authentication.
        '';
      };

      hostKeyAlgorithms = mkOption {
        type = types.listOf types.str;
        default = [];
        example = [ "ssh-ed25519" "ssh-rsa" ];
        description = lib.mdDoc ''
          Specifies the host key algorithms that the client wants to use in order of preference.
        '';
      };


      extraConfig = mkOption {
        type = types.lines;
        default = "";
        description = lib.mdDoc ''
          Extra configuration text written to `/etc/ssh/ssh_config.d/10-extra-nix.conf`.
          See {manpage}`ssh_config(5)` for help.
        '';
      };

      kexAlgorithms = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "curve25519-sha256@libssh.org" "diffie-hellman-group-exchange-sha256" ];
        description = lib.mdDoc ''
          Specifies the available KEX (Key Exchange) algorithms.
        '';
      };

      ciphers = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "chacha20-poly1305@openssh.com" "aes256-gcm@openssh.com" ];
        description = lib.mdDoc ''
          Specifies the ciphers allowed and their order of preference.
        '';
      };

      macs = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "hmac-sha2-512-etm@openssh.com" "hmac-sha1" ];
        description = lib.mdDoc ''
          Specifies the MAC (message authentication code) algorithms in order of preference. The MAC algorithm is used
          for data integrity protection.
        '';
      };
    };
  };

  config = {

    assertions = flip mapAttrsToList cfg.knownHosts (name: data: {
      assertion = (data.publicKey == null && data.publicKeyFile != null) ||
                  (data.publicKey != null && data.publicKeyFile == null);
      message = "knownHost ${name} must contain either a publicKey or publicKeyFile";
    });

    environment.etc = authKeysFiles //
      { "ssh/ssh_known_hosts" = mkIf (builtins.length knownHosts > 0) {
          text = (flip (concatMapStringsSep "\n") knownHosts
            (h: assert h.hostNames != [];
              concatStringsSep "," h.hostNames + " "
              + (if h.publicKey != null then h.publicKey else readFile h.publicKeyFile)
            )) + "\n";
        };
        "ssh/sshd_config.d/101-authorized-keys.conf" = {
          text = ''
            # sshd doesn't like reading from symbolic links, so we cat
            # the file ourselves.
            AuthorizedKeysCommand /bin/cat /etc/ssh/nix_authorized_keys.d/%u
            # Just a simple cat, fine to use _sshd.
            AuthorizedKeysCommandUser _sshd
          '';
          # Allows us to automatically migrate from using a file to a symlink
          knownSha256Hashes = [ oldAuthorizedKeysHash ];
        };
        "ssh/sshd_config.d/10-extra-nix.conf" = {
          text = ''
            ${optionalString (cfg.pubkeyAcceptedKeyTypes != []) "PubkeyAcceptedKeyTypes ${concatStringsSep "," cfg.pubkeyAcceptedKeyTypes}"}

            ${config.programs.ssh.extraConfig}

            ${optionalString (cfg.hostKeyAlgorithms != []) "HostKeyAlgorithms ${concatStringsSep "," cfg.hostKeyAlgorithms}"}
            ${optionalString (cfg.kexAlgorithms != null) "KexAlgorithms ${concatStringsSep "," cfg.kexAlgorithms}"}
            ${optionalString (cfg.ciphers != null) "Ciphers ${concatStringsSep "," cfg.ciphers}"}
            ${optionalString (cfg.macs != null) "MACs ${concatStringsSep "," cfg.macs}"}
          '';
        };
      };

    system.activationScripts.etc.text = ''
      # Clean up .before-nix-darwin file left over from using knownSha256Hashes
      auth_keys_orig=/etc/ssh/sshd_config.d/101-authorized-keys.conf.before-nix-darwin

      if [ -e "$auth_keys_orig" ] && [ "$(shasum -a 256 $auth_keys_orig | cut -d ' ' -f 1)" = "${oldAuthorizedKeysHash}" ]; then
        rm "$auth_keys_orig"
      fi
    '';
  };
}
