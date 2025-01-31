{ config, lib, pkgs, ... }:

with lib;

let
  cfg  = config.programs.ssh;

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
            from a running SSH server with the <command>ssh-keyscan</command>
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
            with the <command>ssh-keyscan</command> command. The content
            of the file should follow the same format as described for
            the <literal>publicKey</literal> option.
          '';
        };
      };
      config = {
        hostNames = mkDefault [ name ];
      };
    };
in

{
  options = {

    users.users = mkOption {
      type = with types; attrsOf (submodule userOptions);
    };

    programs.ssh = {
      knownHosts = mkOption {
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
      };

      pubkeyAcceptedKeyTypes = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "ssh-ed25519" "ssh-rsa" ];
        description = ''
          Specifies the key types that will be used for public key authentication.
        '';
      };

      hostKeyAlgorithms = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "ssh-ed25519" "ssh-rsa" ];
        description = ''
          Specifies the host key algorithms that the client wants to use in order of preference.
        '';
      };

      kexAlgorithms = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [
          "curve25519-sha256@libssh.org"
          "diffie-hellman-group-exchange-sha256"
        ];
        description = ''
          Specifies the available KEX (Key Exchange) algorithms.
        '';
      };
      ciphers = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "chacha20-poly1305@openssh.com" "aes256-gcm@openssh.com" ];
        description = ''
          Specifies the ciphers allowed and their order of preference.
        '';
      };
      macs = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "hmac-sha2-512-etm@openssh.com" "hmac-sha1" ];
        description = ''
          Specifies the MAC (message authentication code) algorithms in order of preference. The MAC algorithm is used
          for data integrity protection.
        '';
      };

      extraConfig = lib.mkOption {
        type = lib.types.lines;
        default = "";
        description = ''
          Extra configuration text loaded in {file}`ssh_config`.
          See {manpage}`ssh_config(5)` for help.
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
              lib.optionalString h.certAuthority "@cert-authority " + concatStringsSep "," h.hostNames + " "
              + (if h.publicKey != null then h.publicKey else readFile h.publicKeyFile)
            )) + "\n";
        };
        "ssh/ssh_config.d/100-nix-darwin.conf".text = ''
          ${optionalString (cfg.pubkeyAcceptedKeyTypes != [ ])
          "PubkeyAcceptedKeyTypes ${
            concatStringsSep "," cfg.pubkeyAcceptedKeyTypes
          }"}

          ${config.programs.ssh.extraConfig}

          ${optionalString (cfg.hostKeyAlgorithms != [ ])
          "HostKeyAlgorithms ${concatStringsSep "," cfg.hostKeyAlgorithms}"}
          ${optionalString (cfg.kexAlgorithms != null)
          "KexAlgorithms ${concatStringsSep "," cfg.kexAlgorithms}"}
          ${optionalString (cfg.ciphers != null)
          "Ciphers ${concatStringsSep "," cfg.ciphers}"}
          ${optionalString (cfg.macs != null)
          "MACs ${concatStringsSep "," cfg.macs}"}
        '';
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
      };
  };
}
