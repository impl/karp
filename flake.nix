# SPDX-FileCopyrightText: 2022-2024 Noah Fontes
#
# SPDX-License-Identifier: Apache-2.0

{
  outputs = { self, nixpkgs }: with nixpkgs.lib; let
    metadata = importTOML ./Cargo.toml;

    allSystems = builtins.map (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      # https://github.com/NixOS/nixpkgs/issues/252838
      lldb' = pkgs.lldb.overrideAttrs (_: {
        outputs = [ "out" "dev" ] ++ optionals (!pkgs.stdenv.isDarwin) [ "lib" ];
      });
    in rec {
      devShells.${system}.default = with pkgs; mkShell {
        packages = [ cargo clippy lldb' rustc rustfmt ]
          ++ optionals (pkgs.stdenv.hostPlatform.isDarwin) [ darwin.apple_sdk.frameworks.Security libiconv ];
      };

      packages.${system}.karp = with pkgs; rustPlatform.buildRustPackage {
        pname = metadata.package.name;
        version = metadata.package.version;

        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        buildInputs = optionals pkgs.stdenv.hostPlatform.isDarwin [ darwin.apple_sdk.frameworks.Security ];

        buildFeatures = optionals pkgs.stdenv.hostPlatform.isLinux [ "secret-service" ]
          ++ optionals pkgs.stdenv.hostPlatform.isDarwin [ "keychain" ];

        meta = {
          inherit (metadata.package) description;
          homepage = metadata.package.repository;
          license = licenses.asl20;
        };
      };

      defaultPackage.${system} = packages.${system}.karp;
    }) systems.flakeExposed;
  in builtins.foldl' recursiveUpdate {} allSystems;
}
