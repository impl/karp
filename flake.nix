# SPDX-FileCopyrightText: 2022 Noah Fontes
#
# SPDX-License-Identifier: Apache-2.0

{
  outputs = { self, nixpkgs }: with nixpkgs.lib; let
    metadata = importTOML ./Cargo.toml;

    allSystems = builtins.map (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in rec {
      devShells.${system}.default = with pkgs; mkShell {
        nativeBuildInputs = [ cargo clippy lldb rustc rustfmt ];
      };

      packages.${system}.karp = with pkgs; rustPlatform.buildRustPackage {
        pname = metadata.package.name;
        version = metadata.package.version;

        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "papergrid-0.4.0" = "sha256-p2cAUsURRK9HS6oj4hHmuxBpr4A7KcppmU2B5Iv5Mco=";
            "tungstenite-0.17.2" = "sha256-kfzvN+4zNiiuTUVSQxZuWChU/rQuVhdhoxeqwd1Td+A=";
          };
        };

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
