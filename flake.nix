{
  description = "C development environment";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: {
    devShells.default = nixpkgs.lib.mkShell {
      packages = with nixpkgs.legacyPackages.x86_64-linux; [
        gcc
        make
        gdb
        valgrind
      ];
    };
  };
}

