{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      python-with-packages = pkgs.python3.withPackages (ps: with ps; [
          pyelftools
          capstone
      ]);
    in
    {
        devShells.${system}.default = pkgs.mkShell {
            buildInputs = with pkgs; [
                gcc
                gnumake
                json_c
                libbpf
                bpftools
                llvm
                llvmPackages.clang-unwrapped
                llvmPackages.bintools
                elfutils
                python-with-packages
            ];
        };
    };
}
