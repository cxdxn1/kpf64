## kpf64
Basic ARM64 patchfinder for XNU kernelcaches - supports all 64-bit kernelcaches except ARM64E (A12+).

More functionality including finding certain useful symbols on stripped kernelcaches, actual kernel patches (which can be incorparated into a jailbreak or exploit) will be added in the forseeable future.

## Compiling
1. Clone the repository
```zsh
git clone https://github.com/cxdxn1/kpf64
```
2. Compile the library
```zsh
cd kpf64
cd libpf64
make
```
3. Compile the source
```zsh
cd ..
make
```
4. Run the binary
```zsh
./kpf64 <your-kernelcache-path-here>
```
## Usage
The patchfinder is made up of a library called libpf64 that contains all source code and everything needed for kernel patchfinding (MachO parsing, finding XREFs, strings, etc) and the actual source code just contains an example of how that library could be used in a KPF context. 

Keep in mind the source code is still pretty limited as it just opens the kernelcache and fetches kernel information using libpf64 however more functionality will be added to this soon as previously mentioned.

## Credits
- [plooshi for plooshfinder](https://github.com/plooshi/plooshfinder)
- [opa334/Alfie for ChOma](https://github.com/opa334/ChOma)

## License
This software is licensed under the MIT license, meaning you may redistribute, modify and use it as you please.
