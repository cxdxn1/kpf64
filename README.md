## kpf64
Basic ARM64 patchfinder for XNU kernelcaches - supports all 64-bit kernelcaches except ARM64E (A12+). 

More functionality including finding certain useful symbols on stripped kernelcaches, actual kernel patches (which can be incorparated into a jailbreak or exploit) and ARM64E support will be added in the forseeable future.

## Compiling
1. Clone the repository
```zsh
git clone https://github.com/cxdxn1/kpf64
```
2. Compile the library
```zsh
cd kpf64
cd lib
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

## Credits
- [plooshi for plooshfinder](https://github.com/plooshi/plooshfinder)
- [opa334/Alfie for ChOma](https://github.com/opa334/ChOma)

## License
This software is licensed under the MIT license, meaning you may redistribute, modify and use it as you please.
