### Compile `debug.cpp`
```bash
g++ -g -no-pie -fno-pie debug.cpp -o debug
```
- **`-g`** makes the symbols available
- **`-no-pie`** (link without PIE) fixed virtual addresses non-PIE (Position Independent Executable)
- **`-fno-pie`** (compile without PIE support)
- **No ASLR** Address Space Layout Randomization.

This is done so that addresses remain the same and easy for debugging

### Object Dump and Source Interleaving
```bash
objdump -d -S ./debug
```
This shows
- C source
- Assembly
- Addresses

### Compile and Run `main.cpp`
```bash
g++ main.cpp -o a
./a ./debug
```