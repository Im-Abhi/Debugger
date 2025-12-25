<p align="center">
  <img src="https://img.shields.io/badge/Language-C++-blue.svg" />
  <img src="https://img.shields.io/badge/Platform-UNIX%2FLinux-orange" />
  <img src="https://img.shields.io/badge/Compiler-G++-red" />
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen" />
</p>

# Minimal Linux Debugger (ptrace)

This project implements a **minimal Linux debugger** using the `ptrace` system call.  
It similar to how `gdb` works internally.

To keep debugging **deterministic and simple**, the target binary is compiled **without PIE and ASLR**, ensuring **stable virtual addresses**.

---

## Build & Run Instructions

### 1. Compile the Target Program (`debug.cpp`)

```bash
g++ -g -no-pie -fno-pie debug.cpp -o debug
```
- **`-g`** makes the symbols available
- **`-no-pie`** (link without PIE) fixed virtual addresses non-PIE (Position Independent Executable)
- **`-fno-pie`** (compile without PIE support)
- **No ASLR** Address Space Layout Randomization.

### 2. Compile the debugger program (`main.cpp`)
```bash
g++ main.cpp -o a
```

### 3. Run the debugger with following format
```bash
./a ./debug
```
## Supported Commands
- `step` steps through a single instruction
- `continue` resumes execution of the debugee
- `regs` currently displays 3 registers (`RIP, RSP, RAX`)
- `b <breakpoint_address>` adds a single breakpoint at the specified address
- `exit` exits the debugger process

### 4. Finding addresses from the debuggee 
```bash
objdump -d -S ./debug
```