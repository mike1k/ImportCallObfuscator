# ImportCallObfuscator (ICO)

Obfuscate calls to imports by patching in stubs. ICO works on both X86 and X64 binaries.

# How it works


ICO adds a new section into the image, then begins building stubs for each import that uses a extremely basic routine to decrypt an RVA and places them into the section. 

ICO then searches for `CALL NEAR` instructions that have a destination within the IAT, and replaces this instruction with a relative near call (opcode `E8`) to the newly generated import stub. This leaves an extra byte for use, which can be NOP'd, or even better, exploited to break disassemblers.

The import stubs increments the return address that is pushed onto the stack via `CALL` instructions by one, and abuses the skipped byte by randomizing it which in turns confuses disassemblers into attempting to decode a (usually) invalid sequence of bytes.

# Build

In order to use ICO, ![pepp](https://github.com/mike1k/pepp) and ![spdlog](https://github.com/gabime/spdlog) need to be included so that the main file can be successfully compile. Then a file can be dropped onto the program in which it will spit out a file in the same directory named `{file}.crypt.exe`.

# Examples

![EX1](https://i.imgur.com/BDoj4Tu.png)
![EX2](https://i.imgur.com/3Zbb272.png)

# Limitations

* Will not work on DLLs. The import stubs use the PEB which use the ImageBaseAddress variable as a base. This can be trivially fixed by changing the shellcode to use a known variable for the module base address.

