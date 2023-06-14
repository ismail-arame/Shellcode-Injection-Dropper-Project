# Shellcode-Injection-Dropper-Project
## Features

    XOR encrypted shellcode and strings
    Obfuscated function calls, by Resolving addresses at runtime using GetProcAddress and GetModuleHandle
    Payload stored in the resources (.rsrc) section of the PE

## Getting Started

By executing implant.exe, a process injection happens into explorer.exe, which pops up the MessageBox coming from the explorer.exe process.
