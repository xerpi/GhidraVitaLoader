# GhidraVitaLoader
VitaLoader script for Ghidra

# Installation
1. Download this script
2. Download the JAR of the [yamlbeans](https://github.com/EsotericSoftware/yamlbeans/releases) library
3. Open Ghidra and add the JAR path to Ghidra's _Edit_ -> _Plugin Path..._
4. Add the script directory to _Window_ -> _Script manager_ -> _Script Directories_ button in the top right

# Usage
1. Load your favorite ELF
2. (Optionally parse the [vitasdk](https://vitasdk.org/) headers, see below)
3. Go to _Window_ -> _Script manager_ (or green play button)
4. Navigate to the _Vita_ folder and run _VitaLoader.java_

# Parsing vitasdk headers
To take full advantage of this script, I recommend parsing the [vitasdk](https://vitasdk.org/) headers before running it:

### 1. Generating a Ghidra-parsable header

1. `$ arm-vita-eabi-gcc -P -E $VITASDK/arm-vita-eabi/include/vitasdk.h -D"__attribute__(x)=" -D"__extension__(x)=" > vitasdk_header.h` (use `vitasdkkern.h` for the kernel headers)
2. Now open `vitasdk_header.h` and remove the `typedef unsigned int wchar_t;` (line 3)
3. Remove all the `inline` macros (`ksceKernelCpu*Context`, `ksceKernelCpuUnrestrictedMemcpy`)
4. Change `SceKernelProcessInfo`'s `unk[0xE8 / 4 - 6]` to `unk[0x34]`

### 2. Parsing the header
1. Open Ghidra and go to _File_ -> _Parse C Source..._ and select `vitasdk_header.h`
