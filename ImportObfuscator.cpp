#include "pepp/PELibrary.hpp"
#include "spdlog/spdlog.h"

#include <filesystem>
#include <map>

#ifdef _WIN64
using Image_t = pepp::Image64;
#else
using Image_t = pepp::Image86;
#endif


#ifdef _WIN64

#define ROTR _rotr64
#define ROTL _rotl64


/*
* x64 import stub
* {
0:  53                      push   rbx                      ; preserve non-volatile registers
1:  52                      push   rdx              
2:  65 48 8b 1c 25 60 00    mov    rbx,QWORD PTR gs:0x60    ; put the PEB in rbx
9:  00 00
b:  48 83 44 24 10 01       add    QWORD PTR [rsp+0x10],0x1 ; increment return address
11: 48 b8 ef be ad de ef    movabs rax,0xdeadbeefdeadbeef   ; mov crypted rva into rax
18: be ad de
1b: 48 ba ef be ad de ef    movabs rdx,0xdeadbeefdeadbeef   ; mov rotated key into rdx
22: be ad de    
25: 48 c1 c2 10             rol    rdx,0x10                 ; rotate to get the correct key
29: 48 31 d0                xor    rax,rdx                  ; xor to get the original rva
2c: 48 03 43 10             add    rax,QWORD PTR [rbx+0x10] ; rva += peb->imagebase
30: 5a                      pop    rdx
31: 5b                      pop    rbx
32: ff 20                   jmp    QWORD PTR [rax]          ; jump into the import
* }
*/

uint8_t import_stub[] = { 0x53, 0x52, 0x65, 0x48, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x83, 0x44, 0x24, 0x10, 0x01, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xC1, 0xC2, 0x10, 0x48, 0x31, 0xD0, 0x48, 0x03, 0x43, 0x10, 0x5A, 0x5B, 0xFF, 0x20 };
uint32_t offset_encrypted_ptr = 0x13;
uint32_t offset_encrypt_key = 0x1d;

#else

#define ROTR _rotr
#define ROTL _rotl
/*
* }
* x86 import stub
* {
0:  53                      push   ebx
1:  52                      push   edx
2:  64 8b 1d 30 00 00 00    mov    ebx,DWORD PTR fs:0x30
9:  83 44 24 08 01          add    DWORD PTR [esp+0x8],0x1
e:  b8 ef be ad de          mov    eax,0xdeadbeef
13: ba ef be ad de          mov    edx,0xdeadbeef
18: c1 c2 10                rol    edx,0x10
1b: 31 d0                   xor    eax,edx
1d: 03 43 08                add    eax,DWORD PTR [ebx+0x8]
20: 5a                      pop    edx
21: 5b                      pop    ebx
22: ff 20                   jmp    DWORD PTR [eax]
* }
*/

uint8_t import_stub[] = { 0x53, 0x52, 0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00, 0x83, 0x44, 0x24, 0x08, 0x01, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xC1, 0xC2, 0x10, 0x31, 0xD0, 0x03, 0x43, 0x08, 0x5A, 0x5B, 0xFF, 0x20 };
uint32_t offset_encrypted_ptr = 0xf;
uint32_t offset_encrypt_key = 0x14;

#endif

uint8_t section_signature[] = { 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x69, 0x6b, 0x65, 0x31, 0x6b, 0x00 };


uintptr_t gen_random_uintptr()
{
    uint8_t rand_bytes[sizeof uintptr_t] {};

    for (int i = 0; i < sizeof(uintptr_t); ++i)
        rand_bytes[i] = (uint8_t)(rand() % 0xFF);

    return *(uintptr_t*)&rand_bytes[0];
}

pepp::Address<> ResolveImportDestination(Image_t& img, pepp::Address<> offset)
{
    std::uint32_t data = img.buffer().deref<uint32_t>((offset + 2).uintptr());
#ifdef _WIN64
    return (img.GetPEHeader().OffsetToRva(offset.uintptr()) + 6 + data);
#else
    return data;
#endif
}

int main(int argc, const char** argv)
{
    //
    // Initialize spdlog.
    std::shared_ptr<spdlog::logger> log = spdlog::default_logger();
    
    log->set_level(spdlog::level::debug);
    log->set_pattern("[%^%l%$] %v");

    //
    // Setup a seed.
    srand((unsigned int)argv + (unsigned int)main);
    srand(rand());

    
    if (argc > 1)
    {
        Image_t img { argv[1] };
        if (img.magic() != IMAGE_DOS_SIGNATURE)
        {
            log->critical("Invalid file fed to ImportObfuscator.");
            return EXIT_FAILURE;
        }

        log->info("Opened file: {}", argv[1]);

        //
        // Grab IAT position.
        std::uint32_t iat_begin{}, iat_end{};

        img.GetImportDirectory().GetIATOffsets(iat_begin, iat_end);

        if (iat_begin == 0)
        {
            log->critical("Could not find an IAT in this file!");
            return EXIT_FAILURE;
        }

        //
        // By default, we use .text. If your binary for whatever reason uses another section name for code, change this.
        pepp::SectionHeader& sec = img.GetSectionHeader(".text");

        //
        // Search for CALL (JMPs excluded for this obfuscation)
        auto results = img.FindBinarySequence(&sec, "FF 15 ? ? ? ?");
        if (!results.empty())
        {
            //
            // Create a section dependent on how many pointers are in the IAT.
            pepp::SectionHeader import_section{};
            std::uint32_t write_offset{};

            img.AppendSection(
                ".mike1k", 
                pepp::Align(((iat_end - iat_begin) / sizeof(uintptr_t)) * sizeof(import_stub), 8) + 0x100 /*extra space if we need it*/,
                pepp::SCN_MEM_READ |
                pepp::SCN_MEM_EXECUTE,
                &import_section);

            write_offset = import_section.GetPointerToRawData();

            memcpy(&img.buffer()[write_offset], section_signature, sizeof(section_signature));
            write_offset += pepp::Align(sizeof(section_signature), 8);

            //
            // Create a map of all rvas to their new destination.
            std::map<uint32_t, uint32_t> import_call;
            
            //
            // Begin creating import stubs
            img.GetImportDirectory().TraverseImports([&](pepp::ModuleImportData_t* imp)
            {
                //
                // Assign this import rva to the map.
                import_call[imp->import_rva] = img.GetPEHeader().OffsetToRva(write_offset);

                //
                // Create a "random" key
                uintptr_t random_key = gen_random_uintptr();
                uintptr_t encrypted_rva = imp->import_rva;

                //
                // XOR, Rotate.
                encrypted_rva ^= random_key;
                random_key = ROTR(random_key, 16);


                std::memcpy(&img.buffer()[write_offset], import_stub, sizeof(import_stub));
                
                //
                // Fill in data.
                std::memcpy(&img.buffer()[write_offset + offset_encrypted_ptr], &encrypted_rva, sizeof(encrypted_rva));
                std::memcpy(&img.buffer()[write_offset + offset_encrypt_key], &random_key, sizeof(random_key));

                //
                // Increment write offset.
                write_offset += pepp::Align(sizeof(import_stub), 8);


                //
                // Log it, why not.
                if (imp->ordinal)
                    log->info("Created import stub for {}!{:08X}", imp->module_name, std::get<uint64_t>(imp->import_variant));
                else
                    log->info("Created import stub for {}!{}", imp->module_name, std::get<std::string>(imp->import_variant));
            });

            //
            // Traverse all matches
            for (auto const match : results)
            {
                // log->info("Checking match @ offset {:X}", match);

                pepp::Address dst = ResolveImportDestination(img, match);
#ifdef _WIN64
                pepp::Address dst_offset = img.GetPEHeader().RvaToOffset(dst.as<uint32_t>());
#else
                pepp::Address dst_offset = img.GetPEHeader().RvaToOffset(dst.as<uint32_t>() - img.GetPEHeader().GetOptionalHeader().GetImageBase());
#endif

                // log->debug("Match: 0x{:X} (rva 0x{:X})", match, img.GetPEHeader().OffsetToRva(match));

                //
                // Found a call to a import.
                if (iat_begin <= dst_offset.uintptr() && dst_offset < iat_end)
                {
#ifdef _WIN64
                    uint32_t rva = import_call[dst.as<uint32_t>()];
#else
                    uint32_t rva = import_call[dst.as<uint32_t>() - img.GetPEHeader().GetOptionalHeader().GetImageBase()];
#endif
                    if (!rva)
                    {
                        log->critical("Import RVA was NULL!");
                        continue;
                    }

                    log->info("Applying import call patch @ offset {:X}", dst_offset.as<uint32_t>());

                    uint8_t call_code[] =
                    {
                        0xe8, 0x00, 0x00, 0x00, 0x00,
                        0x90
                    };

                    //
                    // Write the new destination in.
                    *(std::int32_t*)(&call_code[1]) = (rva - img.GetPEHeader().OffsetToRva(match) - 5);
#
                    // Have some fun with the last byte ;)
                    *(std::uint8_t*)(&call_code[5]) = rand() % 0xff;

                    memcpy(&img.buffer()[match], call_code, sizeof(call_code));

#ifndef WIN64
                    //
                    // HACK: Change the relocation so that it is ignored (absolute relocation type are ignored by PE loader). 
                    // Necessary on X86, or else the PE loader will apply a relocation on the address and cause a crash due to an invalid call.
                    if (img.GetRelocationDirectory().ChangeRelocationType(img.GetPEHeader().OffsetToRva(match + 2), pepp::RelocationType::REL_BASED_ABSOLUTE))
                        log->info("Ignoring relocation @ offset {:X}", match + 2);
#endif
                }
                else
                {
                    log->debug("Skipped call qword ptr @ offset {:X}", match);
                }
            }
        }

        std::filesystem::path path(argv[1]);
        path.replace_extension(".crypt.exe");

        img.WriteToFile(path.string());

        log->info("Finished encrypting import calls.");

        return EXIT_SUCCESS;
    }

    log->critical("Usage: ico [file]");
    return EXIT_FAILURE;
}