#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH_NEW]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT)
            dyn_info[DT_RELACOUNT_NEW] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH)
            dyn_info[DT_GNU_HASH_NEW] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH_NEW); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

void *MapLibrary(const char *libpath)
{
    /*
     * hint:(Addr) *addr = (ElfW(Addr) *)(load_bias + reloc->r_offset);
     * 
     * lib = malloc(sizeof(LinkMap));
     * 
     * foreach segment:
     * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
     *      segment_offset);
     * 
     * lib -> addr = ...;
     * lib -> dyn = ...;
     * 
     * fill_info(lib);
     * setup_hash(lib);
     * 
     * return lib;
    */
   
    /* Your code here */
    
    LinkMap *lib = malloc(sizeof(LinkMap));

    int library_fd = open(libpath, O_RDONLY);
    
    Elf64_Ehdr *elf_header = malloc(sizeof(Elf64_Ehdr));
    read(library_fd, elf_header, sizeof(Elf64_Ehdr));

    Elf64_Phdr *program_header = malloc(elf_header->e_phnum * sizeof(Elf64_Phdr));
    pread(library_fd, program_header, elf_header->e_phnum * sizeof(Elf64_Phdr), elf_header->e_phoff);

    int base = 0;
    while (base < elf_header->e_phnum && program_header[base].p_type != PT_LOAD) ++base;
    int prot = 0;
    prot |= (program_header[base].p_flags & PF_R) ? PROT_READ : 0;
    prot |= (program_header[base].p_flags & PF_W) ? PROT_WRITE : 0;
    prot |= (program_header[base].p_flags & PF_X) ? PROT_EXEC : 0;

    lib->addr = (uint64_t)mmap(NULL, ALIGN_UP(program_header[base].p_memsz,2*getpagesize()), prot, 
            MAP_FILE | MAP_PRIVATE, library_fd, ALIGN_DOWN(program_header[base].p_offset,2*getpagesize()));

    for (int i = base + 1; i < elf_header->e_phnum; ++i) {
        if (program_header[i].p_type == PT_LOAD) {
            int prot = 7;
            prot |= (program_header[i].p_flags & PF_R) ? PROT_READ : 0;
            prot |= (program_header[i].p_flags & PF_W) ? PROT_WRITE : 0;
            prot |= (program_header[i].p_flags & PF_X) ? PROT_EXEC : 0;
            
            void *start_addr = mmap((lib->addr + program_header[i].p_vaddr), 
                    ALIGN_UP(program_header[i].p_memsz, 2*getpagesize()), prot, 
                    MAP_FILE | MAP_PRIVATE, library_fd, ALIGN_DOWN(program_header[i].p_offset, 2*getpagesize()));
//            printf("%llx %llx %llx\n", lib->addr, start_addr, start_addr + program_header[i].p_vaddr);
        }
        if (program_header[i].p_type == PT_DYNAMIC) {
            lib->dyn = (Elf64_Dyn*)(lib->addr + program_header[i].p_vaddr);
        }        
    }    

    free(elf_header);
    free(program_header);

    fill_info(lib);
    setup_hash(lib);

//    Elf64_Sym *symtab = (Elf64_Sym*)(lib->dynInfo[DT_SYMTAB]->d_un.d_val);
//    Elf64_Dyn *strtab = lib->dynInfo[DT_STRTAB]->d_un.d_val;
//    Elf64_Dyn *dynamic = lib->dyn;


//    while (dynamic->d_tag != DT_NULL) {
//        if (dynamic->d_tag == DT_JMPREL) break;
//        ++dynamic;
//    }

//    if (dynamic->d_tag == DT_NULL) return lib;

//    puts("OK");

//    Elf64_Rela *rel = (Elf64_Rela*)lib->dynInfo[DT_JMPREL]->d_un.d_val;
//    symtab += 2;
//    printf("%llx %llx %lx\n", strtab, lib->addr,
//            (long long)rel - lib->addr);


    return lib;
}

//int main() {
//    MapLibrary("lib1.so");
//}
