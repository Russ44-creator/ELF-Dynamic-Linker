#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
    if(dep->fake)
    {
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if(!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            exit(-1);
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; //not this dependency
}

void RelocLibrary(LinkMap *lib, int mode)
{
    /* Your code here */

    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    void *address = dlsym(handle, "puts");

//    printf("ADDRESS: %llx\n", address);

    Elf64_Dyn *dynamic = lib->dyn;
    while (dynamic->d_tag != DT_NULL) {
        if (dynamic->d_tag == DT_JMPREL) break;
        ++dynamic;
    }
    
    if (dynamic->d_tag == DT_NULL) return;

    Elf64_Rela *reltab = (Elf64_Rela*)(lib->dynInfo[DT_JMPREL]->d_un.d_val);

//    Elf64_Sym *symtab = (Elf64_Sym*)(lib->dynInfo[DT_SYMTAB]->d_un.d_val);
//    symtab += 2;
//    Elf64_Dyn *strtab = lib->dynInfo[DT_STRTAB]->d_un.d_val;

    uint64_t *addr = (uint64_t*)((uint64_t)reltab->r_offset + lib->addr);
//    void *p = addr;
  // printf("%llx\n", addr); 
    //printf("%llx",*((uint64_t*)(reltab->r_offset)));
    *addr = (uint64_t)address;
     
//    printf("%llx\n", symtab->st_name);
//    printf("%s\n", symtab->st_name + (uint64_t)strtab);

//    reltab->r_addend = (Elf64_Sxword)symtab->st_name + (Elf64_Sxword)((uint64_t)strtab - lib->addr);
//    printf("%lld\n", reltab->r_addend);
}
