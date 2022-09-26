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
     * hint:
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
    //need code here


    int fd = open(libpath,O_RDONLY);

    Elf64_Ehdr* eptr = malloc(sizeof(Elf64_Ehdr));
    pread(fd, eptr, sizeof(Elf64_Ehdr), 0);
    Elf64_Phdr* phdr = malloc(sizeof(Elf64_Phdr));
    Elf64_Half sz = eptr->e_phentsize;  //each segment size
    Elf64_Half base = eptr->e_phoff;   //current segment offset

    LinkMap* lib = malloc(sizeof(LinkMap));  //lib header


    void* start_addr = NULL;

    for(int i = 0;i < eptr->e_phnum;++i){
        //set to current offset
        pread(fd, phdr, sizeof(Elf64_Phdr), base);
        base += sz; //update offset
        if(phdr->p_type == PT_LOAD){
            //curPtr = curPtr -> next;
            int prot = 0;
            prot |= (phdr->p_flags & PF_R)? PROT_READ : 0;
            prot |= (phdr->p_flags & PF_W)? PROT_WRITE : 0;
            prot |= (phdr->p_flags & PF_X)? PROT_EXEC : 0;
            //align memory pointer
            uint64_t memSize =ALIGN_UP((uint64_t)start_addr + phdr->p_memsz + phdr->p_vaddr, getpagesize()) -
                              ALIGN_DOWN((uint64_t)start_addr + phdr->p_vaddr, getpagesize());
            //after first
            if(start_addr!=NULL) {
                start_addr = ALIGN_DOWN((uint64_t)start_addr + phdr->p_vaddr, getpagesize());
            }
            //first addr->null
            start_addr = mmap(start_addr,memSize, prot,
                              MAP_FILE | MAP_PRIVATE, fd, ALIGN_DOWN(phdr->p_offset, getpagesize()));
            if(lib->addr==NULL){
                lib->addr = start_addr;
            }
        }
        //PT_DYNAMIC
        if (phdr->p_type == PT_DYNAMIC) {
            lib->dyn = lib->addr + phdr->p_vaddr;
        }
    }
    fill_info(lib);
    setup_hash(lib);
    return lib;
}