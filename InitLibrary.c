#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    /* Your code here */
    Elf64_Dyn *ptr = l->dyn;
    while (ptr->d_tag != DT_NULL) {
        if (ptr->d_tag == DT_RELA) break;
        ++ptr;
    }
    //DT_INIT
    if (ptr->d_tag == DT_NULL) return;

    Elf64_Rela *reltab = (Elf64_Rela*)(l->dynInfo[DT_RELA]->d_un.d_val);
    size_t rel_sz = (size_t)(l->dynInfo[DT_RELASZ]->d_un.d_val);
    int n = rel_sz / sizeof(Elf64_Rela);
    
    for(int i = 0;i < n;i++) {
        uint64_t *addr = (uint64_t*)(l->addr + reltab->r_offset);
        if (reltab->r_info == R_X86_64_RELATIVE)
            *addr = (l->addr + reltab->r_addend);
        ++reltab;                              
    }   
    
    void (*init)();
    init = (void*)(l->dynInfo[DT_INIT]->d_un.d_val);
    init();   
    //DT_INIT_ARRAY
    uint64_t *p = l->dynInfo[DT_INIT_ARRAY]->d_un.d_val;
    size_t array_sz = (size_t)(l->dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val);
    n = array_sz / sizeof(uint64_t);
    for(int i = 0;i < n;i++) {
        init = *p;
        init();
        ++p;
    }
}
