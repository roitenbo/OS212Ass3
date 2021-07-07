#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "fs.h"
#include "spinlock.h"
#include "proc.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // map kernel stacks
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// Initialize the one kernel_pagetable
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch h/w page table register to the kernel's page table,
// and enable paging.
void
kvminithart()
{
  w_satp(MAKE_SATP(kernel_pagetable));
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
#ifdef NONE
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}
#endif

#ifndef NONE
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V && *pte & PTE_PG)
      panic("remap");

    if(perm & PTE_PG){
      *pte = PA2PTE(pa) | perm | PTE_PG;
    }
    else{
      *pte = PA2PTE(pa) | perm | PTE_V;
    }

    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}
#endif

// Remove npages of mappings starting from va. va must be
// page-aligned. The mappings must exist.
// Optionally free the physical memory.
#ifdef NONE
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0)
      panic("uvmunmap: walk");
    if((*pte & PTE_V) == 0)
      panic("uvmunmap: not mapped");
    if(PTE_FLAGS(*pte) == PTE_V)
      panic("uvmunmap: not a leaf");
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

#endif

#ifndef NONE
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0)
      panic("uvmunmap: walk");
    if((*pte & (PTE_V | PTE_PG)) == 0)
      panic("uvmunmap: not mapped");
    if(PTE_FLAGS(*pte) == PTE_V)
      panic("uvmunmap: not a leaf");
    if(do_free && (*pte & PTE_V)){ // kfree only if in PTE_V
      uint64 pa = PTE2PA(*pte);
      //printf("here?\n");
      kfree((void*)pa);
    }
    *pte = 0;
  }
}
#endif


// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Load the user initcode into address 0 of pagetable,
// for the very first process.
// sz must be less than a page.
void
uvminit(pagetable_t pagetable, uchar *src, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pagetable, 0, PGSIZE, (uint64)mem, PTE_W|PTE_R|PTE_X|PTE_U);
  memmove(mem, src, sz);
}

#ifdef NONE
// Allocate PTEs and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_W|PTE_X|PTE_R|PTE_U) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}
#endif


int countUsing(void){ // returns how much rams are in use right now
  int c = 0;
  struct proc* p = myproc();
  for(int i=0;i<MAX_PSYC_PAGES;i++){
    if(p->ramPages[i].using)
      c++;
  }
  return c;
}

int isTherePlaceInRamPages(void){
  struct proc* p = myproc();
  for(int i=0;i<MAX_PSYC_PAGES;i+=1){
    if(p->ramPages[i].using == 0)
      return 1;
  }
  return 0;
}

int freePlaceInRamPages(void){
  struct proc* p = myproc();
  for(int i=0;i<MAX_PSYC_PAGES;i+=1){
    if(p->ramPages[i].using == 0)
      return i;
  }
  panic("didnt check good enough if there place in ramPages");
  return 0;
}

#ifndef NONE
// Allocate PTEs and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  struct proc* p = myproc();
  char *mem;
  uint64 a;
  int index = 0;
  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    index = a / PGSIZE;
    if(countUsing() > MAX_PSYC_PAGES){
      panic("bigger than max using rams");
    }
    
    // mem
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_W|PTE_X|PTE_R|PTE_U) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    // mem
    if(isTherePlaceInRamPages()){ // put page in ram
        //printf("page in ram\n");
        //printf("index before = %d\n",index);
        index = freePlaceInRamPages();
        //printf("index after = %d\n",index);
        p->ramPages[index].placeInQueue = myproc()->generalPlaceInQueue++; // scfifo
        p->ramPages[index].nfua = 0; // 2.1
        p->ramPages[index].leastAccessed = 0xFFFFFFFF; // 2.1   111111111111
        p->ramPages[index].using = 1;
        //p->ramPages[index].offset = a; // a = index*PGSIZE
        p->ramPages[index].addr = a; // a = index*PGSIZE
    }
    else{ // moveRamToSwap and than add to ram array
      //printf("swapping\n");
      int ramIndexToSwap = decideAlgorithm();
      moveRamToSwap(ramIndexToSwap); // making space to the new page
      //printf("now we can put page in ram in %d\n",ramIndexToSwap);
      p->ramPages[ramIndexToSwap].placeInQueue = myproc()->generalPlaceInQueue++; // scfifo
      p->ramPages[ramIndexToSwap].nfua = 0; // 2.1
      p->ramPages[ramIndexToSwap].leastAccessed = 0xFFFFFFFF; // 2.1
      p->ramPages[ramIndexToSwap].using = 1;
      p->ramPages[ramIndexToSwap].offset = a;
      p->ramPages[ramIndexToSwap].addr = a;
      //printf("hello\n");
    }
    //printf("NOW IN RAM = %d\n",countUsing());

  }
  return newsz;
}

#endif

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
#ifdef NONE
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0)
      panic("uvmcopy: page not present");
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}
#endif

#ifndef NONE
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & (PTE_V | PTE_PG)) == 0)
      panic("uvmcopy: page not present");
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if(flags & PTE_V){ // kalloc just if page valid in ram
      if((mem = kalloc()) == 0)
        goto err;
      memmove(mem, (char*)pa, PGSIZE);
      if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
      }
    }
    else{
      if(mappages(new, i, PGSIZE, 0, flags) != 0){
        goto err;
      }
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}
#endif

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

void pageFaultTrap(uint64 address) { // from trap.c
  //printf("handling page fault\n");
  
  uint64 va = PGROUNDDOWN(address);
  uint64 buffer = (uint64)kalloc();
  int thereIsPlace = 0; // if we need to replace someone in ramPages or no
  int swapIndexDown = 0;
  int ramIndex = 0;
  //printf("va = %d\n",va);
  //printf("address = %d\n",address);
  for(int i=0 ; i< MAX_PSYC_PAGES; i+= 1){ // find the page who we want
        if(myproc()->swapPages[i].addr == va && myproc()->swapPages[i].using == 1){ // found 
          swapIndexDown = i;
          break;
        }
        //printf("offset = %d\n",myproc()->swapPages[i].offset);
        //printf("using = %d\n",myproc()->swapPages[i].using);
  }
  //printf("swapIndexDown = %d\n",swapIndexDown);
  for(int i = 0 ;i < MAX_PSYC_PAGES ; i += 1){
      if(myproc()->ramPages[i].using == 0){ // found free place to our page
        thereIsPlace = 1;
        ramIndex = i;
        //printf("free index =  %d\n",i);
        break;
      }
  }
    pte_t* pte = walk(myproc()->pagetable,va,0);
  if(thereIsPlace){ // no need to moveRamtoSwap
    //printf("there is place!\n");
    if(readFromSwapFile(myproc(),(char*)buffer,
    myproc()->swapPages[swapIndexDown].offset,PGSIZE) < 0){ // get our page information to buffer
      panic("readFromSwapFile in pageFaultTrap failed!");
    }
    else{ // read succesfully
    
      myproc()->ramPages[ramIndex].placeInQueue = myproc()->generalPlaceInQueue++;
      myproc()->ramPages[ramIndex].nfua = 0; // 2.1
      myproc()->ramPages[ramIndex].leastAccessed = 0xFFFFFFFF; // 2.1
      myproc()->ramPages[ramIndex].using = 1; // 2.1
      //myproc()->ramPages[ramIndex].offset = (ramIndex)*PGSIZE; // 2.1
      myproc()->ramPages[ramIndex].addr = myproc()->swapPages[swapIndexDown].addr; // 2.1

      *pte = PTE_FLAGS(*pte); 
      *pte &= ~PTE_PG; // in ram
      *pte |= PTE_V;   // in ram

      *pte |= PA2PTE(buffer); 
      myproc()->swapPages[swapIndexDown].using = 0;
      //printf("pagefault handeled - moved to ram\n");
      sfence_vma();
    }
  }
  else{ // no place -> moveRamToSwap and then add to ramPages array
    //printf("pagefault - noPlace!!!\n"); // change to printf ~ debug
    int ramIndexToSwap = decideAlgorithm();
    moveRamToSwap(ramIndexToSwap);

    if(readFromSwapFile(myproc(),(char*)buffer,myproc()->swapPages[swapIndexDown].offset,PGSIZE) < 0){
      panic("readFromSwapFile failed!");
    }
    else{ // read succesfully
      
      myproc()->ramPages[ramIndex].placeInQueue = myproc()->generalPlaceInQueue++;
      myproc()->ramPages[ramIndex].nfua = 0; // 2.1
      myproc()->ramPages[ramIndex].leastAccessed = 0xFFFFFFFF; // 2.1
      myproc()->ramPages[ramIndex].using = 1; // 2.1
      //myproc()->ramPages[ramIndex].offset = (ramIndex)*PGSIZE; // 2.1
      myproc()->ramPages[ramIndex].addr = myproc()->swapPages[swapIndexDown].addr; // 2.1

      *pte = PTE_FLAGS(*pte); 
      *pte &= ~PTE_PG; // in ram
      *pte |= PTE_V;   // in ram

      *pte |= PA2PTE(buffer); 
      myproc()->swapPages[swapIndexDown].using = 0;

      sfence_vma();
      //printf("pagefault handeled - moved to ram\n");
    }
  }
}

void resetValidBit(pte_t* pte){
  *pte |= PTE_PG;  // moving to swapPage
  *pte &= ~PTE_V;  // not in ram
  sfence_vma();
}

int countOnes(uint n){ /// 10111 -> 4
  int counter = 0;
  while(n>0){
    counter += n%2;
    n /= 2; 
  }
  return counter;
}

int decideAlgorithm(void){ // decide which ramIndex to move to swapPage according to SELECTION
  int ramIndex = 0;
  #ifdef NONE
  struct proc* p = myproc();
  for(int i = 0;i < MAX_PSYC_PAGES; i+=1){
    if(p->ramPages[i].using == 1){
      ramIndex = i;
      break;
    }
  }
  #endif
  #ifdef NFUA
  struct proc* p = myproc();
  //printf("first nfua = %d\n",myproc()->ramPages[0].nfua);
  ramIndex = 0;
  int flag = 0; // found or not
  for(int i = 0;i < MAX_PSYC_PAGES; i+=1){
   // if(myproc()->ramPages[i].nfua != 0)
    //  printf("here nfua %d\n",myproc()->ramPages[i].nfua);
    for(int j = i ; j<MAX_PSYC_PAGES; j+=1){
      if(p->ramPages[j].using == 1){
        //printf("nfua = %d\n",p->ramPages[j].nfua);
        if(flag == 0){
          ramIndex = j;
          flag = 1;
        }
        else if(p->ramPages[j].nfua <= p->ramPages[ramIndex].nfua){
          //printf("number %d nfua = %d\n",j,myproc()->ramPages[j].nfua);
          //printf("changed nfua = %d\n",myproc()->ramPages[j].nfua);
          ramIndex = j;
          //break;
        }
      }
    }
  }
  #endif
  
  #ifdef LAPA
  struct proc* p = myproc();
  
  //printf("LAPA = %d\n",myproc()->ramPages[0].leastAccessed);
  ramIndex = 0;
  int flag = 0; // found or not
  for(int i = 0;i < MAX_PSYC_PAGES; i+=1){
      //if(myproc()->ramPages[i].leastAccessed != 0)
       // printf("here %d\n",myproc()->ramPages[i].leastAccessed);
      for(int j = i ; j<MAX_PSYC_PAGES; j+=1){
        if(p->ramPages[j].using){
          //printf("%d is used",j);
          if(flag == 0 || 
            (countOnes(p->ramPages[j].leastAccessed) == 
            countOnes(p->ramPages[ramIndex].leastAccessed) &&
            p->ramPages[j].leastAccessed < p->ramPages[ramIndex].leastAccessed)){
            flag = 1;
            //printf("decided = %d\n",p->ramPages[j].leastAccessed);
            ramIndex = j;
          }
          else if(countOnes(p->ramPages[j].leastAccessed) < 
          countOnes(p->ramPages[ramIndex].leastAccessed)){
            flag = 1;
            //printf("decided = %d index = %d\n",p->ramPages[j].leastAccessed,j);
          ramIndex = j;
          }
        }
      }
  }
  //printf("LAPA decided %d\n",ramIndex);
  #endif

  #ifdef SCFIFO
  struct proc* p = myproc();
  //printf("first page scfifo = %d\n",myproc()->ramPages[0].placeInQueue);
  ramIndex = 0;
  uint64 minValue = 0xffffffffffffffff;
  for(int i = 0;i < MAX_PSYC_PAGES; i+=1){
    for(int j = i ; j<MAX_PSYC_PAGES; j+=1){
      if(p->ramPages[j].using == 1 &&
         p->ramPages[j].placeInQueue < minValue){
        minValue = p->ramPages[j].placeInQueue;
        //printf("better one scfifo = %d\n",p->ramPages[j].placeInQueue);
        ramIndex = j;
        //break;
      }
    }
  }
  #endif
  return ramIndex;
}

void moveRamToSwap(int ramIndex){ // giving ramIndex to swapFile
  //int ramIndex = decideAlgorithm();
  int swapIndex = 0;
  struct proc* p = myproc();

  for(int i = 0;i < MAX_PSYC_PAGES; i+=1){ // finding a free place in swapPages array
    if(p->swapPages[i].using == 0){
      swapIndex = i;
      break;
    }
  }  

  pte_t* t = walk(p->pagetable,p->ramPages[ramIndex].addr,0);
  uint64 pa = PTE2PA(*t); // physical address

  //printf("swapIndex = %d ramIndex = %d\n",swapIndex,ramIndex);
  if(writeToSwapFile(p, 
  (char*)(pa) // address of the pte
  ,p->swapPages[swapIndex].offset,PGSIZE) // placeOnFile = index*PGSIZE ??
  < 0){ // writeToSwapFile( proc ,  buffer,  placeOnFile,  size)
    panic("problem with writing to SwapFile");
  }
  else{
    //printf("writeToSwapFile succeeded\n");
    myproc()->swapPages[swapIndex].using = 1;
    myproc()->ramPages[ramIndex].using = 0; // went to swapfile
    myproc()->swapPages[swapIndex].addr = myproc()->ramPages[ramIndex].addr ;
    myproc()->ramPages[ramIndex].addr = 0;
    kfree((void*)pa);
    resetValidBit(t);
    //printf("swapIndex %d filled\n",swapIndex);
    // now we can put in ram the other page
  }
}

void countersUpdate(struct proc* p){
    //printf("updating\nn");
    uint increment = 1 << 31;
    //printf("%d\n",increment );
    for(int i=0;i<MAX_PSYC_PAGES;i+=1){
      pte_t* pte = walk(p->pagetable,p->ramPages[i].addr,0);
      if(*pte & PTE_V){
        p->ramPages[i].nfua =  p->ramPages[i].nfua >> 1; // shift right
        p->ramPages[i].leastAccessed = p->ramPages[i].leastAccessed >> 1; // shift right
        //printf("here %d",myproc()->ramPages[i].leastAccessed);
      }
      if(*pte & PTE_V && *pte & PTE_A){
        //printf("updating222\nn");
        p->ramPages[i].nfua |= increment;
       //printf("%d\n",i);
        p->ramPages[i].leastAccessed |= increment;
        p->ramPages[i].placeInQueue = p->generalPlaceInQueue++;
        //p->generalPlaceInQueue += 1;

        *pte &= ~PTE_A; // turn off access bit
      }
    }
}