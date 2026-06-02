---
title: Kernel Read Write Execute - KRWX
date: 2022-03-14
author: kiks
---
## Introduction
github project: https://github.com/kiks7/KRWX

During the last few months/year I was studying and approaching the Kernel Exploitation subject and during this journey I developed few tools that assissted me (and currently assist) on better understanding specific topics. Today I want to release my favourine one: KRWX (**K**ernel **R**ead **W**rite **E**xecute). It is a simple LKM (Linux Kernel Module) that lets you play with kernel memory, allocate and free kernel objects directly from user-land!

## What
The main goal of this tool is to use kernel functions from userland (from C code) in order to avoid slower kernel debugging and developing of kernel modules to demostrate specific vulnerabilities (instead, you can emulate them with provided IOCTLs). Also, it can assist the exploitation phase.
These are the project main features (all these features are accessible from a low level user from user-land):
- Read and write into kernel memory
- Read entire blocks of memory
- Arbitrary allocate objects directly calling `kmalloc`
- Arbitrary `kfree` objects (and also free arbitrary addresses, if you want)
- Allocate/free multiple objects
- Log every `copy_[from|to]_user`/ `kmalloc`/`kfree` called by the KRWX module through hooking (readable from `dmesg`).

Mainly, a more powerful read and write primitive :]

## Why
Initially I was writing this module to study the SLUB memory allocator in Linux by allocating, freeing and re-allocating arbitrary chunks easily from an userland process. That automatically leads to study also some exploitation techniques that, with this module, I found a lot easier to understand since you can easily play with kernel memory as you are the god of your system. Then I started to heavily use it for multiple purposes and that's the reason why I'm sharing it.

## How
These are some exported functions:
- `void* kmalloc(size_t arg_size, gfp_t flags)` -> Allocate a chunk with specific `size` and `flag` options.
-  `int kfree(void* address)` -> Free arbitrary chunks by their `address` (also, you can free arbitrary memory).
- `unsigned long int kread64(void* address)` -> Read 8 bytes of memory at `address`.
- `int kwrite64(void* address, uint64_t value)` -> Write 8 bytes specified by `value` into `address`.
- `void read_memory(void* start_address, size_t size)` -> Read `size` amount of memory starting from `start_address`.

And, since one of my favourite hobby is overengineer and I'm lazy enough to do not want to write loops everytime:
- `void multiple_kmalloc(void** array, uint32_t n_objs, uint32_t size)` -> Allocate `n_objs` number of objects with specified `size` and return addresses in `array`.
- `void multiple_kfree(void** array, uint64_t to_free[], uint64_t to_free_size)` -> Free specified addresses in `to_free` from `array` (`to_free_size` is the size of the `to_free` array).

 If you're interested in the source code feel free to check out the github project.

## Examples
### Allocate, free and read arbitrary chunks
You can find the full source code in `example/01.c`. Here will follows some snippets and a little walkthrough.

First, include the external library and call its initialization function (`init_krwx`):
```C
#include "./lib/krwx.h"

int main(){
	init_krwx();
	[..]
}
	
```
So, 10 chunks with size 256 are allocated using `multiple_kmalloc`, and the memory of the 7th allocation is read using `read_memory` after writing `0x4141414141414141` at its first bytes:
```C
void* chunks[10];
multiple_kmalloc(&chunks, 10, 256);
kwrite64(chunks[7], 0x4141414141414141);
read_memory(chunks[7], 0x10);
```

The indexes 3, 4 and 7 of the `chunks` array are freed using `multiple_kfree`:
```C
uint64_t to_free[] = {3, 4, 7};
multiple_kfree(&chunks, &to_free, ( sizeof(to_free) / sizeof(uint64_t) ) );
```

Once they are freed, new chunks with the same size are allocated and initialized with `0x4343434343434343`, and the memory of the 7h freed chunk is displayed using `read_memory` again:
```C
kwrite64(kmalloc(256, _GFP_KERN), 0x4343434343434343);
kwrite64(kmalloc(256, _GFP_KERN), 0x4343434343434343);
kwrite64(kmalloc(256, _GFP_KERN), 0x4343434343434343);
kwrite64(kmalloc(256, _GFP_KERN), 0x4343434343434343);
kwrite64(kmalloc(256, _GFP_KERN), 0x4343434343434343);
read_memory(chunks[7], 0x10);

```

The result is:
```bash
[*] Allocating 10 chunks with size 256
[*] Allocated @0xffffffc00503b900
[*] Allocated @0xffffffc00503b600
[*] Allocated @0xffffffc00503b100
[*] Allocated @0xffffffc00503bc00
[*] Allocated @0xffffffc00503b400
[*] Allocated @0xffffffc00503b000
[*] Allocated @0xffffffc00503b500
[*] Allocated @0xffffffc00503b800
[*] Allocated @0xffffffc00503ba00
[*] Allocated @0xffffffc00503bd00
0xffffffc00503b800:     0x4141414141414141 0xffffffc0001a8928
[*] Freeing @0xffffffc00503bc00
[*] Freeing @0xffffffc00503b400
[*] Freeing @0xffffffc00503b800
0xffffffc00503b800:     0x4343434343434343 0xffffffc0001a8928
```

With  few lines of code has been demostrated how  our 7th chunk has been replaced with a new one after it has been freed (the `read_memory` targeted the `chunks[7]`). 
As simple as it is, it has been written for demonstration purposes.

### Use-After-Free
To simulate a UAF scenario it's simple as few lines of code:
```C
void* chunk = kmalloc(<SIZE>, <FLAGS>);
kfree(chunk);
// Allocate your target chunk
// Simulate UAF using k[write|read]64()
```

For example, if we want to simulate an attack scenario where we want to replace our vulnerable freed chunk with a target object (for example an `iovec` struct) we can allocate a chunk with `kmalloc` and later  `kfree` it just before allocating the target structure:
```C
// Allocate the vulnerable object
void* chunk = kmalloc(150, _GFP_KERN);
// Allocate target object
struct iovec iov[10] = {0};
char iov_buf[0x100];
iov[0].iov_base = iov_buf;
iov[0].iov_len = 0x1000;
iov[1].iov_base = iov_buf;
iov[1].iov_len = 0x1337;
int pp[2];
pipe(pp);
if(!fork()){
	kfree(chunk); // Freeing the chunk just before allocating the iovec
	readv(pp[0], iov, 10); // allocate iovec and blocks (keeping the object in the kernel) 
	exit(0);
}
sleep(1); // Give time to the child process
read_memory(chunk, 0x40);


```

Then, with `read_memory` we can show the block of memory in our interest and as you can see from the following output, our arbitrary allocated/freed object has been replaced with the target object: 
```C
Allocated chunk @0xffffffc0052c5a00
0xffffffc0052c5a00:     0x0000007fd311ff58 0x0000000000001000
0xffffffc0052c5a10:     0x0000007fd311ff58 0x0000000000001337
0xffffffc0052c5a20:     0x0000000000000000 0x0000000000000000
0xffffffc0052c5a30:     0x0000000000000000 0x0000000000000000
```

Instead of just print the content, you can simulate a UAF read/write using `k[read|write]` and play with it.

The full code of this example can be found in `client/example/02.c`

## Setup
To compile the module change the `K` variable in the `Makefile` with your compiled kernel root directory and compile with `make`, then `insmod`.

## Conclusions
Personally, I used it to study the SLUB allocator, understand UAF/Heap Overflows/Double Free/userfaultd and some hardening features in the kernel, but it can assist the exploitation phase too or more. Blog posts on some Kernel vulnerabilities and their attack methodologies will follow these months and this module will come useful to demonstrate them. So, stay tuned and enjoy !

PS. The "Execute" part of the name will be a future implementation to control `pc/rip`.