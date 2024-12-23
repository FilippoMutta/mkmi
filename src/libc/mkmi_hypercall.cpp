#include "mkmi.h"

inline __attribute__((always_inline))
size_t __x64_vmmcall(size_t syscall_num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6) {
	asm volatile(
		     "mov %0, %%rax\n\t"
		     "mov %1, %%rdi\n\t"
		     "mov %2, %%rsi\n\t"
		     "mov %3, %%rdx\n\t"
		     "mov %4, %%r8\n\t"
		     "mov %5, %%r9\n\t"
		     "mov %6, %%r10\n\t"
		     "vmmcall\n\t"
		     :
		     : "r"(syscall_num), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
		     : "memory", "cc", "rax", "rdi", "rsi", "rdx", "r8", "r9", "r10");

	return syscall_num;
}

size_t __fast_hypercall(size_t syscall_num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6) {
	return __x64_vmmcall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
}
