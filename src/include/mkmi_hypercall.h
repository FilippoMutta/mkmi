#include <stddef.h>
#include <cdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t __fast_hypercall(size_t syscall_num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6);

#ifdef __cplusplus
}
#endif
