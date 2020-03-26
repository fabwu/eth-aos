#include <stdarg.h>
#include <stdio.h>

#include <aos/aos.h>
#include <aos/sys_debug.h>
#include <grading.h>

void grading_rpc_handle_number(uintptr_t val)
{
    DEBUG_PRINTF("grading_rpc_handle_number() called with val=%d\n", val);
}

void grading_rpc_handler_string(const char *string)
{
    DEBUG_PRINTF("grading_rpc_handle_string() called with string=%s\n", string);
}

void grading_rpc_handler_serial_getchar(void)
{
    DEBUG_PRINTF("grading_rpc_handler_serial_getchar() called\n");
}

void grading_rpc_handler_serial_putchar(char c)
{
    // Don't call this for sanity sake
    // DEBUG_PRINTF("grading_rpc_handler_serial_putchar() called with c=%c\n", c);
}

void grading_rpc_handler_ram_cap(size_t bytes, size_t alignment)
{
    DEBUG_PRINTF("grading_rpc_handler_ram_cap() called with bytes=%d and alignment=%d\n",
                 bytes, alignment);
}

void grading_rpc_handler_process_spawn(char *name, coreid_t core)
{
    DEBUG_PRINTF("grading_rpc_handler_process_spawn() called with name=%s and core %d\n",
                 name, core);
}

void grading_rpc_handler_process_get_name(domainid_t pid)
{
    DEBUG_PRINTF("grading_rpc_handler_process_get_name() called with pid=%d\n", pid);
}

void grading_rpc_handler_process_get_all_pids(void)
{
    DEBUG_PRINTF("grading_rpc_handler_process_get_all_pids() called\n");
}

void grading_rpc_handler_get_device_cap(lpaddr_t paddr, size_t bytes)
{
    DEBUG_PRINTF("grading_rpc_handler_get_device_cap() called with paddr=%p and bytes=%d\n",
                 paddr, bytes);
}
