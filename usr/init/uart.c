/**
 * \file
 * \brief Userspace UART driver management
 */
#include <drivers/lpuart.h>
#include <maps/imx8x_map.h>
#include "uart.h"


errval_t uart_init(void)
{
    errval_t err;
    struct paging_state *st = get_current_paging_state();
    struct capref device_register_capref = { .cnode = { .croot = CPTR_ROOTCN,
                                                        .cnode = CPTR_TASKCN_BASE,
                                                        .level = CNODE_TYPE_OTHER },
                                             .slot = TASKCN_SLOT_DEV };

    struct capability device_register_cap;
    err = cap_direct_identify(device_register_capref, &device_register_cap);
    assert(err_is_ok(err));

    struct capref uart_capref;
    err = slot_alloc(&uart_capref);
    assert(err_is_ok(err));

    err = cap_retype(uart_capref, device_register_capref,
                     IMX8X_UART3_BASE - get_address(&device_register_cap),
                     ObjType_DevFrame, IMX8X_UART_SIZE, 1);
    assert(err_is_ok(err));

    void *uart_vaddr;
    err = paging_map_frame_attr(st, &uart_vaddr, IMX8X_UART_SIZE, uart_capref,
                                VREGION_FLAGS_READ_WRITE_NOCACHE, NULL, NULL);
    assert(err_is_ok(err));

    struct lpuart_s *uart;
    err = lpuart_init(&uart, uart_vaddr);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}
