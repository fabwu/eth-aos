/**
 * \file
 * \brief Userspace UART driver management
 */
#include <aos/inthandler.h>
#include <drivers/gic_dist.h>
#include <drivers/lpuart.h>
#include <maps/imx8x_map.h>
#include "uart.h"

static struct gic_dist_s *gic;
static struct lpuart_s *uart;

static void irq_handler(void *arg)
{
    char c;
    while (!lpuart_getchar(uart, &c)) {
        lpuart_putchar(uart, c);
    }
}

static errval_t gic_setup(void) {
    struct paging_state *st = get_current_paging_state();
    struct capref device_register_capref = { .cnode = { .croot = CPTR_ROOTCN,
                                                        .cnode = CPTR_TASKCN_BASE,
                                                        .level = CNODE_TYPE_OTHER },
                                             .slot = TASKCN_SLOT_DEV };
    errval_t err;

    struct capability device_register_cap;
    err = cap_direct_identify(device_register_capref, &device_register_cap);
    assert(err_is_ok(err));

    struct capref gic_capref;
    err = slot_alloc(&gic_capref);
    assert(err_is_ok(err));

    err = cap_retype(gic_capref, device_register_capref,
                     IMX8X_GIC_DIST_BASE - get_address(&device_register_cap),
                     ObjType_DevFrame, IMX8X_GIC_DIST_SIZE, 1);
    assert(err_is_ok(err));

    void *gic_vaddr;
    err = paging_map_frame_attr(st, &gic_vaddr, IMX8X_GIC_DIST_SIZE, gic_capref,
                                VREGION_FLAGS_READ_WRITE_NOCACHE, NULL, NULL);
    assert(err_is_ok(err));

    err = gic_dist_init(&gic, gic_vaddr);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static errval_t uart_setup(void)
{
    struct paging_state *st = get_current_paging_state();
    struct capref device_register_capref = { .cnode = { .croot = CPTR_ROOTCN,
                                                        .cnode = CPTR_TASKCN_BASE,
                                                        .level = CNODE_TYPE_OTHER },
                                             .slot = TASKCN_SLOT_DEV };
    errval_t err;

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

    err = lpuart_init(&uart, uart_vaddr);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

errval_t uart_init(void)
{
    errval_t err;

    /* initialize interrupt controller */
    err = gic_setup();
    assert(err_is_ok(err));

    /* initialize UART */
    err = uart_setup();
    assert(err_is_ok(err));

    /* get UART IRQ cap */
    struct capref irq_capref;
    err = inthandler_alloc_dest_irq_cap(IMX8X_UART3_INT, &irq_capref);
    assert(err_is_ok(err));

    /* set up IRQ handler (as LMP endpoint) */
    err = inthandler_setup(irq_capref, get_default_waitset(),
                           MKCLOSURE(irq_handler, NULL));
    assert(err_is_ok(err));

    /* enable IRQ in GIC, on core 0, highest priority */
    err = gic_dist_enable_interrupt(gic, IMX8X_UART3_INT, 0x01, 0);
    assert(err_is_ok(err));

    /* enable IRQ in UART */
    err = lpuart_enable_interrupt(uart);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}
