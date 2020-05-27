/**
 * \file
 * \brief Terminal (UART) driver
 */

#include <stdio.h>
#include <aos/aos.h>
#include <aos/lmp_protocol.h>
#include <aos/aos_rpc.h>
#include <aos/nameservice.h>
#include <aos/inthandler.h>
#include <drivers/gic_dist.h>
#include <drivers/lpuart.h>
#include <grading.h>
#include <maps/imx8x_map.h>

#define ASCII_LF        0xA
#define ASCII_CR        0xD
#define ASCII_EOT       0x4

static struct gic_dist_s *gic;
static struct lpuart_s *uart;

#define MAX_LINE_SIZE   4096
static char buffer[MAX_LINE_SIZE];
static int pos, read_pos;
static bool line_ready;
static char line_end = '\n';

static void terminal_handle_rpc(void *st, void *message, size_t bytes,
                                void **response, size_t *response_bytes,
                                struct capref rx_cap, struct capref *tx_cap)
{
    errval_t err;

    if (strcmp(message, "getchar")) {
        DEBUG_PRINTF("Unknown message: %s\n", message);
        return;
    }

    grading_rpc_handler_serial_getchar();

    while (!line_ready) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "event_dispatch failed\n");
            return;
        }
    }

    if (read_pos < pos) {
        /* send next char */
        *response = &buffer[read_pos++];
        *response_bytes = 1;
    } else {
        /* whole line has been sent */
        *response = &line_end;
        *response_bytes = 1;
        pos = 0;
        read_pos = 0;
        line_ready = false;
    }
}

static void irq_handler(void *arg)
{
    char c;

    while (lpuart_getchar(uart, &c) != LPUART_ERR_NO_DATA) {
        /* wait for line to be read before starting a new line */
        if (line_ready)
            continue;

        switch (c) {
        case ASCII_LF:
        case ASCII_CR:
        case ASCII_EOT:
            line_ready = true;
            break;
        default:
            if (pos >= MAX_LINE_SIZE) {
                /* input too long, drop the whole thing */
                lpuart_putchar(uart, ASCII_LF);
                lpuart_putchar(uart, ASCII_CR);
                pos = 0;
                break;
            }
            lpuart_putchar(uart, c);
            buffer[pos++] = c;
            break;
        }
    }
}

static errval_t gic_setup(void) {
    struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    struct capref gic_capref;
    err = aos_rpc_get_device_cap(init_rpc, IMX8X_GIC_DIST_BASE,
                                 IMX8X_GIC_DIST_SIZE, &gic_capref);
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
    struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    struct capref uart_capref;
    err = aos_rpc_get_device_cap(init_rpc, IMX8X_UART3_BASE, IMX8X_UART_SIZE,
                                 &uart_capref);
    assert(err_is_ok(err));

    void *uart_vaddr;
    err = paging_map_frame_attr(st, &uart_vaddr, IMX8X_UART_SIZE, uart_capref,
                                VREGION_FLAGS_READ_WRITE_NOCACHE, NULL, NULL);
    assert(err_is_ok(err));

    err = lpuart_init(&uart, uart_vaddr);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
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

    // TODO make sure nameservice has started before we call this
    err = nameservice_register("terminal", terminal_handle_rpc, NULL);
    assert(err_is_ok(err));

    while (1) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "event_dispatch failed\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

