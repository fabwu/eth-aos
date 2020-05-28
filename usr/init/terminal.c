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
#include "terminal.h"

#define ASCII_LF        0xA
#define ASCII_CR        0xD
#define ASCII_EOT       0x4

static struct gic_dist_s *gic;
static struct lpuart_s *uart;

static struct lmp_chan *receiver;

#define MAX_LINE_SIZE   4096
static char buffer[MAX_LINE_SIZE];
static int pos, read_pos;
static bool line_ready;
#define LINE_END        '\n'

struct print_buffer {
    domainid_t pid;
    char buffer[MAX_LINE_SIZE];
    int print_pos;
    struct print_buffer *next;
};
static struct print_buffer *print_bufs;

static void send_char(char c)
{
    lmp_protocol_send1(receiver, AOS_RPC_SERIAL_GETCHAR, c);
}

void terminal_putchar(char c, domainid_t pid)
{
    grading_rpc_handler_serial_putchar(c);

    struct print_buffer *buf;

    // find print buffer for this process
    for (buf = print_bufs; buf; buf = buf->next) {
        if (buf->pid == pid) {
            break;
        }
    }
    if (buf == NULL) {
        // no print buffer yet, create one
        struct print_buffer *newbuf = calloc(1, sizeof(struct print_buffer));
        newbuf->pid = pid;
        newbuf->next = print_bufs;
        print_bufs = newbuf;
        buf = newbuf;
    }

    buf->buffer[buf->print_pos++] = c;

    if (c == '\n' || buf->print_pos == MAX_LINE_SIZE) {
        for (int i = 0; i < buf->print_pos; i++) {
            lpuart_putchar(uart, buf->buffer[i]);
        }
        if (c == '\n')
            lpuart_putchar(uart, '\r');
        buf->print_pos = 0;
    }
}

void terminal_getchar(struct lmp_chan *chan)
{
    grading_rpc_handler_serial_getchar();

    if (!line_ready) {
        receiver = chan;
    } else if (read_pos < pos) {
        /* send next char */
        send_char(buffer[read_pos++]);
    } else {
        /* whole line has been sent */
        send_char(LINE_END);
        pos = 0;
        read_pos = 0;
        line_ready = false;
    }
}

static void send_first_char(void)
{
    if (receiver) {
        if (pos > 0) {
            send_char(buffer[0]);
            read_pos = 1;
        } else {
            send_char(LINE_END);
            line_ready = false;
        }
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
            send_first_char();
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

errval_t terminal_init(void)
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

