/**
 * \file
 * \brief init rpc
 */

#include "rpc.h"
#include "process.h"
#include <aos/lmp_protocol.h>
#include <aos/kernel_cap_invocations.h>

#if 0
#    define DEBUG_RPC_SETUP(fmt...) debug_printf(fmt);
#else
#    define DEBUG_RPC_SETUP(fmt...) ((void)0)
#endif

struct aos_ump ump;

/**
 * Receives a number.
 */
static errval_t rpc_print_number(uintptr_t number)
{
    // has to be called for grading see chapter 5.10
    grading_rpc_handle_number(number);

    return SYS_ERR_OK;
}

/**
 * Receives a string.
 */
static errval_t rpc_print_string(struct lmp_chan *chan, struct lmp_recv_msg *lookahead)
{
    char *string;
    errval_t err = lmp_protocol_recv_string_cap_la(chan, AOS_RPC_SEND_STRING, NULL,
                                                   &string, lookahead);
    if (err_is_fail(err)) {
        return err;
    }

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_string(string);

    free(string);
    return SYS_ERR_OK;
}

/**
 * Allocates ram, sends capability to child.
 */
static errval_t rpc_send_device(struct lmp_chan *chan, lpaddr_t paddr, size_t bytes)
{
    errval_t err;

    grading_rpc_handler_get_device_cap(paddr, bytes);

    struct capref device_register_capref = { .cnode = { .croot = CPTR_ROOTCN,
                                                        .cnode = CPTR_TASKCN_BASE,
                                                        .level = CNODE_TYPE_OTHER },
                                             .slot = TASKCN_SLOT_DEV };

    struct capability device_register_cap;
    err = cap_direct_identify(device_register_capref, &device_register_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CAP_IDENTIFY);
        goto out;
    }

    struct capref device_register_frame_capref;
    err = slot_alloc(&device_register_frame_capref);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto out;
    }

    err = cap_retype(device_register_frame_capref, device_register_capref,
                     paddr - get_address(&device_register_cap), ObjType_DevFrame, bytes,
                     1);
    if (err_is_fail(err)) {
        errval_t err2 = cap_destroy(device_register_frame_capref);
        if (err_is_fail(err2)) {
            DEBUG_ERR(err2, "Could not cleanup slot");
        }

        err = err_push(err, LIB_ERR_CAP_RETYPE);
        goto out;
    }

out:
    if (err_is_ok(err)) {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_DEVICE_CAP, device_register_frame_capref,
                               paddr, bytes, true);

        // Don't pollute init
        err = cap_destroy(device_register_frame_capref);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

        return SYS_ERR_OK;
    } else {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_DEVICE_CAP, NULL_CAP, paddr, bytes,
                               false);
        return err;
    }
}
/**
 * Allocates ram, sends capability to child.
 */
static errval_t rpc_send_ram(struct lmp_chan *chan, size_t size, size_t alignment)
{
    errval_t err;

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_ram_cap(size, alignment);

    struct capref ram_cap;
    err = slot_alloc(&ram_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto out;
    }

    err = ram_alloc_aligned(&ram_cap, size, alignment);
    if (err_is_fail(err)) {
        // FIXME: Clean up slot
        err = err_push(err, LIB_ERR_RAM_ALLOC_ALIGNED);
        goto out;
    }

out:
    if (err_is_ok(err)) {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_RAM_CAP, ram_cap, size, alignment, true);

        // we have to destroy cap here otw. child cannot free ram later
        err = cap_destroy(ram_cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

        return SYS_ERR_OK;
    } else {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_RAM_CAP, NULL_CAP, 0, alignment, false);
        return err;
    }
}

/**
 * Frees ram at given physical address.
 */
// FIXME: Add mechanism so processes can only free their only ram, why we can't get the
// capability here is because of fram_free
static errval_t rpc_free_ram(struct lmp_chan *chan, genpaddr_t addr)
{
    errval_t err;

    err = ram_free(addr);
    if (err_is_ok(err)) {
        lmp_protocol_send2(chan, AOS_RPC_FREE_RAM_CAP, addr, true);
        return SYS_ERR_OK;
    } else {
        lmp_protocol_send2(chan, AOS_RPC_FREE_RAM_CAP, 0, false);
        return err_push(err, LIB_ERR_RAM_FREE);
    }
}

/**
 * Receives a char from the serial line.
 */
static errval_t rpc_serial_getchar(struct lmp_chan *chan)
{
    grading_rpc_handler_serial_getchar();

    return SYS_ERR_OK;
}

/**
 * Puts a char on the serial line.
 */
// FIXME: Add line buffer, so the output of different processes does not get mixed and
// sys_print() only gets called once per line.
static errval_t rpc_serial_putchar(uintptr_t arg1)
{
    char c = (char)arg1;

    // XXX Here we would call serial_put_char or similar
    char str[2];
    str[0] = c;
    str[1] = '\0';

    sys_print(str, 2);

    grading_rpc_handler_serial_putchar(c);

    return SYS_ERR_OK;
}

static void rpc_ump_handler_recv(void *arg, uint8_t *buf)
{
    uint64_t *numbers = (uint64_t *)buf;
    assert((domainid_t)numbers[0] == 0);
    uintptr_t message_type = numbers[1];
    switch (numbers[1]) {
    case AOS_RPC_PROCESS_SPAWN:
    case AOS_RPC_PROCESS_GET_ALL_PIDS:
    case AOS_RPC_PROCESS_GET_NAME:
    case AOS_RPC_PROCESS_EXIT:
    case AOS_RPC_PROCESS_SPAWN_REMOTE:
        process_handle_ump_request(message_type, buf);
        free(buf);
        break;
    default:
        debug_printf("Unknown ump request: 0x%x\n", message_type);
    }
    aos_protocol_register_recv(0, MKCALLBACK(rpc_ump_handler_recv, arg));
}

void rpc_ump_start_handling(void)
{
    // TODO: errval handling
    aos_protocol_register_recv(0, MKCALLBACK(rpc_ump_handler_recv, NULL));
}

errval_t rpc_dispatch(void)
{
    errval_t err;
    struct waitset *default_ws = get_default_waitset();
    while (1) {
        if (aos_ump_can_dequeue(&ump)) {
            uint8_t *buf = (uint8_t *)malloc(AOS_UMP_MSG_SIZE);
            if (buf == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            err = aos_ump_dequeue(&ump, buf, AOS_UMP_MSG_SIZE);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_UMP_DEQUEUE);
            }

            uint64_t header = ((uint64_t *)buf)[0];
            DEBUG_PRINTF("HEADER %p\n", header);

            domainid_t receiver = AOS_RPC_HEADER_RECV(header);
            bool to_server = ((uint64_t *)buf)[1] == 0x1;
            uintptr_t arg1 = ((uint64_t *)buf)[2];
            uintptr_t arg2 = ((uint64_t *)buf)[3];
            uintptr_t arg3 = ((uint64_t *)buf)[4];
            struct lmp_chan *recv_chan;

            if (to_server) {
                // msg is from client -> forward to server
                init_spawn_get_lmp_server_chan(receiver, &recv_chan);
            } else {
                // msg is from server -> forward to client
                init_spawn_get_lmp_client_chan(receiver, &recv_chan);
            }

            if (recv_chan == NULL) {
                USER_PANIC("Couldn't find lmp chan");
            }

            if (AOS_RPC_HEADER_MSG(header) == AOS_RPC_MSG_NS_RPC) {
                // rpc message -> forge frame and send it to local domain
                genpaddr_t frame_paddr = (genpaddr_t)arg1;
                size_t frame_bytes = (size_t)arg2;
                size_t payload_bytes = (size_t)arg3;

                // forge frame
                struct capref payload_cap;
                err = slot_alloc(&payload_cap);
                if (err_is_fail(err)) {
                    return err_push(err, LIB_ERR_SLOT_ALLOC);
                }
                err = frame_forge(payload_cap, frame_paddr, frame_bytes,
                                  disp_get_current_core_id());
                if (err_is_fail(err)) {
                    return err_push(err, LIB_ERR_FRAME_FORGE);
                }

                // send forged frame and payload size to local domain
                err = lmp_protocol_send_cap1(recv_chan, header, payload_cap,
                                             payload_bytes);
                if (err_is_fail(err)) {
                    USER_PANIC_ERR(err, "Couldn't forward rpc msg\n");
                }
            } else {
                // normal msg -> just forward it to local domain
                err = lmp_protocol_send(recv_chan, header, NULL_CAP, arg1, arg2, arg3);
                if (err_is_fail(err)) {
                    USER_PANIC_ERR(err, "Couldn't forward msg from other core\n");
                }
            }
        } else {
            err = event_dispatch_non_block(default_ws);
            if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
                return err;
            }

            thread_yield();
        }
    }

    return SYS_ERR_OK;
}

static errval_t rpc_send_ump(aos_rpc_header_t header, bool to_server, uintptr_t arg1,
                             uintptr_t arg2, uintptr_t arg3)
{
    errval_t err;
    uint64_t buf[5];
    buf[0] = header;
    buf[1] = to_server;  // if 1 client -> server
    buf[2] = arg1;
    buf[3] = arg2;
    buf[4] = arg3;
    err = aos_ump_enqueue(&ump, (void *)buf, sizeof(uint64_t) * 5);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_UMP_ENQUEUE);
    }

    return SYS_ERR_OK;
}

/**
 * Handles messages from different child channels
 */
static void rpc_handler_recv_closure(void *arg)
{
    errval_t err;
    struct lmp_chan *chan = (struct lmp_chan *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);

    DEBUG_RPC_SETUP("rpc_handler_recv_closure called!\n");

    if (err_is_ok(err)) {
        if (!capref_is_null(cap)) {
            lmp_chan_alloc_recv_slot(chan);
        }
        aos_rpc_header_t header = msg.words[0];
        // domainid_t sender = AOS_RPC_HEADER_SEND(header);
        domainid_t receiver = AOS_RPC_HEADER_RECV(header);
        aos_rpc_msg_t message_type = AOS_RPC_HEADER_MSG(header);

        if (receiver == disp_get_domain_id()) {
            // init is receiver -> handle message
            switch (message_type) {
            case AOS_RPC_SEND_NUMBER:
                rpc_print_number(msg.words[1]);
                break;
            case AOS_RPC_SEND_STRING:
                rpc_print_string(chan, &msg);
                break;
            case AOS_RPC_GET_RAM_CAP:
                err = rpc_send_ram(chan, msg.words[1], msg.words[2]);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "rpc_send_ram failed");
                }
                break;
            case AOS_RPC_FREE_RAM_CAP:
                err = rpc_free_ram(chan, msg.words[1]);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "rpc_free_ram failed");
                }
                break;
            case AOS_RPC_GET_DEVICE_CAP:
                err = rpc_send_device(chan, msg.words[1], msg.words[2]);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "rpc_send_device failed");
                }
                break;
            case AOS_RPC_SERIAL_GETCHAR:
                err = rpc_serial_getchar(chan);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "rpc_serial_getchar failed");
                }
                break;
            case AOS_RPC_SERIAL_PUTCHAR:
                err = rpc_serial_putchar(msg.words[1]);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "rpc_serial_putchar failed");
                }
                break;
            case AOS_RPC_PROCESS_SPAWN:
            case AOS_RPC_PROCESS_GET_ALL_PIDS:
            case AOS_RPC_PROCESS_GET_NAME:
            case AOS_RPC_PROCESS_EXIT:
                process_handle_lmp_request(message_type, &msg, chan);
                break;
            default:
                debug_printf("Unknown request: %" PRIu64 "\n", msg.words[0]);
            }
        } else {
            // Route message to receiver
            coreid_t recv_core_id = AOS_RPC_CORE_ID(receiver);
            bool to_server;
            if (chan->type == LMP_NS_CLIENT) {
                // msg is from client -> forward to server
                to_server = true;
            } else if (chan->type == LMP_NS_SERVER) {
                // msg is from server -> forward to client
                to_server = false;
            } else if (chan->type == LMP_AOS_RPC) {
                USER_PANIC("Messages over LMP_AOS_RPC channel should be handled by init");
            } else {
                USER_PANIC("Unknown channel type\n");
            }

            if (recv_core_id == disp_get_current_core_id()) {
                // use lmp to forward message
                struct lmp_chan *recv_chan;

                if (to_server) {
                    // msg is from client -> forward to server
                    init_spawn_get_lmp_server_chan(receiver, &recv_chan);
                } else {
                    // msg is from server -> forward to client
                    init_spawn_get_lmp_client_chan(receiver, &recv_chan);
                }

                if (recv_chan == NULL) {
                    USER_PANIC("Couldn't find lmp chan");
                }

                err = lmp_protocol_send(recv_chan, msg.words[0], cap, msg.words[1],
                                        msg.words[2], msg.words[3]);
                if (err_is_fail(err)) {
                    USER_PANIC_ERR(err, "Couldn't forward\n");
                }
            } else {
                // domain not on same core -> use ump to forward message
                if (message_type == AOS_RPC_MSG_NS_RPC) {
                    // rpc requires shared frame -> send paddr to other core
                    struct frame_identity fi;
                    err = frame_identify(cap, &fi);
                    if (err_is_fail(err)) {
                        USER_PANIC_ERR(err, "Couldn't identify frame for rpc payload\n");
                    }

                    // UMP msg format for rpc
                    // buf[0]: header (type, sender did, receiver did)
                    // buf[1]: to_server (true if msg goes from client -> server)
                    // buf[2]: paddr of frame
                    // buf[3]: size of frame
                    // buf[4]: size of payload
                    uintptr_t frame_paddr = (uintptr_t)fi.base;
                    uintptr_t frame_bytes = (uintptr_t)fi.bytes;
                    uintptr_t payload_bytes = (uintptr_t)msg.words[1];  // size
                    err = rpc_send_ump(header, to_server, frame_paddr, frame_bytes,
                                       payload_bytes);
                    if (err_is_fail(err)) {
                        USER_PANIC_ERR(err, "Couldn't send rpc frame to other core\n");
                    }
                } else {
                    // normal msg -> just forward it to the other core
                    assert(capref_is_null(cap));

                    err = rpc_send_ump(header, to_server, msg.words[1], msg.words[2],
                                       msg.words[3]);
                    if (err_is_fail(err)) {
                        USER_PANIC_ERR(err, "Couldn't forward msg to other core\n");
                    }
                }
            }
        }

        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_handler_recv_closure success!\n");

        return;
    } else if (lmp_err_is_transient(err)) {
        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_handler_recv_closure retry!\n");

        return;
    }

fail:
    DEBUG_ERR(err, "rpc_handler_recv_closure failed hard");
}

/**
 * Receives a child endpoint cap, saves it in the channel and notify the child
 * that channel is ready.
 */
static void rpc_setup_recv_closure(void *arg)
{
    errval_t err;

    struct lmp_chan *chan = (struct lmp_chan *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);

    DEBUG_RPC_SETUP("rpc_setup_recv_closure called!\n");

    // Got message
    if (err_is_ok(err)) {
        // Check if setup message
        assert(msg.words[0] == AOS_RPC_SETUP);

        chan->remote_cap = cap;

        err = lmp_chan_alloc_recv_slot(chan);
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_setup_recv_closure success!\n");

        err = lmp_protocol_send0(chan, AOS_RPC_SETUP);
        if (err_is_fail(err)) {
            goto fail;
        }

        // Channel to child is setup, switch to child handler
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        return;
    } else if (lmp_err_is_transient(err)) {
        DEBUG_RPC_SETUP("rpc_setup_recv_closure retry!\n");

        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_setup_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

fail:
    DEBUG_ERR(err, "rpc_setup_recv_closure failed hard!\n");
}

/**
 * Creates a channel to a child (to be spawned)
 */
errval_t rpc_create_child_channel_to_init(struct lmp_chan *chan)
{
    errval_t err = SYS_ERR_OK;

    lmp_chan_init(chan);

    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &chan->local_cap, &chan->endpoint);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_ENDPOINT_CREATE);
        goto out;
    }

    chan->connstate = LMP_BIND_WAIT;

    // Preallocate first receive slot
    // lmp_protocol will preallocate new slots when the current slot is used up
    err = lmp_chan_alloc_recv_slot(chan);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
        goto out;
    }

    // Needs to be non-blocking, so lmp_protocol is not used here
    err = lmp_chan_register_recv(chan, get_default_waitset(),
                                 MKCLOSURE(rpc_setup_recv_closure, chan));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
        goto out;
    }

    assert(!capref_is_null(chan->local_cap));
out:
    if (err_is_fail(err)) {
        if (!capref_is_null(chan->endpoint->recv_slot)) {
            cap_destroy(chan->endpoint->recv_slot);
        }
        lmp_chan_destroy(chan);
    }
    return err;
}

