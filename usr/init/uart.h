/**
 * \file
 * \brief Userspace UART driver management
 */
#include <aos/aos.h>
#include <aos/lmp_protocol.h>

errval_t uart_init(void);
void uart_getchar(struct lmp_chan *chan);

