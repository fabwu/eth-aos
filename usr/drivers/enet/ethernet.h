#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <errno.h>
#include <netutil/etharp.h>
#include "enet.h"

struct ethernet_frame_id;

/**
 * \brief Setup ethernet handling.
 */
errval_t ethernet_init(void *rx_base, void *tx_base, struct enet_queue *txq,
                       regionid_t tx_rid);

/**
 * \brief Handle the given buffer. Assuming that the buffer is freed by the client after
 * this function returns.
 */
errval_t ethernet_handle_frame(struct devq_buf *buf);

/**
 * \brief Reserves a send buffer and writes the given values to the ethernet header.
 * Values have to be in network byte order already.
 */
errval_t ethernet_start_send_frame(struct eth_addr dest, struct eth_addr src,
                                   uint16_t type, struct ethernet_frame_id **ret_frame,
                                   void **ret_data);

/**
 * \brief Sends the ethernet frame and frees the buffer after wards.
 * The sending has to be started with ethernet_start_send_frame beforehand.
 */
errval_t ethernet_send_frame(struct ethernet_frame_id *frame, size_t size);

#endif  // ETHERNET_H_