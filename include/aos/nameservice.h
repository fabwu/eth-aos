/**
 * \file nameservice.h
 * \brief 
 */

#ifndef INCLUDE_NAMESERVICE_H_
#define INCLUDE_NAMESERVICE_H_

#include <aos/aos.h>

#define MAX_SERVICE_NAME_LENGTH (AOS_RPC_BUFFER_SIZE - 1)

typedef void* nameservice_chan_t;

///< handler which is called when a message is received over the registered channel
typedef void(nameservice_receive_handler_t)(void *st, 
										    void *message, size_t bytes,
										    void **response, size_t *response_bytes,
                                            struct capref tx_cap, struct capref *rx_cap);
errval_t nameservice_init(void);

/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_byts the size of the response
 * 
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes, 
                         void **response, size_t *response_bytes,
                         struct capref tx_cap, struct capref rx_cap);



/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name, 
	                              nameservice_receive_handler_t recv_handler,
	                              void *st);


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 * 
 * @return error value
 */
errval_t nameservice_deregister(const char *name);


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan);

/**
 * @brief lookup a service and return domain id
 *
 * @param name  name to lookup
 * @param did   domain id of service
 *
 * @return SYS_ERR_OK on success, LIB_ERR_NS_LOOKUP if not found
 */
errval_t nameservice_lookup_did(const char *name, domainid_t *did);

/**
 * @brief enumerates all entries that match an query (prefix match)
 */
errval_t nameservice_enumerate(void);


#endif /* INCLUDE_AOS_AOS_NAMESERVICE_H_ */
