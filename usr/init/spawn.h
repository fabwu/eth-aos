#ifndef _INIT_ROUTING_H_
#define _INIT_ROUTING_H_

#include <aos/aos.h>
#include <spawn/spawn.h>

struct spawn_node {
    struct spawninfo si;
    struct lmp_chan aos_rpc_chan;
    struct lmp_chan client_chan;
    struct lmp_chan server_chan;
    domainid_t pid;

    struct spawn_node *next;
};

errval_t init_spawn_by_name(char *name, domainid_t *did);

errval_t init_spawn_by_argv(int argc, char *argv[], domainid_t *did);

void init_spawn_get_lmp_client_chan(domainid_t did, struct lmp_chan **chan);
void init_spawn_get_lmp_server_chan(domainid_t did, struct lmp_chan **chan);
#endif /* _INIT_ROUTING_H_ */
