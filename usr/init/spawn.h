#ifndef _INIT_ROUTING_H_
#define _INIT_ROUTING_H_

#include <aos/aos.h>
#include <spawn/spawn.h>

struct spawn_node {
    struct spawninfo si;
    struct lmp_chan chan;
    domainid_t pid;

    struct spawn_node *next;
};

errval_t init_spawn_by_name(char *namei, domainid_t *pid);

errval_t init_spawn_by_argv(int argc, char *argv[], domainid_t *pid);

void init_spawn_get_lmp_chan(domainid_t pid, struct lmp_chan **chan);
#endif /* _INIT_ROUTING_H_ */
