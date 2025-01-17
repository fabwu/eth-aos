#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <spawn/spawn.h>

#include <elf/elf.h>
#include <aos/dispatcher_arch.h>
#include <aos/lmp_chan.h>
#include <aos/aos_rpc.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>
#include <stdio.h>
#include <fs/fs.h>
#include <fs/dirent.h>

#define L1_NODE_SLOT_OFFSET 50

#if 0
#    define DEBUG_SPAWN(fmt...) debug_printf(fmt);
#else
#    define DEBUG_SPAWN(fmt...) ((void)0)
#endif


extern struct bootinfo *bi;
extern coreid_t my_core_id;

static domainid_t next_pid = 1;

/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 *
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
static void armv8_set_registers(void *arch_load_info, dispatcher_handle_t handle,
                                arch_registers_state_t *enabled_area,
                                arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t)arch_load_info;

    struct dispatcher_shared_aarch64 *disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}

static errval_t spawn_setup_dispatcher(struct spawninfo *si)
{
    errval_t err;

    err = slot_alloc(&si->dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = dispatcher_create(si->dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER);
    }

    size_t retbytes;
    err = frame_alloc(&si->dispframe, DISPATCHER_FRAME_SIZE, &retbytes);
    if (err_is_fail(err) || retbytes < DISPATCHER_FRAME_SIZE) {
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER_FRAME);
    }

    DEBUG_SPAWN("Created dispatcher DCB and frame\n");

    return SYS_ERR_OK;
}

static errval_t spawn_create_child_cspace(struct spawninfo *si)
{
    struct capref l1_cnode_cap;
    struct cnoderef l1_cnode_ref;
    errval_t err;
    err = cnode_create_l1(&l1_cnode_cap, &l1_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    struct capref task_cnode_cap;
    struct cnoderef task_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_TASKCN, &task_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }
    si->task_cnode_ref = task_cnode_ref;
    task_cnode_cap.cnode = task_cnode_ref;
    task_cnode_cap.slot = TASKCN_SLOT_ROOTCN;
    err = cap_copy(task_cnode_cap, l1_cnode_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    // Create SELFEP capability
    struct capref selfep;
    err = slot_alloc(&selfep);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    err = cap_retype(selfep, si->dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    task_cnode_cap.slot = TASKCN_SLOT_SELFEP;
    err = cap_copy(task_cnode_cap, selfep);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    si->selfep = selfep;

    // cap_copy dispframe and dispatcher caps
    si->child_dispatcher.cnode = si->task_cnode_ref;
    si->child_dispatcher.slot = TASKCN_SLOT_DISPATCHER;
    err = cap_copy(si->child_dispatcher, si->dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER);
    }

    si->child_dispframe.cnode = si->task_cnode_ref;
    si->child_dispframe.slot = TASKCN_SLOT_DISPFRAME;
    err = cap_copy(si->child_dispframe, si->dispframe);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER_FRAME);
    }

    if (!strcmp(si->binary_name, "terminal")) {
        task_cnode_cap.slot = TASKCN_SLOT_IRQ;
        err = cap_copy(task_cnode_cap, cap_irq);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_COPY);
        }
    }

    struct cnoderef alloc_0_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_SLOT_ALLOC0,
                                  &alloc_0_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }

    struct cnoderef alloc_1_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_SLOT_ALLOC1,
                                  &alloc_1_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }

    struct cnoderef alloc_2_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_SLOT_ALLOC2,
                                  &alloc_2_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }

    struct capref base_page_cnode_cap;
    struct cnoderef base_page_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_BASE_PAGE_CN,
                                  &base_page_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }
    base_page_cnode_cap.cnode = base_page_cnode_ref;
    for (int i = 0; i < L2_CNODE_SLOTS; ++i) {
        struct capref ram_cap;
        err = ram_alloc(&ram_cap, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_RAM_ALLOC);
        }
        base_page_cnode_cap.slot = i;
        err = cap_copy(base_page_cnode_cap, ram_cap);
    }

    struct capref page_cnode_cap;
    struct cnoderef page_cnode_ref;
    err = cnode_create_foreign_l2(l1_cnode_cap, ROOTCN_SLOT_PAGECN, &page_cnode_ref);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CNODE_CREATE_FOREIGN_L2);
    }

    page_cnode_cap.cnode = page_cnode_ref;
    page_cnode_cap.slot = 0;
    err = vnode_create(page_cnode_cap, ObjType_VNode_AARCH64_l0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    si->page_cnode_ref = page_cnode_ref;
    si->cspace = l1_cnode_cap;

    return SYS_ERR_OK;
}

static errval_t spawn_child_cspace_set_initep(struct spawninfo *si)
{
    errval_t err;
    // add init ep to domain cnode
    struct capref task_cnode_cap;
    task_cnode_cap.cnode = si->task_cnode_ref;

    task_cnode_cap.slot = TASKCN_SLOT_INIT_AOS_RPC_EP;
    err = cap_copy(task_cnode_cap, si->init_aos_rpc_ep);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    task_cnode_cap.slot = TASKCN_SLOT_INIT_CLIENT_EP;
    err = cap_copy(task_cnode_cap, si->init_client_ep);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    task_cnode_cap.slot = TASKCN_SLOT_INIT_SERVER_EP;
    err = cap_copy(task_cnode_cap, si->init_server_ep);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_create_child_vspace(struct spawninfo *si)
{
    errval_t err;
    struct capref pdir_our;
    struct capref pdir_child;

    pdir_child.cnode = si->page_cnode_ref;
    pdir_child.slot = 0;

    err = slot_alloc(&pdir_our);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = cap_copy(pdir_our, pdir_child);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_COPY);
    }
    // Convention is that we assume that at most slot 0 of l0 pt is used before we get to run
    genvaddr_t max_addr = 1;
    max_addr = (max_addr << VMSAv8_64_L0_BITS) - 1;
    err = paging_init_state_foreign(&si->paging, 0, max_addr, pdir_our,
                                    get_default_slot_allocator());
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_INIT_STATE_FOREIGN);
    }

    // Map dispatcher frame for child
    err = paging_map_frame_attr(&si->paging, (void **)&si->child_dispframe_map,
                                DISPATCHER_FRAME_SIZE, si->child_dispframe,
                                VREGION_FLAGS_READ_WRITE, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_DISPATCHER_SETUP);
    }

    return SYS_ERR_OK;
}

static errval_t elf_alloc(void *state, genvaddr_t base, size_t size, uint32_t flags,
                          void **ret)
{
    struct spawninfo *si = (struct spawninfo *)state;

    // useful command: readelf -l build/armv8/sbin/hello
    int frame_flags;

    switch (flags) {
    case PF_X:
        frame_flags = VREGION_FLAGS_EXECUTE;
        break;
    case PF_W:
        frame_flags = VREGION_FLAGS_WRITE;
        break;
    case PF_R:
        frame_flags = VREGION_FLAGS_READ;
        break;
    case (PF_R | PF_W):
        frame_flags = VREGION_FLAGS_READ_WRITE;
        break;
    case (PF_R | PF_X):
        frame_flags = VREGION_FLAGS_READ_EXECUTE;
        break;
    default:
        // unknown flags
        assert(false);
    }

    DEBUG_SPAWN("Allocate ELF section at address %p with size %d and ELF flags 0x%x and "
                "frame flags 0x%x\n",
                base, size, flags, frame_flags);

    genvaddr_t aligned_base = ROUND_DOWN(base, BASE_PAGE_SIZE);
    size_t aligned_size = ROUND_UP(size + (base - aligned_base), BASE_PAGE_SIZE);

    struct capref frame_cap;
    errval_t err = frame_alloc(&frame_cap, aligned_size, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    err = paging_map_frame(get_current_paging_state(), ret, aligned_size, frame_cap, NULL,
                           NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    *ret += (base - aligned_base);

    err = paging_map_fixed_attr(&si->paging, aligned_base, frame_cap, aligned_size,
                                frame_flags);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FIXED_ATTR);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_setup_args(struct spawninfo *si, int argc, char *argv[])
{
    void *ptr_frame, *ptr_frame_child;
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    /* allocate args page */
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    /* map args page into our vspace so we can write to it */
    err = paging_map_frame(st, &ptr_frame, BASE_PAGE_SIZE, frame_cap, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    /* set up child's cap to args page */
    struct capref task_cnode_cap = { .cnode = si->task_cnode_ref,
                                     .slot = TASKCN_SLOT_ARGSPAGE };
    err = cap_copy(task_cnode_cap, frame_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    /* map args page into child's vspace */
    err = paging_map_frame_attr(&si->paging, &ptr_frame_child, BASE_PAGE_SIZE, frame_cap,
                                VREGION_FLAGS_READ, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }
    si->child_args_addr = (lvaddr_t)ptr_frame_child;

    /* zero args page */
    memset(ptr_frame, 0, BASE_PAGE_SIZE);

    /* set up args struct at beginning of args page */
    struct spawn_domain_params *params = ptr_frame;
    params->argc = argc;
    params->envp[0] = NULL;
    params->pagesize = BASE_PAGE_SIZE;
    memcpy(params->argv, argv, MAX_CMDLINE_ARGS * sizeof(char *));

    /* put argument strings after struct */
    // Copy all argument string contiguously right after the params struct
    // and update all params->argv pointers to point to the correct string.
    void *argv_str = ptr_frame + sizeof(*params);
    lvaddr_t argv_str_child = si->child_args_addr + sizeof(*params);
    size_t offset = 0;
    for (int i = 0; argv[i]; ++i) {
        // Copy argument i
        size_t str_len = strlen(argv[i]) + 1;
        assert(argv_str + offset + str_len <= ptr_frame + BASE_PAGE_SIZE);
        memcpy(argv_str + offset, argv[i], str_len);
        // Update params->argv pointer for child VA
        params->argv[i] = (char *)(argv_str_child + offset);

        offset += str_len;
    }

    /* unmap args page from our vspace */
    err = paging_unmap(st, (lvaddr_t)ptr_frame, frame_cap, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_UNMAP);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_dispatch(struct spawninfo *si, domainid_t pid)
{
    errval_t err;
    struct paging_state *st = get_current_paging_state();

    // Map dispatcher frame and get references to dispatcher structs
    err = paging_map_frame_attr(st, &si->dispbase, DISPATCHER_FRAME_SIZE, si->dispframe,
                                VREGION_FLAGS_READ_WRITE, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_DISPATCHER_SETUP);
    }

    dispatcher_handle_t handle = (dispatcher_handle_t)si->dispbase;

    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle);

    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle);

    disp_gen->core_id = disp_get_core_id();
    disp_gen->domain_id = pid;
    // Virtual address of the dispatcher frame in child’s VSpace
    disp->udisp = si->child_dispframe_map;
    disp->disabled = 1;                                   // Start in disabled mode
    strncpy(disp->name, si->binary_name, DISP_NAME_LEN);  // Dispatcher name for debugging

    // Set program counter (where it should start to execute)
    disabled_area->named.pc = si->entrypoint;
    enabled_area->named.x0 = (uint64_t)si->child_args_addr;

    // Initialize offset registers
    // got_addr is the address of the .got in the child’s VSpace
    struct Elf64_Shdr *got = elf64_find_section_header_name((genvaddr_t)si->module_base,
                                                            si->module_size, ".got");
    if (got == NULL) {
        return SPAWN_ERR_DISPATCHER_SETUP;
    }
    armv8_set_registers((void *)got->sh_addr, handle, enabled_area, disabled_area);

    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    DEBUG_SPAWN("Dispatcher setup completed\n");
    // dump_dispatcher(disp);

    struct capref vspace = { .cnode = si->page_cnode_ref, .slot = 0 };
    err = invoke_dispatcher(si->dispatcher, cap_dispatcher, si->cspace, vspace,
                            si->child_dispframe, true);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_RUN);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_free(struct spawninfo *si)
{
    errval_t err;
    struct paging_state *st = get_current_paging_state();

    // Free dispatcher
    err = paging_unmap(st, (lvaddr_t)si->dispbase, si->dispframe, DISPATCHER_FRAME_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_UNMAP);
    }

    err = cap_destroy(si->dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_DESTROY_DISAPTCHER);
    }

    err = cap_destroy(si->dispframe);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_DESTROY_DISFRAME);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si,
                                domainid_t *pid)
{
    assert(argv[0]);
    errval_t err;

    // init spawn_info
    si->binary_name = argv[0];

    // Set pid (core specific)
    assert(disp_get_core_id() <= 0xf);
    domainid_t domain_id = (next_pid & 0xffff) | ((disp_get_core_id() & 0xf) << 12);
    next_pid += 1;

    if (pid != NULL) {
        *pid = domain_id;
    }

    // currently the location of the binary is given by si->module_base and si->module_size
    DEBUG_SPAWN("Located ELF binary at address %p with size %d\n", si->module_base,
                si->module_size);

    uint8_t magic_number = *(uint8_t *)si->module_base;
    DEBUG_SPAWN("ELF Magic number: 0x%hhx\n",
                magic_number);  // Required for assessment milestone2
    if (magic_number != 0x7f) {
        return ELF_ERR_HEADER;
    }

    err = spawn_setup_dispatcher(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_SETUP_DISPATCHER);
    }

    err = spawn_create_child_cspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    err = spawn_child_cspace_set_initep(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CHILD_CSPACE_SET_INITEP);
    }

    err = spawn_create_child_vspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_VSPACE);
    }

    err = elf_load(EM_AARCH64, elf_alloc, si, (genvaddr_t)si->module_base,
                   si->module_size, &si->entrypoint);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_ELF_LOAD);
    }

    err = spawn_setup_args(si, argc, argv);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_SETUP_ARGS);
    }

    err = spawn_dispatch(si, domain_id);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_DISPATCH);
    }

    err = spawn_free(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_FREE);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_load_module_argv(struct mem_region *module, int argc, char *argv[],
                                       struct spawninfo *si, domainid_t *pid)
{
    errval_t err;
    assert(argc > 0);
    assert(module != NULL);

    // map elf binary into current vspace
    si->module_size = module->mrmod_size;

    struct paging_state *st = get_current_paging_state();
    struct capref module_frame = { .cnode = cnode_module, .slot = module->mrmod_slot };
    size_t aligned_size = ROUND_UP(si->module_size, BASE_PAGE_SIZE);

    err = paging_map_frame_attr(st, &si->module_base, aligned_size, module_frame,
                                VREGION_FLAGS_READ, NULL, NULL);

    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_MAP_MODULE);
    }

    DEBUG_SPAWN("Found image of type %d and size %d at paddress %p with data diff %d\n",
                module->mr_type, module->mrmod_size, module->mr_base, module->mrmod_data);

    // spawn binary
    err = spawn_load_argv(argc, argv, si, pid);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_LOAD_ARGV);
    }

    // Free ELF
    err = paging_unmap(st, (lvaddr_t)si->module_base, module_frame, aligned_size);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_UNMAP);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_load_module_argv_sdcard(const char *dir, int argc, char *argv[],
                                              struct spawninfo *si, domainid_t *pid)
{
    errval_t err;

    // This might fail because of rpc
    err = filesystem_init();
    if (err_is_fail(err)) {
        return err;
    }

    FILE *f;
    f = fopen(dir, "r");
    err = ferror(f);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_OPEN);
    }

    err = fseek(f, 0, SEEK_END);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_SEEK);
    }

    struct fs_fileinfo finfo;
    long size = ftell(f);
    if (size < 0) {
        return FS_ERR_TELL;
    }
    finfo.size = size;

    err = fseek(f, 0, SEEK_SET);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_SEEK);
    }

    void *buf = malloc(finfo.size);
    if (buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    size_t read;
    read = fread(buf, 1, finfo.size, f);
    err = ferror(f);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_READ);
    }
    assert(read < finfo.size);

    finfo.size = read;

    err = fclose(f);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_CLOSE);
    }

    si->module_size = finfo.size;
    si->module_base = buf;

    assert(argc > 0);

    DEBUG_SPAWN("Found image of size %zu\n", finfo.size);

    // spawn binary
    err = spawn_load_argv(argc, argv, si, pid);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_LOAD_ARGV);
    }

    // free elf
    free(buf);

    return SYS_ERR_OK;
}


errval_t spawn_load_by_name_sdcard(const char *dir, const char *name,
                                   struct spawninfo *si, domainid_t *pid)
{
    char **argv = malloc(sizeof(char *) * 2);
    if (argv == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    argv[0] = (char *)name;
    argv[1] = NULL;

    return spawn_load_module_argv_sdcard(dir, 1, argv, si, pid);
}


/**
 * \brief Spawn a new dispatcher executing argv[0]
 *
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
    assert(argc > 0);
    assert(argv[0]);

    // find multiboot image
    struct mem_region *module = multiboot_find_module(bi, argv[0]);
    if (module == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }

    return spawn_load_module_argv(module, argc, argv, si, pid);
}

/**
 * \brief Spawn a new dispatcher executing 'binary_name'
 *
 * Arguments are parsed from the multiboot image.
 *
 * \param binary_name The name of the binary.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid)
{
    errval_t err = SYS_ERR_OK;

    // find multiboot image
    struct mem_region *module = multiboot_find_module(bi, binary_name);
    if (module == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }

    // parse args
    int argc = 0;
    char **argv;
    char *argv_str;

    const char *args = multiboot_module_opts(module);
    argv = make_argv(args, &argc, &argv_str);
    if (argv == NULL) {
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }

    err = spawn_load_module_argv(module, argc, argv, si, pid);
    assert(err_is_ok(err));

    free_argv(argv, argv_str);

    return err;
}

