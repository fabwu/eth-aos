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

extern struct bootinfo *bi;
extern coreid_t my_core_id;

/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 *
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
__attribute__((__used__)) static void
armv8_set_registers(void *arch_load_info, dispatcher_handle_t handle,
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
    task_cnode_cap.cnode = task_cnode_ref;
    // TODO: Populate task_cnode_cap
    // Need dispatcher
    // SELFEP
    // DISPATCHER
    // ROOTCN, give child(more probably dispatcher?) to child l1 cnode
    task_cnode_cap.slot = TASKCN_SLOT_ROOTCN;
    // TODO: Is this how it is done??
    err = cap_copy(task_cnode_cap, l1_cnode_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_COPY);
    }
    // DISPFRAME
    // ARGSPACE

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

    return SYS_ERR_OK;
}

static errval_t spawn_copy_child_vspace(struct spawninfo *si)
{
    errval_t err;
    err = paging_copy_capabilities(&si->paging, si->page_cnode_ref, 1, L2_CNODE_SLOTS);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_COPY_CAPABILITIES);
    }

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher called 'argv[0]' with 'argc' arguments.
 *
 * This function spawns a new dispatcher running the ELF binary called
 * 'argv[0]' with 'argc' - 1 additional arguments. It fills out 'si'
 * and 'pid'.
 *
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to the spawninfo struct representing
 * the child. It will be filled out by this function. Must not be NULL.
 * \param pid A pointer to a domainid_t variable that will be
 * assigned to by this function. Must not be NULL.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
    // TODO: Implement me
    // - Initialize the spawn_info struct
    // - Get the module from the multiboot image
    //   and map it (take a look at multiboot.c)
    // - Setup the child's cspace
    // - Setup the child's vspace
    // - Load the ELF binary
    // - Setup the dispatcher
    // - Setup the environment
    // - Make the new dispatcher runnable

    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t locate_elf_binary(char *binary_name, struct spawninfo *si)
{
    errval_t err = SYS_ERR_OK;

    assert(bi);
    assert(binary_name);
    assert(si);

    struct mem_region *module = multiboot_find_module(bi, binary_name);

    if (module == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }

    DEBUG_PRINTF("Found image of type %d and size %d at paddress %p with data diff %d\n",
                 module->mr_type, module->mrmod_size, module->mr_base, module->mrmod_data);

    // map binary frame into vaddress space
    struct capref child_frame = { .cnode = cnode_module, .slot = module->mrmod_slot };

    si->binary_size = module->mrmod_size;

    void *elf_binary;

    // XXX What about this frame? Can we remove it if ELF sections are mapped?
    err = paging_map_frame_attr(get_current_paging_state(), (void **)&elf_binary,
                                si->binary_size, child_frame, VREGION_FLAGS_READ, NULL,
                                NULL);

    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_MAP_MODULE);
    }

    si->binary_base = (lvaddr_t)elf_binary;

    uint8_t magic_number = *(uint8_t *)si->binary_base;
    if (magic_number != 0x7f) {
        return ELF_ERR_HEADER;
    }

    return err;
}

static errval_t elf_alloc(void *state, genvaddr_t base, size_t size, uint32_t flags,
                          void **ret)
{
    errval_t err = SYS_ERR_OK;

    // XXX useful command: readelf -l build/armv8/sbin/hello
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

    DEBUG_PRINTF("Allocate ELF section at address %p with size %d and ELF flags 0x%x and "
                 "frame flags 0x%x\n",
                 base, size, flags, frame_flags);

    struct capref frame_cap;
    err = frame_alloc(&frame_cap, size, NULL);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_ELF_FRAME);
    }

    err = paging_map_frame_attr(get_current_paging_state(), ret, size, frame_cap,
                                frame_flags, NULL, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    // TODO Map frame into child

    return err;
}

/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher executing 'binary_name'
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
    // TODO: Implement me
    // - Get the mem_region from the multiboot image
    // - Fill in argc/argv from the multiboot command line
    // - Call spawn_load_argv
    errval_t err = SYS_ERR_OK;
    si->binary_name = binary_name;

    err = spawn_create_child_cspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_CSPACE);
    }

    err = spawn_create_child_vspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_CHILD_VSPACE);
    }

    err = locate_elf_binary(binary_name, si);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_PRINTF("Located ELF binary at address %p with size %d\n", si->binary_base,
                 si->binary_size);

    err = spawn_copy_child_vspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_COPY_CHILD_VSPACE);
    }

    // TODO init cspace and vspace
    // TODO Init state which gets passed to each alloc call
    err = elf_load(EM_AARCH64, elf_alloc, NULL, si->binary_base, si->binary_size,
                   &si->entrypoint);
    if (err_is_fail(err)) {
        return err;
    }

    return err;
}

