#include <aos/aos.h>
#include <aos/coreboot.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <string.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>

#define ARMv8_KERNEL_OFFSET 0xffff000000000000

#define CPU_DRIVER_EP_SYM "arch_init"
#define BOOT_DRIVER_EP_SYM "boot_entry_psci"

extern struct bootinfo *bi;

struct binary_info {
    struct capref frame;  ///> frame which holds binary
    genvaddr_t addr;      ///> vaddr in current address space where binary is mapped
    size_t size;          ///> size of binary
};

/**
 * \brief holds information about a specific memory region for the new core
 * (e.g. kernel stack)
 */
struct mem_info {
    size_t size;         ///> Size in bytes of the memory region
    void *buf;           ///> Address where the region is currently mapped
    lpaddr_t phys_base;  ///> Physical base address
};

/**
 * \brief This struct holds a contiguous block for all memory required to boot a core.
 *
 * This block is divided into mem_infos.
 */
struct core_mem_block {
    struct capref frame;  ///> frame for the whole block
    size_t size;          ///> size of the block
    void *buf;            ///> location where block is mapped in current vaddr space
    lpaddr_t phys_base;   ///> physical base of this block
};

/**
 * \brief all memory regions required by the new core
 */
struct core_mem {
    struct mem_info boot_driver;
    struct mem_info cpu_driver;
    struct mem_info core_data;
    struct mem_info kernel_stack;
    struct mem_info init;
};

#if 1
#    define DEBUG_COREBOOT(fmt...) debug_printf(fmt);
#else
#    define DEBUG_COREBOOT(fmt...) ((void)0)
#endif

/**
 * \brief Load a ELF image into memory.
 *
 * \param binary            Valid pointer to ELF image in current address space
 * \param mem               Where the ELF will be loaded
 * \param entry_point       Virtual address of the entry point
 * \param reloc_entry_point Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t load_elf_binary(genvaddr_t binary,
                                                          const struct mem_info *mem,
                                                          genvaddr_t entry_point,
                                                          genvaddr_t *reloc_entry_point)

{
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point = 0;
    bool loaded = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                         ", memory size 0x%" PRIx64 " SKIP\n",
                         i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                     ", memory size 0x%" PRIx64 " LOAD\n",
                     i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void *dest = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if (entry_point >= phdr[i].p_vaddr
                && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
                *reloc_entry_point = (dest_phys + (entry_point - phdr[i].p_vaddr));
                found_entry_point = 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image.
 *
 * \param binary        Valid pointer to ELF image in current address space
 * \param mem           Where the ELF is loaded
 * \param load_offset   offset for relocating
 */
__attribute__((__used__)) static errval_t
relocate_elf(genvaddr_t binary, struct mem_info *mem, lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t shnum = ehdr->e_shnum;
    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for (size_t i = 0; i < shnum; i++) {
        struct Elf64_Shdr *shdr = &shead[i];
        if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if (shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                             " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base = phdr[0].p_vaddr;
            uint64_t segment_load_base = mem->phys_base;
            uint64_t segment_delta = segment_load_base - segment_elf_base;
            uint64_t segment_vdelta = (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if (shdr->sh_type == SHT_REL) {
                rsize = sizeof(struct Elf64_Rel);
            } else {
                rsize = sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel = shdr->sh_size / rsize;

            void *reldata = (void *)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for (size_t ii = 0; ii < nrel; ii++) {
                void *reladdr = reldata + ii * rsize;

                switch (shdr->sh_type) {
                case SHT_REL:
                    DEBUG_PRINTF("SHT_REL unimplemented.\n");
                    return ELF_ERR_PROGHDR;
                case SHT_RELA: {
                    struct Elf64_Rela *rel = reladdr;

                    uint64_t offset = rel->r_offset;
                    uint64_t sym = ELF64_R_SYM(rel->r_info);
                    uint64_t type = ELF64_R_TYPE(rel->r_info);
                    uint64_t addend = rel->r_addend;

                    uint64_t *rel_target = (void *)offset + segment_vdelta;

                    switch (type) {
                    case R_AARCH64_RELATIVE:
                        if (sym != 0) {
                            DEBUG_PRINTF("Relocation references a"
                                         " dynamic symbol, which is"
                                         " unsupported.\n");
                            return ELF_ERR_PROGHDR;
                        }

                        /* Delta(S) + A */
                        *rel_target = addend + segment_delta + load_offset;
                        break;

                    default:
                        DEBUG_PRINTF("Unsupported relocation type %d\n", type);
                        return ELF_ERR_PROGHDR;
                    }
                } break;
                default:
                    DEBUG_PRINTF("Unexpected type\n");
                    break;
                }
            }
        }
    }

    return SYS_ERR_OK;
}

/**
 * Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
 *
 * \param ret_addr paddr of KCB
 */
static errval_t create_kcb(genpaddr_t *ret_addr)
{
    errval_t err;

    // TODO: HACK until mm_alloc_aligned supports >4k alignment
    struct capref ram_cap;
    int ctr = 0;
    do {
        err = ram_alloc_aligned(&ram_cap, OBJSIZE_KCB, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_RAM_ALLOC_ALIGNED);
        }
        err = cap_get_phys_addr(ram_cap, ret_addr);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_GET_PHYS_ADDR);
        }
        ctr++;
    } while ((*ret_addr) % (16 * 1024) != 0);
    DEBUG_PRINTF("FIXME: allocated 0x%lx bytes %i times (total %lu bytes) until found 16k alignment\n", OBJSIZE_KCB, ctr, OBJSIZE_KCB * ctr);

    struct capref kcb_cap;
    slot_alloc(&kcb_cap);
    err = cap_retype(kcb_cap, ram_cap, 0, ObjType_KernelControlBlock, OBJSIZE_KCB, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    // Comment says should be aligned to 16k...
    assert((*ret_addr) % (16 * 1024) == 0);

    return SYS_ERR_OK;
}

/**
 * Loads a binary from multiboot and maps it to current address space.
 *
 * \param name name of the binary to load
 * \param binary get filled out with infos where binary is mapped
 */
static errval_t load_multiboot(const char *name, struct binary_info *binary)
{
    errval_t err;

    struct mem_region *module = multiboot_find_module(bi, name);
    if (module == NULL) {
        return SPAWN_ERR_MULTIBOOT_FIND_MODULE;
    }

    binary->frame.cnode = cnode_module;
    binary->frame.slot = module->mrmod_slot;

    binary->size = module->mrmod_size;

    size_t aligned_size = ROUND_UP(binary->size, BASE_PAGE_SIZE);

    err = paging_map_frame_attr(get_current_paging_state(), (void **)&binary->addr,
                                aligned_size, binary->frame, VREGION_FLAGS_READ, NULL,
                                NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
    }

    return SYS_ERR_OK;
}

/**
 * Finds the entry point specified by symbol_name.
 */
static errval_t find_entry_point(struct binary_info *binary, char *symbol_name,
                                 genvaddr_t *ret_vaddr)
{
    struct Elf64_Sym *sym;
    uintptr_t sindex = 0;

    sym = elf64_find_symbol_by_name(binary->addr, binary->size, symbol_name, 0, STT_FUNC,
                                    &sindex);

    if (sym == NULL) {
        return LIB_ERR_COREBOOT_FIND_EP;
    }

    *ret_vaddr = sym->st_value;

    return SYS_ERR_OK;
}

/**
 * \brief allocates memory to start a new core.
 *
 * First, we create the address space using an offset to specify where a region
 * should be place in memory. Then we use that offset to create a large block
 * of contiguous memory and create a struct for each region. The addresses in
 * the structs are adjusted by the offset.
 */
static errval_t allocate_memory(size_t boot_binary_size, size_t cpu_binary_size,
                                size_t init_binary_size,
                                struct core_mem_block *core_block, struct core_mem *mem)
{
    errval_t err;

    // calculate offsets for regions
    size_t offset = 0;

    size_t boot_binary_offset = offset;

    // cpu binary has to be page aligned otw. relocation doesn't work
    offset = ROUND_UP(boot_binary_size + offset, BASE_PAGE_SIZE);
    size_t cpu_binary_offset = offset;

    // core data should be page aligned
    offset = ROUND_UP(cpu_binary_size + offset, BASE_PAGE_SIZE);
    size_t core_data_size = BASE_PAGE_SIZE;
    size_t core_data_offset = offset;

    // kernel stack should be page aligned
    offset = ROUND_UP(core_data_size + offset, BASE_PAGE_SIZE);
    size_t kernel_stack_size = 16 * BASE_PAGE_SIZE;
    size_t kernel_stack_offset = offset;

    offset += kernel_stack_size;
    size_t init_size = init_binary_size + ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE;
    size_t init_offset = offset;

    // used to calculate required size for memory block
    offset += init_size;

    // allocate contiguous memory block for new core memory
    size_t req_size = offset;
    err = frame_alloc(&core_block->frame, req_size, &core_block->size);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }
    assert(core_block->size >= req_size);

    err = paging_map_frame_attr(get_current_paging_state(), &core_block->buf,
                                core_block->size, core_block->frame,
                                VREGION_FLAGS_READ_WRITE, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
    }

    err = cap_get_phys_addr(core_block->frame, &core_block->phys_base);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_GET_PHYS_ADDR);
    }

    // find physical address of this block
    DEBUG_COREBOOT("Allocated contiguous memory block at vaddr %p, paddr %p with size "
                   "0x%llx\n",
                   core_block->buf, core_block->phys_base, core_block->size);

    // create structs for memory sections
    mem->boot_driver.size = boot_binary_size;
    mem->boot_driver.buf = core_block->buf + boot_binary_offset;
    mem->boot_driver.phys_base = core_block->phys_base + boot_binary_offset;

    mem->cpu_driver.size = cpu_binary_size;
    mem->cpu_driver.buf = core_block->buf + cpu_binary_offset;
    mem->cpu_driver.phys_base = core_block->phys_base + cpu_binary_offset;

    mem->core_data.size = core_data_size;
    mem->core_data.buf = core_block->buf + core_data_offset;
    mem->core_data.phys_base = core_block->phys_base + core_data_offset;

    mem->kernel_stack.size = kernel_stack_size;
    mem->kernel_stack.buf = core_block->buf + kernel_stack_offset;
    mem->kernel_stack.phys_base = core_block->phys_base + kernel_stack_offset;

    mem->init.size = init_size;
    mem->init.buf = core_block->buf + init_offset;
    mem->init.phys_base = core_block->phys_base + init_offset;

    return SYS_ERR_OK;
}

errval_t coreboot(coreid_t mpid, const char *boot_driver, const char *cpu_driver,
                  const char *init, struct frame_identity urpc_frame_id)
{
    errval_t err;

    // creater KCB
    genpaddr_t kcb_paddr;
    err = create_kcb(&kcb_paddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_CREATE_KCB);
    }
    DEBUG_COREBOOT("Created KCB at paddr %p\n", kcb_paddr);

    // load boot, cpu and init binary
    // readelf -W -a build/armv8/sbin/boot_armv8_generic
    struct binary_info boot_binary;
    err = load_multiboot(boot_driver, &boot_binary);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_LOAD_MULTIBOOT);
    }
    DEBUG_COREBOOT("Found boot driver module with size 0x%llx and mapped it to %p\n",
                   boot_binary.size, boot_binary.addr);

    struct binary_info cpu_binary;
    err = load_multiboot(cpu_driver, &cpu_binary);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_LOAD_MULTIBOOT);
    }
    DEBUG_COREBOOT("Found cpu driver module with size 0x%llx and mapped it to %p\n",
                   cpu_binary.size, cpu_binary.addr);

    struct binary_info init_binary;
    err = load_multiboot(init, &init_binary);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_LOAD_MULTIBOOT);
    }
    DEBUG_COREBOOT("Found init module with size 0x%llx and mapped it to %p\n",
                   init_binary.size, init_binary.addr);

    // find cpu and boot entry point
    genvaddr_t cpu_ep_vaddr;
    err = find_entry_point(&cpu_binary, CPU_DRIVER_EP_SYM, &cpu_ep_vaddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_FIND_ENTRY_POINT);
    }
    DEBUG_COREBOOT("Found symbol %s with value 0x%llx\n", CPU_DRIVER_EP_SYM, cpu_ep_vaddr);

    genvaddr_t boot_ep_vaddr;
    err = find_entry_point(&boot_binary, BOOT_DRIVER_EP_SYM, &boot_ep_vaddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_FIND_ENTRY_POINT);
    }
    DEBUG_COREBOOT("Found symbol %s with value 0x%llx\n", BOOT_DRIVER_EP_SYM,
                   boot_ep_vaddr);

    // allocate memory for new core
    struct core_mem_block core_block;
    struct core_mem mem;
    err = allocate_memory(boot_binary.size, cpu_binary.size,
                          elf_virtual_size(init_binary.addr), &core_block, &mem);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_ALLOCATE_MEMORY);
    }

    // load boot driver binary
    lpaddr_t boot_ep_paddr;
    err = load_elf_binary(boot_binary.addr, &mem.boot_driver, boot_ep_vaddr,
                          &boot_ep_paddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_LOAD_ELF_BINARY);
    }

    // boot driver runs with 1:1 VA->PA mapping so offset is zero
    err = relocate_elf(boot_binary.addr, &mem.boot_driver, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_RELOCATE_ELF);
    }

    // load cpu driver binary
    lpaddr_t cpu_ep_paddr;
    err = load_elf_binary(cpu_binary.addr, &mem.cpu_driver, cpu_ep_vaddr, &cpu_ep_paddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_LOAD_ELF_BINARY);
    }

    // cpu driver runs at offset ARMV8_KERNEL_OFFSET
    err = relocate_elf(cpu_binary.addr, &mem.cpu_driver, ARMv8_KERNEL_OFFSET);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_COREBOOT_RELOCATE_ELF);
    }

    struct armv8_core_data *core_data = (struct armv8_core_data *)mem.core_data.buf;
    core_data->boot_magic = ARMV8_BOOTMAGIC_PSCI;

    // use highest valid address as stack grows downwards
    core_data->cpu_driver_stack = mem.kernel_stack.phys_base + mem.kernel_stack.size;
    core_data->cpu_driver_stack_limit = mem.kernel_stack.phys_base;
    DEBUG_COREBOOT("cpu driver stack goes from %p to %p\n", core_data->cpu_driver_stack,
                   core_data->cpu_driver_stack_limit);

    core_data->cpu_driver_entry = cpu_ep_vaddr + ARMv8_KERNEL_OFFSET;
    DEBUG_COREBOOT("cpu driver entry point vaddr %p\n", core_data->cpu_driver_entry);

    // set everything to zero as no arguments
    memset(core_data->cpu_driver_cmdline, 0, sizeof(core_data->cpu_driver_cmdline));

    core_data->memory.base = mem.init.phys_base;
    core_data->memory.length = mem.init.size;
    DEBUG_COREBOOT("cpu driver mem region with size %lld at paddr %p\n",
                   core_data->memory.length, core_data->memory.base);

    core_data->urpc_frame.base = urpc_frame_id.base;
    core_data->urpc_frame.length = urpc_frame_id.bytes;
    DEBUG_COREBOOT("urpc frame with size %lld at paddr %p\n",
                   core_data->urpc_frame.length, core_data->urpc_frame.base);

    err = cap_get_phys_addr(init_binary.frame, &core_data->monitor_binary.base);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_GET_PHYS_ADDR);
    }
    core_data->monitor_binary.length = init_binary.size;
    DEBUG_COREBOOT("init elf image with size %lld at paddr %p\n",
                   core_data->monitor_binary.length, core_data->monitor_binary.base);

    core_data->kcb = kcb_paddr;
    DEBUG_COREBOOT("KCB at paddr %p\n", core_data->kcb);

    core_data->src_core_id = disp_get_core_id();
    core_data->src_arch_id = disp_get_core_id();

    core_data->dst_core_id = mpid;
    core_data->dst_arch_id = mpid;

    DEBUG_COREBOOT("invoking log/phys core id %lld/%lld\n", core_data->src_core_id,
                   core_data->src_arch_id);

    DEBUG_COREBOOT("started log/phys core id %lld/%lld\n", core_data->dst_core_id,
                   core_data->dst_arch_id);

    // Flush the cache
    cpu_dcache_wb_range((genvaddr_t)core_block.buf, core_block.size);

    err = invoke_monitor_spawn_core(core_data->dst_arch_id, CPU_ARM8, boot_ep_paddr,
                                    mem.core_data.phys_base, 0);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldnt spawn\n");
        return err;
    }

    // dump boot driver readelf -W -x .text build/armv8/sbin/boot_armv8_generic
    // debug_dump_mem(0x8000beb000, 0x8000beb000 + BASE_PAGE_SIZE, 0);

    // dump cpu driver readelf -W -x .text build/armv8/sbin/cpu_imx8x
    // genvaddr_t cpu_addr = (genvaddr_t)mem.cpu_driver.buf;
    // debug_dump_mem(cpu_addr, cpu_addr + BASE_PAGE_SIZE, 0);

    // dump core_data
    // genvaddr_t core_addr = (genvaddr_t)mem.core_data.buf;
    // debug_dump_mem(core_addr, core_addr + BASE_PAGE_SIZE, 0);

    return SYS_ERR_OK;
}
