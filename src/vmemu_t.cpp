#include <vmemu_t.hpp>

namespace vm {
emu_t::emu_t(vm::vmctx_t* vm_ctx)
    : m_vm(vm_ctx), vip(vm_ctx->get_vip()), vsp(vm_ctx->get_vsp()) {}

emu_t::~emu_t() {
  if (uc)
    uc_close(uc);
}

bool emu_t::init() {
  uc_err err;
  if ((err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc))) {
    std::printf("> uc_open err = %d\n", err);
    return false;
  }

  if ((err = uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL))) {
    std::printf("> uc_mem_map stack err, reason = %d\n", err);
    return false;
  }

  if ((err = uc_mem_map(uc, m_vm->m_module_base, m_vm->m_image_size,
                        UC_PROT_ALL))) {
    std::printf("> map memory failed, reason = %d\n", err);
    return false;
  }

  if ((err = uc_mem_write(uc, m_vm->m_module_base,
                          reinterpret_cast<void*>(m_vm->m_module_base),
                          m_vm->m_image_size))) {
    std::printf("> failed to write memory... reason = %d\n", err);
    return false;
  }

  if ((err = uc_hook_add(uc, &code_exec_hook, UC_HOOK_CODE,
                         (void*)&vm::emu_t::code_exec_callback, this,
                         m_vm->m_module_base,
                         m_vm->m_module_base + m_vm->m_image_size))) {
    std::printf("> uc_hook_add error, reason = %d\n", err);
    return false;
  }

  if ((err = uc_hook_add(uc, &int_hook, UC_HOOK_INTR,
                         (void*)&vm::emu_t::int_callback, this, 0ull, 0ull))) {
    std::printf("> uc_hook_add error, reason = %d\n", err);
    return false;
  }

  if ((err =
           uc_hook_add(uc, &invalid_mem_hook,
                       UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                           UC_HOOK_MEM_FETCH_UNMAPPED,
                       (void*)&vm::emu_t::invalid_mem, this, true, false))) {
    std::printf("> uc_hook_add error, reason = %d\n", err);
    return false;
  }
  return true;
}

bool emu_t::emulate(std::uint32_t vmenter_rva, vm::instrs::vrtn_t& vrtn) {
  uc_err err;
  std::uintptr_t rip = vmenter_rva + m_vm->m_module_base,
                 rsp = STACK_BASE + STACK_SIZE - PAGE_4KB;

  if ((err = uc_reg_write(uc, UC_X86_REG_RSP, &rsp))) {
    std::printf("> uc_reg_write error, reason = %d\n", err);
    return false;
  }

  if ((err = uc_reg_write(uc, UC_X86_REG_RIP, &rip))) {
    std::printf("> uc_reg_write error, reason = %d\n", err);
    return false;
  }

  cc_trace.m_uc = uc;
  cc_trace.m_vip = vip;
  cc_trace.m_vsp = vsp;
  vrtn.m_rva = vmenter_rva;

  vm::instrs::vblk_t blk;
  blk.m_vip = {0ull, 0ull};

  cc_blk = &blk;
  cc_vrtn = &vrtn;

  std::printf("> beginning execution at = %p\n", rip);
  if ((err = uc_emu_start(uc, rip, 0ull, 0ull, 0ull))) {
    std::printf("> error starting emu... reason = %d\n", err);
    return false;
  }

  std::printf(
      "> blk_%p, number of virtual instructions = %d, could have a jcc = %d\n",
      blk.m_vip.img_base, blk.m_vinstrs.size(), could_have_jcc(blk.m_vinstrs));
  return true;
}

void emu_t::int_callback(uc_engine* uc, std::uint32_t intno, emu_t* obj) {
  uc_err err;
  std::uintptr_t rip = 0ull;
  static thread_local zydis_decoded_instr_t instr;

  if ((err = uc_reg_read(uc, UC_X86_REG_RIP, &rip))) {
    std::printf("> failed to read rip... reason = %d\n", err);
    return;
  }

  if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(vm::utils::g_decoder.get(),
                                             reinterpret_cast<void*>(rip),
                                             PAGE_4KB, &instr))) {
    std::printf("> failed to decode instruction at = 0x%p\n", rip);
    if ((err = uc_emu_stop(uc))) {
      std::printf("> failed to stop emulation, exiting... reason = %d\n", err);
      exit(0);
    }
    return;
  }

  // advance rip over the instruction that caused the exception... this is
  // usually a division by 0...
  rip += instr.length;

  if ((err = uc_reg_write(uc, UC_X86_REG_RIP, &rip))) {
    std::printf("> failed to write rip... reason = %d\n", err);
    return;
  }
}

bool emu_t::code_exec_callback(uc_engine* uc,
                               uint64_t address,
                               uint32_t size,
                               emu_t* obj) {
  uc_err err;
  static thread_local zydis_decoded_instr_t instr;
  if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(vm::utils::g_decoder.get(),
                                             reinterpret_cast<void*>(address),
                                             PAGE_4KB, &instr))) {
    std::printf("> failed to decode instruction at = 0x%p\n", address);
    if ((err = uc_emu_stop(uc))) {
      std::printf("> failed to stop emulation, exiting... reason = %d\n", err);
      exit(0);
    }
    return false;
  }

  if (instr.mnemonic == ZYDIS_MNEMONIC_INVALID)
    return false;

  uc_context* ctx;
  uc_context_alloc(uc, &ctx);
  uc_context_save(uc, ctx);

  // if this is the first instruction of this handler then save the stack...
  if (!obj->cc_trace.m_instrs.size()) {
    obj->cc_trace.m_stack = reinterpret_cast<std::uint8_t*>(malloc(STACK_SIZE));
    uc_mem_read(uc, STACK_BASE, obj->cc_trace.m_stack, STACK_SIZE);
  }

  obj->cc_trace.m_instrs.push_back({instr, ctx});

  // RET or JMP REG means the end of a vm handler...
  if (instr.mnemonic == ZYDIS_MNEMONIC_RET ||
      (instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
       instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)) {
    // deobfuscate the instruction stream before profiling...
    // makes it easier for profiles to be correct...
    vm::instrs::deobfuscate(obj->cc_trace);

    // find the last MOV REG, DWORD PTR [VIP] in the instruction stream, then
    // remove any instructions from this instruction to the JMP/RET...
    const auto rva_fetch = std::find_if(
        obj->cc_trace.m_instrs.rbegin(), obj->cc_trace.m_instrs.rend(),
        [&vip = obj->vip](const vm::instrs::emu_instr_t& instr) -> bool {
          const auto& i = instr.m_instr;
          return i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 i.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 i.operands[1].mem.base == vip && i.operands[1].size == 32;
        });

    if (rva_fetch != obj->cc_trace.m_instrs.rend())
      obj->cc_trace.m_instrs.erase((rva_fetch + 1).base(),
                                   obj->cc_trace.m_instrs.end());

    // set the virtual code block vip address information...
    if (!obj->cc_blk->m_vip.rva || !obj->cc_blk->m_vip.img_base) {
      auto vip_write = std::find_if(
          obj->cc_trace.m_instrs.rbegin(), obj->cc_trace.m_instrs.rend(),
          [&vip = obj->vip](vm::instrs::emu_instr_t& instr) -> bool {
            const auto& i = instr.m_instr;
            return i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   i.operands[0].reg.value == vip;
          });

      uc_context* backup;
      uc_context_alloc(uc, &backup);
      uc_context_save(uc, backup);
      uc_context_restore(uc, (vip_write - 1)->m_cpu);

      auto uc_reg =
          vm::instrs::reg_map[vip_write->m_instr.operands[0].reg.value];

      std::uintptr_t vip_addr = 0ull;
      uc_reg_read(uc, uc_reg, &vip_addr);

      obj->cc_blk->m_vip.rva = vip_addr -= obj->m_vm->m_module_base;
      obj->cc_blk->m_vip.img_base = vip_addr += obj->m_vm->m_image_base;

      uc_context_restore(uc, backup);
      uc_context_free(backup);
    } else {
      const auto vinstr =
          vm::instrs::determine(obj->vip, obj->vsp, obj->cc_trace);

      if (vinstr.mnemonic != vm::instrs::mnemonic_t::unknown) {
        if (vinstr.imm.has_imm)
          std::printf("> %s %p\n",
                      vm::instrs::get_profile(vinstr.mnemonic)->name.c_str(),
                      vinstr.imm.val);
        else
          std::printf("> %s\n",
                      vm::instrs::get_profile(vinstr.mnemonic)->name.c_str());
      } else {
        zydis_rtn_t inst_stream;
        std::for_each(obj->cc_trace.m_instrs.begin(),
                      obj->cc_trace.m_instrs.end(),
                      [&](vm::instrs::emu_instr_t& instr) {
                        inst_stream.push_back({instr.m_instr});
                      });

        vm::utils::print(inst_stream);
        std::getchar();
      }

      obj->cc_trace.m_vip = obj->vip;
      obj->cc_trace.m_vsp = obj->vsp;
      obj->cc_blk->m_vinstrs.push_back(vinstr);

      if (vinstr.mnemonic == vm::instrs::mnemonic_t::jmp) {
        uc_context *backup, *copy;

        // backup current unicorn-engine context...
        uc_context_alloc(uc, &backup);
        uc_context_alloc(uc, &copy);
        uc_context_save(uc, backup);

        // make a copy of the first cpu context of the jmp handler...
        uc_context_restore(uc, obj->cc_trace.m_instrs.begin()->m_cpu);
        uc_context_save(uc, copy);

        // restore the unicorn-engine context... also free the backup...
        uc_context_restore(uc, backup);
        uc_context_free(backup);

        // set current code block virtual jmp instruction information...
        obj->cc_blk->m_jmp.ctx = copy;
        obj->cc_blk->m_jmp.stack = new std::uint8_t[STACK_SIZE];
        uc_mem_read(uc, STACK_BASE, obj->cc_blk->m_jmp.stack, STACK_SIZE);
      }

      if (vinstr.mnemonic == vm::instrs::mnemonic_t::jmp ||
          vinstr.mnemonic == vm::instrs::mnemonic_t::vmexit)
        uc_emu_stop(obj->uc);
    }

    // -- free the trace since we will start a new one...
    std::for_each(obj->cc_trace.m_instrs.begin(), obj->cc_trace.m_instrs.end(),
                  [&](const vm::instrs::emu_instr_t& instr) {
                    uc_context_free(instr.m_cpu);
                  });

    free(obj->cc_trace.m_stack);
    obj->cc_trace.m_instrs.clear();
  }
  return true;
}

void emu_t::invalid_mem(uc_engine* uc,
                        uc_mem_type type,
                        uint64_t address,
                        int size,
                        int64_t value,
                        emu_t* obj) {
  switch (type) {
    case UC_MEM_READ_UNMAPPED: {
      uc_mem_map(uc, address & ~0xFFFull, PAGE_4KB, UC_PROT_ALL);
      std::printf(">>> reading invalid memory at address = %p, size = 0x%x\n",
                  address, size);
      break;
    }
    case UC_MEM_WRITE_UNMAPPED: {
      uc_mem_map(uc, address & ~0xFFFull, PAGE_4KB, UC_PROT_ALL);
      std::printf(
          ">>> writing invalid memory at address = %p, size = 0x%x, val = "
          "0x%x\n",
          address, size, value);
      break;
    }
    case UC_MEM_FETCH_UNMAPPED: {
      std::printf(">>> fetching invalid instructions at address = %p\n",
                  address);

      std::uintptr_t rip, rsp;
      uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
      uc_mem_read(uc, rsp, &rip, sizeof rip);
      rsp += 8;
      uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
      uc_reg_write(uc, UC_X86_REG_RIP, &rip);
      std::printf(">>> injecting return to try and recover... rip = %p\n", rip);
      break;
    }
    default:
      break;
  }
}

bool emu_t::could_have_jcc(std::vector<vm::instrs::vinstr_t>& vinstrs) {
  // check to see if there is at least 3 LCONST %i64's
  if (std::accumulate(
          vinstrs.begin(), vinstrs.end(), 0u,
          [&](std::uint32_t val, vm::instrs::vinstr_t& v) -> std::uint32_t {
            return v.mnemonic == vm::instrs::mnemonic_t::lconst &&
                           v.imm.size == 64
                       ? ++val
                       : val;
          }) < 3)
    return false;

  // extract the lconst64's out of the virtual instruction stream...
  static const auto lconst64_chk = [&](vm::instrs::vinstr_t& v) -> bool {
    return v.mnemonic == vm::instrs::mnemonic_t::lconst && v.imm.size == 64;
  };

  const auto lconst1 =
      std::find_if(vinstrs.rbegin(), vinstrs.rend(), lconst64_chk);

  if (lconst1 == vinstrs.rend())
    return false;

  const auto lconst2 = std::find_if(lconst1 + 1, vinstrs.rend(), lconst64_chk);

  if (lconst2 == vinstrs.rend())
    return false;

  // check to see if the imm val is inside of the image...
  if (lconst1->imm.val > m_vm->m_image_base + m_vm->m_image_size ||
      lconst1->imm.val < m_vm->m_image_base ||
      lconst2->imm.val > m_vm->m_image_base + m_vm->m_image_size ||
      lconst2->imm.val < m_vm->m_image_base)
    return false;

  // check to see if the imm's points to something inside of an executable
  // section...
  if (!vm::utils::scn::executable(
          m_vm->m_module_base,
          (lconst1->imm.val - m_vm->m_image_base) + m_vm->m_module_base) ||
      !vm::utils::scn::executable(
          m_vm->m_module_base,
          (lconst2->imm.val - m_vm->m_image_base) + m_vm->m_module_base))
    return false;

  return true;
}
}  // namespace vm