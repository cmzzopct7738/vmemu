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
  m_vm_enter = true;

  vm::instrs::vblk_t blk;
  blk.m_vip = {0ull, 0ull};
  blk.m_cpu = {nullptr, nullptr};
  cc_blk = &blk;

  std::printf("> beginning execution at = %p\n", rip);
  if ((err = uc_emu_start(uc, rip, 0ull, 0ull, 0ull))) {
    std::printf("> error starting emu... reason = %d\n", err);
    return false;
  }

  std::printf("> blk address = %p\n", blk.m_vip.img_base);
  const auto jcc_result = has_jcc(blk.m_vinstrs);
  std::printf("> jcc result = %d\n", jcc_result.has_value());
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

  // save the current cpu's context (all register values and such)...
  // create a new emu_instr_t with this information... this info will be used by
  // profiles to grab decrypted values and such...
  uc_context* cpu_ctx;
  uc_context_alloc(obj->uc, &cpu_ctx);
  uc_context_save(obj->uc, cpu_ctx);

  std::uint8_t* stack = reinterpret_cast<std::uint8_t*>(malloc(STACK_SIZE));
  uc_mem_read(uc, STACK_BASE, stack, STACK_SIZE);

  vm::instrs::emu_instr_t emu_instr{instr, cpu_ctx, stack};
  obj->cc_trace.m_instrs.push_back(emu_instr);

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

    // extract vip address out of the vm enter trace...
    if (obj->m_vm_enter) {
      auto vip_addr_set = std::find_if(
          obj->cc_trace.m_instrs.rbegin(), obj->cc_trace.m_instrs.rend(),
          [&vip = obj->vip](vm::instrs::emu_instr_t& emu_instr) -> bool {
            const auto& i = emu_instr.m_instr;
            return i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   i.operands[0].reg.value == vip;
          });

      // get the cpu context from the instruction after the instruction that
      // writes to vip...
      --vip_addr_set;

      uc_context* backup;
      uc_context_alloc(uc, &backup);
      uc_context_save(uc, backup);
      uc_context_restore(uc, vip_addr_set->m_cpu);

      std::uintptr_t vip_addr = 0ull;
      uc_reg_read(uc, vm::instrs::reg_map[obj->vip], &vip_addr);
      obj->cc_blk->m_vip.rva = vip_addr -= obj->m_vm->m_module_base;
      obj->cc_blk->m_vip.img_base = vip_addr += obj->m_vm->m_image_base;

      uc_context_restore(uc, backup);
      uc_context_free(backup);
      obj->m_vm_enter = false;
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
        uc_context *b1, *b2;
        uc_context_alloc(uc, &b1);
        uc_context_alloc(uc, &b2);
        uc_context_save(uc, b1);
        uc_context_restore(uc, obj->cc_trace.m_instrs.begin()->m_cpu);
        uc_context_save(uc, b2);
        uc_context_restore(uc, b1);

        std::uint8_t* stack =
            reinterpret_cast<std::uint8_t*>(malloc(STACK_SIZE));

        std::memcpy(stack, obj->cc_trace.m_instrs.begin()->stack, STACK_SIZE);

        obj->cc_blk->m_cpu.ctx = b2;
        obj->cc_blk->m_cpu.stack = stack;
      }

      if (vinstr.mnemonic == vm::instrs::mnemonic_t::jmp ||
          vinstr.mnemonic == vm::instrs::mnemonic_t::vmexit)
        uc_emu_stop(obj->uc);
    }

    // -- free the trace since we will start a new one...
    std::for_each(obj->cc_trace.m_instrs.begin(), obj->cc_trace.m_instrs.end(),
                  [&](const vm::instrs::emu_instr_t& instr) {
                    uc_context_free(instr.m_cpu);
                    free(instr.stack);
                  });

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

std::optional<std::pair<std::uintptr_t, std::uintptr_t>> emu_t::has_jcc(
    std::vector<vm::instrs::vinstr_t>& vinstrs) {
  if (vinstrs.back().mnemonic == vm::instrs::mnemonic_t::vmexit)
    return {};

  // number of LCONST virtual instructions which load 64bit imm's...
  const std::uint32_t lconst_num = std::accumulate(
      vinstrs.begin(), vinstrs.end(), 0,
      [&](std::uint32_t val, vm::instrs::vinstr_t& v) -> std::uint32_t {
        return v.mnemonic == vm::instrs::mnemonic_t::lconst && v.imm.size == 64
                   ? ++val
                   : val;
      });

  if (lconst_num < 3)
    return {};

  const auto lconst1 = std::find_if(
      vinstrs.rbegin(), vinstrs.rend(), [&](vm::instrs::vinstr_t& v) -> bool {
        return v.mnemonic == vm::instrs::mnemonic_t::lconst && v.imm.size == 64;
      });

  const auto lconst2 = std::find_if(
      lconst1 + 1, vinstrs.rend(), [&](vm::instrs::vinstr_t& v) -> bool {
        return v.mnemonic == vm::instrs::mnemonic_t::lconst && v.imm.size == 64;
      });

  static const auto exec_callbk = [&](uc_engine* uc, uint64_t address,
                                      uint32_t size, emu_t* obj) {};

  uc_context *backup, *br1, *br2;
  uc_context_alloc(uc, &backup);
  uc_context_alloc(uc, &br1);
  uc_context_alloc(uc, &br2);
  uc_context_save(uc, backup);

  uc_context_restore(uc, cc_blk->m_cpu.ctx);
  uc_mem_write(uc, STACK_BASE, cc_blk->m_cpu.stack, STACK_SIZE);

  uc_context_restore(uc, backup);
  uc_context_free(backup);
  uc_context_free(br1);
  uc_context_free(br2);
  return {};
}
}  // namespace vm