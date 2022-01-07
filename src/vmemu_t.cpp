#include <vmemu_t.hpp>

namespace vm {
emu_t::emu_t(vm::vmctx_t* vm_ctx) : m_vm(vm_ctx) {}

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
  vrtn.m_rva = vmenter_rva;

  auto& blk = vrtn.m_blks.emplace_back();
  blk.m_vip = {0ull, 0ull};
  blk.m_vm = {m_vm->get_vip(), m_vm->get_vsp()};

  cc_blk = &blk;
  cc_vrtn = &vrtn;
  cc_trace.m_uc = uc;

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

  cc_trace.m_vip = cc_blk->m_vm.vip;
  cc_trace.m_vsp = cc_blk->m_vm.vsp;

  std::printf("> beginning execution at = %p\n", rip);
  if ((err = uc_emu_start(uc, rip, 0ull, 0ull, 0ull))) {
    std::printf("> error starting emu... reason = %d\n", err);
    return false;
  }

  auto br_info = could_have_jcc(cc_blk->m_vinstrs);
  if (br_info.has_value()) {
    auto [br1, br2] = br_info.value();

    // convert to absolute addresses...
    br1 -= m_vm->m_image_base;
    br2 -= m_vm->m_image_base;
    br1 += m_vm->m_module_base;
    br2 += m_vm->m_module_base;

    auto br1_legit = legit_branch(*cc_blk, br1);
    auto br2_legit = legit_branch(*cc_blk, br2);
    std::printf("> br1 legit: %d, br2 legit: %d\n", br1_legit, br2_legit);
  }

  // keep track of the emulated blocks... by their addresses...
  std::vector<std::uintptr_t> blk_addrs;
  blk_addrs.push_back(blk.m_vip.img_base);

  // the vector containing the vblk's grows inside of this for loop
  // thus we cannot use an advanced for loop (which uses itr's)...
  for (auto idx = 0u; idx < cc_vrtn->m_blks.size(); ++idx) {
    auto& blk = cc_vrtn->m_blks[idx];
    if (blk.branch_type != vm::instrs::vbranch_type::none) {
      std::uintptr_t rip = 0ull, vsp = 0ull;
      uc_context_restore(uc, blk.m_jmp.ctx);
      uc_mem_write(uc, STACK_BASE, blk.m_jmp.stack, STACK_SIZE);
      uc_reg_read(uc, vm::instrs::reg_map[blk.m_vm.vsp], &vsp);
      uc_reg_read(uc, UC_X86_REG_RIP, &rip);

      // force the emulation of all branches...
      for (const auto br : blk.branches) {
        // only emulate blocks that havent been emulated before...
        if (std::find(blk_addrs.begin(), blk_addrs.end(), br) !=
            blk_addrs.end())
          continue;

        // setup new cc_blk...
        auto& new_blk = vrtn.m_blks.emplace_back();
        new_blk.m_vip = {0ull, 0ull};
        new_blk.m_vm = {blk.m_jmp.m_vm.vip, blk.m_jmp.m_vm.vsp};
        cc_blk = &new_blk;

        // emulate the branch...
        uc_mem_write(uc, vsp, &br, sizeof br);
        uc_emu_start(uc, rip, 0ull, 0ull, 0ull);
      }
    }
  }

  // free all virtual code block virtual jmp information...
  std::for_each(vrtn.m_blks.begin(), vrtn.m_blks.end(),
                [&](vm::instrs::vblk_t& blk) {
                  if (blk.m_jmp.ctx)
                    uc_context_free(blk.m_jmp.ctx);

                  if (blk.m_jmp.stack)
                    delete[] blk.m_jmp.stack;
                });

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

bool emu_t::branch_pred_spec_exec(uc_engine* uc,
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
    obj->cc_trace.m_stack = new std::uint8_t[STACK_SIZE];
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
        [&vip = obj->cc_trace.m_vip](
            const vm::instrs::emu_instr_t& instr) -> bool {
          const auto& i = instr.m_instr;
          return i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 i.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 i.operands[1].mem.base == vip && i.operands[1].size == 32;
        });

    if (rva_fetch != obj->cc_trace.m_instrs.rend())
      obj->cc_trace.m_instrs.erase((rva_fetch + 1).base(),
                                   obj->cc_trace.m_instrs.end());

    const auto vinstr = vm::instrs::determine(obj->cc_trace);

    // -- free the trace since we will start a new one...
    std::for_each(obj->cc_trace.m_instrs.begin(), obj->cc_trace.m_instrs.end(),
                  [&](const vm::instrs::emu_instr_t& instr) {
                    uc_context_free(instr.m_cpu);
                  });

    delete[] obj->cc_trace.m_stack;
    obj->cc_trace.m_instrs.clear();

    if (vinstr.mnemonic != vm::instrs::mnemonic_t::jmp) {
      if (vinstr.mnemonic != vm::instrs::mnemonic_t::sreg)
        uc_emu_stop(uc);

      if (!vinstr.imm.has_imm)
        uc_emu_stop(uc);

      if (vinstr.imm.size != 8 || vinstr.imm.val > 8 * VIRTUAL_REGISTER_COUNT)
        uc_emu_stop(uc);

      // -- stop after 10 legit SREG's...
      if (++obj->m_sreg_cnt == 10)
        uc_emu_stop(uc);
    }
  }
  return true;
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
    obj->cc_trace.m_stack = new std::uint8_t[STACK_SIZE];
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
        [&vip = obj->cc_trace.m_vip](
            const vm::instrs::emu_instr_t& instr) -> bool {
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
      // find the last write done to VIP...
      auto vip_write = std::find_if(
          obj->cc_trace.m_instrs.rbegin(), obj->cc_trace.m_instrs.rend(),
          [&vip = obj->cc_trace.m_vip](vm::instrs::emu_instr_t& instr) -> bool {
            const auto& i = instr.m_instr;
            return i.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   i.operands[0].reg.value == vip;
          });

      uc_context* backup;
      uc_context_alloc(uc, &backup);
      uc_context_save(uc, backup);
      uc_context_restore(uc, vip_write->m_cpu);

      auto uc_reg =
          vm::instrs::reg_map[vip_write->m_instr.operands[0].reg.value];

      std::uintptr_t vip_addr = 0ull;
      uc_reg_read(uc, uc_reg, &vip_addr);

      obj->cc_blk->m_vip.rva = vip_addr -= obj->m_vm->m_module_base;
      obj->cc_blk->m_vip.img_base = vip_addr += obj->m_vm->m_image_base;

      uc_context_restore(uc, backup);
      uc_context_free(backup);
    } else {
      const auto vinstr = vm::instrs::determine(obj->cc_trace);
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

        std::printf("> err: please define the following vm handler:\n");
        vm::utils::print(inst_stream);
        return false;
      }

      if (obj->cc_blk->m_vinstrs.size()) {
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
          obj->cc_blk->m_jmp.m_vm = {obj->cc_trace.m_vip, obj->cc_trace.m_vsp};
          std::memcpy(obj->cc_blk->m_jmp.stack, obj->cc_trace.m_stack,
                      STACK_SIZE);
        }

        if (vinstr.mnemonic == vm::instrs::mnemonic_t::jmp ||
            vinstr.mnemonic == vm::instrs::mnemonic_t::vmexit)
          uc_emu_stop(obj->uc);
      }

      obj->cc_blk->m_vinstrs.push_back(vinstr);
    }

    // -- free the trace since we will start a new one...
    std::for_each(obj->cc_trace.m_instrs.begin(), obj->cc_trace.m_instrs.end(),
                  [&](const vm::instrs::emu_instr_t& instr) {
                    uc_context_free(instr.m_cpu);
                  });

    delete[] obj->cc_trace.m_stack;
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

bool emu_t::legit_branch(vm::instrs::vblk_t& vblk, std::uintptr_t branch_addr) {
  // remove normal execution callback...
  uc_hook_del(uc, code_exec_hook);

  // add branch pred hook...
  uc_hook_add(uc, &branch_pred_hook, UC_HOOK_CODE,
              (void*)&vm::emu_t::branch_pred_spec_exec, this,
              m_vm->m_module_base, m_vm->m_module_base + m_vm->m_image_size);

  // make a backup of the current emulation state...
  uc_context* backup;
  uc_context_alloc(uc, &backup);
  uc_context_save(uc, backup);
  std::uint8_t* stack = new std::uint8_t[STACK_SIZE];
  uc_mem_read(uc, STACK_BASE, stack, STACK_SIZE);

  // restore cpu and stack back to the virtual jump handler...
  uc_context_restore(uc, vblk.m_jmp.ctx);
  uc_mem_write(uc, STACK_BASE, vblk.m_jmp.stack, STACK_SIZE);

  // force the virtual machine to try and emulate the branch address...
  std::uintptr_t vsp = 0ull, rip = 0ull;
  uc_reg_read(uc, UC_X86_REG_RIP, &rip);
  uc_reg_read(uc, vm::instrs::reg_map[vblk.m_vm.vsp], &vsp);
  uc_mem_write(uc, vsp, &branch_addr, sizeof branch_addr);

  m_sreg_cnt = 0u;
  uc_emu_start(uc, rip, 0ull, 0ull, 0ull);

  // restore original cpu and stack...
  uc_mem_write(uc, STACK_BASE, stack, STACK_SIZE);
  uc_context_restore(uc, backup);
  uc_context_free(backup);
  delete[] stack;

  // add normal execution callback back...
  uc_hook_add(uc, &code_exec_hook, UC_HOOK_CODE,
              (void*)&vm::emu_t::code_exec_callback, this, m_vm->m_module_base,
              m_vm->m_module_base + m_vm->m_image_size);

  // we will consider this a legit branch if there is at least 10
  // SREG instructions...
  return m_sreg_cnt == 10;
}

std::optional<std::pair<std::uintptr_t, std::uintptr_t>> emu_t::could_have_jcc(
    std::vector<vm::instrs::vinstr_t>& vinstrs) {
  if (vinstrs.back().mnemonic == vm::instrs::mnemonic_t::vmexit)
    return {};

  // check to see if there is at least 3 LCONST %i64's
  if (std::accumulate(
          vinstrs.begin(), vinstrs.end(), 0u,
          [&](std::uint32_t val, vm::instrs::vinstr_t& v) -> std::uint32_t {
            return v.mnemonic == vm::instrs::mnemonic_t::lconst &&
                           v.imm.size == 64
                       ? ++val
                       : val;
          }) < 3)
    return {};

  // extract the lconst64's out of the virtual instruction stream...
  static const auto lconst64_chk = [&](vm::instrs::vinstr_t& v) -> bool {
    return v.mnemonic == vm::instrs::mnemonic_t::lconst && v.imm.size == 64;
  };

  const auto lconst1 =
      std::find_if(vinstrs.rbegin(), vinstrs.rend(), lconst64_chk);

  if (lconst1 == vinstrs.rend())
    return {};

  const auto lconst2 = std::find_if(lconst1 + 1, vinstrs.rend(), lconst64_chk);

  if (lconst2 == vinstrs.rend())
    return {};

  // check to see if the imm val is inside of the image...
  if (lconst1->imm.val > m_vm->m_image_base + m_vm->m_image_size ||
      lconst1->imm.val < m_vm->m_image_base ||
      lconst2->imm.val > m_vm->m_image_base + m_vm->m_image_size ||
      lconst2->imm.val < m_vm->m_image_base)
    return {};

  // check to see if the imm's points to something inside of an executable
  // section...
  if (!vm::utils::scn::executable(
          m_vm->m_module_base,
          (lconst1->imm.val - m_vm->m_image_base) + m_vm->m_module_base) ||
      !vm::utils::scn::executable(
          m_vm->m_module_base,
          (lconst2->imm.val - m_vm->m_image_base) + m_vm->m_module_base))
    return {};

  return {{lconst1->imm.val, lconst2->imm.val}};
}
}  // namespace vm