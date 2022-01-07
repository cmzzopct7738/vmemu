#pragma once
#include <unicorn/unicorn.h>
#include <atomic>
#include <functional>
#include <nt/image.hpp>
#include <numeric>
#include <string>
#include <vmctx.hpp>
#include <vmprofiler.hpp>

#define PAGE_4KB 0x1000
#define STACK_SIZE PAGE_4KB * 512
#define STACK_BASE 0xFFFF000000000000

namespace vm {
class emu_t {
 public:
  explicit emu_t(vm::vmctx_t* vm_ctx);
  ~emu_t();
  bool init();
  bool emulate(std::uint32_t vmenter_rva, vm::instrs::vrtn_t& vrtn);

 private:
  uc_engine* uc;
  const vm::vmctx_t* m_vm;

  /// <summary>
  /// used in branch_pred_spec_exec to count legit SREG virtual instructions...
  /// </summary>
  std::uint8_t m_sreg_cnt;

  /// <summary>
  /// current code trace...
  /// </summary>
  vm::instrs::hndlr_trace_t cc_trace;

  /// <summary>
  /// current virtual code block...
  /// block...
  /// </summary>
  vm::instrs::vblk_t* cc_blk;

  /// <summary>
  /// current code virtual routine...
  /// </summary>
  vm::instrs::vrtn_t* cc_vrtn;

  /// <summary>
  /// unicorn engine hook
  /// </summary>
  uc_hook code_exec_hook, invalid_mem_hook, int_hook, branch_pred_hook;

  /// <summary>
  /// code execution callback for executable memory ranges of the vmprotect'ed
  /// module... essentially used to single step the processor over virtual
  /// handlers...
  /// </summary>
  /// <param name="uc"></param>
  /// <param name="address"></param>
  /// <param name="size"></param>
  /// <param name="obj"></param>
  /// <returns></returns>
  static bool code_exec_callback(uc_engine* uc,
                                 uint64_t address,
                                 uint32_t size,
                                 emu_t* obj);

  /// <summary>
  /// branch predicition with speculative execution (emulation)... this callback
  /// ensures there are at least 10 SREG's and that all of the imm values are
  /// legit...
  /// </summary>
  /// <param name="uc"></param>
  /// <param name="address"></param>
  /// <param name="size"></param>
  /// <param name="obj"></param>
  /// <returns></returns>
  static bool branch_pred_spec_exec(uc_engine* uc,
                                    uint64_t address,
                                    uint32_t size,
                                    emu_t* obj);

  /// <summary>
  /// invalid memory access handler. no runtime values can possibly effect the
  /// decryption of virtual instructions. thus invalid memory accesses can be
  /// ignored entirely...
  /// </summary>
  /// <param name="uc">uc engine context pointer...</param>
  /// <param name="type">type of memory access...</param>
  /// <param name="address">address of the memory access...</param>
  /// <param name="size">size of the memory access...</param>
  /// <param name="value">value being read...</param>
  /// <param name="obj">emu_t object pointer...</param>
  static void invalid_mem(uc_engine* uc,
                          uc_mem_type type,
                          uint64_t address,
                          int size,
                          int64_t value,
                          emu_t* obj);

  /// <summary>
  /// interrupt callback for unicorn engine. this is used to advance rip over
  /// division instructions which div by 0...
  /// </summary>
  /// <param name="uc">the uc engine pointer...</param>
  /// <param name="intno">interrupt number...</param>
  /// <param name="obj">emu_t object...</param>
  static void int_callback(uc_engine* uc, std::uint32_t intno, emu_t* obj);

  /// <summary>
  /// determines if there *could* be a JCC in the virtual code block... its not
  /// 100%... speculative execution is required to ensure that both branches
  /// discovered are legit...
  /// </summary>
  /// <param name="vinstrs"></param>
  /// <returns></returns>
  std::optional<std::pair<std::uintptr_t, std::uintptr_t>> could_have_jcc(
      std::vector<vm::instrs::vinstr_t>& vinstrs);

  /// <summary>
  /// determines if a branch is legit or not...
  /// </summary>
  /// <param name="vblk"></param>
  /// <param name="branch_addr"></param>
  /// <returns></returns>
  bool legit_branch(vm::instrs::vblk_t& vblk, std::uintptr_t branch_addr);
};
}  // namespace vm
