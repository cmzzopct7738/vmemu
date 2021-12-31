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
  zydis_reg_t vip, vsp;

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
  uc_hook code_exec_hook, invalid_mem_hook, int_hook;

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
  /// determines if its possible that the virtual instruction stream contains a
  /// virtual JCC...
  ///
  /// this simply checks to see if there are at least 3 LCONST that load 64bit
  /// constant values...
  ///
  /// it also checks if the last 2 LCONST's load image based addresses which
  /// land inside of executable sections...
  ///
  /// this function cannot be used to determine if there is a virtual branch or
  /// not... it is only a useful/preliminary function...
  /// </summary>
  /// <param name="vinstrs">vector of virtual instructions...</param>
  /// <returns>returns true if there is at least 3 LCONST in the virtual
  /// instruction stream that load 64bit values...</returns>
  bool could_have_jcc(std::vector<vm::instrs::vinstr_t>& vinstrs);
};
}  // namespace vm
