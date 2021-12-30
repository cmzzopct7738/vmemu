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
  void emulate();

  /// <summary>
  /// emulates a single virtual instruction and returns it... this function is
  /// used internally to determine if virtual JCC addresses are legit...
  /// </summary>
  /// <returns>returns the single virtual instruction that was
  /// emulated...</returns>
  vm::instrs::vinstr_t step();

 private:
  uc_engine* uc;
  const vm::vmctx_t* m_vm;
  zydis_reg_t vip, vsp;

  /// <summary>
  /// single step structure information...
  /// </summary>
  struct {
    bool m_toggle;
    uc_context* cpu_context;
    std::uint8_t stack[STACK_SIZE];
  } m_single_step;

  std::vector<vm::instrs::vinstr_t> vinstrs;
  vm::instrs::hndlr_trace_t cc_trace;

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
  /// determines if there is a JCC in the virtual instruction stream, if there
  /// is returns a pair of image based addresses for both of the branches...
  /// </summary>
  /// <param name="vinstrs">vector of virtual instructions...</param>
  /// <returns>returns a pair of imaged based addresses, one for each branch
  /// address... if there is no jcc then it returns nothing...</returns>
  std::optional<std::pair<std::uintptr_t, std::uintptr_t>> has_jcc(
      std::vector<vm::instrs::vinstr_t>& vinstrs);
};
}  // namespace vm
