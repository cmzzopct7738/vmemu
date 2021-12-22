#pragma once
#include <unicorn/unicorn.h>
#include <atomic>
#include <nt/image.hpp>
#include <vmctx.hpp>
#include <vmprofiler.hpp>

#define PAGE_4KB 0x1000
#define STACK_SIZE PAGE_4KB * 512
#define STACK_BASE 0xFFFF000000000000

namespace vm {
class emu_t {
 public:
  explicit emu_t(
      vm::vmctx_t* vm_ctx,
      std::map<std::uint32_t, vm::instrs::profiler_t*>* known_hndlrs);

  ~emu_t();
  bool init();
  void emulate();

 private:
  uc_engine* uc;
  const vm::vmctx_t* m_vm;
  zydis_reg_t vip, vsp;
  std::map<std::uint32_t, vm::instrs::profiler_t*>* m_known_hndlrs;
  std::unique_ptr<vm::instrs::hndlr_trace_t> cc_trace;
  uc_hook code_exec_hook, invalid_mem_hook, int_hook;

  static void int_callback(uc_engine* uc, std::uint32_t intno, emu_t* obj);
  static bool code_exec_callback(uc_engine* uc,
                                 uint64_t address,
                                 uint32_t size,
                                 emu_t* obj);

  static void invalid_mem(uc_engine* uc,
                          uc_mem_type type,
                          uint64_t address,
                          int size,
                          int64_t value,
                          emu_t* obj);
};
}  // namespace vm
