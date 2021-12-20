#include <cli-parser.hpp>
#include <fstream>
#include <iostream>
#include <thread>

#define NUM_THREADS 20

int __cdecl main(int argc, const char* argv[]) {
  argparse::argument_parser_t parser("VMEmu",
                                     "VMProtect 3 VM Handler Emulator");
  parser.add_argument()
      .name("--vmentry")
      .description("relative virtual address to a vm entry...");
  parser.add_argument()
      .name("--bin")
      .description("path to unpacked virtualized binary...")
      .required(true);
  parser.add_argument()
      .name("--out")
      .description("output file name...")
      .required(true);
  parser.add_argument().name("--unpack").description("unpack a vmp2 binary...");
  parser.add_argument()
      .names({"-f", "--force"})
      .description("force emulation of unknown vm handlers...");
  parser.add_argument()
      .name("--emuall")
      .description(
          "scan for all vm enters and trace all of them... this may take a few "
          "minutes...");

  parser.enable_help();
  auto result = parser.parse(argc, argv);

  if (result) {
    std::printf("[!] error parsing commandline arguments... reason = %s\n",
                result.what().c_str());
    return -1;
  }

  if (parser.exists("help")) {
    parser.print_help();
    return 0;
  }
}