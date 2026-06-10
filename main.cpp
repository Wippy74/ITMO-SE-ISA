#include "parser.hpp"
#include "disassembler.hpp"
#include "output.hpp"
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Wrong input" << '\n';
    return 1;
  }
  try {
    ElfParser elf;
    elf.parse(argv[1]);
    disassemble(elf, argv[2]);
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << '\n';
    return 2;
  }
  return 0;
}