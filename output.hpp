#pragma once
#include "parser.hpp"
#include "disassembler.hpp"
#include <fstream>
#include <ostream>
#include <set>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <format>
#include <algorithm>
#include <unordered_map>

namespace {

std::unordered_map<uint32_t, std::string> MakeLabels(const ElfParser& elf) {
  std::unordered_map<uint32_t, std::string> labels;
  auto better = [](const Symbol& cand, const Symbol& curr) {
    return (cand.type == 2 && curr.type != 2);
  };
  std::unordered_map<uint32_t, Symbol> named;
  for (const auto& s : elf.symbols()) {
    if (s.name.empty() || s.type == 3 || s.type == 4) {
      continue;
    }
    auto it = named.find(s.value);
    if (it == named.end() || better(s, it->second)) {
      named[s.value] = s;
    }
  }
  for (const auto& [addr, sp] : named) {
    labels.emplace(addr, sp.name);
  }
  const auto& text = elf.text();
  const uint32_t text_addr = elf.TextAddr();
  std::vector<uint32_t> unnamed;
  for (size_t i = 0; i + 4 <= text.size(); i += 4) {
    const uint32_t w = static_cast<uint32_t>(text[i]) | (static_cast<uint32_t>(text[i + 1]) << 8) | (static_cast<uint32_t>(text[i + 2]) << 16) | (static_cast<uint32_t>(text[i + 3]) << 24);
    const Decoded d = decode(w, text_addr + i);
    if ((d.type == Decoded::Type::B || d.type == Decoded::Type::J) && labels.find(d.target) == labels.end()) {
      if (std::find(unnamed.begin(), unnamed.end(), d.target) == unnamed.end()) {
        unnamed.push_back(d.target);
      }
    }
  }
  int n = 0;
  for (uint32_t a : unnamed) {
    labels.emplace(a, "L" + std::to_string(n++));
  }
  return labels;
}

void WriteText(std::ostream& out, const ElfParser& elf, const std::unordered_map<uint32_t, std::string>& labels) {
  out << ".text\n";
  const auto& text = elf.text();
  const uint32_t base = elf.TextAddr();
  for (size_t i = 0; i + 4 <= text.size(); i += 4) {
    const uint32_t addr = base + i;
    const uint32_t word = static_cast<uint32_t>(text[i]) | (static_cast<uint32_t>(text[i + 1]) << 8) | (static_cast<uint32_t>(text[i + 2]) << 16) | (static_cast<uint32_t>(text[i + 3]) << 24);
    auto it = labels.find(addr);
    if (it != labels.end()) {
      out << std::format("{:08x}   <{}>:\n", addr, it->second);
    }
    const Decoded d = decode(word, addr);
    switch (d.type) {
      case Decoded::Type::R:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}, {}\n", addr, word, d.str_name, ToABI(d.rd), ToABI(d.rs1), ToABI(d.rs2));
        break;
      case Decoded::Type::I: {
        std::string name = d.str_name;
        if (name == "slli" || name == "srli" || name == "srai") {
          out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}, {}\n", addr, word, d.str_name, ToABI(d.rd), ToABI(d.rs1), d.shift);
        } 
        else if (name == "lb" || name == "lh" || name == "lw" || name == "lbu" || name == "lhu" || name == "jalr") {
          out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}({})\n", addr, word, d.str_name, ToABI(d.rd), d.imm, ToABI(d.rs1));
        } 
        else if (name == "ecall" || name == "ebreak" || name == "fence" || name == "fence.tso" || name == "pause") {
          out << std::format(" {:05x}:\t{:08x}\t{:>7}\n", addr, word, d.str_name);
        } 
        else {
          out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}, {}\n", addr, word, d.str_name, ToABI(d.rd), ToABI(d.rs1), d.imm);
        }
        break;
      }
      case Decoded::Type::S:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}({})\n", addr, word, d.str_name, ToABI(d.rs2), d.imm, ToABI(d.rs1));
        break;
      case Decoded::Type::B:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}, {} ; 0x{:x}\n", addr, word, d.str_name, ToABI(d.rs1), ToABI(d.rs2), labels.find(d.target)->second, d.target);
        break;
      case Decoded::Type::U:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {}\n", addr, word, d.str_name, ToABI(d.rd), d.imm);
        break;
      case Decoded::Type::J:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\t{}, {} ; 0x{:x}\n", addr, word, d.str_name, ToABI(d.rd), labels.find(d.target)->second, d.target);
        break;
      case Decoded::Type::UNKNOWN:
        out << std::format(" {:05x}:\t{:08x}\t{:>7}\n", addr, word, "unknown_instruction");
        break;
    }
  }
}

const char* SymType(uint8_t type) {
  switch (type) {
    case 0: return "NOTYPE";
    case 1: return "OBJECT";
    case 2: return "FUNC";
    case 3: return "SECTION";
    case 4: return "FILE";
    case 5: return "COMMON";
    case 6: return "TLS";
    default: return "UNKNOWN";
  }
}

const char* SymBind(uint8_t bind) {
  switch (bind) {
    case 0: return "LOCAL";
    case 1: return "GLOBAL";
    case 2: return "WEAK";
    default: return "UNKNOWN";
  }
}

const char* SymVis(uint8_t vis) {
  switch (vis) {
    case 0: return "DEFAULT";
    case 1: return "INTERNAL";
    case 2: return "HIDDEN";
    case 3: return "PROTECTED";
    default: return "UNKNOWN";
  }
} 

std::string SymShndx(uint16_t idx) {
  switch (idx) {
    case 0: return "UNDEF";
    case 0xFFF1: return "ABS";
    case 0xFFF2: return "COMMON";
    default: return std::to_string(idx);
  }
}
 
void WriteSymtab(std::ostream& out, const ElfParser& elf) {
  out << ".symtab\n";
  out << "Symbol Value              Size Type     Bind     Vis       Index Name\n";
  int i = 0;
  for (const auto& s : elf.symbols()) {
    out << std::format("[{:>4}] 0x{:<15X} {:>5} {:<8} {:<8} {:<8} {:>6} {}\n", i++, s.value, s.size, SymType(s.type), SymBind(s.bind), SymVis(s.vis), SymShndx(s.idx), s.name);
  }
}

} // namespace

void disassemble(const ElfParser& elf, const std::string& out_path) {
  std::ofstream f(out_path, std::ios::binary);
  if (!f) {
    throw std::runtime_error("Cannot open output: " + out_path);
  }
  const auto labels = MakeLabels(elf);
  WriteText(f, elf, labels);
  f << "\n";
  WriteSymtab(f, elf);
}