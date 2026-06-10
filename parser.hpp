#pragma once
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>

namespace {

struct ExHeader {
  uint8_t ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t shoff;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
};

struct SecHeader {
  uint32_t name;
  uint32_t type;
  uint32_t addr;
  uint32_t offset;
  uint32_t size;
  uint32_t link;
  uint32_t entsize;
};

struct ElfSym {
  uint32_t name;
  uint32_t value;
  uint32_t size;
  uint8_t info;
  uint8_t vis;
  uint16_t idx;
};

uint8_t Read8(const std::vector<uint8_t>& d, size_t off) {
  return d[off];
}

uint16_t Read16(const std::vector<uint8_t>& d, size_t off) {
  return static_cast<uint16_t>(d[off]) | (static_cast<uint16_t>(d[off + 1]) << 8);
}

uint32_t Read32(const std::vector<uint8_t>& d, size_t off) {
  return static_cast<uint32_t>(d[off]) | (static_cast<uint32_t>(d[off + 1]) << 8) | (static_cast<uint32_t>(d[off + 2]) << 16) | (static_cast<uint32_t>(d[off + 3]) << 24);
}

std::string ReadStr(const std::vector<uint8_t>& d, size_t off) {
  const auto begin = d.begin() + off;
  const auto end = std::find(begin, d.end(), 0);
  return std::string(begin, end);
}

ExHeader ReadHeader(const std::vector<uint8_t>& d) {
  ExHeader ex_header;
  for (int i = 0; i < 16; ++i) {
    ex_header.ident[i] = Read8(d, i);
  }
  ex_header.type = Read16(d, 16);
  ex_header.machine = Read16(d, 18);
  ex_header.shoff = Read32(d, 32);
  ex_header.shentsize = Read16(d, 46);
  ex_header.shnum = Read16(d, 48);
  ex_header.shstrndx = Read16(d, 50);
  return ex_header;
}

SecHeader ReadSecHeader(const std::vector<uint8_t>& d, size_t off) {
  SecHeader sec_header;
  sec_header.name = Read32(d, off + 0);
  sec_header.type = Read32(d, off + 4);
  sec_header.addr = Read32(d, off + 12);
  sec_header.offset = Read32(d, off + 16);
  sec_header.size = Read32(d, off + 20);
  sec_header.link = Read32(d, off + 24);
  sec_header.entsize = Read32(d, off + 36);
  return sec_header;
}

ElfSym ReadSym(const std::vector<uint8_t>& d, size_t off) {
  ElfSym sym;
  sym.name = Read32(d, off + 0);
  sym.value = Read32(d, off + 4);
  sym.size = Read32(d, off + 8);
  sym.info = Read8(d, off + 12);
  sym.vis = Read8(d, off + 13);
  sym.idx = Read16(d, off + 14);
  return sym;
}

}  // namespace

struct Symbol {
  uint32_t value;
  uint32_t size;
  uint8_t type;
  uint8_t bind;
  uint8_t vis;
  uint16_t idx;
  std::string name;
};

class ElfParser {
private:
  uint32_t TextAddr_ = 0;
  std::vector<uint8_t> text_;
  std::vector<Symbol> symbols_;
public:
  void parse(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
      throw std::runtime_error("Cannot open file: " + path);
    }
    f.seekg(0, std::ios::end);
    const auto file_size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(file_size);
    if (!f.read(reinterpret_cast<char*>(data.data()), file_size)) {
      throw std::runtime_error("Read error: " + path);
    }

    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
      throw std::runtime_error("Magic discrepancy");
    }
    if (data[4] != 1) {
      throw std::runtime_error("Not a 32-bit ELF-file");
    }
    if (data[5] != 1) {
      throw std::runtime_error("Not a LE ELF-file");
    }

    const ExHeader eh = ReadHeader(data);
    if (eh.machine != 243) {
      throw std::runtime_error("ISA is not RISC-V");
    }
    if (eh.shoff == 0 || eh.shnum == 0) {
      throw std::runtime_error("ELF-file has no section header table");
    }

    std::vector<SecHeader> sh;
    for (uint16_t i = 0; i < eh.shnum; ++i) {
      const size_t off = eh.shoff + i * eh.shentsize;
      sh.push_back(ReadSecHeader(data, off));
    }

    const SecHeader& shstr = sh[eh.shstrndx];
    if (shstr.offset + shstr.size > data.size()) {
      throw std::runtime_error(".shstrtab out of range");
    }

    int TextIdx = -1;
    int SymtabIdx = -1;
    for (uint16_t i = 0; i < eh.shnum; ++i) {
      const std::string name = ReadStr(data, shstr.offset + sh[i].name);
      if (TextIdx < 0 && name == ".text") {
        TextIdx = i;
      }
      if (SymtabIdx < 0 && name == ".symtab") {
        SymtabIdx = i;
      }
    }
    if (TextIdx < 0) {
      throw std::runtime_error(".text section not found");
    }
    if (SymtabIdx < 0) {
      throw std::runtime_error(".symtab section not found");
    }
    
    const SecHeader& TextSh = sh[TextIdx];
    if (TextSh.offset + TextSh.size > data.size()) {
      throw std::runtime_error(".text out of range");
    }
    TextAddr_ = TextSh.addr;
    text_.assign(data.begin() + TextSh.offset, data.begin() + TextSh.offset + TextSh.size);

    const SecHeader& SymtabSh = sh[SymtabIdx];
    if (SymtabSh.entsize != 16) {
      throw std::runtime_error("Unexpected .symtab entry size");
    }
    if (SymtabSh.link >= eh.shnum) {
      throw std::runtime_error(".symtab.sh_link points outside section table");
    }

    const SecHeader& StrtabSh = sh[SymtabSh.link];
    if (SymtabSh.offset + SymtabSh.size > data.size()) {
      throw std::runtime_error(".symtab out of range");
    }
    if (StrtabSh.offset + StrtabSh.size > data.size()) {
      throw std::runtime_error(".strtab out of range");
    }
    const size_t n = SymtabSh.size / 16;

    for (size_t i = 0; i < n; ++i) {
      const ElfSym sym = ReadSym(data, SymtabSh.offset + i * 16);
      Symbol out;
      out.value = sym.value;
      out.size = sym.size;
      out.bind = sym.info >> 4;
      out.type = sym.info & 0x0F;
      out.vis = sym.vis & 0x03;
      out.idx = sym.idx;
      out.name = ReadStr(data, StrtabSh.offset + sym.name);
      symbols_.push_back(std::move(out));
    }
  }

  uint32_t TextAddr() const {
    return TextAddr_;
  }
  const std::vector<uint8_t>& text() const {
    return text_;
  }
  const std::vector<Symbol>& symbols() const {
    return symbols_;
  }
};