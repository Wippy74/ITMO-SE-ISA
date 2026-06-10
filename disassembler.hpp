#pragma once
#include <ostream>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <unordered_map>

const char* ABI[32] = {"zero","ra", "sp", "gp", "tp", "t0", "t1", "t2","s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5","a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7","s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

const char* ToABI(int reg) {
  if (reg < 0 || reg >= 32) {
    return "?";
  }
  return ABI[reg];
}

struct Decoded {
  enum class Type {
    R,
    I,
    S,
    B,
    U,
    J,
    UNKNOWN
  };
  Type type = Type::UNKNOWN;
  const char* str_name = "unknown_instruction";
  int rd;
  int rs1;
  int rs2;
  int32_t imm;
  uint32_t shift;
  uint32_t target;
};

const std::unordered_map<int, const char*> map_r = {
  {0,"add"}, {1,"sll"}, {2,"slt"}, {3,"sltu"}, {4,"xor"}, {5,"srl"}, {6,"or"}, {7,"and"},
  {0x200,"mul"}, {0x201,"mulh"}, {0x202,"mulhsu"}, {0x203,"mulhu"}, {0x204,"div"},
  {0x205,"divu"}, {0x206,"rem"}, {0x207,"remu"}, {0x4000,"sub"}, {0x4005,"sra"}
};
const std::unordered_map<int, const char*> map_i = {{0,"addi"},{2,"slti"},{3,"sltiu"},{4,"xori"},{6,"ori"},{7,"andi"}};
const std::unordered_map<int, const char*> map_i_load = {{0,"lb"},{1,"lh"},{2,"lw"},{4,"lbu"},{5,"lhu"}};
const std::unordered_map<int, const char*> map_i_store = {{0,"sb"},{1,"sh"},{2,"sw"}};
const std::unordered_map<int, const char*> map_b = {{0,"beq"},{1,"bne"},{4,"blt"},{5,"bge"},{6,"bltu"},{7,"bgeu"}};
const std::unordered_map<int, const char*> map_fence = {{0x833,"fence.tso"}, {0x010,"pause"}};
const std::unordered_map<int, const char*> map_sys = {{0,"ecall"}, {1,"ebreak"}};

Decoded decode(uint32_t i, uint32_t pc) {
  Decoded d;
  int op = i & 0x7F;
  int f3 = (i >> 12) & 0x7;
  int f7 = (i >> 25) & 0x7F;
  d.rd = (i >> 7) & 0x1F; 
  d.rs1 = (i >> 15) & 0x1F; 
  d.rs2 = (i >> 20) & 0x1F;
  auto to_sign = [](uint32_t v, int b) {
    return static_cast<int32_t>(v << (32 - b)) >> (32 - b);
  };
  switch (op) {
    case 51:
      d.type = Decoded::Type::R;
      if (auto it = map_r.find((f7 << 9) | f3); it != map_r.end()) d.str_name = it->second;
      break;
    case 19:
      d.type = Decoded::Type::I; 
      d.imm = to_sign((i >> 20) & 0xFFF, 12);
      if (f3 == 1 && f7 == 0) {
        d.str_name = "slli";
        d.shift = d.rs2;
        break;
      }
      if (f3 == 5 && f7 == 0) {
        d.str_name = "srli";
        d.shift = d.rs2;
        break;
      }
      if (f3 == 5 && f7 == 32) {
        d.str_name = "srai";
        d.shift = d.rs2;
        break;
      }
      if (auto it = map_i.find(f3); it != map_i.end()) {
        d.str_name = it->second;
      }
      break;
    case 3:
      d.type = Decoded::Type::I; 
      d.imm = to_sign((i >> 20) & 0xFFF, 12);
      if (auto it = map_i_load.find(f3); it != map_i_load.end()) {
        d.str_name = it->second;
      }
      break;
    case 35:
      d.type = Decoded::Type::S; 
      d.imm = to_sign((f7 << 5) | d.rd, 12); 
      if (auto it = map_i_store.find(f3); it != map_i_store.end()) {
        d.str_name = it->second;
      }
      break;
    case 99:
      d.type = Decoded::Type::B; 
      d.imm = to_sign(((i >> 31) << 12) | (((i >> 25) & 0x3F) << 5) | (((i >> 8) & 0xF) << 1) | (((i >> 7) & 1) << 11), 13);
      d.target = pc + d.imm;
      if (auto it = map_b.find(f3); it != map_b.end()) {
        d.str_name = it->second;
      }
      break;
    case 103:
      if (f3 == 0) {
        d.type = Decoded::Type::I;
        d.imm = to_sign((i >> 20) & 0xFFF, 12);
        d.str_name = "jalr";
      }
      break;
    case 111:
      d.type = Decoded::Type::J; 
      d.imm = to_sign(((i >> 31) << 20) | (((i >> 21) & 0x3FF) << 1) | (((i >> 20) & 1) << 11) | (((i >> 12) & 0xFF) << 12), 21);
      d.target = pc + d.imm;
      d.str_name = "jal";
      break;
    case 55: 
      d.type = Decoded::Type::U; 
      d.imm = (i >> 12) & 0xFFFFF; 
      d.str_name = "lui";
      break;
    case 23: 
      d.type = Decoded::Type::U;
      d.imm = (i >> 12) & 0xFFFFF;
      d.str_name = "auipc";
      break;
    case 15:
      if (f3 == 0) {
        d.type = Decoded::Type::I; 
        int imm12 = (i >> 20) & 0xFFF;
        if (auto it = map_fence.find(imm12); it != map_fence.end()) {
          d.str_name = it->second;
        }
      } else {
        d.str_name = "fence";
      }
      break;
    case 115:
      if (f3 == 0) {
        d.type = Decoded::Type::I; 
        int imm12 = (i >> 20) & 0xFFF;
        if (auto it = map_sys.find(imm12); it != map_sys.end()) {
          d.str_name = it->second;
        }
      }
      break;
  }
  return d;
}