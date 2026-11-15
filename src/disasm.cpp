// disasm.cpp -- Capstone-backed decoding, function discovery, CFG recovery.
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <set>

#include "model.h"

namespace bcd {
namespace {

csh g_handle = 0;

bool open_capstone() {
    if (g_handle != 0) {
        return true;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &g_handle) != CS_ERR_OK) {
        return false;
    }
    cs_option(g_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(g_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    return true;
}

bool is_cond_jump_name(const std::string& m) {
    static const std::set<std::string> kCond = {
        "ja",   "jae",  "jb",   "jbe",  "jc",   "je",   "jg",   "jge",  "jl",
        "jle",  "jna",  "jnae", "jnb",  "jnbe", "jnc",  "jne",  "jng",  "jnge",
        "jnl",  "jnle", "jno",  "jnp",  "jns",  "jnz",  "jo",   "jp",   "jpe",
        "jpo",  "js",   "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"};
    return kCond.count(m) != 0;
}

bool is_cond_jump(const cs_insn& ci) {
    return is_cond_jump_name(ci.mnemonic);
}

std::string canon_mnem(const std::string& m) {
    if (m == "jnz" || m == "jne") return "jne";
    if (m == "jz" || m == "je") return "je";
    if (m == "jae" || m == "jnb" || m == "jnc") return "jae";
    if (m == "jb" || m == "jnae" || m == "jc") return "jb";
    if (m == "jbe" || m == "jna") return "jbe";
    if (m == "ja" || m == "jnbe") return "ja";
    if (m == "jge" || m == "jnl") return "jge";
    if (m == "jl" || m == "jnge") return "jl";
    if (m == "jle" || m == "jng") return "jle";
    if (m == "jg" || m == "jnle") return "jg";
    if (m == "je" || m == "jz") return "je";
    if (m == "movabs") return "mov";
    if (m == "retq" || m == "retn") return "ret";
    if (m == "callq") return "call";
    if (m == "jmpq") return "jmp";
    if (m == "endbr64" || m == "endbr32") return "endbr";
    if (m == "sete" || m == "setz") return "sete";
    if (m == "setne" || m == "setnz") return "setne";
    return m;
}

bool is_nop_mnem(const std::string& m) {
    return m == "nop" || m == "nopw" || m == "nopl" || m == "nopd" || m == "fnop" ||
           m == "pause";
}

}  // namespace

// ---------------------------------------------------------------------------
// decoding helpers
// ---------------------------------------------------------------------------

namespace {

struct Decoded {
    Insn insn;
    bool ok = false;
};

// Fill Insn from a Capstone instruction. `bin` supplies address validation for
// RIP-relative references and immediate constants.
void fill_insn(const cs_insn& ci, const Binary& bin, Insn& out) {
    out.addr = ci.address;
    out.len = (uint8_t)ci.size;
    out.cs_id = ci.id;
    for (unsigned i = 0; i < ci.size && i < sizeof(out.bytes); ++i) {
        out.bytes[i] = ci.bytes[i];
    }
    out.mnemonic.assign(ci.mnemonic);
    out.op_str.assign(ci.op_str);
    out.is_invalid = (ci.id == 0);

    const std::string m = out.mnemonic;
    const cs_x86& x = ci.detail->x86;

    for (int i = 0; i < x.op_count && i < 8; ++i) {
        const cs_x86_op& src = x.operands[i];
        Operand op;
        op.size = src.size;
        op.writes = (src.access & CS_AC_WRITE) != 0;
        switch (src.type) {
        case X86_OP_REG:
            op.kind = Operand::REG;
            op.reg = (int)src.reg;
            op.reg_name = cs_reg_name(g_handle, src.reg) ? cs_reg_name(g_handle, src.reg) : "?";
            break;
        case X86_OP_IMM:
            op.kind = Operand::IMM;
            op.imm = (int64_t)src.imm;
            break;
        case X86_OP_MEM: {
            op.kind = Operand::MEM;
            op.mem_base = (int)src.mem.base;
            op.mem_index = (int)src.mem.index;
            op.mem_scale = src.mem.scale;
            op.mem_disp = (int64_t)src.mem.disp;
            if (src.mem.base) {
                op.mem_base_name =
                    cs_reg_name(g_handle, src.mem.base) ? cs_reg_name(g_handle, src.mem.base) : "?";
            }
            if (src.mem.index) {
                op.mem_index_name = cs_reg_name(g_handle, src.mem.index)
                                        ? cs_reg_name(g_handle, src.mem.index)
                                        : "?";
            }
            if (src.mem.base == X86_REG_RIP || src.mem.base == X86_REG_EIP) {
                op.rip_rel = true;
                op.rip_target = ci.address + ci.size + (uint64_t)src.mem.disp;
            }
            break;
        }
        default:
            op.kind = Operand::OTHER;
            break;
        }
        out.ops.push_back(op);
    }

    out.is_call = (ci.id == X86_INS_CALL || ci.id == X86_INS_LCALL);
    out.is_ret = (ci.id == X86_INS_RET || ci.id == X86_INS_RETF || ci.id == X86_INS_RETFQ);
    out.is_jcc = is_cond_jump(ci);
    out.is_jmp = (ci.id == X86_INS_JMP || ci.id == X86_INS_LJMP) && !out.is_jcc &&
                 !out.is_call;
    out.is_indirect = false;
    out.is_nop = is_nop_mnem(m);
    out.is_int3 = (m == "int3");
    out.is_halt = (m == "ud0" || m == "ud1" || m == "ud2" || m == "hlt" || m == "iret" ||
                   m == "iretd" || m == "iretq");
    out.is_syscall = (m == "syscall" || m == "sysenter");
    out.is_pad = out.is_nop || out.is_int3;

    if ((out.is_jmp || out.is_jcc || out.is_call) && !out.ops.empty()) {
        const Operand& o = out.ops[0];
        if (o.kind == Operand::IMM) {
            out.branch_target = (uint64_t)o.imm;
            out.targets.push_back((uint64_t)o.imm);
            out.is_indirect = false;
        } else {
            out.is_indirect = true;
        }
    }
    if (out.is_jmp && out.ops.size() == 1 && out.ops[0].kind == Operand::MEM) {
        out.is_indirect = true;
    }

    // First immediate that is not a branch target.
    for (const auto& op : out.ops) {
        if (op.kind != Operand::IMM) {
            continue;
        }
        if ((out.is_jmp || out.is_jcc) && op.imm == (int64_t)out.branch_target) {
            continue;
        }
        out.has_imm = true;
        out.imm_value = op.imm;
        // Treat as constant unless it lands inside a loaded section.
        out.imm_is_const = !(op.imm >= 0 && op.imm < (int64_t)0x7fffffffLL &&
                             bin.section_containing((uint64_t)op.imm) != nullptr);
        break;
    }

    out.writes_memory = false;
    out.reads_memory = false;
    for (const auto& op : out.ops) {
        if (op.kind != Operand::MEM) {
            continue;
        }
        if (op.writes) {
            out.writes_memory = true;
        } else {
            out.reads_memory = true;
        }
    }

    out.ends_block = out.is_ret || out.is_jmp || out.is_jcc || out.is_halt || out.is_indirect;
    out.falls_through = !(out.is_ret || out.is_jmp || out.is_halt) && !out.is_int3;
}

// Build the address-independent token used for similarity: mnemonic plus
// operand shapes. Stack displacements are collapsed because frame layout shifts
// between builds; in-image addresses are collapsed to a marker.
std::string coarse_token(const Insn& in, const Binary& bin) {
    const std::string canon = canon_mnem(in.mnemonic);
    if (in.is_nop) {
        return "nop";
    }
    std::string t = canon;
    for (size_t k = 0; k < in.ops.size(); ++k) {
        const Operand& op = in.ops[k];
        t += k == 0 ? " " : ",";
        switch (op.kind) {
        case Operand::REG:
            t += "r";
            break;
        case Operand::IMM:
            if ((in.is_jmp || in.is_jcc || in.is_call) &&
                op.imm == (int64_t)in.branch_target) {
                t += "tgt";
            } else if (!in.imm_is_const) {
                t += "addr";
            } else {
                t += "i" + std::to_string(op.imm);
            }
            break;
        case Operand::MEM: {
            t += "m:";
            const std::string& b = op.mem_base_name;
            if (op.rip_rel) {
                // Section or literal target: keep literal identity, it is stable
                // across rebuilds even when addresses shift.
                if (bin.section_containing(op.rip_target)) {
                    t += "lit";
                } else {
                    t += "rip";
                }
            } else if (b == "rsp" || b == "rbp" || b == "esp" || b == "ebp") {
                t += "stk";
            } else if (!b.empty()) {
                t += "r";
            } else {
                t += "abs";
            }
            if (op.mem_index != 0) {
                t += "+idx" + std::to_string(op.mem_scale);
            }
            break;
        }
        default:
            t += "?";
            break;
        }
    }
    if (in.ops.empty()) {
        t += " ";
    }
    return t;
}

bool disasm_at(const Binary& bin, uint64_t addr, Insn& out) {
    const Section* sec = bin.section_containing(addr);
    if (!sec || !sec->exec()) {
        return false;
    }
    // Gather up to 15 bytes of contiguous code inside the section.
    uint8_t buf[16] = {0};
    size_t maxn = std::min<size_t>(15, (size_t)(sec->addr + sec->size - addr));
    if (maxn == 0 || !bin.read(addr, buf, maxn)) {
        return false;
    }
    cs_insn* ci = nullptr;
    size_t n = cs_disasm(g_handle, buf, maxn, addr, 1, &ci);
    if (n == 0) {
        return false;
    }
    fill_insn(ci[0], bin, out);
    out.coarse = coarse_token(out, bin);
    cs_free(ci, n);
    return true;
}

// Resolve a direct branch target's sanity: must be inside an executable section.
bool branch_ok(const Binary& bin, uint64_t target) {
    return bin.in_exec(target);
}

// ---------------------------------------------------------------------------
// jump-table recovery
// ---------------------------------------------------------------------------

struct TableGuess {
    uint64_t base = 0;
    int count = 0;
    int width = 4;
};

// Look backwards from an indirect jmp for the classic
//   lea base,[rip+table]; cmp idx,N; movsxd reg,[base+idx*4]; add base,reg; jmp reg
// shape. Returns guesses in preference order.
std::vector<TableGuess> guess_tables(const std::vector<Insn>& insns, int jmp_idx,
                                     const Binary& bin) {
    std::vector<TableGuess> out;
    int lo = std::max(0, jmp_idx - 14);
    uint64_t base = 0;
    int width = 0;
    int count = 0;
    bool has_add = false;
    for (int i = jmp_idx - 1; i >= lo; --i) {
        const Insn& in = insns[i];
        const std::string cm = canon_mnem(in.mnemonic);
        if (cm == "lea" && in.ops.size() == 2 && in.ops[1].kind == Operand::MEM &&
            in.ops[1].rip_rel) {
            if (base == 0) {
                base = in.ops[1].rip_target;
            }
        } else if ((cm == "movsxd" || cm == "mov" || cm == "movsx" || cm == "movslq") &&
                   in.ops.size() == 2 && in.ops[1].kind == Operand::MEM &&
                   in.ops[1].mem_index != 0) {
            const Operand& mop = in.ops[1];
            int w = mop.size;
            if (w == 4 || w == 8) {
                width = w;
            } else if (mop.mem_scale == 4) {
                width = 4;
            } else if (mop.mem_scale == 8) {
                width = 8;
            }
            if (mop.rip_rel && mop.mem_base == 0) {
                base = mop.rip_target;
            }
        } else if (cm == "add" && in.ops.size() == 2) {
            has_add = true;
        } else if (cm == "cmp" && in.ops.size() == 2 && in.ops[1].kind == Operand::IMM) {
            if (in.ops[1].imm >= 0 && in.ops[1].imm < 4096) {
                count = (int)in.ops[1].imm + 1;
            }
        } else if (cm == "jmp" && in.ops.size() == 1 && in.ops[0].kind == Operand::MEM &&
                   in.ops[0].mem_index != 0) {
            // jmp qword ptr [table + idx*8]
            const Operand& mop = in.ops[0];
            if (mop.rip_rel) {
                TableGuess g;
                g.base = mop.rip_target;
                g.width = 8;
                g.count = count ? count : 64;
                out.push_back(g);
            }
        }
    }
    if (base != 0 && width != 0) {
        TableGuess g;
        g.base = base;
        g.width = width;
        g.count = count ? count : 64;
        out.push_back(g);
        (void)has_add;
    }
    return out;
}

std::vector<uint64_t> read_table(const Binary& bin, const TableGuess& g) {
    std::vector<uint64_t> targets;
    const Section* sec = bin.section_containing(g.base);
    if (!sec) {
        return targets;
    }
    int limit = std::min(g.count, 4096);
    int invalid_run = 0;
    for (int i = 0; i < limit; ++i) {
        uint64_t entry_addr = g.base + (uint64_t)i * (uint64_t)g.width;
        uint8_t raw[8] = {0};
        if (!bin.read(entry_addr, raw, (size_t)g.width)) {
            break;
        }
        uint64_t target = 0;
        if (g.width == 4) {
            int32_t off = 0;
            std::memcpy(&off, raw, 4);
            target = g.base + (uint64_t)(int64_t)off;
        } else {
            std::memcpy(&target, raw, 8);
        }
        bool ok = target != 0 && target != g.base && branch_ok(bin, target);
        if (!ok) {
            if (++invalid_run >= 2) {
                break;
            }
            continue;
        }
        invalid_run = 0;
        targets.push_back(target);
    }
    return targets;
}

}  // namespace

// ---------------------------------------------------------------------------
// Program construction
// ---------------------------------------------------------------------------

void build_program(const Binary& bin, Program& prog) {
    prog = Program{};
    prog.bin = &bin;
    if (!open_capstone()) {
        return;
    }

    // Collect executable ranges in address order.
    std::vector<const Section*> execs;
    for (const auto& s : bin.sections) {
        if (s.exec() && s.size != 0 && s.type != 8) {
            execs.push_back(&s);
        }
    }
    std::sort(execs.begin(), execs.end(),
              [](const Section* a, const Section* b) { return a->addr < b->addr; });

    // -----------------------------------------------------------------
    // Function discovery.
    //
    // When a .symtab is present it is authoritative: every FUNC symbol in an
    // executable section becomes a function, with its trailing alignment
    // padding trimmed. Heuristic sweep is only used for stripped inputs, and
    // then only for seeds that look like real entries (call targets, pointer
    // targets, or a recognizable prologue) so that inter-function padding is
    // never turned into a phantom function.
    // -----------------------------------------------------------------

    struct Body {
        uint64_t start;
        uint64_t end;  // exclusive
        std::string name;
        bool from_symbol;
        bool recovered;
    };

    // Address -> next function-start boundary from symbols (used to bound
    // zero-size symbols and to clamp heuristic growth).
    std::map<uint64_t, uint64_t> sym_end;
    std::map<uint64_t, std::string> sym_name;
    std::vector<uint64_t> sym_starts;
    if (bin.has_symtab) {
        for (const auto& s : bin.symbols) {
            if (!s.is_func() || s.addr == 0 || s.shndx == 0 || !bin.in_exec(s.addr)) {
                continue;
            }
            sym_starts.push_back(s.addr);
        }
        std::sort(sym_starts.begin(), sym_starts.end());
        sym_starts.erase(std::unique(sym_starts.begin(), sym_starts.end()),
                         sym_starts.end());
        for (const auto& s : bin.symbols) {
            if (!s.is_func() || s.addr == 0 || s.shndx == 0 || !bin.in_exec(s.addr)) {
                continue;
            }
            uint64_t start = s.addr;
            uint64_t end = s.size ? start + s.size : 0;
            if (end == 0) {
                auto it = std::upper_bound(sym_starts.begin(), sym_starts.end(), start);
                if (it != sym_starts.end()) {
                    end = *it;
                } else {
                    end = bin.exec_end_after(start);
                }
            }
            end = std::min(end, bin.exec_end_after(start));
            auto it = sym_end.find(start);
            if (it == sym_end.end() || end > it->second) {
                sym_end[start] = end;
            }
            auto nit = sym_name.find(start);
            if (nit == sym_name.end() || s.bind != 0) {
                sym_name[start] = s.name;
            }
        }
    }

    std::vector<Body> bodies;

    if (!sym_end.empty()) {
        // Symbol-driven discovery.
        for (const auto& kv : sym_end) {
            Body b;
            b.start = kv.first;
            b.end = kv.second;
            b.name = sym_name.count(kv.first) ? sym_name[kv.first] : "";
            b.from_symbol = true;
            b.recovered = false;
            if (b.end > b.start) {
                bodies.push_back(b);
            }
        }
    } else {
        // Heuristic discovery for stripped binaries.
        std::vector<uint64_t> seeds;
        auto add_seed = [&](uint64_t a) {
            if (a != 0 && bin.in_exec(a)) {
                seeds.push_back(a);
            }
        };
        add_seed(bin.entry);
        // Direct call targets (E8 rel32) and 8-byte pointers into .text.
        for (const Section* sec : execs) {
            if (sec->offset >= bin.data.size()) {
                continue;
            }
            size_t n = std::min<size_t>((size_t)sec->size,
                                        bin.data.size() - (size_t)sec->offset);
            const uint8_t* p = bin.data.data() + sec->offset;
            for (size_t i = 0; i + 5 <= n; ++i) {
                if (p[i] != 0xe8) {
                    continue;
                }
                int32_t rel = 0;
                std::memcpy(&rel, p + i + 1, 4);
                add_seed(sec->addr + i + 5 + (uint64_t)(int64_t)rel);
            }
        }
        for (const auto& s : bin.sections) {
            if (!s.alloc() || s.type == 8 || s.offset >= bin.data.size() ||
                (s.exec() && false)) {
                continue;
            }
            size_t n = std::min<size_t>((size_t)s.size, bin.data.size() - (size_t)s.offset);
            const uint8_t* p = bin.data.data() + s.offset;
            for (size_t i = 0; i + 8 <= n; ++i) {
                uint64_t v = 0;
                std::memcpy(&v, p + i, 8);
                if (bin.in_exec(v)) {
                    add_seed(v);
                }
            }
        }
        std::sort(seeds.begin(), seeds.end());
        seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());

        // A seed only counts as a function entry when it decodes and does not
        // start in the middle of a nop/aligned pad or with a padding byte.
        auto entry_plausible = [&](uint64_t a) -> bool {
            Insn in;
            if (!disasm_at(bin, a, in) || in.is_invalid || in.is_pad) {
                return false;
            }
            // Reject seeds that begin with a branch into the middle of nothing.
            if (in.is_jmp && !in.is_indirect && !branch_ok(bin, in.branch_target)) {
                return false;
            }
            return true;
        };

        std::vector<uint64_t> accepted;
        for (uint64_t s : seeds) {
            if (entry_plausible(s)) {
                accepted.push_back(s);
            }
        }
        std::sort(accepted.begin(), accepted.end());
        accepted.erase(std::unique(accepted.begin(), accepted.end()), accepted.end());

        for (size_t si = 0; si < accepted.size(); ++si) {
            uint64_t seed = accepted[si];
            uint64_t limit = bin.exec_end_after(seed);
            if (si + 1 < accepted.size() && accepted[si + 1] > seed) {
                limit = std::min(limit, accepted[si + 1]);
            }
            // Grow the body along the flow graph.
            uint64_t last = seed;
            std::set<uint64_t> visited;
            std::vector<uint64_t> pending{seed};
            int guard = 0;
            bool ok = true;
            while (!pending.empty() && guard++ < 200000) {
                uint64_t pc = pending.back();
                pending.pop_back();
                while (pc < limit && bin.in_exec(pc)) {
                    if (!visited.insert(pc).second) {
                        break;
                    }
                    Insn in;
                    if (!disasm_at(bin, pc, in) || in.is_invalid) {
                        ok = false;
                        break;
                    }
                    // Alignment nops inside a body (loop headers, tail padding
                    // before a branch target) are part of the function; only a
                    // terminating instruction ends it. Trailing pads are trimmed
                    // after discovery.
                    if (!in.is_pad) {
                        last = std::max(last, pc + in.len);
                    }
                    if (in.is_ret || in.is_halt) {
                        break;
                    }
                    if (in.is_jmp) {
                        if (!in.is_indirect && in.branch_target >= seed &&
                            in.branch_target < limit) {
                            pending.push_back(in.branch_target);
                        }
                        break;
                    }
                    if (in.is_jcc && in.branch_target >= seed && in.branch_target < limit) {
                        pending.push_back(in.branch_target);
                    }
                    pc += in.len;
                }
            }
            if (!ok || last <= seed) {
                continue;
            }
            Body b;
            b.start = seed;
            b.end = last;
            b.from_symbol = false;
            b.recovered = true;
            bodies.push_back(b);
        }
    }

    // Gap sweep: executable bytes that no body covers are linear-swept one
    // function at a time. A function's linear extent ends at a terminator
    // (ret/halt, unconditional jmp, or any branch leaving the section); the
    // alignment nops printed after it are skipped before the next blob starts.
    // Interior nops (loop alignment) are therefore not mistaken for a boundary.
    {
        std::vector<std::pair<uint64_t, uint64_t>> span;
        for (const auto& b : bodies) {
            span.push_back({b.start, b.end});
        }
        std::sort(span.begin(), span.end());
        std::vector<std::pair<uint64_t, uint64_t>> gaps;
        for (const Section* sec : execs) {
            uint64_t a = sec->addr;
            uint64_t b = sec->addr + sec->size;
            for (const auto& sp : span) {
                if (sp.second <= a || sp.first >= b) {
                    continue;
                }
                uint64_t g1 = std::min(sp.first, b);
                if (g1 > a) {
                    gaps.push_back({a, g1});
                }
                a = std::max(a, sp.second);
            }
            if (b > a) {
                gaps.push_back({a, b});
            }
        }
        for (auto& g : gaps) {
            uint64_t cursor = g.first;
            uint64_t gap_end = g.second;
            while (cursor < gap_end) {
                Insn in;
                if (!disasm_at(bin, cursor, in) || in.is_invalid) {
                    cursor += 1;
                    continue;
                }
                if (in.is_pad) {
                    cursor += in.len;
                    continue;
                }
                uint64_t body_start = cursor;
                uint64_t last_good = cursor;
                uint64_t pc = cursor;
                while (pc < gap_end) {
                    Insn t;
                    if (!disasm_at(bin, pc, t) || t.is_invalid) {
                        break;
                    }
                    pc += t.len;
                    if (!t.is_pad) {
                        last_good = pc;
                    }
                    if (t.is_ret || t.is_halt) {
                        break;
                    }
                    if (t.is_jmp) {
                        break;
                    }
                }
                if (last_good > body_start) {
                    Body nb;
                    nb.start = body_start;
                    nb.end = last_good;
                    nb.from_symbol = false;
                    nb.recovered = true;
                    bodies.push_back(nb);
                    cursor = last_good;
                    continue;
                }
                cursor = body_start + 1;
            }
        }
    }

    // Merge adjacent recovered bodies. Compilers insert alignment padding
    // *between* functions and none inside one, so two recovered bodies that are
    // byte-adjacent are parts of the same function (the gap sweep splits at
    // every ret, which is wrong for functions with early returns).
    if (!sym_end.empty()) {
        // Symbol bodies are authoritative boundaries; nothing to merge.
    } else {
        std::sort(bodies.begin(), bodies.end(), [](const Body& a, const Body& b) {
            if (a.start != b.start) return a.start < b.start;
            return a.end < b.end;
        });
        std::vector<Body> merged;
        for (const auto& b : bodies) {
            if (!merged.empty() && merged.back().end == b.start) {
                merged.back().end = std::max(merged.back().end, b.end);
                merged.back().from_symbol = merged.back().from_symbol && b.from_symbol;
                continue;
            }
            if (!merged.empty() && b.start < merged.back().end) {
                // Overlapping: keep the union.
                merged.back().end = std::max(merged.back().end, b.end);
                continue;
            }
            merged.push_back(b);
        }
        bodies.swap(merged);
    }

    // Trim trailing alignment padding (nop / int3 runs) from every body, then
    // drop bodies that turn out to be empty or wholly padding.
    for (auto& b : bodies) {
        std::vector<Insn> tmp;
        uint64_t pc = b.start;
        while (pc < b.end) {
            Insn in;
            if (!disasm_at(bin, pc, in) || in.is_invalid) {
                break;
            }
            if (pc + in.len > b.end) {
                break;
            }
            tmp.push_back(in);
            pc += in.len;
        }
        while (!tmp.empty() && tmp.back().is_pad) {
            tmp.pop_back();
        }
        if (tmp.empty()) {
            b.end = b.start;  // mark for removal
            continue;
        }
        b.end = tmp.back().addr + tmp.back().len;
    }
    bodies.erase(std::remove_if(bodies.begin(), bodies.end(),
                                [](const Body& b) { return b.end <= b.start; }),
                 bodies.end());

    std::sort(bodies.begin(), bodies.end(),
              [](const Body& a, const Body& b) { return a.start < b.start; });

    // Drop fully-contained bodies (a symbol range always wins over a recovered
    // fragment; otherwise keep the outer, larger one).
    std::vector<Body> final_bodies;
    for (size_t i = 0; i < bodies.size(); ++i) {
        bool contained = false;
        for (size_t j = 0; j < bodies.size(); ++j) {
            if (i == j) {
                continue;
            }
            const Body& a = bodies[i];
            const Body& b = bodies[j];
            if (b.start <= a.start && b.end >= a.end &&
                (b.start < a.start || b.end > a.end)) {
                if (b.from_symbol || !a.from_symbol) {
                    contained = true;
                    break;
                }
            }
        }
        if (!contained) {
            final_bodies.push_back(bodies[i]);
        }
    }


    // Build CFGs.
    prog.funcs.reserve(final_bodies.size());
    for (size_t fi = 0; fi < final_bodies.size(); ++fi) {
        const Body& b = final_bodies[fi];
        Func f;
        f.index = (int)fi;
        f.start = b.start;
        f.end = b.end;
        f.name = b.name;
        f.named = !b.name.empty();
        f.from_symbol = b.from_symbol;
        f.recovered = b.recovered;

        // Decode the function body linearly; unreachable gaps are only entered
        // through branch targets, so a linear decode is safe as long as it
        // stops at the declared end. Instructions that decode invalid are
        // recorded so the CFG builder can cut the block.
        uint64_t pc = b.start;
        while (pc < b.end) {
            Insn in;
            if (!disasm_at(bin, pc, in) || in.is_invalid) {
                f.has_bad_insn = true;
                break;
            }
            if (pc + in.len > b.end) {
                break;
            }
            f.addr_to_insn[pc] = (int)f.insns.size();
            f.insns.push_back(in);
            pc += in.len;
        }
        if (f.insns.empty()) {
            continue;
        }

        // Resolve jump tables and collect targets.
        std::set<uint64_t> leaders;
        leaders.insert(b.start);
        for (size_t ii = 0; ii < f.insns.size(); ++ii) {
            const Insn& in = f.insns[ii];
            if (in.is_call && !in.is_indirect && in.targets.size()) {
                f.call_targets.push_back(in.targets[0]);
            }
            if (in.is_jcc || (in.is_jmp && !in.is_indirect)) {
                uint64_t t = in.branch_target;
                if (t >= b.start && t < b.end) {
                    leaders.insert(t);
                }
            }
            if (in.is_jmp && in.is_indirect) {
                for (const auto& g : guess_tables(f.insns, (int)ii, bin)) {
                    auto tgts = read_table(bin, g);
                    if (tgts.size() >= 3) {
                        std::vector<uint64_t> inside;
                        for (uint64_t t : tgts) {
                            if (t >= b.start && t < b.end) {
                                inside.push_back(t);
                                leaders.insert(t);
                            }
                        }
                        if (inside.size() >= 3) {
                            f.jump_tables[in.addr] = inside;
                        }
                    }
                }
            }
            if (in.ends_block && ii + 1 < f.insns.size()) {
                leaders.insert(f.insns[ii + 1].addr);
            }
        }

        // Build blocks from leaders.
        std::map<uint64_t, int> leader_block;
        std::vector<Block> blocks;
        for (size_t ii = 0; ii < f.insns.size(); ++ii) {
            uint64_t a = f.insns[ii].addr;
            if (leaders.count(a)) {
                Block blk;
                blk.id = (int)blocks.size();
                blk.start = a;
                blk.end = a;
                blk.entry = (a == b.start);
                leader_block[a] = blk.id;
                blocks.push_back(blk);
            }
            if (blocks.empty()) {
                Block blk;
                blk.id = 0;
                blk.start = a;
                blk.end = a;
                blk.entry = (a == b.start);
                leader_block[a] = 0;
                blocks.push_back(blk);
            }
            Block& cur = blocks.back();
            cur.insns.push_back((int)ii);
            cur.end = a + f.insns[ii].len;
        }
        // Remove empty blocks (leaders that landed on a boundary).
        {
            std::vector<Block> cleaned;
            for (auto& blk : blocks) {
                if (!blk.insns.empty()) {
                    blk.id = (int)cleaned.size();
                    cleaned.push_back(blk);
                }
            }
            blocks.swap(cleaned);
        }
        f.blocks = blocks;
        f.entry_block = 0;

        // Edges.
        std::map<uint64_t, int> start_to_block;
        for (auto& blk : f.blocks) {
            start_to_block[blk.start] = blk.id;
        }
        auto block_for = [&](uint64_t addr) -> int {
            auto it = start_to_block.find(addr);
            if (it != start_to_block.end()) {
                return it->second;
            }
            // Address inside a block: use that block (mid-block branch target).
            for (const auto& blk : f.blocks) {
                if (addr >= blk.start && addr < blk.end) {
                    return blk.id;
                }
            }
            return -1;
        };
        for (auto& blk : f.blocks) {
            const Insn& last = f.insns[blk.insns.back()];
            auto add_edge = [&](int to, int kind) {
                if (to < 0) {
                    return;
                }
                for (size_t e = 0; e < blk.succ.size(); ++e) {
                    if (blk.succ[e] == to) {
                        return;
                    }
                }
                blk.succ.push_back(to);
                blk.succ_kind.push_back(kind);
                f.blocks[to].pred.push_back(blk.id);
            };
            blk.has_call = false;
            blk.has_write = false;
            for (int ii : blk.insns) {
                if (f.insns[ii].is_call) {
                    blk.has_call = true;
                }
                if (f.insns[ii].writes_memory) {
                    blk.has_write = true;
                }
            }
            if (last.is_ret || last.is_halt) {
                continue;
            }
            if (last.is_jcc) {
                int to = block_for(last.branch_target);
                if (to >= 0) {
                    add_edge(to, 1);
                } else {
                    f.has_tail_calls = true;
                }
                int fb = blk.id + 1;
                if (fb < (int)f.blocks.size() &&
                    f.blocks[fb].start == blk.end) {
                    add_edge(fb, 0);
                }
                continue;
            }
            if (last.is_jmp) {
                if (last.is_indirect) {
                    auto it = f.jump_tables.find(last.addr);
                    if (it != f.jump_tables.end()) {
                        for (uint64_t t : it->second) {
                            add_edge(block_for(t), 2);
                        }
                    }
                } else {
                    int to = block_for(last.branch_target);
                    if (to >= 0) {
                        add_edge(to, 1);
                    } else {
                        f.has_tail_calls = true;
                    }
                }
                continue;
            }
            int fb = blk.id + 1;
            if (fb < (int)f.blocks.size() && f.blocks[fb].start == blk.end) {
                add_edge(fb, 0);
            }
        }

        // Reachability from entry.
        if (!f.blocks.empty()) {
            std::vector<int> stack{f.entry_block};
            f.blocks[f.entry_block].reachable = true;
            while (!stack.empty()) {
                int b = stack.back();
                stack.pop_back();
                for (int s : f.blocks[b].succ) {
                    if (!f.blocks[s].reachable) {
                        f.blocks[s].reachable = true;
                        stack.push_back(s);
                    }
                }
            }
        }

        prog.n_insns += f.insns.size();
        prog.n_blocks += f.blocks.size();
        prog.func_by_start[f.start] = f.index;
        for (const auto& in : f.insns) {
            prog.covers[in.addr] = f.index;
        }
        prog.funcs.push_back(std::move(f));
    }

    for (auto& s : prog.funcs) {
        if (s.name.empty()) {
            s.name = "sub_" + hex(s.start);
        }
    }
}

int Program::func_at(uint64_t addr) const {
    int best = -1;
    for (const auto& f : funcs) {
        if (addr >= f.start && addr < f.end) {
            if (best < 0 || f.start >= funcs[best].start) {
                best = f.index;
            }
        }
    }
    return best;
}

int Program::func_at_insn(uint64_t addr) const {
    auto it = covers.find(addr);
    return it == covers.end() ? -1 : it->second;
}

const Block* Func::block_at(uint64_t addr) const {
    for (const auto& b : blocks) {
        if (addr >= b.start && addr < b.end) {
            return &b;
        }
    }
    return nullptr;
}

int Block::find_insn(uint64_t addr) const {
    (void)addr;
    return -1;
}

}  // namespace bcd
