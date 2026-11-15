// diff.cpp -- basic-block alignment inside a pair and change detection.
#include "model.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <set>

namespace bcd {
namespace {

// Semantic token: mnemonic + operand *kinds* + constant values, with call and
// branch targets rewritten to function names. Two instructions with the same
// semantic token do the same thing modulo register allocation and addresses.
std::string semantic_token(const Insn& in, const Program& prog,
                           const std::vector<std::string>* func_names) {
    std::string t = in.mnemonic;
    // Normalise mnemonics that differ only by encoding width.
    if (t == "movabs") t = "mov";
    if (t == "callq") t = "call";
    if (t == "retq") t = "ret";
    if (t == "jz" || t == "je") t = "je";
    if (t == "jnz" || t == "jne") t = "jne";
    for (size_t i = 0; i < in.ops.size(); ++i) {
        const Operand& op = in.ops[i];
        t += i == 0 ? " " : ",";
        switch (op.kind) {
        case Operand::REG:
            t += "r";
            break;
        case Operand::IMM: {
            if (in.is_call && i == 0 && !in.is_indirect) {
                int fi = prog.func_at_insn((uint64_t)op.imm);
                if (fi >= 0 && func_names) {
                    t += "call:" + (*func_names)[fi];
                } else {
                    t += "call:sub_" + hex((uint64_t)op.imm);
                }
            } else if ((in.is_jmp || in.is_jcc) && i == 0) {
                t += "tgt";
            } else {
                t += "i" + std::to_string(op.imm);
            }
            break;
        }
        case Operand::MEM: {
            if (op.rip_rel) {
                std::string lit;
                if (prog.bin->read_cstr(op.rip_target, lit) && lit.size() >= 3) {
                    t += "str:\"" + lit + "\"";
                } else {
                    t += "rip";
                }
            } else if (op.mem_base_name == "rsp" || op.mem_base_name == "rbp" ||
                       op.mem_base_name == "esp" || op.mem_base_name == "ebp") {
                // Stack slots shift between builds; compare shape only.
                t += "stk";
            } else {
                t += "m";
            }
            break;
        }
        default:
            t += "?";
            break;
        }
    }
    return t;
}

}  // namespace

void assign_canonical_names(Program& op, Program& np, const std::vector<FuncPair>& pairs) {
    op.canon.assign(op.funcs.size(), "");
    np.canon.assign(np.funcs.size(), "");
    // Matched functions: one shared label. Prefer a real symbol name; fall back
    // to the old-side address, which is stable within the report.
    int anon = 0;
    for (const auto& p : pairs) {
        if (p.old_idx < 0 || p.new_idx < 0) continue;
        const Func& of = op.funcs[p.old_idx];
        const Func& nf = np.funcs[p.new_idx];
        std::string label;
        for (const Func* f : {&of, &nf}) {
            if (f->named && f->name.rfind("sub_", 0) != 0) {
                label = f->name;
                break;
            }
        }
        if (label.empty()) {
            label = "f" + std::to_string(anon++);
        }
        op.canon[p.old_idx] = label;
        np.canon[p.new_idx] = label;
    }
    // Unmatched functions keep their own name when they have a real one (a new
    // symbol in the patch, e.g. a freshly added validator); only genuinely
    // anonymous ones get an ordinal placeholder.
    for (size_t i = 0; i < op.funcs.size(); ++i) {
        if (op.canon[i].empty()) {
            op.canon[i] = (op.funcs[i].named && op.funcs[i].name.rfind("sub_", 0) != 0)
                              ? "old:" + op.funcs[i].name
                              : "oldonly" + std::to_string(i);
        }
    }
    for (size_t j = 0; j < np.funcs.size(); ++j) {
        if (np.canon[j].empty()) {
            np.canon[j] = (np.funcs[j].named && np.funcs[j].name.rfind("sub_", 0) != 0)
                              ? "new:" + np.funcs[j].name
                              : "newonly" + std::to_string(j);
        }
    }
}

// Assign semantic tokens to every instruction in both programs. Call targets
// are resolved to the *matched function name* so a renamed or relocated callee
// does not read as a change.
void compute_semantics(Program& op, Program& np, const std::vector<FuncPair>& pairs) {
    // Build a canonical name per function: for matched pairs use the old name
    // (stable across versions); unmatched ones keep their own name.
    std::vector<std::string> old_names(op.funcs.size());
    std::vector<std::string> new_names(np.funcs.size());
    for (size_t i = 0; i < op.funcs.size(); ++i) {
        old_names[i] = op.funcs[i].name;
    }
    for (size_t j = 0; j < np.funcs.size(); ++j) {
        new_names[j] = np.funcs[j].name;
    }
    for (const auto& p : pairs) {
        if (p.old_idx >= 0 && p.new_idx >= 0) {
            new_names[p.new_idx] = old_names[p.old_idx];
        }
    }
    for (auto& f : op.funcs) {
        for (auto& in : f.insns) {
            in.sem = semantic_token(in, op, &old_names);
        }
    }
    for (auto& f : np.funcs) {
        for (auto& in : f.insns) {
            in.sem = semantic_token(in, np, &new_names);
        }
    }
}

namespace {

// Align two instruction streams with LCS; returns one op per element.
void align_streams(const std::vector<const Insn*>& a, const std::vector<const Insn*>& b,
                   std::vector<char>& ops, std::vector<int>& ai, std::vector<int>& bi) {
    const size_t n = a.size(), m = b.size();
    ops.clear();
    ai.clear();
    bi.clear();
    if (n == 0) {
        for (size_t j = 0; j < m; ++j) {
            ops.push_back('+');
            ai.push_back(-1);
            bi.push_back((int)j);
        }
        return;
    }
    if (m == 0) {
        for (size_t i = 0; i < n; ++i) {
            ops.push_back('-');
            ai.push_back((int)i);
            bi.push_back(-1);
        }
        return;
    }
    if (n * m > 2000000ull) {
        // Fallback: positional compare.
        size_t k = 0;
        for (; k < std::min(n, m); ++k) {
            ops.push_back(a[k]->sem == b[k]->sem ? '=' : '~');
            ai.push_back((int)k);
            bi.push_back((int)k);
        }
        for (size_t i = k; i < n; ++i) {
            ops.push_back('-');
            ai.push_back((int)i);
            bi.push_back(-1);
        }
        for (size_t j = k; j < m; ++j) {
            ops.push_back('+');
            ai.push_back(-1);
            bi.push_back((int)j);
        }
        return;
    }
    std::vector<std::vector<int>> dp(n + 1, std::vector<int>(m + 1, 0));
    for (size_t i = 1; i <= n; ++i) {
        for (size_t j = 1; j <= m; ++j) {
            if (a[i - 1]->sem == b[j - 1]->sem) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }
    // Backtrack.
    std::vector<char> rev_ops;
    std::vector<int> rev_ai, rev_bi;
    size_t i = n, j = m;
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && a[i - 1]->sem == b[j - 1]->sem) {
            rev_ops.push_back('=');
            rev_ai.push_back((int)(i - 1));
            rev_bi.push_back((int)(j - 1));
            --i;
            --j;
        } else if (j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j])) {
            rev_ops.push_back('+');
            rev_ai.push_back(-1);
            rev_bi.push_back((int)(j - 1));
            --j;
        } else if (i > 0) {
            rev_ops.push_back('-');
            rev_ai.push_back((int)(i - 1));
            rev_bi.push_back(-1);
            --i;
        } else {
            break;
        }
    }
    ops.assign(rev_ops.rbegin(), rev_ops.rend());
    ai.assign(rev_ai.rbegin(), rev_ai.rend());
    bi.assign(rev_bi.rbegin(), rev_bi.rend());
}

std::string block_sem(const Func& f, const Block& b) {
    std::string s;
    for (int i : b.insns) {
        s += f.insns[i].sem;
        s += ';';
    }
    return s;
}

double block_similarity(const Func& of, const Block& a, const Func& nf, const Block& b) {
    std::vector<const Insn*> va, vb;
    for (int i : a.insns) va.push_back(&of.insns[i]);
    for (int i : b.insns) vb.push_back(&nf.insns[i]);
    std::vector<char> ops;
    std::vector<int> ai, bi;
    align_streams(va, vb, ops, ai, bi);
    if (ops.empty()) {
        return 1.0;
    }
    size_t eq = 0;
    for (char c : ops) {
        if (c == '=') ++eq;
    }
    double dice = 2.0 * (double)eq / (double)(va.size() + vb.size());
    // Same terminator shape is a strong signal that two blocks belong together.
    std::string ta = va.back()->is_jcc ? "jcc"
                     : va.back()->is_jmp ? (va.back()->is_indirect ? "ijmp" : "jmp")
                     : va.back()->is_ret ? "ret"
                                         : "seq";
    std::string tb = vb.back()->is_jcc ? "jcc"
                     : vb.back()->is_jmp ? (vb.back()->is_indirect ? "ijmp" : "jmp")
                     : vb.back()->is_ret ? "ret"
                                         : "seq";
    double term = (ta == tb) ? 1.0 : 0.0;
    double size = 1.0 - std::fabs((double)va.size() - (double)vb.size()) /
                            (double)std::max(va.size(), vb.size());
    return 0.55 * dice + 0.25 * term + 0.20 * size;
}

}  // namespace

void diff_all(Program& op, Program& np, const std::vector<FuncPair>& pairs,
              std::vector<FuncDiff>& diffs) {
    diffs.assign(pairs.size(), FuncDiff{});
    for (size_t pi = 0; pi < pairs.size(); ++pi) {
        const FuncPair& p = pairs[pi];
        FuncDiff& fd = diffs[pi];
        if (p.old_idx < 0 || p.new_idx < 0) {
            continue;
        }
        const Func& of = op.funcs[p.old_idx];
        const Func& nf = np.funcs[p.new_idx];

        // Block matching: greedy over similarity, then structural anchors.
        std::vector<std::pair<double, std::pair<int, int>>> cands;
        for (const auto& ob : of.blocks) {
            if (!ob.reachable) continue;
            std::string so = block_sem(of, ob);
            for (const auto& nb : nf.blocks) {
                if (!nb.reachable) continue;
                std::string sn = block_sem(nf, nb);
                if (so == sn) {
                    cands.push_back({2.0, {ob.id, nb.id}});
                }
            }
        }
        std::sort(cands.begin(), cands.end(),
                  [](const auto& x, const auto& y) { return x.first > y.first; });
        std::vector<int> map_o(of.blocks.size(), -1), map_n(nf.blocks.size(), -1);
        for (auto& c : cands) {
            int a = c.second.first, b = c.second.second;
            if (map_o[a] >= 0 || map_n[b] >= 0) continue;
            map_o[a] = b;
            map_n[b] = a;
        }
        // Remaining blocks by similarity.
        std::vector<std::pair<double, std::pair<int, int>>> rest;
        for (const auto& ob : of.blocks) {
            if (!ob.reachable || map_o[ob.id] >= 0) continue;
            for (const auto& nb : nf.blocks) {
                if (!nb.reachable || map_n[nb.id] >= 0) continue;
                double s = block_similarity(of, ob, nf, nb);
                if (s >= 0.35) {
                    rest.push_back({s, {ob.id, nb.id}});
                }
            }
        }
        std::sort(rest.begin(), rest.end(),
                  [](const auto& x, const auto& y) { return x.first > y.first; });
        std::vector<double> block_sim(of.blocks.size(), 0.0);
        for (auto& c : rest) {
            int a = c.second.first, b = c.second.second;
            if (map_o[a] >= 0 || map_n[b] >= 0) continue;
            map_o[a] = b;
            map_n[b] = a;
            block_sim[a] = c.first;
        }

        // Emit BlockMatch entries in old-block order, then new-only blocks.
        for (const auto& ob : of.blocks) {
            if (!ob.reachable) continue;
            BlockMatch bm;
            bm.old_b = ob.id;
            bm.new_b = map_o[ob.id];
            std::vector<const Insn*> va, vb;
            for (int i : ob.insns) {
                va.push_back(&of.insns[i]);
            }
            if (bm.new_b >= 0) {
                const Block& nb = nf.blocks[bm.new_b];
                for (int i : nb.insns) {
                    vb.push_back(&nf.insns[i]);
                }
                align_streams(va, vb, bm.ops, bm.old_i, bm.new_i);
                // align_streams yields indices into the block-local pointer
                // vectors; remap them to indices into Func::insns so report and
                // JSON code can index directly.
                for (auto& idx : bm.old_i) {
                    idx = idx >= 0 ? ob.insns[idx] : -1;
                }
                for (auto& idx : bm.new_i) {
                    idx = idx >= 0 ? nb.insns[idx] : -1;
                }
                for (char c : bm.ops) {
                    if (c == '+') ++bm.n_added;
                    if (c == '-') ++bm.n_removed;
                }
                bm.sim = block_similarity(of, ob, nf, nb);
                bm.status = (bm.n_added == 0 && bm.n_removed == 0) ? "same" : "modified";
                if (bm.status == "same") {
                    ++fd.blocks_same;
                } else {
                    ++fd.blocks_modified;
                }
                fd.insns_added += bm.n_added;
                fd.insns_removed += bm.n_removed;
            } else {
                bm.status = "removed";
                bm.old_i = ob.insns;
                bm.new_i.assign(ob.insns.size(), -1);
                bm.ops.assign(ob.insns.size(), '-');
                bm.n_removed = (int)va.size();
                ++fd.blocks_removed;
                fd.insns_removed += (int)va.size();
            }
            fd.blocks.push_back(std::move(bm));
        }
        for (const auto& nb : nf.blocks) {
            if (!nb.reachable || map_n[nb.id] >= 0) continue;
            BlockMatch bm;
            bm.old_b = -1;
            bm.new_b = nb.id;
            bm.status = "added";
            bm.new_i = nb.insns;
            bm.old_i.assign(nb.insns.size(), -1);
            bm.ops.assign(nb.insns.size(), '+');
            bm.n_added = (int)bm.new_i.size();
            ++fd.blocks_added;
            fd.insns_added += bm.n_added;
            fd.blocks.push_back(std::move(bm));
        }
        fd.identical = (fd.insns_added == 0 && fd.insns_removed == 0 &&
                        fd.blocks_added == 0 && fd.blocks_removed == 0 &&
                        fd.blocks_modified == 0 && of.insns.size() == nf.insns.size());
        // Cross-check: an all-"same" block diff but different body hash means
        // the change is in an unreachable block or in a branch target layout.
        if (fd.identical) {
            bool same = of.insns.size() == nf.insns.size();
            for (size_t k = 0; same && k < of.insns.size(); ++k) {
                if (of.insns[k].sem != nf.insns[k].sem) same = false;
            }
            fd.identical = same;
        }
    }
}

// ---------------------------------------------------------------------------
// findings
//
// Detection works on the *aligned* block diff rather than on raw branch
// counts: only instructions that appear as '+' in a matched block, or blocks
// that exist only in the new binary, can be a "new check". That keeps the
// inlined memcpy loop in a rebuilt function from being reported as a dozen
// invented bounds checks.
// ---------------------------------------------------------------------------

namespace {

// A guard is a compare/test feeding a conditional branch, where the branch
// either (a) leaves the fall-through path towards an error/return path, or
// (b) is an unsigned upper-bound test (the canonical length check shape).
struct Guard {
    uint64_t cmp_addr = 0;
    uint64_t branch_addr = 0;
    uint64_t target = 0;
    std::string mnem;         // cmp | test
    std::string cond;         // jcc mnemonic as printed
    bool has_imm = false;
    int64_t imm = 0;
    bool imm_unsigned = false;
    bool imm_mask = false;   // test with an immediate: a bitmask probe
    bool mem_operand = false;
    bool stack_mem = false;
    int reg_operand = 0;
    bool unsigned_upper = false;
    bool signed_cmp = false;
    bool zero_test = false;
};

bool is_guard_mnem(const std::string& m) {
    return m == "cmp" || m == "test" || m == "cmpl" || m == "cmpq" || m == "cmpw" ||
           m == "cmpb" || m == "testl" || m == "testq" || m == "sub" || m == "subq" ||
           m == "subl";
}

bool is_unsigned_upper_cond(const std::string& m) {
    return m == "ja" || m == "jae" || m == "jb" || m == "jbe" || m == "jna" ||
           m == "jnae" || m == "jnb" || m == "jnbe";
}

bool is_signed_cond(const std::string& m) {
    return m == "jl" || m == "jle" || m == "jg" || m == "jge" || m == "jng" ||
           m == "jnge" || m == "jnl" || m == "jnle";
}

bool is_zero_test_cond(const std::string& m) {
    return m == "je" || m == "jne" || m == "jz" || m == "jnz";
}

// Scan a straight-line instruction list (a block, or a whole added block) for
// compare+branch pairs. `base` is the block the list belongs to.
std::vector<Guard> scan_guards(const std::vector<const Insn*>& list) {
    std::vector<Guard> out;
    const Insn* cmp = nullptr;
    for (size_t k = 0; k < list.size(); ++k) {
        const Insn& in = *list[k];
        if (is_guard_mnem(in.mnemonic) && in.ops.size() >= 2) {
            cmp = &in;
            continue;
        }
        // Only an immediately following conditional branch tests this compare.
        // Anything in between (a setcc, orb, extra mov) either destroys the
        // flags or belongs to a compiler-emitted multi-flag idiom that is not a
        // guard; gluing them together invents checks that never existed.
        if (in.is_jcc && cmp && k > 0 && list[k - 1] == cmp &&
            cmp->addr + cmp->len == in.addr) {
            Guard g;
            g.cmp_addr = cmp->addr;
            g.branch_addr = in.addr;
            g.target = in.branch_target;
            g.mnem = cmp->mnemonic;
            g.cond = in.mnemonic;
            g.unsigned_upper = is_unsigned_upper_cond(in.mnemonic);
            g.signed_cmp = is_signed_cond(in.mnemonic);
            g.zero_test = is_zero_test_cond(in.mnemonic);
            for (const auto& op : cmp->ops) {
                if (op.kind == Operand::IMM) {
                    g.has_imm = true;
                    g.imm = op.imm;
                    // A sign-extended negative constant is a sentinel/rounding
                    // trick (cmp $0xfffffffffffffffc = cmp $-4), never a size
                    // bound. Require a small non-negative value.
                    g.imm_unsigned = op.imm >= 0 && op.imm <= 0x7fffffffLL;
                    g.imm_mask = (cmp->mnemonic == "test");
                } else if (op.kind == Operand::MEM) {
                    g.mem_operand = true;
                    if (op.mem_base_name == "rsp" || op.mem_base_name == "rbp" ||
                        op.mem_base_name == "esp" || op.mem_base_name == "ebp") {
                        g.stack_mem = true;
                    }
                } else if (op.kind == Operand::REG) {
                    g.reg_operand = op.reg;
                }
            }
            out.push_back(g);
            cmp = nullptr;
            continue;
        }
        cmp = nullptr;
    }
    return out;
}

bool guard_is_null_test(const Guard& g) {
    // test reg,reg is the null/zero idiom. test reg,imm is a bitmask probe and
    // says nothing about validity.
    return g.mnem == "test" && !g.imm_mask;
}

bool guard_is_candidate(const Guard& g) {
    // Only shapes that read like validation: an immediate bound, a stack-slot
    // bound (array/struct size), a register-vs-register size comparison, or a
    // zero test on a pointer/length.
    if (guard_is_null_test(g)) {
        return true;
    }
    if (g.has_imm && g.imm_unsigned && !g.imm_mask) {
        return true;
    }
    if (g.mem_operand) {
        return true;
    }
    if (g.unsigned_upper && g.reg_operand != 0) {
        return true;  // size-vs-capacity compare: cmp len, cap; ja fail
    }
    return false;
}

std::string guard_evidence(const Guard& g, const std::string& func) {
    std::string s = g.mnem;
    if (g.has_imm) {
        s += ", 0x" + hex((uint64_t)g.imm);
    } else if (g.mem_operand) {
        s += g.stack_mem ? ", [frame]" : ", [mem]";
    } else {
        s += " reg, reg";
    }
    return s + "  →  " + g.cond + " 0x" + hex(g.target);
}

// Does any instruction between `from` (exclusive) and the block end look like
// an abort/report path? Used to raise confidence for error-path guards.
// Does the block that starts at `addr` reach a memory write before it returns?
// Used to decide whether a guard actually protects a write from an over-large
// length: the fall-through path writes, the taken path does not.
bool path_writes_memory(const Func& f, uint64_t start_addr, int max_blocks) {
    const Block* b = f.block_at(start_addr);
    if (!b) return false;
    std::set<int> seen;
    std::vector<const Block*> work{b};
    int n = 0;
    while (!work.empty() && n++ < max_blocks) {
        const Block* cur = work.back();
        work.pop_back();
        if (!cur || !seen.insert(cur->id).second) continue;
        for (int ii : cur->insns) {
            if (f.insns[ii].writes_memory) return true;
        }
        for (int sc : cur->succ) {
            work.push_back(&f.blocks[sc]);
        }
    }
    return false;
}

// Does the path that the guard *diverts to* look like a failure exit?
//
// The classic validation shape is
//     cmp   len, bound
//     jbe   ok          ; or: ja fail
//   fail: [report/return]
//   ok:   [do the work]
// so the diagnostic is: one side of the branch writes memory (the work) and the
// other side does not (the exit), or the diverting side returns/calls without
// writing. A guard in the middle of compiler-generated loop machinery has work
// on both sides, which is what makes it a false positive.
enum class GuardRole { Unknown, ErrorExit, WorkEntry, Loop };

// A "short exit" is a path that reaches a return in a handful of instructions
// without doing iterative or memory-mutating work. That is the shape of a
// guard-clause bail-out (`if (bad) return err;`).
bool is_short_exit(const Func& f, const Block* start, int budget) {
    if (!start) return false;
    int steps = 0;
    const Block* cur = start;
    std::set<int> seen;
    while (cur && steps <= budget) {
        if (!seen.insert(cur->id).second) return false;  // loop
        for (int ii : cur->insns) {
            const Insn& in = f.insns[ii];
            if (in.writes_memory) return false;
            if (in.is_call && !in.is_indirect) {
                // A reporting helper call then return still counts as an exit.
            }
            ++steps;
            if (in.is_ret) return true;
            if (steps > budget) return false;
        }
        // Follow the single forward successor; more than one means a decision
        // point, which is not a straight-line bail-out.
        const Block* next = nullptr;
        int forward = 0;
        for (int sc : cur->succ) {
            if (sc > cur->id) {
                next = &f.blocks[sc];
                ++forward;
            }
        }
        if (forward != 1) return false;
        cur = next;
    }
    return false;
}

// Number of reachable basic blocks, capped: a proxy for "this path does work".
int path_weight(const Func& f, const Block* start, int cap) {
    if (!start) return 0;
    std::set<int> seen;
    std::vector<const Block*> work{start};
    while (!work.empty() && (int)seen.size() < cap) {
        const Block* cur = work.back();
        work.pop_back();
        if (!cur || !seen.insert(cur->id).second) continue;
        for (int sc : cur->succ) work.push_back(&f.blocks[sc]);
    }
    return (int)seen.size();
}

GuardRole classify_guard(const Func& f, const Guard& g) {
    const Block* b = f.block_at(g.branch_addr);
    if (!b) return GuardRole::Unknown;

    const Block* fall = nullptr;
    const Block* taken = nullptr;
    for (size_t e = 0; e < b->succ.size(); ++e) {
        int kind = e < b->succ_kind.size() ? b->succ_kind[e] : 0;
        if (kind == 0) {
            fall = &f.blocks[b->succ[e]];
        } else {
            taken = &f.blocks[b->succ[e]];
        }
    }
    if (!fall && b->id + 1 < (int)f.blocks.size()) fall = &f.blocks[b->id + 1];
    if (!taken) taken = f.block_at(g.target);
    if (!fall || !taken) return GuardRole::Unknown;

    // A branch whose target is address-wise behind it is a loop back edge: that
    // is compiler loop machinery, not validation, no matter what it compares.
    if (taken->start < b->start) return GuardRole::Loop;
    if (fall->id == taken->id) return GuardRole::Unknown;

    bool taken_short = is_short_exit(f, taken, 10);
    bool fall_short = is_short_exit(f, fall, 10);
    int taken_w = path_weight(f, taken, 64);
    int fall_w = path_weight(f, fall, 64);

    // Exactly one side is a terse bail-out and the other is the substantial
    // path: a guard clause.
    if (taken_short && !fall_short && fall_w >= std::max(2, taken_w + 1)) {
        return GuardRole::ErrorExit;
    }
    if (fall_short && !taken_short && taken_w >= std::max(2, fall_w + 1)) {
        return GuardRole::ErrorExit;
    }
    // Both sides do comparable work: an if/else inside the real logic.
    if (taken_w > 1 && fall_w > 1) return GuardRole::WorkEntry;
    return GuardRole::Unknown;
}

bool reaches_error_call(const Func& f, uint64_t from_addr, uint64_t limit_addr,
                        std::string* callee) {
    (void)limit_addr;
    const Block* b = f.block_at(from_addr);
    if (!b) return false;
    for (int sc : b->succ) {
        const Block& nb = f.blocks[sc];
        for (int ii : nb.insns) {
            const Insn& in = f.insns[ii];
            if (in.is_call && !in.is_indirect) {
                if (callee && !in.targets.empty()) *callee = "0x" + hex(in.targets[0]);
                return true;
            }
            if (in.writes_memory) break;
            if (in.is_ret) return true;
        }
    }
    return false;
}

}  // namespace

void detect_findings(Analysis& a) {
    const Program& op = a.oldp;
    const Program& np = a.newp;
    auto& findings = a.findings;

    // Names as they appear in each binary, for evidence text.
    std::vector<std::string> old_names, new_names;
    for (auto& f : op.funcs) old_names.push_back(f.name);
    for (auto& f : np.funcs) new_names.push_back(f.name);

    for (size_t pi = 0; pi < a.pairs.size(); ++pi) {
        const FuncPair& p = a.pairs[pi];
        const FuncDiff& fd = a.diffs[pi];

        // ---- added / removed functions ------------------------------------
        if (p.old_idx < 0 && p.new_idx >= 0) {
            const Func& nf = np.funcs[p.new_idx];
            Finding f;
            f.kind = "new-function";
            f.category = "info";
            f.pair_index = (int)pi;
            f.new_func = p.new_idx;
            f.new_addr = nf.start;
            f.confidence = 1.0;
            f.title = "New function " + nf.name;
            size_t callers = 0;
            std::vector<std::string> names;
            for (const auto& f2 : np.funcs) {
                for (uint64_t t : f2.call_targets) {
                    if (t == nf.start) {
                        ++callers;
                        names.push_back(f2.name);
                    }
                }
            }
            f.detail = "Present only in the new binary: " + std::to_string(nf.insns.size()) +
                       " instructions, " + std::to_string(nf.blocks.size()) +
                       " basic blocks" +
                       (callers ? ", called from " + join(names, ", ") : ", no callers found") +
                       ".";
            // A small leaf that only compares and selects is a validator.
            bool saw_cmp = false, has_call = false;
            for (const auto& in : nf.insns) {
                if (in.is_call) has_call = true;
                std::string m = in.mnemonic;
                if (m == "cmp" || m == "test" || m.rfind("cmov", 0) == 0 ||
                    m.rfind("set", 0) == 0 || in.is_jcc) {
                    saw_cmp = true;
                }
            }
            bool is_validator = false;
            if (!has_call && saw_cmp) {
                f.evidence.push_back("leaf helper made of comparisons and select branches");
                f.confidence = 0.95;
                is_validator = true;
            }
            if (is_validator && callers) {
                f.category = "security";
                f.kind = "validator-introduced";
                f.title = "New validation helper " + nf.name + " introduced";
                f.detail = "The patch adds " + nf.name + ", a leaf function whose body is "
                           "only comparisons and select branches, and wires it into " +
                           join(names, ", ") + ". That is the usual shape of a range or "
                           "bounds validator extracted so it can be reused and tested.";
                f.confidence = 0.85;
            }
            if (callers) {
                f.evidence.push_back("referenced by " + std::to_string(callers) + " function(s)");
            }
            findings.push_back(std::move(f));
            continue;
        }
        if (p.new_idx < 0 && p.old_idx >= 0) {
            const Func& of = op.funcs[p.old_idx];
            Finding f;
            f.kind = "removed-function";
            f.category = "info";
            f.pair_index = (int)pi;
            f.old_func = p.old_idx;
            f.old_addr = of.start;
            f.confidence = 1.0;
            f.title = "Function removed: " + of.name;
            f.detail = "Present only in the old binary: " + std::to_string(of.insns.size()) +
                       " instructions. Typical of dead-code removal or an API change.";
            // Note whether anything still referenced it.
            size_t refs = 0;
            for (const auto& f2 : op.funcs) {
                for (uint64_t t : f2.call_targets) {
                    if (t == of.start) ++refs;
                }
            }
            if (refs) {
                f.evidence.push_back("called by " + std::to_string(refs) +
                                     " function(s) in the old binary");
            }
            findings.push_back(std::move(f));
            continue;
        }
        if (p.old_idx < 0 || p.new_idx < 0) {
            continue;
        }
        if (fd.identical) {
            continue;
        }
        const Func& of = op.funcs[p.old_idx];
        const Func& nf = np.funcs[p.new_idx];

        // Collect instructions that the diff marks as new in matched blocks,
        // plus every instruction of a wholly new block. These are the only
        // places a new guard may live.
        std::vector<const Insn*> added_stream;
        std::vector<const Insn*> removed_stream;
        for (const auto& bm : fd.blocks) {
            if (bm.status == "same") continue;
            if (bm.new_b >= 0) {
                const Block& nb = nf.blocks[bm.new_b];
                if (bm.status == "added") {
                    for (int i : nb.insns) added_stream.push_back(&nf.insns[i]);
                    continue;
                }
                for (size_t k = 0; k < bm.ops.size(); ++k) {
                    if (bm.ops[k] != '+') continue;
                    if (k < bm.new_i.size() && bm.new_i[k] >= 0 &&
                        bm.new_i[k] < (int)nf.insns.size()) {
                        added_stream.push_back(&nf.insns[bm.new_i[k]]);
                    }
                }
            }
            if (bm.old_b >= 0) {
                const Block& ob = of.blocks[bm.old_b];
                if (bm.status == "removed") {
                    for (int i : ob.insns) removed_stream.push_back(&of.insns[i]);
                    continue;
                }
                for (size_t k = 0; k < bm.ops.size(); ++k) {
                    if (bm.ops[k] != '-') continue;
                    if (k < bm.old_i.size() && bm.old_i[k] >= 0 &&
                        bm.old_i[k] < (int)of.insns.size()) {
                        removed_stream.push_back(&of.insns[bm.old_i[k]]);
                    }
                }
            }
        }

        // A guard in the added stream is a real addition. A pair of guards that
        // is merely re-encoded (new block layout, same compare) is not: the
        // block matcher already reports that as a modified block, and the
        // instruction-level LCS removes the unchanged ones from the stream.
        std::stable_sort(added_stream.begin(), added_stream.end(),
                         [](const Insn* x, const Insn* y) { return x->addr < y->addr; });
        std::stable_sort(removed_stream.begin(), removed_stream.end(),
                         [](const Insn* x, const Insn* y) { return x->addr < y->addr; });
        std::vector<Guard> new_guards = scan_guards(added_stream);

        // Prefer guards that branch to an error path (call/return) or are
        // unsigned bounds; everything else is reported at lower confidence so
        // it cannot bury the real finding.
        // Guards already present anywhere in the old function are not new, no
        // matter how the block matcher realigned them.
        auto guard_key = [](const Guard& g) {
            std::string k = g.mnem + "|" + g.cond;
            if (g.has_imm) {
                k += "|0x" + hex((uint64_t)g.imm);
            } else if (g.mem_operand) {
                k += g.stack_mem ? "|stack" : "|mem";
            } else {
                k += "|reg";
            }
            return k;
        };
        std::set<std::string> old_guard_keys;
        {
            std::vector<const Insn*> all_old;
            for (const auto& in : of.insns) all_old.push_back(&in);
            for (const auto& g : scan_guards(all_old)) {
                if (guard_is_candidate(g)) old_guard_keys.insert(guard_key(g));
            }
        }
        // A guard is only interesting when it protects *work*: the fall-through
        // path (what happens when the check passes) must write memory or reach
        // an error path. Guards on loop bookkeeping in a rebuilt memcpy satisfy
        // neither, and are what produces phantom "bounds checks" when the whole
        // function was recompiled at a different optimisation level.
        auto guard_context = [&](const Guard& g) {
            const Block* b = nf.block_at(g.branch_addr);
            if (!b) return false;
            // The fall-through successor of the guard's block.
            for (size_t e = 0; e < b->succ.size(); ++e) {
                if (e < b->succ_kind.size() && b->succ_kind[e] == 0) {
                    const Block& fb = nf.blocks[b->succ[e]];
                    if (path_writes_memory(nf, fb.start, 24)) return true;
                }
            }
            // Or the instruction stream right after the guard writes.
            for (int ii : b->insns) {
                if (nf.insns[ii].addr <= g.branch_addr) continue;
                if (nf.insns[ii].writes_memory) return true;
                if (nf.insns[ii].is_ret) break;
            }
            return false;
        };

        // A function that changed too much cannot support instruction-level
        // claims: when the block diff rewrote a large share of the body (typical
        // of a rebuild at a different -O level), guards are reported as a
        // low-confidence rewrite note instead of individual security findings.
        double rewrite_ratio = 0.0;
        {
            size_t total = of.insns.size() + nf.insns.size();
            size_t changed = (size_t)(fd.insns_added + fd.insns_removed);
            if (total) rewrite_ratio = (double)changed / (double)total;
        }
        bool heavily_rewritten = rewrite_ratio > 0.45;

        std::vector<Guard> strong, weak;
        for (const auto& g : new_guards) {
            if (!guard_is_candidate(g)) continue;
            if (old_guard_keys.count(guard_key(g))) continue;
            GuardRole role = classify_guard(nf, g);
            bool protects_work = guard_context(g);
            bool bound_shape = g.unsigned_upper && g.has_imm && g.imm_unsigned &&
                               !g.imm_mask;
            bool capacity_shape = g.unsigned_upper && g.reg_operand && !g.has_imm;
            bool null_shape = guard_is_null_test(g) && g.zero_test;
            // A guard is real input validation when it separates a work path
            // from an exit path, or when a real bound/immediate protects a write.
            bool validation_role = role == GuardRole::ErrorExit ||
                                   role == GuardRole::WorkEntry;
            if (role == GuardRole::Loop) {
                weak.push_back(g);
            } else if (bound_shape && (protects_work || validation_role)) {
                strong.push_back(g);
            } else if ((capacity_shape || null_shape) && validation_role) {
                strong.push_back(g);
            } else if (bound_shape && g.imm >= 4) {
                // A plausible constant bound whose role is unclear: keep it, at
                // reduced confidence, rather than dropping a possible fix.
                weak.push_back(g);
            } else {
                weak.push_back(g);
            }
        }
        // Weak guards are reported at most once per function and always as
        // informational, so they cannot outrank or dilute the real checks.
        std::vector<Guard> reported = strong;
        bool weak_only = false;
        if (reported.empty() && !weak.empty()) {
            reported.push_back(weak.front());
            weak_only = true;
        }

        for (const auto& g : reported) {
            Finding f;
            f.pair_index = (int)pi;
            f.old_func = p.old_idx;
            f.new_func = p.new_idx;
            f.new_addr = g.cmp_addr ? g.cmp_addr : g.branch_addr;
            f.old_addr = of.start;
            bool has_err = reaches_error_call(nf, g.branch_addr, g.branch_addr, nullptr);
            if (g.unsigned_upper && g.has_imm) {
                f.kind = "bounds-check-added";
                f.category = "security";
                f.title = "Length/bounds check added in " + nf.name;
                f.detail = "New unsigned upper-bound comparison against 0x" +
                           hex((uint64_t)g.imm) + " (" + g.cond +
                           "). Unsigned 'jbe/ja/jae' against a constant is the canonical "
                           "shape of a length or index validation; the old version had "
                           "no such test on this path.";
                f.confidence = 0.92;
            } else if (guard_is_null_test(g) && g.zero_test) {
                f.kind = "null-check-added";
                f.category = "security";
                f.title = "Pointer/length zero check added in " + nf.name;
                f.detail = "New test-and-branch (" + g.cond +
                           ") on a value that the following path dereferences or "
                           "subtracts. The old version proceeded without it.";
                f.confidence = 0.8;
            } else if (g.signed_cmp) {
                f.kind = "range-check-added";
                f.category = "security";
                f.title = "Signed range check added in " + nf.name;
                f.detail = "New signed comparison (" + g.cond + ") guarding the following path.";
                f.confidence = 0.75;
            } else if (g.unsigned_upper && !g.has_imm) {
                f.kind = "capacity-check-added";
                f.category = "security";
                f.title = "Length-vs-capacity check added in " + nf.name;
                f.detail = "New unsigned comparison between two register values (" +
                           g.cond +
                           "), i.e. a length compared against a capacity/bound held in "
                           "another register, with failure branching out. The old version "
                           "performed the copy without this test.";
                f.confidence = 0.9;
            } else if (g.has_imm) {
                f.kind = "bounds-check-added";
                f.category = "security";
                f.title = "New bounded comparison in " + nf.name;
                f.detail = "New comparison against constant 0x" + hex((uint64_t)g.imm) +
                           " with branch " + g.cond + ".";
                f.confidence = 0.7;
            } else {
                f.kind = "error-path-added";
                f.category = "security";
                f.title = "New guarded error path in " + nf.name;
                f.detail = "New comparison/branch that diverts to an error path.";
                f.confidence = 0.65;
            }
            if (weak_only) {
                f.kind = "guard-added";
                f.category = "info";
                f.title = "New conditional guard in " + nf.name;
                f.detail = heavily_rewritten
                              ? "This function was substantially recompiled (over 45% of "
                                "its instructions differ), so individual comparison "
                                "differences are not reliable evidence of a logic change. "
                                "Reported as informational; inspect the block diff."
                              : "A new comparison/branch appeared but does not guard a "
                                "memory write or an error path, so it is not treated as "
                                "input validation. Reported as informational.";
                f.confidence = heavily_rewritten ? 0.3 : 0.45;
            }
            f.evidence.push_back(guard_evidence(g, nf.name));
            if (has_err) {
                f.evidence.push_back("branch target leads to a call or return (error path)");
                f.confidence = std::min(1.0, f.confidence + 0.05);
            }
            // Show the guard's immediate context.
            for (const auto& in : nf.insns) {
                if (in.addr + 40 < g.cmp_addr || in.addr > g.branch_addr + 8) continue;
                std::string t = in.mnemonic;
                if (!in.op_str.empty()) t += " " + in.op_str;
                f.new_insns.push_back("0x" + hex(in.addr) + "  " + t);
            }
            findings.push_back(std::move(f));
        }

        // Guards that existed before and are gone now: report once per function
        // only when the whole guard (cmp+branch) disappeared, not when the pair
        // moved between blocks.
        if (!heavily_rewritten) {
            std::vector<Guard> old_guards = scan_guards(removed_stream);
            std::set<std::string> new_keys;
            for (const auto& in : nf.insns) {
                // Reconstruct guard keys from the new function's full stream so a
                // guard that moved is not reported as removed.
                (void)in;
            }
            std::vector<const Insn*> all_new;
            for (const auto& in : nf.insns) all_new.push_back(&in);
            for (const auto& g : scan_guards(all_new)) {
                new_keys.insert(g.mnem + "/" +
                                (g.has_imm ? "0x" + hex((uint64_t)g.imm) : std::string("r")));
            }
            int emitted = 0;
            for (const auto& g : old_guards) {
                if (!guard_is_candidate(g)) continue;
                std::string key =
                    g.mnem + "/" + (g.has_imm ? "0x" + hex((uint64_t)g.imm) : std::string("r"));
                if (new_keys.count(key)) continue;
                // A guard that only branches back into loop machinery is
                // compiler-emitted bookkeeping, and rebuilds change its constant
                // and placement freely. Require an actual error-exit role.
                if (classify_guard(of, g) != GuardRole::ErrorExit) {
                    continue;
                }
                // If the new function still has a guard with the same mnemonic
                // and condition, the test survived with a different constant;
                // that is a recompiled bound, not a removed check.
                bool same_shape = false;
                for (const auto& in : nf.insns) {
                    (void)in;
                }
                {
                    std::vector<const Insn*> all_new2;
                    for (const auto& in : nf.insns) all_new2.push_back(&in);
                    for (const auto& ng : scan_guards(all_new2)) {
                        if (ng.mnem == g.mnem && ng.cond == g.cond) {
                            same_shape = true;
                            break;
                        }
                    }
                }
                if (same_shape) continue;
                if (emitted >= 2) break;
                ++emitted;
                Finding f;
                f.kind = "check-removed";
                f.category = "risk";
                f.pair_index = (int)pi;
                f.old_func = p.old_idx;
                f.new_func = p.new_idx;
                f.old_addr = g.cmp_addr;
                f.new_addr = nf.start;
                f.title = "Validation branch gone in " + nf.name;
                f.detail = "The old function tested with '" + g.mnem + "' and branched '" +
                           g.cond + "' at 0x" + hex(g.cmp_addr) +
                           "; no equivalent guard exists anywhere in the new function. "
                           "Confirm this is not a lost bounds/validity check.";
                f.confidence = 0.6;
                f.evidence.push_back(guard_evidence(g, of.name));
                findings.push_back(std::move(f));
            }
        }

        // ---- call graph changes -------------------------------------------
        // Compare callees by canonical identity: for a stripped binary a raw
        // target address is a different value in every build, so address
        // comparison would report every call as new and another as dropped.
        {
            auto canonical_of = [](const Program& prog, uint64_t target) {
                int fi = prog.func_at_insn(target);
                if (fi < 0) return std::string("external");
                if (!prog.canon.empty() && !prog.canon[fi].empty()) {
                    return prog.canon[fi];
                }
                return prog.funcs[fi].named ? prog.funcs[fi].name : std::string("anon");
            };
            auto canonical_key = [&](const Program& prog, const Insn& in) {
                if (in.is_indirect) return std::string("indirect");
                if (in.targets.empty()) return std::string("unknown");
                return canonical_of(prog, in.targets[0]);
            };
            // Callees that are plain external calls (PLT stubs, syscall wrappers
            // outside the image) are not interesting on their own.
            std::set<std::string> old_calls, new_calls;
            for (const auto& in : of.insns) {
                if (in.is_call) old_calls.insert(canonical_key(op, in));
            }
            for (const auto& in : nf.insns) {
                if (in.is_call) new_calls.insert(canonical_key(np, in));
            }
            auto display = [&](const std::string& key) -> std::string {
                if (key.rfind("oldonly", 0) == 0 || key.rfind("newonly", 0) == 0) {
                    // Stripped binaries: the callee has no name, but its code
                    // region is still useful to point at. The address is in the
                    // finding's evidence rather than here.
                    return std::string("a new helper (no symbol)");
                }
                if (key.rfind("old:", 0) == 0 || key.rfind("new:", 0) == 0) {
                    return key.substr(4);
                }
                if (key == "external") return "an external symbol";
                if (key == "anon") return "an unnamed local helper";
                if (key == "indirect") return "an indirect target";
                return key;
            };
            for (const auto& c : new_calls) {
                if (old_calls.count(c) || c == "indirect" || c == "external" ||
                    c == "unknown") {
                    continue;
                }
                Finding f;
                f.kind = "call-added";
                f.category = "info";
                f.pair_index = (int)pi;
                f.old_func = p.old_idx;
                f.new_func = p.new_idx;
                f.title = "New call to " + display(c) + " in " + nf.name;
                f.detail = "The patched function makes a call the old version did not.";
                f.confidence = 0.85;
                findings.push_back(std::move(f));
            }
            for (const auto& c : old_calls) {
                if (new_calls.count(c) || c == "indirect" || c == "external" ||
                    c == "unknown") {
                    continue;
                }
                Finding f;
                f.kind = "call-removed";
                f.category = "info";
                f.pair_index = (int)pi;
                f.old_func = p.old_idx;
                f.new_func = p.new_idx;
                f.title = "Call dropped in " + nf.name;
                f.detail = "The old version called " + display(c) +
                           "; the new one no longer does.";
                f.confidence = 0.75;
                findings.push_back(std::move(f));
            }
        }
    }

    // Stable order: security first, then risk, then info; by pair index inside
    // each category.
    auto rank = [](const std::string& c) {
        return c == "security" ? 0 : c == "risk" ? 1 : 2;
    };
    std::stable_sort(findings.begin(), findings.end(),
                     [&](const Finding& x, const Finding& y) {
                         if (rank(x.category) != rank(y.category)) {
                             return rank(x.category) < rank(y.category);
                         }
                         if (x.confidence != y.confidence) {
                             return x.confidence > y.confidence;
                         }
                         return x.pair_index < y.pair_index;
                     });
}

}  // namespace bcd
