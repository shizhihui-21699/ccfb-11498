// features.cpp -- per-function feature extraction, similarity, pairing.
#include "model.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <queue>
#include <set>
#include <tuple>

namespace bcd {

namespace {

double jaccard_int(const std::set<int64_t>& a, const std::set<int64_t>& b) {
    if (a.empty() && b.empty()) {
        return 1.0;
    }
    size_t inter = 0;
    auto ia = a.begin();
    auto ib = b.begin();
    while (ia != a.end() && ib != b.end()) {
        if (*ia == *ib) {
            ++inter;
            ++ia;
            ++ib;
        } else if (*ia < *ib) {
            ++ia;
        } else {
            ++ib;
        }
    }
    size_t uni = a.size() + b.size() - inter;
    return uni ? (double)inter / (double)uni : 1.0;
}

double jaccard_u64(const std::set<uint64_t>& a, const std::set<uint64_t>& b) {
    if (a.empty() && b.empty()) {
        return 1.0;
    }
    size_t inter = 0;
    auto ia = a.begin();
    auto ib = b.begin();
    while (ia != a.end() && ib != b.end()) {
        if (*ia == *ib) {
            ++inter;
            ++ia;
            ++ib;
        } else if (*ia < *ib) {
            ++ia;
        } else {
            ++ib;
        }
    }
    size_t uni = a.size() + b.size() - inter;
    return uni ? (double)inter / (double)uni : 1.0;
}

// Multiset Dice over *sorted* token vectors, via a linear merge. This runs in
// the inner loop of candidate generation, so it must not allocate.
double multiset_dice(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    if (a.empty() && b.empty()) {
        return 1.0;
    }
    size_t i = 0, j = 0, inter = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] < b[j]) {
            ++i;
        } else if (b[j] < a[i]) {
            ++j;
        } else {
            ++inter;
            ++i;
            ++j;
        }
    }
    return (2.0 * (double)inter) / (double)(a.size() + b.size());
}

double size_score(const FuncFeatures& a, const FuncFeatures& b) {
    int hi = std::max(a.ninsn, b.ninsn);
    int lo = std::min(a.ninsn, b.ninsn);
    if (hi == 0) {
        return 1.0;
    }
    double r = (double)lo / (double)hi;
    if (lo == 0) {
        return 0.0;
    }
    return r;
}

// CFG shape distance: degree multiset + cyclomatic + block size profile.
double cfg_score(const FuncFeatures& a, const FuncFeatures& b) {
    if (a.nblocks == 0 && b.nblocks == 0) {
        return 1.0;
    }
    double nb = 1.0 - std::fabs((double)a.nblocks - (double)b.nblocks) /
                          (double)std::max(1, std::max(a.nblocks, b.nblocks));
    double ne = 1.0 - std::fabs((double)a.nedges - (double)b.nedges) /
                          (double)std::max(1, std::max(a.nedges, b.nedges));
    double cy = 1.0 - std::fabs((double)a.cyclomatic - (double)b.cyclomatic) /
                          (double)std::max(1, std::max(a.cyclomatic, b.cyclomatic));
    double loops = 1.0 - std::fabs((double)a.nloops - (double)b.nloops) /
                              (double)std::max(1, std::max(a.nloops, b.nloops));
    double branches = 1.0 - std::fabs((double)(a.njcc + a.njmp) - (double)(b.njcc + b.njmp)) /
                                (double)std::max(1, std::max(a.njcc + a.njmp, b.njcc + b.njmp));
    return 0.30 * nb + 0.25 * ne + 0.20 * cy + 0.10 * loops + 0.15 * branches;
}

}  // namespace

// ---------------------------------------------------------------------------
// features
// ---------------------------------------------------------------------------

void compute_features(const Program& prog, std::vector<FuncFeatures>& feats) {
    const Binary& bin = *prog.bin;
    feats.assign(prog.funcs.size(), FuncFeatures{});
    for (const auto& f : prog.funcs) {
        FuncFeatures& ft = feats[f.index];
        ft.ninsn = (int)f.insns.size();
        ft.nblocks = (int)f.blocks.size();
        for (const auto& b : f.blocks) {
            ft.nedges += (int)b.succ.size();
        }
        if (ft.nblocks > 0) {
            ft.cyclomatic = ft.nedges - ft.nblocks + 1;
        }
        // Back edges -> loop count (approximate but stable across builds).
        {
            std::map<uint64_t, int> order;
            int k = 0;
            for (const auto& b : f.blocks) {
                order[b.start] = k++;
            }
            for (const auto& b : f.blocks) {
                for (size_t e = 0; e < b.succ.size(); ++e) {
                    if (order[f.blocks[b.succ[e]].start] <= order[b.start] &&
                        b.succ_kind[e] != 0) {
                        ++ft.nloops;
                    }
                }
            }
        }
        for (const auto& in : f.insns) {
            ft.seq.push_back(in.coarse);
            const std::string cm = in.mnemonic;
            std::string key = cm;
            if (cm == "jne" || cm == "jnz") key = "jcc";
            else if (cm == "je" || cm == "jz") key = "jcc";
            else if (cm.rfind("j", 0) == 0 && cm != "jmp" && cm != "jmpq") key = "jcc";
            ft.mnems[key]++;
            if (in.is_call) {
                ++ft.ncall;
                if (!in.is_indirect) {
                    int tgt = prog.func_at_insn(in.targets.empty() ? 0 : in.targets[0]);
                    if (tgt >= 0) {
                        const Func& callee = prog.funcs[tgt];
                        ft.callees.push_back(
                            !prog.canon.empty() && !prog.canon[tgt].empty()
                                ? prog.canon[tgt]
                                : (callee.named && callee.name.rfind("sub_", 0) != 0
                                       ? callee.name
                                       : "anon"));
                    } else {
                        // A call out of the analysed image: keep the target's
                        // offset from the section base is meaningless, so group
                        // all external calls together.
                        ft.callees.push_back("external");
                    }
                } else {
                    ft.callees.push_back("indirect");
                }
            }
            if (in.is_jcc) ++ft.njcc;
            if (in.is_jmp) ++ft.njmp;
            if (in.is_indirect && (in.is_jmp || in.is_call)) ++ft.nind;
            if (in.is_ret) ++ft.nret;
            if (in.writes_memory) ++ft.nwrite;
            if (in.has_imm && in.imm_is_const && !in.is_jmp && !in.is_jcc) {
                ++ft.nimm;
                ft.imms.insert(in.imm_value);
            }
            for (const auto& op : in.ops) {
                if (op.kind == Operand::MEM && op.rip_rel) {
                    const Section* sec = bin.section_containing(op.rip_target);
                    if (sec && !sec->exec() && !sec->writable()) {
                        uint64_t h = op.rip_target;
                        std::string lit;
                        if (bin.read_cstr(op.rip_target, lit) && lit.size() >= 3) {
                            h = fnv1a(lit.data(), lit.size(), 0x9e3779b97f4a7c15ull);
                        }
                        ft.strings.insert(h);
                        ++ft.nstrings;
                    }
                }
            }
        }
        ft.body_hash = fnv1a(ft.seq.empty() ? "" : ft.seq[0].c_str(), 0);
        // Structural hash: block/edge degree signature, order-insensitive.
        {
            std::vector<std::pair<int, int>> deg;
            for (const auto& b : f.blocks) {
                deg.push_back({(int)b.pred.size(), (int)b.succ.size()});
            }
            std::sort(deg.begin(), deg.end());
            uint64_t h = 1469598103934665603ull;
            for (auto& d : deg) {
                h ^= (uint64_t)(uint32_t)d.first;
                h *= 1099511628211ull;
                h ^= (uint64_t)(uint32_t)d.second * 0x100000001b3ull;
                h *= 1099511628211ull;
            }
            ft.shape_hash = h;
        }
        for (auto& kv : ft.mnems) {
            for (int i = 0; i < kv.second; ++i) {
                ft.mnemVec.push_back(kv.first);
            }
        }
        std::sort(ft.mnemVec.begin(), ft.mnemVec.end());
        ft.seqSorted = ft.seq;
        std::sort(ft.seqSorted.begin(), ft.seqSorted.end());
        std::sort(ft.callees.begin(), ft.callees.end());
        uint64_t bh = 1469598103934665603ull;
        for (auto& t : ft.seq) {
            bh = fnv1a(t.data(), t.size(), bh);
        }
        ft.body_hash = bh;
    }
}

// ---------------------------------------------------------------------------
// similarity
// ---------------------------------------------------------------------------

SimResult similarity(const FuncFeatures& a, const FuncFeatures& b, const Weights& w,
                     double name_sim, bool have_name) {
    SimResult r;
    auto add = [&](const std::string& key, double weight, double value) {
        if (weight <= 0.0) {
            return;
        }
        value = std::max(0.0, std::min(1.0, value));
        r.parts[key] = value;
        r.applied[key] = weight;
        r.weight_sum += weight;
        r.score += weight * value;
    };

    if (have_name && w.name > 0.0) {
        add("name", w.name, name_sim);
    }
    add("seq", w.seq, seq_ratio(a.seq, b.seq));
    add("cfg", w.cfg, cfg_score(a, b));
    add("strings", w.strings, jaccard_u64(a.strings, b.strings));
    add("imms", w.imms, jaccard_int(a.imms, b.imms));
    add("calls", w.calls, multiset_dice(a.callees, b.callees));
    add("size", w.size, size_score(a, b));
    add("mnem", w.mnem, multiset_dice(a.mnemVec, b.mnemVec));
    // Normalise over the weights actually applied. When no symbols are present
    // the name term is simply absent and the remaining weights are renormalised
    // by the same division, which keeps scores on a [0,1] scale.
    r.score = r.weight_sum > 0 ? r.score / r.weight_sum : 0.0;
    return r;
}

namespace {

double name_similarity(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) {
        return 0.0;
    }
    if (a == b) {
        return 1.0;
    }
    // Strip a shared prefix (e.g. "sub_"), then compare edit distance.
    size_t n = a.size(), m = b.size();
    if (n * m > 250000) {
        size_t common = 0;
        for (size_t i = 0; i < std::min(n, m); ++i) {
            if (a[i] == b[i]) {
                ++common;
            } else {
                break;
            }
        }
        return (double)common / (double)std::max(n, m);
    }
    std::vector<int> prev(m + 1), cur(m + 1);
    for (size_t j = 0; j <= m; ++j) prev[j] = (int)j;
    for (size_t i = 1; i <= n; ++i) {
        cur[0] = (int)i;
        for (size_t j = 1; j <= m; ++j) {
            int cost = a[i - 1] == b[j - 1] ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        prev.swap(cur);
    }
    double d = (double)prev[m];
    return 1.0 - d / (double)std::max(n, m);
}

}  // namespace

// ---------------------------------------------------------------------------
// pairing: greedy over a globally sorted score list, then a refinement pass
// that allows swaps when they raise total score.
// ---------------------------------------------------------------------------

std::vector<FuncPair> match_functions(const Program& op, const Program& np,
                                      const std::vector<FuncFeatures>& of,
                                      const std::vector<FuncFeatures>& nf,
                                      const Weights& w, double threshold, bool verbose) {
    const size_t NO = op.funcs.size(), NN = np.funcs.size();
    std::vector<FuncPair> out;

    // Candidate generation. Only pairs above a floor are scored in full; the
    // floor uses cheap filters (size ratio, mnemonic overlap) to avoid N*M on
    // large binaries.
    struct Cand {
        double score;
        int i, j;
        SimResult sim;
    };
    std::vector<Cand> cands;
    cands.reserve(NO * 4);

    bool have_names = false;
    for (const auto& f : op.funcs) {
        if (f.named) {
            have_names = true;
            break;
        }
    }

    // Two-stage candidate generation.
    //
    // Stage A scores every (old, new) pair with the cheap features only (no
    // sequence alignment) and keeps, per old function, its best K candidates.
    // Stage B runs the full similarity, including LCS, on that shortlist. The
    // shortlist is a superset of every pair whose score can reach the threshold,
    // because the cheap features are a subset of the full score and the dropped
    // candidates scored far below the best one for the same function.
    auto has_real_name = [](const Func& f) {
        return f.named && f.name.rfind("sub_", 0) != 0;
    };
    constexpr size_t kShortlist = 12;
    struct CheapCand {
        double score;
        int j;
    };
    std::vector<std::vector<CheapCand>> per_old(NO);

    // Bucket new functions by instruction count so each old function only
    // considers size-compatible candidates. Size is a hard precondition: the
    // size term already rejects pairs outside a 16x ratio, and a function whose
    // size changed by more than 16x has no meaningful structural pairing.
    std::vector<size_t> order_n(NN);
    for (size_t j = 0; j < NN; ++j) order_n[j] = j;
    std::sort(order_n.begin(), order_n.end(), [&](size_t x, size_t y) {
        return nf[x].ninsn < nf[y].ninsn;
    });
    std::vector<int> sizes(NN);
    for (size_t k = 0; k < NN; ++k) sizes[k] = nf[order_n[k]].ninsn;

    for (size_t i = 0; i < NO; ++i) {
        const FuncFeatures& a = of[i];
        per_old[i].reserve(std::min<size_t>(NN, kShortlist * 2));
        int low_n = std::max(1, a.ninsn / 16);
        int high_n = a.ninsn * 16 + 16;
        size_t lo = (size_t)(std::lower_bound(sizes.begin(), sizes.end(), low_n) -
                             sizes.begin());
        size_t hi = (size_t)(std::upper_bound(sizes.begin(), sizes.end(), high_n) -
                             sizes.begin());
        for (size_t k = lo; k < hi; ++k) {
            size_t j = order_n[k];
            const FuncFeatures& b = nf[j];
            if (a.ninsn > 8 && b.ninsn > 8 && multiset_dice(a.mnemVec, b.mnemVec) < 0.10) {
                continue;
            }
            if (a.ninsn > 24 && b.ninsn > 24 && multiset_dice(a.seqSorted, b.seqSorted) < 0.06) {
                continue;
            }
            // Cheap score: everything except the O(n*m) sequence term.
            double cheap = 0.0, wsum = 0.0;
            if (w.cfg > 0) { cheap += w.cfg * cfg_score(a, b); wsum += w.cfg; }
            if (w.strings > 0) { cheap += w.strings * jaccard_u64(a.strings, b.strings); wsum += w.strings; }
            if (w.imms > 0) { cheap += w.imms * jaccard_int(a.imms, b.imms); wsum += w.imms; }
            if (w.calls > 0) { cheap += w.calls * multiset_dice(a.callees, b.callees); wsum += w.calls; }
            if (w.size > 0) { cheap += w.size * size_score(a, b); wsum += w.size; }
            if (w.mnem > 0) { cheap += w.mnem * multiset_dice(a.mnemVec, b.mnemVec); wsum += w.mnem; }
            if (w.name > 0 && have_names && has_real_name(op.funcs[i]) &&
                has_real_name(np.funcs[j])) {
                cheap += w.name * name_similarity(op.funcs[i].name, np.funcs[j].name);
                wsum += w.name;
            }
            double cheap_score = wsum > 0 ? cheap / wsum : 0.0;
            per_old[i].push_back({cheap_score, (int)j});
        }
        if (per_old[i].size() > kShortlist) {
            std::partial_sort(per_old[i].begin(), per_old[i].begin() + kShortlist,
                              per_old[i].end(),
                              [](const CheapCand& x, const CheapCand& y) {
                                  return x.score > y.score;
                              });
            per_old[i].resize(kShortlist);
        }
    }

    // Stage B: full score on the shortlist.
    std::map<std::pair<int, int>, std::pair<double, SimResult>> full_cache;
    for (size_t i = 0; i < NO; ++i) {
        for (const auto& cc : per_old[i]) {
            size_t j = (size_t)cc.j;
            const FuncFeatures& a = of[i];
            const FuncFeatures& b = nf[j];
            double ns = 0.0;
            bool names_here = have_names && has_real_name(op.funcs[i]) &&
                              has_real_name(np.funcs[j]);
            if (names_here) {
                ns = name_similarity(op.funcs[i].name, np.funcs[j].name);
            }
            SimResult sim = similarity(a, b, w, ns, names_here);
            if (sim.score < 0.12) {
                continue;
            }
            full_cache[{(int)i, (int)j}] = {sim.score, sim};
            cands.push_back({sim.score, (int)i, (int)j, std::move(sim)});
        }
    }
    std::sort(cands.begin(), cands.end(),
              [](const Cand& x, const Cand& y) { return x.score > y.score; });

    std::vector<int> map_o(NO, -1), map_n(NN, -1);
    std::vector<double> best_o(NO, -1.0), best_n(NN, -1.0);
    for (auto& c : cands) {
        if (map_o[c.i] >= 0 || map_n[c.j] >= 0) {
            continue;
        }
        map_o[c.i] = c.j;
        map_n[c.j] = c.i;
        best_o[c.i] = c.score;
        best_n[c.j] = c.score;
        out.push_back(FuncPair{c.i, c.j, c.score, "modified", c.sim.parts,
                               c.sim.applied, ""});
    }

    // Refinement: pairwise swaps among matched pairs, but only between pairs
    // that could plausibly be confused (similar size and score). Swapping two
    // functions with different sizes can never raise the objective, and skipping
    // those pairs keeps this pass near-linear on multi-thousand-function inputs.
    std::map<std::pair<int, int>, double> score_cache;
    auto score_of = [&](int i, int j) -> double {
        if (i < 0 || j < 0) {
            return 0.0;
        }
        auto key = std::make_pair(i, j);
        auto it = score_cache.find(key);
        if (it != score_cache.end()) {
            return it->second;
        }
        auto has_real_name = [](const Func& f) {
            return f.named && f.name.rfind("sub_", 0) != 0;
        };
        bool names_here = have_names && has_real_name(op.funcs[i]) &&
                          has_real_name(np.funcs[j]);
        double ns = names_here ? name_similarity(op.funcs[i].name, np.funcs[j].name) : 0.0;
        double v = similarity(of[i], nf[j], w, ns, names_here).score;
        score_cache[key] = v;
        return v;
    };
    auto siblings = [&](size_t p, size_t q) {
        int i1 = out[p].old_idx, j1 = out[p].new_idx;
        int i2 = out[q].old_idx, j2 = out[q].new_idx;
        if (i1 < 0 || i2 < 0) return false;
        // A pair this confident is not a swap candidate.
        if (out[p].score >= 0.995 || out[q].score >= 0.995) return false;
        // Same ripple bucket: sizes within 1.6x and scores within 0.15.
        double s1 = size_score(of[i1], nf[j1]);
        double s2 = size_score(of[i2], nf[j2]);
        if (s1 < 0.62 || s2 < 0.62) return false;
        return std::fabs(out[p].score - out[q].score) <= 0.15;
    };
    bool all_confident = true;
    for (const auto& p : out) {
        if (p.score < 0.99) {
            all_confident = false;
            break;
        }
    }
    for (int pass = 0; pass < (all_confident ? 1 : 4); ++pass) {
        bool changed = false;
        for (size_t p = 0; p < out.size(); ++p) {
            for (size_t q = p + 1; q < out.size(); ++q) {
                int i1 = out[p].old_idx, j1 = out[p].new_idx;
                int i2 = out[q].old_idx, j2 = out[q].new_idx;
                if (i1 < 0 || i2 < 0) {
                    continue;
                }
                if (!siblings(p, q)) {
                    continue;
                }
                double cur = score_of(i1, j1) + score_of(i2, j2);
                double swapped = score_of(i1, j2) + score_of(i2, j1);
                if (swapped > cur + 1e-6) {
                    out[p].new_idx = j2;
                    out[q].new_idx = j1;
                    map_o[i1] = j2;
                    map_o[i2] = j1;
                    changed = true;
                }
            }
        }
        if (!changed) {
            break;
        }
    }
    // Refresh scores after swaps. Reuse the cached value where the (old,new)
    // pair was already scored, and recompute only for pairs that changed.
    for (auto& p : out) {
        auto key = std::make_pair(p.old_idx, p.new_idx);
        auto cached = full_cache.find(key);
        if (cached != full_cache.end()) {
            p.score = cached->second.first;
            p.parts = cached->second.second.parts;
            p.weights_used = cached->second.second.applied;
            continue;
        }
        auto has_real_name = [](const Func& f) {
            return f.named && f.name.rfind("sub_", 0) != 0;
        };
        bool names_here = have_names && has_real_name(op.funcs[p.old_idx]) &&
                          has_real_name(np.funcs[p.new_idx]);
        double ns = names_here
                        ? name_similarity(op.funcs[p.old_idx].name, np.funcs[p.new_idx].name)
                        : 0.0;
        SimResult sim = similarity(of[p.old_idx], nf[p.new_idx], w, ns, names_here);
        p.score = sim.score;
        p.parts = sim.parts;
        p.weights_used = sim.applied;
        full_cache[key] = {sim.score, sim};
    }

    // Threshold: low-confidence pairs are demoted to add/remove pairs so the
    // report does not claim a match the evidence does not support.
    std::vector<int> demoted;
    for (size_t p = 0; p < out.size(); ++p) {
        if (out[p].score < threshold) {
            demoted.push_back((int)p);
        }
    }
    for (int idx : demoted) {
        out[idx].status = "split";
        out[idx].reason = "below pair threshold";
    }

    // Unity matches: exact body hash + shape hash => identical.
    for (auto& p : out) {
        if (p.status == "split") {
            continue;
        }
        const FuncFeatures& a = of[p.old_idx];
        const FuncFeatures& b = nf[p.new_idx];
        if (a.body_hash == b.body_hash && a.shape_hash == b.shape_hash &&
            a.ninsn == b.ninsn && a.seq == b.seq) {
            p.status = "identical";
        }
    }

    // Emit final pairs: matched, then removed, then added.
    std::vector<FuncPair> final_pairs;
    std::vector<char> used_o(NO, 0), used_n(NN, 0);
    for (auto& p : out) {
        if (p.status == "split") {
            used_o[p.old_idx] = 0;
            used_n[p.new_idx] = 0;
            continue;
        }
        used_o[p.old_idx] = 1;
        used_n[p.new_idx] = 1;
        final_pairs.push_back(p);
    }
    for (size_t i = 0; i < NO; ++i) {
        if (!used_o[i]) {
            FuncPair p;
            p.old_idx = (int)i;
            p.new_idx = -1;
            p.status = "removed";
            p.reason = "no counterpart above threshold";
            final_pairs.push_back(p);
        }
    }
    for (size_t j = 0; j < NN; ++j) {
        if (!used_n[j]) {
            FuncPair p;
            p.old_idx = -1;
            p.new_idx = (int)j;
            p.status = "added";
            p.reason = "no counterpart above threshold";
            final_pairs.push_back(p);
        }
    }
    std::sort(final_pairs.begin(), final_pairs.end(), [&](const FuncPair& a, const FuncPair& b) {
        auto key = [&](const FuncPair& p) -> std::pair<uint64_t, int> {
            if (p.old_idx >= 0) {
                return {op.funcs[p.old_idx].start, 0};
            }
            return {np.funcs[p.new_idx].start, 1};
        };
        return key(a) < key(b);
    });
    if (verbose) {
        size_t matched = 0, identical = 0;
        for (auto& p : final_pairs) {
            if (p.status == "identical") ++identical;
            if (p.old_idx >= 0 && p.new_idx >= 0) ++matched;
        }
        std::fprintf(stderr,
                     "  pairing: %zu candidates, %zu matched (%zu identical), "
                     "%zu old-only, %zu new-only\n",
                     cands.size(), matched, identical,
                     (size_t)std::count_if(final_pairs.begin(), final_pairs.end(),
                                           [](const FuncPair& p) { return p.old_idx >= 0 && p.new_idx < 0; }),
                     (size_t)std::count_if(final_pairs.begin(), final_pairs.end(),
                                           [](const FuncPair& p) { return p.old_idx < 0 && p.new_idx >= 0; }));
    }
    return final_pairs;
}

std::map<std::string, double> Weights::as_map() const {
    return {{"name", name},   {"seq", seq},     {"cfg", cfg},       {"strings", strings},
            {"imms", imms},   {"calls", calls}, {"size", size},     {"mnem", mnem}};
}

bool Weights::parse(const std::string& spec, Weights& out, std::string& err) {
    std::map<std::string, double*> fields{
        {"name", &out.name},   {"seq", &out.seq},     {"cfg", &out.cfg},
        {"strings", &out.strings}, {"imms", &out.imms}, {"calls", &out.calls},
        {"size", &out.size},   {"mnem", &out.mnem}};
    size_t pos = 0;
    while (pos < spec.size()) {
        size_t comma = spec.find(',', pos);
        std::string item = spec.substr(pos, comma == std::string::npos ? std::string::npos
                                                                        : comma - pos);
        pos = comma == std::string::npos ? spec.size() : comma + 1;
        if (item.empty()) {
            continue;
        }
        size_t eq = item.find('=');
        if (eq == std::string::npos) {
            err = "weight entry must be key=value: " + item;
            return false;
        }
        std::string key = item.substr(0, eq);
        std::string val = item.substr(eq + 1);
        auto it = fields.find(key);
        if (it == fields.end()) {
            err = "unknown weight key: " + key;
            return false;
        }
        try {
            size_t used = 0;
            double d = std::stod(val, &used);
            if (used != val.size() || d < 0.0) {
                err = "bad weight value for " + key + ": " + val;
                return false;
            }
            *it->second = d;
        } catch (...) {
            err = "bad weight value for " + key + ": " + val;
            return false;
        }
    }
    double sum = 0;
    for (auto& kv : out.as_map()) {
        sum += kv.second;
    }
    if (sum <= 1e-9) {
        err = "all weights are zero";
        return false;
    }
    return true;
}

}  // namespace bcd
