// json.cpp -- machine-readable report.
#include "model.h"

#include <cmath>
#include <cstdio>
#include <sstream>

namespace bcd {
namespace {

std::string jstr(const std::string& s) {
    std::string o = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                o += buf;
            } else {
                o += (char)c;
            }
        }
    }
    o += "\"";
    return o;
}

std::string jnum(double d) {
    if (std::isnan(d) || std::isinf(d)) {
        return "null";
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.4f", d);
    return buf;
}

std::string insn_text(const Insn& in) {
    std::string s = in.mnemonic;
    if (!in.op_str.empty()) s += " " + in.op_str;
    return s;
}

std::string jbytes(const Insn& in) {
    std::string o;
    for (int i = 0; i < in.len; ++i) {
        o += hex(in.bytes[i], 2);
    }
    return o;
}

}  // namespace

std::string build_report_json(const Analysis& a) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"tool\": \"bcdiff\",\n";
    o << "  \"generated\": " << jstr(a.generated) << ",\n";
    o << "  \"mode\": " << jstr(a.mode) << ",\n";
    o << "  \"elapsed_ms\": " << jnum(a.elapsed_ms) << ",\n";
    o << "  \"pair_threshold\": " << jnum(a.min_pair) << ",\n";
    o << "  \"weights\": {";
    bool first = true;
    for (const auto& kv : a.weights.as_map()) {
        if (!first) o << ", ";
        first = false;
        o << jstr(kv.first) << ": " << jnum(kv.second);
    }
    o << "},\n";

    auto dump_bin = [&](const char* key, const Binary& b, const Program& p) {
        o << "  \"" << key << "\": {\n";
        o << "    \"path\": " << jstr(b.path) << ",\n";
        o << "    \"sha256\": " << jstr(b.sha256) << ",\n";
        o << "    \"build_id\": " << jstr(b.build_id) << ",\n";
        o << "    \"entry\": " << b.entry << ",\n";
        o << "    \"size\": " << b.data.size() << ",\n";
        o << "    \"stripped\": " << (b.stripped ? "true" : "false") << ",\n";
        o << "    \"functions\": " << p.funcs.size() << ",\n";
        o << "    \"instructions\": " << p.n_insns << ",\n";
        o << "    \"basic_blocks\": " << p.n_blocks << "\n";
        o << "  },\n";
    };
    dump_bin("old_binary", a.oldb, a.oldp);
    dump_bin("new_binary", a.newb, a.newp);

    int sec = 0, risk = 0, info = 0;
    for (const auto& f : a.findings) {
        if (f.category == "security") ++sec;
        else if (f.category == "risk") ++risk;
        else ++info;
    }
    o << "  \"summary\": {\"security\": " << sec << ", \"risk\": " << risk
      << ", \"info\": " << info << "},\n";

    o << "  \"findings\": [\n";
    for (size_t k = 0; k < a.findings.size(); ++k) {
        const Finding& f = a.findings[k];
        o << "    {\"kind\": " << jstr(f.kind) << ", \"category\": " << jstr(f.category)
          << ", \"title\": " << jstr(f.title) << ", \"detail\": " << jstr(f.detail)
          << ", \"confidence\": " << jnum(f.confidence);
        if (f.old_func >= 0) {
            o << ", \"old_func\": " << jstr(a.oldp.funcs[f.old_func].name)
              << ", \"old_addr\": " << a.oldp.funcs[f.old_func].start;
        }
        if (f.new_func >= 0) {
            o << ", \"new_func\": " << jstr(a.newp.funcs[f.new_func].name)
              << ", \"new_addr\": " << a.newp.funcs[f.new_func].start;
        }
        if (f.new_addr) o << ", \"site\": " << f.new_addr;
        o << ", \"evidence\": [";
        for (size_t e = 0; e < f.evidence.size(); ++e) {
            if (e) o << ", ";
            o << jstr(f.evidence[e]);
        }
        o << "]}";
        if (k + 1 < a.findings.size()) o << ",";
        o << "\n";
    }
    o << "  ],\n";

    o << "  \"functions\": [\n";
    for (size_t pi = 0; pi < a.pairs.size(); ++pi) {
        const FuncPair& p = a.pairs[pi];
        const FuncDiff& fd = a.diffs[pi];
        std::string name = p.old_idx >= 0 ? a.oldp.funcs[p.old_idx].name
                                          : a.newp.funcs[p.new_idx].name;
        std::string status = p.status;
        if (status == "modified" && fd.identical) status = "identical";
        o << "    {\"name\": " << jstr(name) << ", \"status\": " << jstr(status)
          << ", \"score\": " << jnum(p.score);
        if (p.old_idx >= 0) {
            const Func& f = a.oldp.funcs[p.old_idx];
            o << ", \"old\": {\"addr\": " << f.start << ", \"insns\": " << f.insns.size()
              << ", \"blocks\": " << f.blocks.size() << ", \"recovered\": "
              << (f.recovered ? "true" : "false") << "}";
        } else {
            o << ", \"old\": null";
        }
        if (p.new_idx >= 0) {
            const Func& f = a.newp.funcs[p.new_idx];
            o << ", \"new\": {\"addr\": " << f.start << ", \"insns\": " << f.insns.size()
              << ", \"blocks\": " << f.blocks.size() << ", \"recovered\": "
              << (f.recovered ? "true" : "false") << "}";
        } else {
            o << ", \"new\": null";
        }
        o << ", \"blocks\": {\"same\": " << fd.blocks_same << ", \"modified\": "
          << fd.blocks_modified << ", \"added\": " << fd.blocks_added
          << ", \"removed\": " << fd.blocks_removed << "}, \"insns\": {\"added\": "
          << fd.insns_added << ", \"removed\": " << fd.insns_removed << "}";
        if (!p.parts.empty()) {
            o << ", \"parts\": {";
            bool f1 = true;
            for (const auto& kv : p.parts) {
                if (!f1) o << ", ";
                f1 = false;
                o << jstr(kv.first) << ": " << jnum(kv.second);
            }
            o << "}";
        }
        // Changed instructions, capped for size.
        if (p.old_idx >= 0 && p.new_idx >= 0 && !fd.identical) {
            o << ", \"changes\": [";
            int emitted = 0;
            for (const auto& bm : fd.blocks) {
                if (bm.status == "same") continue;
                for (size_t k = 0; k < bm.ops.size() && emitted < 400; ++k) {
                    char c = bm.ops[k];
                    if (c == '=') continue;
                    o << (emitted ? ", " : "");
                    o << "{\"op\": \"" << c << "\"";
                    if (k < bm.old_i.size() && bm.old_i[k] >= 0) {
                        const Insn& in = a.oldp.funcs[p.old_idx].insns[bm.old_i[k]];
                        o << ", \"old\": {\"addr\": " << in.addr << ", \"text\": "
                          << jstr(insn_text(in)) << "}";
                    }
                    if (k < bm.new_i.size() && bm.new_i[k] >= 0) {
                        const Insn& in = a.newp.funcs[p.new_idx].insns[bm.new_i[k]];
                        o << ", \"new\": {\"addr\": " << in.addr << ", \"text\": "
                          << jstr(insn_text(in)) << ", \"bytes\": " << jstr(jbytes(in))
                          << "}";
                    }
                    o << "}";
                    ++emitted;
                }
            }
            o << "]";
        }
        o << "}";
        if (pi + 1 < a.pairs.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

}  // namespace bcd
