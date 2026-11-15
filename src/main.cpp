// main.cpp -- bcdiff command line driver.
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "model.h"

namespace {

void usage() {
    std::printf(
        "bcdiff -- function-level x86-64 ELF binary diff with CFG comparison\n"
        "\n"
        "usage: bcdiff OLD.elf NEW.elf [options]\n"
        "\n"
        "options:\n"
        "  -o, --html FILE       HTML report path (default bcdiff-report.html)\n"
        "      --json FILE       also write a machine-readable JSON report\n"
        "      --weights SPEC    similarity weights, comma separated, e.g.\n"
        "                        name=0.32,seq=0.22,cfg=0.14,strings=0.10,\n"
        "                        imms=0.08,calls=0.07,size=0.04,mnem=0.03\n"
        "      --threshold X     minimum score to accept a pair (default 0.42)\n"
        "      --no-symbols      ignore symbol tables (rank names are not\n"
        "                        allowed to influence pairing)\n"
        "      --fragment        treat inputs as code fragments without a usable\n"
        "                        entry point: every aligned function-like blob is\n"
        "                        considered a seed\n"
        "      --full            do not truncate instruction output\n"
        "  -v, --verbose         progress on stderr\n"
        "  -h, --help            this message\n"
        "\n"
        "exit status: 0 no differences, 1 differences found, 2 error\n");
}

std::string now_string() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

double now_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

bool write_file(const std::string& path, const std::string& content, std::string& err) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        err = "cannot write " + path;
        return false;
    }
    size_t n = std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);
    if (n != content.size()) {
        err = "short write to " + path;
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    bcd::Options opt;
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: %s requires an argument\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "-o" || a == "--html" || a == "--output") {
            opt.html_out = next("--html");
        } else if (a == "--json") {
            opt.json_out = next("--json");
        } else if (a == "--weights") {
            std::string err;
            if (!bcd::Weights::parse(next("--weights"), opt.weights, err)) {
                std::fprintf(stderr, "error: %s\n", err.c_str());
                return 2;
            }
        } else if (a == "--threshold") {
            try {
                opt.min_pair = std::stod(next("--threshold"));
            } catch (...) {
                std::fprintf(stderr, "error: bad --threshold value\n");
                return 2;
            }
            if (opt.min_pair < 0.0 || opt.min_pair > 1.0) {
                std::fprintf(stderr, "error: --threshold must be within [0,1]\n");
                return 2;
            }
        } else if (a == "--no-symbols") {
            opt.use_symbols = false;
        } else if (a == "--fragment") {
            opt.fragment = true;
        } else if (a == "--full") {
            opt.full_cfg = true;
        } else if (a == "-v" || a == "--verbose") {
            opt.verbose = true;
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "error: unknown option %s\n", a.c_str());
            usage();
            return 2;
        } else {
            positional.push_back(a);
        }
    }
    if (positional.size() != 2) {
        usage();
        return 2;
    }
    opt.old_path = positional[0];
    opt.new_path = positional[1];

    double t0 = now_ms();
    bcd::Analysis A;
    A.weights = opt.weights;
    A.min_pair = opt.min_pair;

    std::string err;
    if (!bcd::load_elf(opt.old_path, A.oldb, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    if (!bcd::load_elf(opt.new_path, A.newb, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    if (opt.verbose) {
        std::fprintf(stderr, "old: %s (%zu bytes, entry 0x%llx, symtab=%d)\n",
                     A.oldb.path.c_str(), A.oldb.data.size(),
                     (unsigned long long)A.oldb.entry, (int)A.oldb.has_symtab);
        std::fprintf(stderr, "new: %s (%zu bytes, entry 0x%llx, symtab=%d)\n",
                     A.newb.path.c_str(), A.newb.data.size(),
                     (unsigned long long)A.newb.entry, (int)A.newb.has_symtab);
    }

    // Symbol policy: --no-symbols hides names from the matcher and report so
    // the comparison is purely structural.
    if (!opt.use_symbols) {
        for (auto& s : A.oldb.symbols) {
            if (s.is_func()) s.bind = 0;
        }
        for (auto& s : A.newb.symbols) {
            if (s.is_func()) s.bind = 0;
        }
    }

    A.mode = (A.oldb.has_symtab && A.newb.has_symtab) ? "symbols" : "stripped";
    if (opt.fragment) {
        A.mode += "+fragment";
    }

    double t1 = now_ms();
    bcd::build_program(A.oldb, A.oldp);
    bcd::build_program(A.newb, A.newp);
    if (opt.verbose) std::fprintf(stderr, "  timing: discovery %.0f ms\n", now_ms() - t1);
    if (A.oldp.funcs.empty() || A.newp.funcs.empty()) {
        std::fprintf(stderr, "error: no functions recovered in %s\n",
                     A.oldp.funcs.empty() ? opt.old_path.c_str() : opt.new_path.c_str());
        return 2;
    }
    if (opt.verbose) {
        std::fprintf(stderr, "old program: %zu functions, %zu instructions, %zu blocks\n",
                     A.oldp.funcs.size(), A.oldp.n_insns, A.oldp.n_blocks);
        std::fprintf(stderr, "new program: %zu functions, %zu instructions, %zu blocks\n",
                     A.newp.funcs.size(), A.newp.n_insns, A.newp.n_blocks);
    }

    // Pass 1: pair on structure + symbols. Pass 2 rebuilds the callee feature
    // with version-independent callee identities (a matched callee gets the old
    // side's label, an unmatched one a stable placeholder) and re-pairs. This
    // keeps call-graph similarity meaningful for stripped binaries, where raw
    // function names are addresses that always differ.
    double t2 = now_ms();
    bcd::compute_features(A.oldp, A.oldf);
    bcd::compute_features(A.newp, A.newf);
    if (opt.verbose) std::fprintf(stderr, "  timing: features %.0f ms\n", now_ms() - t2);
    std::vector<bcd::FuncPair> first = bcd::match_functions(
        A.oldp, A.newp, A.oldf, A.newf, opt.weights, opt.min_pair, false);
    bcd::assign_canonical_names(A.oldp, A.newp, first);
    bcd::compute_features(A.oldp, A.oldf);
    bcd::compute_features(A.newp, A.newf);
    double t3 = now_ms();
    A.pairs = bcd::match_functions(A.oldp, A.newp, A.oldf, A.newf, opt.weights,
                                   opt.min_pair, opt.verbose);
    if (opt.verbose) std::fprintf(stderr, "  timing: match(2 passes) %.0f ms\n", now_ms() - t3);
    if (opt.verbose) {
        size_t bad = 0;
        for (const auto& p : A.pairs) {
            if (p.old_idx >= 0 && p.new_idx >= 0 && p.score < opt.min_pair) ++bad;
        }
        std::fprintf(stderr, "low-confidence pairs below threshold: %zu\n", bad);
    }
    double t4 = now_ms();
    bcd::compute_semantics(A.oldp, A.newp, A.pairs);
    bcd::diff_all(A.oldp, A.newp, A.pairs, A.diffs);
    bcd::detect_findings(A);
    if (opt.verbose) std::fprintf(stderr, "  timing: diff+findings %.0f ms\n", now_ms() - t4);

    // If every matched pair is identical and the function sets line up, the
    // binaries are equivalent at this granularity.
    bool any_change = false;
    for (size_t i = 0; i < A.pairs.size(); ++i) {
        const auto& p = A.pairs[i];
        if (p.old_idx < 0 || p.new_idx < 0) {
            any_change = true;
            continue;
        }
        if (!A.diffs[i].identical) any_change = true;
    }
    A.elapsed_ms = now_ms() - t0;
    A.generated = now_string();

    double t5 = now_ms();
    std::string html = bcd::build_report_html(A, true);
    if (opt.verbose) std::fprintf(stderr, "  timing: html %.0f ms (%zu bytes)\n", now_ms() - t5, html.size());
    if (!write_file(opt.html_out, html, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    if (!opt.json_out.empty()) {
        std::string js = bcd::build_report_json(A);
        if (!write_file(opt.json_out, js, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 2;
        }
    }

    int sec = 0, risk = 0, info = 0;
    for (const auto& f : A.findings) {
        if (f.category == "security") ++sec;
        else if (f.category == "risk") ++risk;
        else ++info;
    }
    int matched = 0, identical = 0, modified = 0, added = 0, removed = 0;
    for (const auto& p : A.pairs) {
        if (p.old_idx >= 0 && p.new_idx >= 0) {
            ++matched;
            if (p.status == "identical") ++identical;
            else ++modified;
        } else if (p.new_idx >= 0) {
            ++added;
        } else {
            ++removed;
        }
    }
    std::printf("bcdiff: %s -> %s\n", opt.old_path.c_str(), opt.new_path.c_str());
    std::printf("  functions: %zu old, %zu new | matched %d (identical %d, modified %d), "
                "added %d, removed %d\n",
                A.oldp.funcs.size(), A.newp.funcs.size(), matched, identical, modified,
                added, removed);
    std::printf("  findings: %d security, %d risk, %d info\n", sec, risk, info);
    for (const auto& f : A.findings) {
        if (f.category == "security") {
            std::printf("  [security] %s\n", f.title.c_str());
        }
    }
    std::printf("  report: %s%s%s\n", opt.html_out.c_str(),
                opt.json_out.empty() ? "" : " , ", opt.json_out.c_str());
    return any_change ? 1 : 0;
}
