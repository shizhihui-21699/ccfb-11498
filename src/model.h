// model.h -- shared data model for the binary diff engine.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bcd {

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

struct Section {
    std::string name;
    uint32_t type = 0;
    uint64_t flags = 0;
    uint64_t addr = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t entsize = 0;
    uint32_t link = 0;
    uint32_t info = 0;

    bool alloc() const { return (flags & 0x2u) != 0; }
    bool exec() const { return (flags & 0x4u) != 0; }
    bool writable() const { return (flags & 0x1u) != 0; }
};

struct Symbol {
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint8_t type = 0;
    uint8_t bind = 0;
    uint16_t shndx = 0;
    uint8_t other = 0;

    bool is_func() const { return type == 2 || type == 10; }  // FUNC, GNU_IFUNC
};

struct Binary {
    std::string path;
    std::vector<uint8_t> data;
    std::string sha256;
    uint64_t entry = 0;
    uint16_t elf_type = 0;
    uint16_t machine = 0;
    std::string build_id;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    bool has_symtab = false;
    bool has_dynsym = false;
    bool stripped = true;

    const Section* section_containing(uint64_t addr) const;
    const Section* section_named(const std::string& name) const;
    bool read(uint64_t addr, void* out, size_t n) const;
    bool read_cstr(uint64_t addr, std::string& out, size_t maxlen = 4096) const;
    bool in_exec(uint64_t addr) const;
    uint64_t exec_end_after(uint64_t addr) const;  // end of section containing addr
    const Symbol* symbol_at(uint64_t addr) const;
    const Symbol* symbol_containing(uint64_t addr) const;
    const Symbol* exported_symbol_named(const std::string& name) const;
    size_t executable_sections() const;
};

bool load_elf(const std::string& path, Binary& out, std::string& err);

// ---------------------------------------------------------------------------
// instructions / functions / CFG
// ---------------------------------------------------------------------------

struct Operand {
    enum Kind { REG, IMM, MEM, OTHER };
    Kind kind = OTHER;
    int reg = 0;  // capstone register id (0 = none)
    std::string reg_name;
    int64_t imm = 0;
    int mem_base = 0;
    int mem_index = 0;
    int mem_scale = 1;
    std::string mem_base_name;
    std::string mem_index_name;
    int64_t mem_disp = 0;
    bool rip_rel = false;
    uint64_t rip_target = 0;
    int size = 0;
    bool writes = false;  // operand is written by the instruction
};

struct Insn {
    uint64_t addr = 0;
    uint8_t len = 0;
    uint8_t bytes[16] = {0};
    unsigned cs_id = 0;
    std::string mnemonic;
    std::string op_str;

    std::vector<Operand> ops;

    bool is_call = false;
    bool is_jmp = false;   // unconditional direct or indirect jump
    bool is_jcc = false;   // conditional jump
    bool is_ret = false;
    bool is_indirect = false;
    bool is_nop = false;
    bool is_int3 = false;
    bool is_halt = false;  // ud2/hlt/iret
    bool is_syscall = false;
    bool is_invalid = false;
    bool is_pad = false;
    bool writes_memory = false;
    bool reads_memory = false;

    bool ends_block = false;
    bool falls_through = true;

    std::vector<uint64_t> targets;   // direct branch/call targets, jump-table cases
    uint64_t branch_target = 0;      // primary direct target (0 if none)
    bool has_imm = false;
    int64_t imm_value = 0;           // first non-branch immediate operand
    bool imm_is_const = false;       // value is not a plausible in-image address

    std::string coarse;  // address-independent similarity token
    std::string sem;     // semantic token, branch targets resolved (set by diff stage)

    const Operand* first_mem() const;
    bool is_terminator() const { return ends_block; }
};

struct Block {
    int id = -1;
    uint64_t start = 0;
    uint64_t end = 0;
    std::vector<int> insns;  // indices into Func::insns
    std::vector<int> succ;
    std::vector<int> pred;
    std::vector<int> succ_kind;  // 0 fallthrough, 1 taken, 2 switch, 3 indirect, 4 tailcall
    bool entry = false;
    bool reachable = false;
    bool has_call = false;
    bool has_write = false;

    int find_insn(uint64_t addr) const;
};

struct Func {
    int index = -1;
    uint64_t start = 0;
    uint64_t end = 0;
    std::string name;
    bool named = false;
    bool from_symbol = false;
    bool recovered = false;  // boundary heuristic used
    bool has_bad_insn = false;
    bool has_tail_calls = false;

    std::vector<Insn> insns;
    std::vector<Block> blocks;
    int entry_block = -1;
    std::unordered_map<uint64_t, int> addr_to_insn;
    std::map<uint64_t, std::vector<uint64_t>> jump_tables;  // jmp site -> targets
    std::vector<uint64_t> call_targets;

    const Block* block_at(uint64_t addr) const;
};

struct Program {
    const Binary* bin = nullptr;
    std::vector<Func> funcs;
    std::unordered_map<uint64_t, int> func_by_start;
    std::unordered_map<uint64_t, int> covers;  // instruction start -> func index
    std::vector<std::pair<uint64_t, uint64_t>> unclaimed;  // exec gaps left as data
    // Canonical, version-independent identity per function, filled in after the
    // first pairing pass. Used so a callee appears under the same identifier in
    // both binaries even when symbol names are absent.
    std::vector<std::string> canon;
    size_t n_insns = 0;
    size_t n_blocks = 0;

    int func_at(uint64_t addr) const;  // function whose range contains addr
    int func_at_insn(uint64_t addr) const;
};

struct JumpTable {
    uint64_t site = 0;
    uint64_t base = 0;
    int count = 0;
    std::vector<uint64_t> targets;
    bool ok = false;
};

// ---------------------------------------------------------------------------
// features / matching
// ---------------------------------------------------------------------------

struct Weights {
    double name = 0.32;
    double seq = 0.22;
    double cfg = 0.14;
    double strings = 0.10;
    double imms = 0.08;
    double calls = 0.07;
    double size = 0.04;
    double mnem = 0.03;

    std::map<std::string, double> as_map() const;
    static bool parse(const std::string& spec, Weights& out, std::string& err);
};

struct FuncFeatures {
    int ninsn = 0;
    int nblocks = 0;
    int nedges = 0;
    int cyclomatic = 0;
    int nloops = 0;
    int ncall = 0;
    int njcc = 0;
    int njmp = 0;
    int nind = 0;
    int nret = 0;
    int nwrite = 0;
    int nstrings = 0;
    int nimm = 0;

    std::map<std::string, int> mnems;
    std::vector<std::string> mnemVec;  // sorted, for fast histogram overlap
    std::set<int64_t> imms;
    std::set<uint64_t> strings;  // hashes of referenced literals
    std::vector<std::string> callees;
    std::vector<std::string> seq;        // coarse tokens, program order
    std::vector<std::string> seqSorted;  // same tokens, sorted, for histograms

    uint64_t body_hash = 0;
    uint64_t shape_hash = 0;
};

struct SimResult {
    double score = 0.0;
    std::map<std::string, double> parts;
    std::map<std::string, double> applied;  // feature -> weight actually used
    double weight_sum = 0.0;
};

struct FuncPair {
    int old_idx = -1;
    int new_idx = -1;
    double score = 0.0;
    std::string status;  // identical | modified | added | removed
    std::map<std::string, double> parts;
    std::map<std::string, double> weights_used;
    std::string reason;
};

// ---------------------------------------------------------------------------
// diff / findings
// ---------------------------------------------------------------------------

struct BlockMatch {
    int old_b = -1;
    int new_b = -1;
    std::string status;  // same | modified | added | removed
    double sim = 0.0;
    bool reordered = false;
    std::vector<char> ops;     // '=' '-' '+' relative to old/new instruction streams
    std::vector<int> old_i;    // parallel to ops
    std::vector<int> new_i;
    int n_added = 0;
    int n_removed = 0;
};

struct FuncDiff {
    std::vector<BlockMatch> blocks;
    int blocks_same = 0;
    int blocks_modified = 0;
    int blocks_added = 0;
    int blocks_removed = 0;
    int insns_added = 0;
    int insns_removed = 0;
    int insns_changed = 0;
    bool identical = false;
};

struct Finding {
    std::string kind;      // length-check | bounds-check | range-check | null-check |
                           // error-path | check-removed | const-changed | new-function |
                           // removed-function | call-added
    std::string category;  // security | risk | info
    std::string title;
    std::string detail;
    int pair_index = -1;
    int old_func = -1;
    int new_func = -1;
    uint64_t old_addr = 0;
    uint64_t new_addr = 0;
    double confidence = 0.0;
    std::vector<std::string> evidence;
    std::vector<std::string> old_insns;
    std::vector<std::string> new_insns;
};

// ---------------------------------------------------------------------------
// pipeline
// ---------------------------------------------------------------------------

struct Options {
    bool verbose = false;
    bool use_symbols = true;
    bool fragment = false;
    bool full_cfg = false;
    double min_pair = 0.42;
    size_t max_report_bytes = 12u * 1024u * 1024u;
    Weights weights;
    std::string json_out;
    std::string html_out = "bcdiff-report.html";
    std::string old_path;
    std::string new_path;
};

struct Analysis {
    Binary oldb;
    Binary newb;
    Program oldp;
    Program newp;
    std::vector<FuncFeatures> oldf;
    std::vector<FuncFeatures> newf;
    std::vector<FuncPair> pairs;
    std::vector<FuncDiff> diffs;      // parallel to pairs
    std::vector<Finding> findings;
    Weights weights;
    double min_pair = 0.42;
    std::string mode;  // symbols | stripped
    double elapsed_ms = 0.0;
    std::string generated;
};

void build_program(const Binary& bin, Program& prog);
void compute_features(const Program& prog, std::vector<FuncFeatures>& feats);
SimResult similarity(const FuncFeatures& a, const FuncFeatures& b, const Weights& w,
                     double name_sim = 0.0, bool have_name = false);
std::vector<FuncPair> match_functions(const Program& op, const Program& np,
                                      const std::vector<FuncFeatures>& of,
                                      const std::vector<FuncFeatures>& nf,
                                      const Weights& w, double threshold,
                                      bool verbose);
void compute_semantics(Program& op, Program& np, const std::vector<FuncPair>& pairs);
// Give every function a label that means the same thing in both binaries:
// matched pairs share the old side's name, unmatched ones get ordinals.
void assign_canonical_names(Program& op, Program& np, const std::vector<FuncPair>& pairs);
void diff_all(Program& op, Program& np, const std::vector<FuncPair>& pairs,
              std::vector<FuncDiff>& diffs);
void detect_findings(Analysis& a);
std::string build_report_html(const Analysis& a, bool standalone);
std::string build_report_json(const Analysis& a);

// util
std::string hex(uint64_t v, int width = 0);
std::string hex0x(uint64_t v);
std::string lower(std::string s);
std::string sha256_hex(const std::vector<uint8_t>& data);
uint64_t fnv1a(const void* data, size_t n, uint64_t seed = 1469598103934665603ull);
std::string join(const std::vector<std::string>& v, const std::string& sep);
std::string html_escape(const std::string& s);
double seq_ratio(const std::vector<std::string>& a, const std::vector<std::string>& b);

}  // namespace bcd
