// elf.cpp -- self-contained ELF64 little-endian reader (x86-64 focused).
#include "model.h"

#include <cstring>

namespace bcd {
namespace {

constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_NOTE = 7;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_DYNSYM = 11;

template <typename T>
bool take(const std::vector<uint8_t>& d, size_t off, T& out) {
    if (off > d.size() || d.size() - off < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, d.data() + off, sizeof(T));
    return true;
}

struct Ehdr64 {
    uint8_t ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};

struct Shdr64 {
    uint32_t name, type;
    uint64_t flags, addr, offset, size;
    uint32_t link, info;
    uint64_t addralign, entsize;
};

struct Phdr64 {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};

struct Sym64 {
    uint32_t name;
    uint8_t info, other;
    uint16_t shndx;
    uint64_t value, size;
};

}  // namespace

const Section* Binary::section_containing(uint64_t addr) const {
    for (const auto& s : sections) {
        if (!s.alloc() || s.type == SHT_NOBITS || s.size == 0) {
            continue;
        }
        if (addr >= s.addr && addr < s.addr + s.size) {
            return &s;
        }
    }
    return nullptr;
}

const Section* Binary::section_named(const std::string& name) const {
    for (const auto& s : sections) {
        if (s.name == name) {
            return &s;
        }
    }
    return nullptr;
}

bool Binary::read(uint64_t addr, void* out, size_t n) const {
    const Section* s = section_containing(addr);
    if (!s || addr + n > s->addr + s->size) {
        return false;
    }
    size_t off = (size_t)(s->offset + (addr - s->addr));
    if (off > data.size() || data.size() - off < n) {
        return false;
    }
    std::memcpy(out, data.data() + off, n);
    return true;
}

bool Binary::read_cstr(uint64_t addr, std::string& out, size_t maxlen) const {
    out.clear();
    const Section* s = section_containing(addr);
    if (!s) {
        return false;
    }
    size_t off = (size_t)(s->offset + (addr - s->addr));
    size_t limit = std::min<size_t>(maxlen, (size_t)(s->offset + s->size - off));
    for (size_t i = 0; i < limit; ++i) {
        if (off + i >= data.size()) {
            return false;
        }
        char c = (char)data[off + i];
        if (c == 0) {
            return true;
        }
        out.push_back(c);
    }
    return false;
}

bool Binary::in_exec(uint64_t addr) const {
    for (const auto& s : sections) {
        if (s.exec() && addr >= s.addr && addr < s.addr + s.size) {
            return true;
        }
    }
    return false;
}

uint64_t Binary::exec_end_after(uint64_t addr) const {
    for (const auto& s : sections) {
        if (s.exec() && addr >= s.addr && addr < s.addr + s.size) {
            return s.addr + s.size;
        }
    }
    return addr;
}

const Symbol* Binary::symbol_at(uint64_t addr) const {
    for (const auto& s : symbols) {
        if (s.is_func() && s.addr == addr) {
            return &s;
        }
    }
    return nullptr;
}

const Symbol* Binary::symbol_containing(uint64_t addr) const {
    const Symbol* best = nullptr;
    for (const auto& s : symbols) {
        if (!s.is_func() || s.addr == 0) {
            continue;
        }
        if (addr >= s.addr && (s.size == 0 ? addr == s.addr : addr < s.addr + s.size)) {
            if (!best || s.addr >= best->addr) {
                best = &s;
            }
        }
    }
    return best;
}

const Symbol* Binary::exported_symbol_named(const std::string& name) const {
    for (const auto& s : symbols) {
        if (s.bind != 0 && s.name == name) {
            return &s;
        }
    }
    return nullptr;
}

size_t Binary::executable_sections() const {
    size_t n = 0;
    for (const auto& s : sections) {
        if (s.exec() && s.size != 0) {
            ++n;
        }
    }
    return n;
}

bool load_elf(const std::string& path, Binary& out, std::string& err) {
    out.path = path;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        err = "cannot open " + path;
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        std::fclose(f);
        err = "empty file " + path;
        return false;
    }
    out.data.resize((size_t)sz);
    size_t got = std::fread(out.data.data(), 1, out.data.size(), f);
    std::fclose(f);
    if (got != out.data.size()) {
        err = "short read " + path;
        return false;
    }
    out.sha256 = sha256_hex(out.data);

    Ehdr64 eh{};
    if (!take(out.data, 0, eh) || std::memcmp(eh.ident, "\x7f"
                                                          "ELF",
                                              4) != 0) {
        err = "not an ELF file: " + path;
        return false;
    }
    if (eh.ident[4] != 2) {
        err = "not ELF64 (class " + std::to_string((int)eh.ident[4]) + "): " + path;
        return false;
    }
    if (eh.ident[5] != 1) {
        err = "not little-endian: " + path;
        return false;
    }
    if (eh.machine != 62) {
        err = "not x86-64 (e_machine=" + std::to_string(eh.machine) + "): " + path;
        return false;
    }
    out.entry = eh.entry;
    out.elf_type = eh.type;
    out.machine = eh.machine;

    // Section headers.
    if (eh.shoff != 0 && eh.shnum != 0) {
        std::vector<Shdr64> sh(eh.shnum);
        for (uint16_t i = 0; i < eh.shnum; ++i) {
            if (!take(out.data, (size_t)(eh.shoff + (uint64_t)i * eh.shentsize), sh[i])) {
                err = "truncated section header table: " + path;
                return false;
            }
        }
        std::string shstr;
        if (eh.shstrndx < sh.size() && sh[eh.shstrndx].type == SHT_STRTAB) {
            const auto& s = sh[eh.shstrndx];
            if (s.offset < out.data.size()) {
                size_t n = std::min<size_t>((size_t)s.size, out.data.size() - (size_t)s.offset);
                shstr.assign((const char*)out.data.data() + s.offset, n);
            }
        }
        for (uint16_t i = 0; i < eh.shnum; ++i) {
            Section s;
            if (sh[i].name < shstr.size()) {
                s.name = shstr.c_str() + sh[i].name;
            }
            s.type = sh[i].type;
            s.flags = sh[i].flags;
            s.addr = sh[i].addr;
            s.offset = sh[i].offset;
            s.size = sh[i].size;
            s.entsize = sh[i].entsize;
            s.link = sh[i].link;
            s.info = sh[i].info;
            out.sections.push_back(s);
        }
        // Symbols from .symtab and .dynsym.
        for (uint16_t i = 0; i < eh.shnum; ++i) {
            const auto& s = sh[i];
            if (s.type != SHT_SYMTAB && s.type != SHT_DYNSYM) {
                continue;
            }
            if (s.link >= sh.size() || sh[s.link].type != SHT_STRTAB) {
                continue;
            }
            const auto& strsec = sh[s.link];
            if (s.offset >= out.data.size() || strsec.offset >= out.data.size()) {
                continue;
            }
            size_t strn = std::min<size_t>((size_t)strsec.size, out.data.size() - (size_t)strsec.offset);
            const char* base = (const char*)out.data.data() + strsec.offset;
            size_t count = (size_t)(s.size / (s.entsize ? s.entsize : sizeof(Sym64)));
            for (size_t k = 0; k < count; ++k) {
                Sym64 sym{};
                if (!take(out.data, (size_t)(s.offset + k * (s.entsize ? s.entsize : sizeof(Sym64))),
                         sym)) {
                    break;
                }
                if (sym.name >= strn) {
                    continue;
                }
                Symbol sy;
                sy.name = base + sym.name;
                sy.addr = sym.value;
                sy.size = sym.size;
                sy.type = sym.info & 0xf;
                sy.bind = sym.info >> 4;
                sy.other = sym.other;
                sy.shndx = sym.shndx;
                out.symbols.push_back(std::move(sy));
            }
            if (s.type == SHT_SYMTAB) {
                out.has_symtab = true;
            } else {
                out.has_dynsym = true;
            }
        }
    }

    // Build-id from PT_NOTE / .note.gnu.build-id.
    for (const auto& s : out.sections) {
        if (s.type != SHT_NOTE || s.offset >= out.data.size()) {
            continue;
        }
        size_t off = (size_t)s.offset;
        size_t end = std::min<size_t>(out.data.size(), off + (size_t)s.size);
        while (off + 12 <= end) {
            uint32_t namesz, descsz, ntype;
            std::memcpy(&namesz, out.data.data() + off, 4);
            std::memcpy(&descsz, out.data.data() + off + 4, 4);
            std::memcpy(&ntype, out.data.data() + off + 8, 4);
            size_t nameoff = off + 12;
            size_t descoff = nameoff + ((namesz + 3u) & ~3u);
            if (descoff + descsz > end) {
                break;
            }
            std::string nm((const char*)out.data.data() + nameoff,
                           std::min<size_t>(namesz, descoff - nameoff));
            if (ntype == 3 && nm.find("GNU") != std::string::npos) {
                std::string id;
                for (uint32_t k = 0; k < descsz && descoff + k < out.data.size(); ++k) {
                    id += hex(out.data[descoff + k], 2);
                }
                out.build_id = id;
                break;
            }
            off = descoff + ((descsz + 3u) & ~3u);
        }
        if (!out.build_id.empty()) {
            break;
        }
    }

    out.stripped = !out.has_symtab;

    if (out.executable_sections() == 0) {
        err = "no executable section in " + path;
        return false;
    }
    return true;
}

}  // namespace bcd
