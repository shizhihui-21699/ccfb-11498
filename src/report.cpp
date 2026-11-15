// report.cpp -- standalone HTML report with CFG comparisons.
#include "model.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace bcd {
namespace {

std::string insn_text(const Insn& in) {
    std::string s = in.mnemonic;
    if (!in.op_str.empty()) {
        s += " " + in.op_str;
    }
    return s;
}

const char* kBg = "#0f1117";
const char* kPanel = "#161a23";
const char* kPanel2 = "#1c2230";
const char* kLine = "#2a3242";
const char* kText = "#dfe6f2";
const char* kDim = "#8c99b0";
const char* kAccent = "#6aa8ff";
const char* kGreen = "#3fb950";
const char* kRed = "#f85149";
const char* kAmber = "#d29922";
const char* kPurple = "#bc8cff";

// ---------------------------------------------------------------------------
// CFG layout + SVG
// ---------------------------------------------------------------------------

struct CfgNode {
    int block = -1;
    double x = 0, y = 0, w = 0, h = 0;
    std::string label;
    std::string status;  // same | modified | added | removed | unreachable
    std::string detail;  // tooltip
};

struct CfgEdge {
    int from = -1, to = -1;
    int kind = 0;
    bool back = false;
};

struct CfgLayout {
    std::vector<CfgNode> nodes;
    std::vector<CfgEdge> edges;
    double width = 0, height = 0;
    bool truncated = false;
};

CfgLayout layout_cfg(const Program& prog, const Func& f, const FuncDiff* diff,
                     bool is_new) {
    CfgLayout L;
    // Map block -> diff status.
    std::map<int, std::string> status;
    std::map<int, std::string> note;
    if (diff) {
        for (const auto& bm : diff->blocks) {
            int b = is_new ? bm.new_b : bm.old_b;
            if (b < 0) continue;
            status[b] = bm.status;
            std::string s;
            if (bm.status == "modified") {
                s = "+" + std::to_string(bm.n_added) + " / -" + std::to_string(bm.n_removed);
            } else if (bm.status == "added") {
                s = "+" + std::to_string(bm.n_added);
            } else if (bm.status == "removed") {
                s = "-" + std::to_string(bm.n_removed);
            }
            note[b] = s;
        }
    }

    const size_t kMaxNodes = 160;
    // Determine nodes in an order that keeps layout stable: DFS preorder from
    // entry, then any unreachable blocks in address order.
    std::vector<int> order;
    std::vector<char> seen(f.blocks.size(), 0);
    std::vector<int> stack;
    if (f.entry_block >= 0 && f.entry_block < (int)f.blocks.size()) {
        stack.push_back(f.entry_block);
    }
    while (!stack.empty()) {
        int b = stack.back();
        stack.pop_back();
        if (b < 0 || b >= (int)f.blocks.size() || seen[b]) continue;
        seen[b] = 1;
        order.push_back(b);
        const auto& blk = f.blocks[b];
        for (size_t e = blk.succ.size(); e-- > 0;) {
            stack.push_back(blk.succ[e]);
        }
    }
    for (const auto& b : f.blocks) {
        if (!seen[b.id]) order.push_back(b.id);
        if (order.size() >= kMaxNodes) {
            L.truncated = true;
            break;
        }
    }
    if (order.size() > kMaxNodes) {
        order.resize(kMaxNodes);
        L.truncated = true;
    }

    // Rank = longest path depth from entry (ignoring back edges).
    std::map<int, int> depth;
    for (int b : order) depth[b] = 0;
    for (int pass = 0; pass < 6; ++pass) {
        bool changed = false;
        for (int b : order) {
            for (size_t e = 0; e < f.blocks[b].succ.size(); ++e) {
                int s = f.blocks[b].succ[e];
                int kind = e < f.blocks[b].succ_kind.size() ? f.blocks[b].succ_kind[e] : 0;
                if (kind == 0) continue;  // fallthrough handled by order
                if (depth[s] < depth[b] + 1) {
                    depth[s] = depth[b] + 1;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }
    // Clamp depth so a long switch fan-out does not make a giant canvas.
    int maxdepth = 0;
    for (auto& kv : depth) maxdepth = std::max(maxdepth, kv.second);
    if (maxdepth > 40) {
        for (auto& kv : depth) kv.second = kv.second * 40 / maxdepth;
        maxdepth = 40;
    }
    std::map<int, std::vector<int>> by_depth;
    for (int b : order) by_depth[depth[b]].push_back(b);

    const double kNodeW = 208, kNodeGapX = 26, kRowH = 74;
    const double kPad = 18;
    double maxrow = 1;
    for (auto& kv : by_depth) maxrow = std::max(maxrow, (double)kv.second.size());
    L.width = kPad * 2 + maxrow * (kNodeW + kNodeGapX);
    L.height = kPad * 2 + (maxdepth + 1) * kRowH;

    std::map<int, int> node_index;
    for (auto& kv : by_depth) {
        int d = kv.first;
        auto& row = kv.second;
        std::sort(row.begin(), row.end());
        double row_w = row.size() * kNodeW + (row.size() - 1) * kNodeGapX;
        double x0 = std::max(kPad, (L.width - row_w) / 2.0);
        for (size_t k = 0; k < row.size(); ++k) {
            int b = row[k];
            CfgNode n;
            n.block = b;
            n.x = x0 + (double)k * (kNodeW + kNodeGapX);
            n.y = kPad + (double)d * kRowH;
            n.w = kNodeW;
            n.h = 44;
            auto it = status.find(b);
            if (it != status.end()) {
                n.status = it->second;
            } else if (diff && is_new) {
                n.status = "removed";
            } else if (diff) {
                n.status = "added";
            }
            const Block& blk = f.blocks[b];
            char buf[160];
            std::snprintf(buf, sizeof(buf), "B%d  %s  (%zu insn)", b,
                          hex(blk.start).c_str(), blk.insns.size());
            n.label = buf;
            std::string det = "block B" + std::to_string(b) + " @ 0x" + hex(blk.start) +
                              " – 0x" + hex(blk.end) + "\\n";
            for (size_t ii = 0; ii < blk.insns.size() && ii < 12; ++ii) {
                det += "0x" + hex(f.insns[blk.insns[ii]].addr) + "  " +
                       insn_text(f.insns[blk.insns[ii]]) + "\\n";
            }
            if (blk.insns.size() > 12) det += "…\\n";
            n.detail = det;
            node_index[b] = (int)L.nodes.size();
            L.nodes.push_back(n);
        }
    }

    // Edges.
    std::map<int, int> depth_of;
    for (auto& kv : depth) depth_of[kv.first] = kv.second;
    for (const auto& blk : f.blocks) {
        auto it = node_index.find(blk.id);
        if (it == node_index.end()) continue;
        for (size_t e = 0; e < blk.succ.size(); ++e) {
            int s = blk.succ[e];
            auto jt = node_index.find(s);
            if (jt == node_index.end()) continue;
            CfgEdge ed;
            ed.from = it->second;
            ed.to = jt->second;
            ed.kind = e < blk.succ_kind.size() ? blk.succ_kind[e] : 0;
            ed.back = depth_of[s] <= depth_of[blk.id] && ed.kind != 0;
            L.edges.push_back(ed);
        }
    }
    return L;
}

std::string svg_cfg(const CfgLayout& L, bool is_new) {
    std::ostringstream o;
    // Size the canvas to its container instead of emitting the absolute layout
    // width: a wide switch fan-out must not force a horizontal scrollbar.
    o << "<svg class=\"cfg\" viewBox=\"0 0 " << (int)L.width << " " << (int)L.height
      << "\" preserveAspectRatio=\"xMinYMin meet\" xmlns=\"http://www.w3.org/2000/svg\""
      << " role=\"img\">";
    o << "<defs>";
    for (const char* id : {"arw", "arww", "arwb", "arwr", "arwg"}) {
        const char* col = std::string(id) == "arwr" ? kRed
                          : std::string(id) == "arwg" ? kGreen
                          : std::string(id) == "arww" ? kAmber
                                                      : kDim;
        o << "<marker id=\"" << id
          << "\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" "
             "markerHeight=\"6\" orient=\"auto-start-reverse\">"
          << "<path d=\"M0,0 L10,5 L0,10 z\" fill=\"" << col << "\"/></marker>";
    }
    o << "</defs>";

    // Edges first so boxes cover them.
    for (const auto& e : L.edges) {
        const CfgNode& a = L.nodes[e.from];
        const CfgNode& b = L.nodes[e.to];
        double x1 = a.x + a.w / 2, y1 = a.y + a.h;
        double x2 = b.x + b.w / 2, y2 = b.y;
        const char* col = e.back ? kAmber : (e.kind == 2 ? kPurple : kDim);
        const char* marker = e.back ? "arww" : (e.kind == 2 ? "arww" : "arw");
        std::string dash = e.kind == 0 ? "" : " stroke-dasharray=\"4 3\"";
        if (e.kind == 0 && b.y <= a.y) dash = " stroke-dasharray=\"4 3\"";
        o << "<path d=\"M" << x1 << "," << y1;
        if (std::fabs(x1 - x2) < 1.0) {
            o << " L" << x2 << "," << y2;
        } else {
            double my = (y1 + y2) / 2;
            o << " C" << x1 << "," << my << " " << x2 << "," << my << " " << x2 << ","
              << y2;
        }
        o << "\" fill=\"none\" stroke=\"" << col << "\" stroke-width=\"1.4\"" << dash
          << " marker-end=\"url(#" << marker << ")\"/>";
    }
    for (const auto& n : L.nodes) {
        std::string fill = kPanel2, stroke = kLine, fg = kText;
        if (n.status == "added" || (is_new && n.status == "added")) {
            fill = "#0f2d17";
            stroke = kGreen;
        } else if (n.status == "removed" || (!is_new && n.status == "removed")) {
            fill = "#2d1214";
            stroke = kRed;
        } else if (n.status == "modified") {
            fill = is_new ? "#2b2411" : "#2b2411";
            stroke = kAmber;
        } else if (n.status == "same") {
            stroke = is_new ? "#2f6b3a" : "#3a4a5f";
        }
        if (n.status.empty()) {
            stroke = kLine;
        }
        o << "<g class=\"node\" data-b=\"" << n.block << "\">";
        o << "<title>" << html_escape(n.detail) << "</title>";
        o << "<rect x=\"" << n.x << "\" y=\"" << n.y << "\" width=\"" << n.w
          << "\" height=\"" << n.h << "\" rx=\"7\" fill=\"" << fill
          << "\" stroke=\"" << stroke << "\" stroke-width=\"1.5\"/>";
        o << "<text x=\"" << (n.x + 10) << "\" y=\"" << (n.y + 18)
          << "\" fill=\"" << fg
          << "\" font-family=\"ui-monospace,SFMono-Regular,Menlo,monospace\" "
             "font-size=\"11\">"
          << html_escape(n.label) << "</text>";
        std::string st = n.status;
        if (st == "added") st = "added";
        if (!st.empty() && st != "same") {
            const char* c = st == "added" ? kGreen : st == "removed" ? kRed : kAmber;
            o << "<text x=\"" << (n.x + 10) << "\" y=\"" << (n.y + 33)
              << "\" fill=\"" << c
              << "\" font-family=\"ui-monospace,SFMono-Regular,Menlo,monospace\" "
                 "font-size=\"10\">"
              << html_escape(st) << "</text>";
        } else if (st == "same") {
            o << "<text x=\"" << (n.x + 10) << "\" y=\"" << (n.y + 33)
              << "\" fill=\"" << kDim
              << "\" font-family=\"ui-monospace,SFMono-Regular,Menlo,monospace\" "
                 "font-size=\"10\">unchanged</text>";
        }
        o << "</g>";
    }
    o << "</svg>";
    return o.str();
}

// ---------------------------------------------------------------------------
// diff table rendering
// ---------------------------------------------------------------------------

std::string render_side_by_side(const Analysis& a, const FuncPair& p, const FuncDiff& fd,
                                int max_rows) {
    std::ostringstream o;
    if (p.old_idx < 0 || p.new_idx < 0) {
        return "";
    }
    const Func& of = a.oldp.funcs[p.old_idx];
    const Func& nf = a.newp.funcs[p.new_idx];

    o << "<div class=\"sbs\">";
    int rows = 0;
    bool truncated = false;
    for (size_t bi = 0; bi < fd.blocks.size(); ++bi) {
        const BlockMatch& bm = fd.blocks[bi];
        if (bm.status == "same") {
            // Collapse identical blocks unless the whole function is shown.
            continue;
        }
        o << "<div class=\"blk\"><div class=\"blkh\">";
        o << "<span class=\"tag " << (bm.status == "added" ? "add" : bm.status == "removed" ? "del" : "mod")
          << "\">" << html_escape(bm.status) << "</span>";
        if (bm.old_b >= 0) {
            o << "<span>old B" << bm.old_b << " @ 0x"
              << hex(of.blocks[bm.old_b].start) << "</span>";
        }
        if (bm.new_b >= 0) {
            o << "<span>new B" << bm.new_b << " @ 0x"
              << hex(nf.blocks[bm.new_b].start) << "</span>";
        }
        if (bm.n_added || bm.n_removed) {
            o << "<span class=\"delta\">+" << bm.n_added << "/-" << bm.n_removed
              << "</span>";
        }
        o << "</div><table class=\"rows\"><tbody>";
        for (size_t k = 0; k < bm.ops.size(); ++k) {
            if (rows >= max_rows) {
                truncated = true;
                break;
            }
            char c = bm.ops[k];
            std::string cls = c == '+' ? "ins-add" : c == '-' ? "ins-del" : "";
            o << "<tr class=\"" << cls << "\">";
            o << "<td class=\"mark\">" << (c == '=' ? "" : std::string(1, c)) << "</td>";
            if (k < bm.old_i.size() && bm.old_i[k] >= 0 &&
                bm.old_i[k] < (int)of.insns.size()) {
                const Insn& in = of.insns[bm.old_i[k]];
                o << "<td class=\"addr\">" << hex(in.addr) << "</td><td class=\"code\">"
                  << html_escape(insn_text(in)) << "</td>";
            } else {
                o << "<td class=\"addr\"></td><td class=\"code empty\"></td>";
            }
            if (k < bm.new_i.size() && bm.new_i[k] >= 0 &&
                bm.new_i[k] < (int)nf.insns.size()) {
                const Insn& in = nf.insns[bm.new_i[k]];
                o << "<td class=\"addr\">" << hex(in.addr) << "</td><td class=\"code\">"
                  << html_escape(insn_text(in)) << "</td>";
            } else {
                o << "<td class=\"addr\"></td><td class=\"code empty\"></td>";
            }
            o << "</tr>";
            ++rows;
        }
        o << "</tbody></table></div>";
        if (truncated) break;
    }
    if (rows == 0) {
        o << "<p class=\"muted\">No basic-block level changes detected.</p>";
    }
    if (truncated) {
        o << "<p class=\"muted\">Output truncated at " << max_rows
          << " rows; open the JSON or run with --full for everything.</p>";
    }
    o << "</div>";
    return o.str();
}

std::string fmt(double v, int places = 3) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.*f", places, v);
    return buf;
}

std::string status_class(const std::string& s) {
    if (s == "identical") return "ok";
    if (s == "modified") return "chg";
    if (s == "added") return "new";
    if (s == "removed") return "del";
    return "muted";
}

}  // namespace

std::string build_report_html(const Analysis& a, bool standalone) {
    (void)standalone;
    std::ostringstream o;
    o << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
      << "<title>Binary diff report</title><style>";

    o << R"CSS(
*{box-sizing:border-box}
:root{--bg:)CSS" << kBg << R"CSS(;--panel:)CSS" << kPanel << R"CSS(;--panel2:)CSS"
      << kPanel2 << R"CSS(;--line:)CSS" << kLine << R"CSS(;--fg:)CSS" << kText
      << R"CSS(;--dim:)CSS" << kDim << R"CSS(;--accent:)CSS" << kAccent
      << R"CSS(;--green:)CSS" << kGreen << R"CSS(;--red:)CSS" << kRed
      << R"CSS(;--amber:)CSS" << kAmber << R"CSS(;--purple:)CSS" << kPurple << R"CSS(;}
html,body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:26px 22px 80px}
header.top{display:flex;flex-wrap:wrap;gap:18px;align-items:baseline;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:22px}
h1{font-size:21px;margin:0;letter-spacing:-.01em}
h2{font-size:16px;margin:30px 0 12px;letter-spacing:.01em}
h3{font-size:14px;margin:18px 0 8px}
.sub{color:var(--dim);font-size:12.5px}
.mono,code,.code,.addr,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:8px 0 4px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 15px}
.card .k{color:var(--dim);font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:23px;font-weight:600;margin-top:4px}
.card .v small{font-size:12px;color:var(--dim);font-weight:400}
.card.sec{border-color:#5a2226}.card.sec .v{color:var(--red)}
.card.ok{border-color:#24522f}.card.ok .v{color:var(--green)}
.card.warn{border-color:#5a4a1a}.card.warn .v{color:var(--amber)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0;background:var(--panel);z-index:2}
tr:hover td{background:#1a2030}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid var(--line);white-space:nowrap}
.pill.ok{color:var(--green);border-color:#24522f;background:#0d1f12}
.pill.chg{color:var(--amber);border-color:#5a4a1a;background:#241e0c}
.pill.new{color:var(--green);border-color:#24522f;background:#0d1f12}
.pill.del{color:var(--red);border-color:#5a2226;background:#241012}
.pill.info{color:var(--accent);border-color:#22406b;background:#0d1728}
.pill.risk{color:var(--amber);border-color:#5a4a1a;background:#241e0c}
.pill.security{color:var(--red);border-color:#5a2226;background:#241012}
.muted{color:var(--dim)}
small.mono{font-size:11px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:8px}
.meta .row{display:flex;gap:8px;font-size:12.5px;padding:3px 0;border-bottom:1px dashed #202838}
.meta .row .k{color:var(--dim);min-width:92px}
.hash{word-break:break-all;font-size:11px;color:var(--dim)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--line);border-radius:8px;padding:13px 15px;margin:10px 0}
.finding.security{border-left-color:var(--red)}
.finding.risk{border-left-color:var(--amber)}
.finding.info{border-left-color:var(--accent)}
.finding h3{margin:0 0 4px;font-size:14px}
.finding .cond{color:var(--dim);font-size:12px;margin-bottom:6px}
.finding ul{margin:6px 0 0;padding-left:18px;color:var(--dim);font-size:12.5px}
details{border:1px solid var(--line);border-radius:9px;margin:10px 0;background:var(--panel)}
details>summary{cursor:pointer;padding:11px 14px;list-style:none;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details>summary::-webkit-details-marker{display:none}
details>summary .caret{color:var(--dim);transition:transform .15s}
details[open]>summary .caret{transform:rotate(90deg)}
details .body{padding:4px 14px 16px;border-top:1px solid var(--line)}
.cfgwrap{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:1000px){.cfgwrap{grid-template-columns:1fr}}
.cfgpanel{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:8px;overflow:auto hidden;max-height:460px}
.cfgpanel .cap{font-size:11.5px;color:var(--dim);padding:2px 4px 6px;display:flex;justify-content:space-between}
svg.cfg{display:block;width:100%;height:auto}
.sbs{display:grid;gap:12px}
.blk{background:var(--panel2);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.blkh{display:flex;gap:14px;flex-wrap:wrap;align-items:center;padding:7px 11px;background:#1a2130;font-size:12px;color:var(--dim)}
.tag{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;padding:1px 6px;border-radius:4px}
.tag.add{color:var(--green);background:#0d1f12;border:1px solid #24522f}
.tag.del{color:var(--red);background:#241012;border:1px solid #5a2226}
.tag.mod{color:var(--amber);background:#241e0c;border:1px solid #5a4a1a}
table.rows td{padding:2px 7px;border-bottom:none;font-size:12px;white-space:pre}
table.rows td.mark{width:14px;color:var(--dim);text-align:center}
table.rows td.addr{width:80px;color:#5f6d84}
table.rows td.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
table.rows td.empty{background:#141924}
tr.ins-add td{background:#0f2415}
tr.ins-add td.mark{color:var(--green)}
tr.ins-del td{background:#251013}
tr.ins-del td.mark{color:var(--red)}
tr.ins-add td.addr{color:#3a7a48}
tr.ins-del td.addr{color:#8a3b3b}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
input[type=search],select{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:7px 10px;font-size:13px}
input[type=search]{min-width:260px}
.btn{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:7px 11px;font-size:12.5px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.on{border-color:var(--accent);color:var(--accent)}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:11.5px;color:var(--dim);margin:6px 0 0}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:middle}
.footer{margin-top:40px;border-top:1px solid var(--line);padding-top:14px;color:var(--dim);font-size:11.5px}
.bar{height:6px;background:#202838;border-radius:999px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#3d6fd0,#6aa8ff)}
.weights{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:8px}
.wcell{background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:7px 9px;font-size:12px}
.wcell b{color:var(--accent);font-weight:600}
)CSS";
    o << "</style></head><body><div class=\"wrap\">";

    // Header.
    o << "<header class=\"top\"><div><h1>Function-level binary diff</h1><div class=\"sub\">"
      << html_escape(a.oldb.path) << " &nbsp;→&nbsp; " << html_escape(a.newb.path)
      << "</div></div><div class=\"sub\">mode <b>" << html_escape(a.mode)
      << "</b> · pair threshold " << fmt(a.min_pair, 2) << " · " << fmt(a.elapsed_ms, 0)
      << " ms</div></header>";

    // Counters.
    int sec = 0;
    for (const auto& f : a.findings) {
        if (f.category == "security") ++sec;
    }
    int matched = 0, identical = 0, modified = 0, added = 0, removed = 0;
    for (const auto& p : a.pairs) {
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
    o << "<div class=\"grid\">";
    auto card = [&](const char* cls, const char* k, const std::string& v,
                    const std::string& small) {
        o << "<div class=\"card " << cls << "\"><div class=\"k\">" << k
          << "</div><div class=\"v\">" << v;
        if (!small.empty()) o << " <small>" << small << "</small>";
        o << "</div></div>";
    };
    card(sec ? "sec" : "ok", "Security-relevant changes", std::to_string(sec), "findings");
    card("", "Functions matched", std::to_string(matched),
         "of " + std::to_string(a.oldp.funcs.size()) + "/" +
             std::to_string(a.newp.funcs.size()));
    card("", "Identical", std::to_string(identical), "");
    card("warn", "Modified", std::to_string(modified), "");
    card("", "Added / removed", std::to_string(added) + " / " + std::to_string(removed), "");
    card("", "Functions recovered", std::to_string(a.oldp.funcs.size()) + " / " +
                                        std::to_string(a.newp.funcs.size()),
         "old / new");
    o << "</div>";

    // Input metadata.
    o << "<div class=\"meta\">";
    auto meta_col = [&](const char* title, const Binary& b) {
        o << "<div class=\"card\"><div class=\"k\">" << title << "</div>";
        o << "<div class=\"row\"><span class=\"k\">path</span><span class=\"mono\">"
          << html_escape(b.path) << "</span></div>";
        o << "<div class=\"row\"><span class=\"k\">sha256</span><span class=\"hash\">"
          << b.sha256 << "</span></div>";
        o << "<div class=\"row\"><span class=\"k\">build-id</span><span class=\"mono\">"
          << (b.build_id.empty() ? "<span class=muted>none</span>" : b.build_id)
          << "</span></div>";
        o << "<div class=\"row\"><span class=\"k\">symbols</span><span class=\"mono\">"
          << (b.has_symtab ? "symtab" : "") << (b.has_dynsym ? " dynsym" : "")
          << (b.stripped ? " (stripped)" : "") << "</span></div>";
        o << "<div class=\"row\"><span class=\"k\">entry</span><span class=\"mono\">0x"
          << hex(b.entry) << "</span></div>";
        o << "<div class=\"row\"><span class=\"k\">size</span><span class=\"mono\">"
          << b.data.size() << " bytes</span></div>";
        o << "</div>";
    };
    meta_col("Old binary", a.oldb);
    meta_col("New binary", a.newb);
    o << "</div>";

    // Quick verdict.
    if (sec > 0) {
        o << "<div class=\"finding security\"><h3>Verdict</h3><div class=\"cond\">"
          << "The patch adds " << sec
          << " security-relevant guard(s). The most likely intent is input validation "
             "(bounds/length/range checks) on paths that previously proceeded unchecked."
          << "</div></div>";
    } else if (modified > 0 || added + removed > 0) {
        o << "<div class=\"finding info\"><h3>Verdict</h3><div class=\"cond\">"
          << "Code changed but no guard-shaped construct was detected automatically. "
             "Review the modified functions below."
          << "</div></div>";
    } else {
        o << "<div class=\"finding info\"><h3>Verdict</h3><div class=\"cond\">"
          << "The two binaries are functionally identical at function granularity."
          << "</div></div>";
    }

    // Findings.
    if (!a.findings.empty()) {
        o << "<h2>Findings</h2>";
        for (const auto& f : a.findings) {
            o << "<div class=\"finding " << f.category << "\">";
            o << "<h3>" << html_escape(f.title) << " <span class=\"pill " << f.category
              << "\">" << f.kind << "</span> <span class=\"pill info\">conf "
              << fmt(f.confidence, 2) << "</span></h3>";
            o << "<div class=\"cond\">" << html_escape(f.detail) << "</div>";
            o << "<div class=\"cond mono\">";
            if (f.old_func >= 0) {
                o << "old " << html_escape(a.oldp.funcs[f.old_func].name) << " @ 0x"
                  << hex(a.oldp.funcs[f.old_func].start) << "  ";
            }
            if (f.new_func >= 0) {
                o << "new " << html_escape(a.newp.funcs[f.new_func].name) << " @ 0x"
                  << hex(a.newp.funcs[f.new_func].start) << "  ";
            }
            if (f.new_addr) o << "site 0x" << hex(f.new_addr);
            o << "</div>";
            if (!f.evidence.empty()) {
                o << "<ul>";
                for (auto& e : f.evidence) o << "<li>" << html_escape(e) << "</li>";
                o << "</ul>";
            }
            o << "</div>";
        }
    }

    // Scoring weights, for transparency / tuning.
    o << "<h2>Pairing weights</h2><div class=\"card\"><div class=\"sub\">"
         "Score = Σ wᵢ·sᵢ / Σ wᵢ over the features below. Adjust with "
         "<span class=\"mono\">--weights name=0.3,seq=0.2,...</span></div>"
         "<div class=\"weights\">";
    for (const auto& kv : a.weights.as_map()) {
        o << "<div class=\"wcell\"><b>" << kv.first << "</b> = " << fmt(kv.second, 2)
          << "</div>";
    }
    o << "</div></div>";

    // Function table.
    o << "<h2>Functions</h2>";
    o << "<div class=\"controls\">"
         "<input id=\"q\" type=\"search\" placeholder=\"filter by name or address…\">"
         "<select id=\"st\"><option value=\"\">all statuses</option>"
         "<option value=\"changed\">changed only</option>"
         "<option value=\"identical\">identical</option>"
         "<option value=\"added\">added</option>"
         "<option value=\"removed\">removed</option></select>"
         "<button class=\"btn\" id=\"expand\">expand all</button>"
         "<button class=\"btn\" id=\"collapse\">collapse all</button>"
         "<span class=\"sub\" id=\"count\"></span></div>";
    o << "<div class=\"legend\"><span><i style=\"background:#0f2d17;border:1px solid #3fb950\"></i>added</span>"
         "<span><i style=\"background:#2d1214;border:1px solid #f85149\"></i>removed</span>"
         "<span><i style=\"background:#2b2411;border:1px solid #d29922\"></i>modified block</span>"
         "<span><i style=\"background:#161a23;border:1px solid #2a3242\"></i>unchanged</span></div>";

    // Build findings-per-pair index.
    std::map<int, std::vector<int>> findings_by_pair;
    for (size_t k = 0; k < a.findings.size(); ++k) {
        if (a.findings[k].pair_index >= 0) {
            findings_by_pair[a.findings[k].pair_index].push_back((int)k);
        }
    }

    for (size_t pi = 0; pi < a.pairs.size(); ++pi) {
        const FuncPair& p = a.pairs[pi];
        const FuncDiff& fd = a.diffs[pi];
        std::string name = p.old_idx >= 0 ? a.oldp.funcs[p.old_idx].name
                                          : a.newp.funcs[p.new_idx].name;
        std::string disp_status = p.status;
        if (p.status == "modified" && fd.identical) disp_status = "identical";
        bool changed = !(disp_status == "identical");
        auto fit = findings_by_pair.find((int)pi);
        std::string extra;
        if (fit != findings_by_pair.end()) {
            int nsec = 0;
            for (int k : fit->second) {
                if (a.findings[k].category == "security") ++nsec;
            }
            extra = "<span class=\"pill security\">" + std::to_string(fit->second.size()) +
                    " finding" + (fit->second.size() == 1 ? "" : "s") + "</span>";
            if (nsec == 0) {
                extra = "<span class=\"pill risk\">" + std::to_string(fit->second.size()) +
                        " finding" + (fit->second.size() == 1 ? "" : "s") + "</span>";
            }
        }
        o << "<details class=\"func\" data-status=\"" << (changed ? "changed" : "identical")
          << "\" data-name=\"" << html_escape(lower(name)) << " "
          << hex(p.old_idx >= 0 ? a.oldp.funcs[p.old_idx].start : 0) << " "
          << hex(p.new_idx >= 0 ? a.newp.funcs[p.new_idx].start : 0) << "\">";
        o << "<summary><span class=\"caret\">▶</span>";
        o << "<span class=\"pill " << status_class(disp_status) << "\">" << disp_status
          << "</span>";
        o << "<b class=\"mono\">" << html_escape(name) << "</b>";
        if (p.old_idx >= 0) {
            o << "<span class=\"sub mono\">old 0x" << hex(a.oldp.funcs[p.old_idx].start)
              << " · " << a.oldp.funcs[p.old_idx].insns.size() << " insn</span>";
        }
        if (p.new_idx >= 0) {
            o << "<span class=\"sub mono\">new 0x" << hex(a.newp.funcs[p.new_idx].start)
              << " · " << a.newp.funcs[p.new_idx].insns.size() << " insn</span>";
        }
        if (p.old_idx >= 0 && p.new_idx >= 0) {
            o << "<span class=\"sub\">score <b>" << fmt(p.score, 3) << "</b></span>";
            if (fd.blocks_added || fd.blocks_removed || fd.blocks_modified) {
                o << "<span class=\"sub\">blocks +" << fd.blocks_added << " −"
                  << fd.blocks_removed << " ~" << fd.blocks_modified << "</span>";
            }
            if (fd.insns_added || fd.insns_removed) {
                o << "<span class=\"sub\">insn +" << fd.insns_added << " −"
                  << fd.insns_removed << "</span>";
            }
        }
        o << extra;
        o << "</summary><div class=\"body\">";

        // Score breakdown.
        if (!p.parts.empty()) {
            o << "<div class=\"sub\" style=\"margin-bottom:8px\">Score breakdown</div>"
                 "<div class=\"weights\">";
            for (const auto& kv : p.parts) {
                o << "<div class=\"wcell\">" << kv.first << " <b>" << fmt(kv.second, 2)
                  << "</b>";
                auto wt = p.weights_used.find(kv.first);
                if (wt != p.weights_used.end()) {
                    o << " <span class=\"muted\">×" << fmt(wt->second, 2) << "</span>";
                }
                o << "<div class=\"bar\"><i style=\"width:"
                  << (int)std::lround(std::max(0.0, std::min(1.0, kv.second)) * 100.0)
                  << "%\"></i></div></div>";
            }
            o << "</div>";
        }

        // CFG comparison.
        if (p.old_idx >= 0 && p.new_idx >= 0) {
            const Func& of = a.oldp.funcs[p.old_idx];
            const Func& nf = a.newp.funcs[p.new_idx];
            CfgLayout lo = layout_cfg(a.oldp, of, &fd, false);
            CfgLayout ln = layout_cfg(a.newp, nf, &fd, true);
            o << "<h3>Control-flow graphs</h3><div class=\"cfgwrap\">";
            o << "<div class=\"cfgpanel\"><div class=\"cap\"><span>old · " << of.blocks.size()
              << " blocks</span><span>0x" << hex(of.start) << "</span></div>"
              << svg_cfg(lo, false);
            if (lo.truncated) o << "<div class=\"cap muted\">layout truncated</div>";
            o << "</div>";
            o << "<div class=\"cfgpanel\"><div class=\"cap\"><span>new · " << nf.blocks.size()
              << " blocks</span><span>0x" << hex(nf.start) << "</span></div>"
              << svg_cfg(ln, true);
            if (ln.truncated) o << "<div class=\"cap muted\">layout truncated</div>";
            o << "</div></div>";
        } else if (p.new_idx >= 0) {
            const Func& nf = a.newp.funcs[p.new_idx];
            CfgLayout ln = layout_cfg(a.newp, nf, &fd, true);
            o << "<h3>Control-flow graph (added)</h3><div class=\"cfgpanel\">"
              << svg_cfg(ln, true) << "</div>";
        } else if (p.old_idx >= 0) {
            const Func& of = a.oldp.funcs[p.old_idx];
            CfgLayout lo = layout_cfg(a.oldp, of, &fd, false);
            o << "<h3>Control-flow graph (removed)</h3><div class=\"cfgpanel\">"
              << svg_cfg(lo, false) << "</div>";
        }

        // Instruction-level diff.
        if (p.old_idx >= 0 && p.new_idx >= 0 && !fd.identical) {
            o << "<h3>Basic-block diff</h3>"
              << render_side_by_side(a, p, fd, 4000);
        }
        o << "</div></details>";
    }

    // Footer.
    o << "<div class=\"footer\">Generated " << html_escape(a.generated)
      << " · bcdiff · pairing threshold " << fmt(a.min_pair, 2)
      << " · weights " << [&] {
             std::vector<std::string> v;
             for (auto& kv : a.weights.as_map()) {
                 v.push_back(kv.first + "=" + fmt(kv.second, 2));
             }
             return html_escape(join(v, ", "));
         }()
      << "</div>";

    // Script.
    o << R"JS(<script>
(function(){
  var q=document.getElementById('q'),st=document.getElementById('st'),
      cnt=document.getElementById('count'),items=[].slice.call(document.querySelectorAll('details.func'));
  function apply(){
    var term=(q.value||'').trim().toLowerCase(),mode=st.value,n=0;
    items.forEach(function(el){
      var okName=!term||el.getAttribute('data-name').indexOf(term)>=0;
      var okStat=!mode||el.getAttribute('data-status')===mode||
        (mode==='added'&&el.querySelector('.pill.new'))||
        (mode==='removed'&&el.querySelector('.pill.del'));
      var show=okName&&okStat;el.style.display=show?'':'none';if(show)n++;
    });
    cnt.textContent=n+' of '+items.length+' functions';
  }
  q.addEventListener('input',apply);st.addEventListener('change',apply);
  document.getElementById('expand').onclick=function(){items.forEach(function(e){e.open=true})};
  document.getElementById('collapse').onclick=function(){items.forEach(function(e){e.open=false})};
  apply();
})();
</script>)JS";
    o << "</div></body></html>";
    return o.str();
}

}  // namespace bcd
