"""Self-contained, interactive HTML report.

Data-driven: findings are embedded as JSON and rendered client-side, giving
expandable rows with highlighted multi-line context, copy buttons and rich
filtering. No external dependencies; works offline.
"""
from __future__ import annotations

import json
import re

_TEMPLATE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exhume — __TARGET__</title>
<style>
:root{
 --bg:#0a0d13;--panel:#121722;--panel2:#171e2b;--line:#222c3c;--txt:#e7ebf2;--mut:#8a97ab;
 --crit:#f43f5e;--high:#f59e0b;--med:#38bdf8;--live:#22c55e;--accent:#8b5cf6;--accent2:#6d8cff;--mark:#fde047;
 --crit-bg:rgba(244,63,94,.12);--high-bg:rgba(245,158,11,.12);--med-bg:rgba(56,189,248,.12);--live-bg:rgba(34,197,94,.12);
 --shadow:0 10px 30px -12px rgba(0,0,0,.55);
}
*{box-sizing:border-box}
html{scrollbar-color:#2c3a52 var(--bg)}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#242f42;border-radius:8px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:#324059}
body{margin:0;background:
 radial-gradient(900px 480px at 15% -8%,rgba(139,92,246,.09),transparent 60%),
 radial-gradient(900px 480px at 100% 0%,rgba(56,189,248,.07),transparent 55%),
 var(--bg);
 color:var(--txt);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
 font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;font-size:14px}
a{color:var(--med)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
header{padding:18px 28px;background:linear-gradient(180deg,#151c2c,#0c1019);border-bottom:1px solid var(--line);
 position:sticky;top:0;z-index:30;box-shadow:var(--shadow)}
header::before{content:"";display:block;height:3px;margin:-18px -28px 15px;
 background:linear-gradient(90deg,var(--accent),var(--accent2),var(--med))}
.brand{display:flex;align-items:center;gap:9px;font-size:19px;font-weight:800;letter-spacing:.2px}
.brand .paw{font-size:22px}
.brand::before{content:"";width:9px;height:9px;border-radius:50%;background:var(--accent);
 box-shadow:0 0 0 4px rgba(139,92,246,.18)}
.brand .tag{color:var(--mut);font-weight:500;font-size:13px}
.meta{color:var(--mut);font-size:12.5px;margin-top:7px;line-height:1.6;overflow-wrap:anywhere}
.meta .tgt{color:#c7cedb;background:var(--panel2);border-radius:5px;padding:1px 6px}
.meta .mgen{color:#5b6677;font-size:11.5px;margin-left:9px}
.metachips{display:flex;flex-wrap:wrap;align-items:flex-start;gap:7px;margin-top:9px}
.mchip{background:var(--panel2);border:1px solid var(--line);border-radius:999px;padding:3px 11px;
 font-size:12px;color:var(--mut);display:inline-flex;gap:5px;align-items:center}
.mchip b{color:var(--txt);font-weight:700;font-variant-numeric:tabular-nums}
/* A floating popover, not an inline expand: the old in-flow <details> pushed its flex sibling
   (part of .metachips) down and to the side when opened, leaving a large empty gap in the row —
   position:absolute keeps it from disturbing the chips' layout at all. */
.covdetails{position:relative;display:inline-block}
.covdetails summary{list-style:none;cursor:pointer;background:var(--panel2);border:1px solid var(--line);
 border-radius:999px;padding:3px 11px;font-size:12px;color:var(--mut)}
.covdetails summary::-webkit-details-marker{display:none}
.covdetails summary::after{content:" \25BE";color:var(--accent)}
.covdetails[open] summary::after{content:" \25B4"}
.covpanel{position:absolute;top:calc(100% + 6px);left:0;z-index:25;min-width:300px;max-width:min(420px,80vw);
 background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;box-shadow:var(--shadow)}
.covgroup+.covgroup{margin-top:10px;padding-top:10px;border-top:1px solid var(--line)}
.covgroup h4{margin:0 0 6px;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:700}
.covlist{list-style:none;margin:0;padding:0;font-size:12px;color:var(--mut);display:flex;flex-direction:column;gap:6px}
.covlist b{color:var(--txt);font-variant-numeric:tabular-nums;margin-right:4px}
.covhint{display:block;color:#93c5fd;font-size:11px;margin-top:1px}
.mnoterow{display:flex;flex-wrap:wrap;align-items:flex-start;gap:8px;margin-top:8px}
.mnote{font-size:12.5px;border-radius:9px;padding:7px 12px}
.mnote b{font-variant-numeric:tabular-nums}
.mnote.warn{background:#1c140a;border:1px solid #5a3d1a;color:#ffcf99}
.mnote.warn b{color:#ffdca8}
.mnote.ai{background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.35);color:#c4b5fd;white-space:nowrap}
.mnote.ai b{color:#ded0ff}
.badge-mask{background:#2a1d10;color:#ffcf99;border:1px solid #5a3d1a;border-radius:6px;padding:1px 7px;font-size:11px;margin-left:8px}
main{padding:24px 28px 60px;max-width:1600px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:18px}
@media (max-width:860px){.cards{grid-template-columns:repeat(2,1fr)}main{padding:18px 14px 50px}}
@media (max-width:480px){.cards{grid-template-columns:1fr}}
.card{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 17px;
 cursor:pointer;overflow:hidden;transition:transform .14s ease,border-color .14s,box-shadow .14s}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--line)}
.card:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.card.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.card .n{font-size:28px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-top:7px;font-weight:600}
.card.crit .n{color:var(--crit)}.card.high .n{color:var(--high)}.card.med .n{color:var(--med)}
.card.live .n{color:var(--live)}
.card.crit::before{background:var(--crit)}.card.high::before{background:var(--high)}
.card.med::before{background:var(--med)}.card.live::before{background:var(--live)}
.card.crit{background:linear-gradient(160deg,var(--crit-bg),var(--panel) 55%)}
.card.high{background:linear-gradient(160deg,var(--high-bg),var(--panel) 55%)}
.card.med{background:linear-gradient(160deg,var(--med-bg),var(--panel) 55%)}
.card.live{background:linear-gradient(160deg,var(--live-bg),var(--panel) 55%)}
.bar{height:7px;border-radius:6px;overflow:hidden;display:flex;margin:2px 0 18px;background:var(--panel2);box-shadow:inset 0 0 0 1px var(--line)}
.bar i{display:block;height:100%;transition:width .3s ease}
.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:14px;background:var(--panel);
 border:1px solid var(--line);border-radius:12px;padding:10px}
.toolbar input[type=text],.toolbar select{padding:9px 12px;background:var(--panel2);border:1px solid var(--line);
 color:var(--txt);border-radius:9px;font-size:13.5px;transition:border-color .12s}
.toolbar input[type=text]:focus,.toolbar select:focus{border-color:var(--accent);outline:none}
.toolbar input[type=text]{flex:1;min-width:240px}
.sep{width:1px;align-self:stretch;background:var(--line);margin:2px 2px}
@media (max-width:860px){.sep{display:none}}
.seg{display:flex;border:1px solid var(--line);border-radius:9px;overflow:hidden;background:var(--panel2)}
.seg button{padding:8px 13px;background:transparent;color:var(--mut);border:0;cursor:pointer;font-size:13px;font-weight:600;transition:background .12s,color .12s}
.seg button:hover{color:var(--txt)}
.seg button.active{background:var(--accent);color:#fff}
.tog{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none}
.tog input[type=checkbox]{accent-color:var(--accent)}
.count{color:var(--mut);font-size:13px;margin-left:auto}
/* No overflow-x here on purpose: it would make this element a scroll container, which hijacks
   position:sticky on the th's below (they'd stick to this box's edge instead of the page's), causing
   the header row to detach and float mid-table. Location/value are truncated instead so the table
   doesn't need its own horizontal scrollbar; on anything narrower the whole page scrolls. */
.tablewrap{border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{border-collapse:collapse;width:100%}
thead th{position:sticky;top:var(--hdrH,73px);background:#0f1420;z-index:10;text-align:left;color:var(--mut);
 font-weight:700;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;padding:11px 12px;border-bottom:1px solid var(--line)}
thead th:first-child{border-top-left-radius:12px}
thead th:last-child{border-top-right-radius:12px}
thead th.sortable{cursor:pointer;user-select:none}
thead th.sortable:hover{color:var(--txt)}
.sortarrow{margin-left:4px;color:var(--accent);display:inline-block;width:9px}
tbody td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr.row{cursor:pointer;transition:background .1s}
tbody tr.row:hover{background:#121a28}
tbody tr.row.picked{background:rgba(139,92,246,.12);box-shadow:inset 3px 0 0 var(--accent)}
tbody tr.row.picked:hover{background:rgba(139,92,246,.18)}
tbody tr:last-child td{border-bottom:none}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;font-size:10.5px;font-weight:800;letter-spacing:.04em}
.pill::before{content:"";width:6px;height:6px;border-radius:50%}
.p3{background:#3a1420;color:#fda4af}.p3::before{background:var(--crit)}
.p2{background:#3a2c12;color:#fcd34d}.p2::before{background:var(--high)}
.p1{background:#0e2c3f;color:#7dd3fc}.p1::before{background:var(--med)}
.vbadge{font-weight:800;font-size:12px}.v-live,.v-valid{color:var(--live)}.v-dead,.v-invalid{color:#64748b}
.v-unknown{color:#5b6677;font-weight:700;cursor:help;border-bottom:1px dotted #5b6677}
.det{color:var(--txt)}
.loc{color:var(--mut);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.loc{word-break:break-all}
.locpath{display:inline-block;max-width:min(540px,42vw);overflow:hidden;text-overflow:ellipsis;
 white-space:nowrap;vertical-align:bottom;color:var(--mut);font-family:ui-monospace,Menlo,Consolas,monospace;
 font-size:12px;cursor:pointer}
.locpath:hover{color:var(--txt);text-decoration:underline;text-decoration-style:dotted}
body.report .locpath{cursor:default}
body.report .locpath:hover{color:var(--mut);text-decoration:none}
.val{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#fef08a;max-width:360px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom;cursor:pointer}
.val:hover{text-decoration:underline;text-decoration-style:dotted}
.occ{display:inline-block;background:var(--panel2);color:var(--mut);border:1px solid var(--line);
 border-radius:999px;padding:0 7px;font-size:10.5px;font-weight:700;margin-left:7px;vertical-align:1px}
.locs{list-style:none;margin:6px 0 0;padding:0;max-height:220px;overflow:auto;
 font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.locs li{padding:3px 0;border-bottom:1px solid var(--line);word-break:break-all;color:#cbd5e1}
.locs .more{color:var(--mut);padding-top:5px}
.caret{color:var(--mut);transition:transform .14s;display:inline-block}
tr.open .caret{transform:rotate(90deg);color:var(--accent)}
.detail td{background:#0c1119;padding:0}
.detailbox{padding:16px 18px;border-left:3px solid var(--accent);margin:2px 0;
 background:linear-gradient(90deg,rgba(139,92,246,.05),transparent 240px)}
.dgrid{display:flex;flex-wrap:wrap;gap:10px 22px;margin-bottom:12px;font-size:12.5px}
.dgrid>div{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 11px}
.dgrid .k{color:var(--mut);margin-right:6px;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.btn{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:7px;padding:6px 11px;
 cursor:pointer;font-size:12px;font-weight:600;margin-right:6px;transition:border-color .12s,transform .08s,background .12s}
.btn:hover{border-color:var(--accent);background:#1c2334}
.btn:active{transform:translateY(1px)}
.code{background:#0a0e16;border:1px solid var(--line);border-radius:10px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;margin-top:10px}
.code .ln{display:flex;white-space:pre}
.code .ln.hit{background:rgba(139,92,246,.14);box-shadow:inset 3px 0 0 var(--accent)}
.code .gutter{color:#475569;text-align:right;padding:1px 12px;user-select:none;min-width:52px;border-right:1px solid var(--line);background:#0b1017}
.code .src{padding:1px 14px;color:#cbd5e1;white-space:pre}
mark{background:var(--mark);color:#111;border-radius:3px;padding:0 2px;font-weight:700}
h3{margin:16px 0 4px;color:#cbd5e1;font-size:13.5px}
.sz{color:#5b6677}
.asset ul{columns:2;gap:22px;padding-left:18px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.asset li{margin:3px 0;break-inside:avoid}
.susp{color:var(--high);font-size:12.5px;margin:4px 0}
.aiinsight{color:#c4b5fd;font-size:12.5px;margin:4px 0;font-style:italic}
.subt{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:6px}
.subt th,.subt td{border:1px solid var(--line);padding:5px 9px;text-align:left}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:18px 0;color:var(--mut);font-size:13px}
.pager button:disabled{opacity:.4;cursor:default}
.pager input{width:64px;padding:5px 7px;background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:7px}
.trunc{background:#2a1d10;color:#ffcf99;border:1px solid #5a3d1a;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}

.hdrrow{display:flex;align-items:flex-start;gap:14px;justify-content:space-between}
.hdrbtns{display:flex;gap:8px;flex-shrink:0}
.btn.on{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.danger:hover{border-color:var(--crit);color:#fda4af}
.x{background:none;border:0;color:#64748b;cursor:pointer;font-size:16px;padding:3px 8px;border-radius:6px;transition:background .12s,color .12s}
.x:hover{background:#3a1420;color:#fda4af}
tr.row.dis,tr.row.inv{opacity:.5}
tr.row.dis .det,tr.row.dis .val,tr.row.dis .loc{text-decoration:line-through}
.rbanner{display:none;align-items:center;gap:10px;background:#10231a;border:1px solid #1f5a3a;color:#86efac;
 border-radius:10px;padding:11px 16px;margin-bottom:14px;font-size:13px;line-height:1.5}
.rbanner .ic{font-size:17px;flex-shrink:0}
body.report .rbanner{display:flex}
body.report .noreport,body.report .toolbar .tog,body.report #pager,body.report .x,body.report .detailbtns,
body.report #assetsec,body.report .trunc,body.report .ai,body.report .card[data-sev=live]{display:none!important}
body.report .val{cursor:default}
body.report .meta .tgt{letter-spacing:.08em}
body.report .code .src{white-space:pre-wrap;word-break:break-all}
.tree details{margin:2px 0}
.tree summary{cursor:pointer;padding:5px 8px;border-radius:7px;list-style:none;font-size:13px}
.tree summary::-webkit-details-marker{display:none}
.tree summary::before{content:"▸";display:inline-block;width:16px;color:var(--mut);transition:transform .1s}
.tree details[open]>summary::before{transform:rotate(90deg)}
.tree summary:hover{background:var(--panel2)}
.tree .kids{margin-left:14px;border-left:1px solid var(--line);padding-left:8px}
.tree .file{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;padding:4px 8px 4px 22px;color:#cbd5e1;
 display:flex;justify-content:space-between;gap:14px;word-break:break-all;border-radius:6px}
.tree .file:hover{background:var(--panel2);color:var(--txt)}
.tree .cnt{color:var(--mut);font-size:12px;margin-left:6px}
.tree .more{margin:4px 0 4px 22px}
.cat{margin-top:8px}
.cat:first-child{margin-top:0}
.cat>summary{display:flex;align-items:center;gap:10px;font-weight:600;font-size:13.5px;background:var(--panel2);
 border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.cat>summary::before{align-self:center}
.cat .icon{font-size:16px;flex-shrink:0}
.cat .catlabel{display:flex;flex-direction:column;gap:1px;flex:1;min-width:0}
.cat .catdesc{color:var(--mut);font-size:11.5px;font-weight:500}
.cat .cnt{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:1px 10px;margin-left:0}
.cat .kids{margin-top:6px;margin-left:8px}
.empty{color:var(--mut);padding:40px 26px;text-align:center;font-size:13.5px}
footer{color:#48525f;font-size:12px;text-align:center;padding:30px 26px;border-top:1px solid var(--line);margin-top:30px}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(6px);background:var(--accent);color:#fff;
 padding:10px 18px;border-radius:10px;font-size:13px;font-weight:600;opacity:0;box-shadow:var(--shadow);
 transition:opacity .2s,transform .2s;pointer-events:none;z-index:50}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.ai,.assetpanel{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:18px;overflow:hidden;box-shadow:var(--shadow)}
.ai .hd,.assetpanel .hd{display:flex;align-items:center;gap:10px;padding:12px 18px;border-bottom:1px solid var(--line);background:#10151e}
.ai .hd .t,.assetpanel .hd .t{font-weight:700;font-size:14px;color:var(--txt)}
.ai .hd .tag,.assetpanel .hd .tag{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);
 border:1px solid var(--line);border-radius:999px;padding:2px 9px}
.ai .hd .by,.assetpanel .hd .by{color:#5b6677;font-size:11.5px;margin-left:auto}
.ai .bd{padding:4px 18px 14px}
.assetpanel .bd{padding:10px 14px 14px}
.ai h3{color:var(--mut);margin:14px 0 6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em}
.ai ul{margin:4px 0;padding:0;list-style:none}
.ai li{margin:5px 0;color:#cfd6e2;padding-left:16px;position:relative}
.ai li::before{content:"";position:absolute;left:2px;top:8px;width:5px;height:5px;border-radius:50%;background:var(--med)}
.ai p{margin:6px 0;color:#d2d8e2}
</style></head><body>
<header>
 <div class="hdrrow"><div>
 <div class="brand">Exhume <span class="tag">audit report</span>__MASKBADGE__</div>
 <div class="meta">__METALINE__</div></div>
 <div class="hdrbtns"><button class="btn" id="rmode" onclick="toggleReport()" title="Censor values and hide controls so you can take a client-safe screenshot">📷 Report mode</button></div></div>
</header>
<main>
 <div class="cards" id="cards">
  <div class="card crit" data-sev="3"><div class="n">__C3__</div><div class="l">Critical</div></div>
  <div class="card high" data-sev="2"><div class="n">__C2__</div><div class="l">High</div></div>
  <div class="card med"  data-sev="1"><div class="n">__C1__</div><div class="l">Medium</div></div>
  <div class="card live" data-sev="live"><div class="n">__LIVE__</div><div class="l">Verified live</div></div>
  <div class="card" data-sev="all"><div class="n">__TOTAL__</div><div class="l">Unique findings</div></div>
 </div>
 <div class="rbanner"><span class="ic">📷</span><span>REPORT MODE · values are censored, paths are relative and dismissed findings are excluded. Check the box on any row to pick it, then "Show only picked" to curate exactly what's visible for a screenshot. Click "Exit report mode" to go back.</span></div>
 <div class="bar">__BAR__</div>
 __AISECTION__
 __TRUNCNOTE__
 <div class="toolbar">
  <input type="text" id="q" placeholder="Filter by text, path, detector, value…" oninput="render()">
  <div class="seg" id="sevseg">
   <button data-sev="all" class="active" onclick="setSev('all')">All</button>
   <button data-sev="3" onclick="setSev('3')">Critical</button>
   <button data-sev="2" onclick="setSev('2')">High</button>
   <button data-sev="1" onclick="setSev('1')">Medium</button>
  </div>
  <select id="detsel" onchange="render()"><option value="">All detectors</option></select>
  <span class="sep"></span>
  <label class="tog"><input type="checkbox" id="liveonly" onchange="render()"> Verified only</label>
  <label class="tog"><input type="checkbox" id="expall" onchange="toggleAll(this.checked)"> Expand all</label>
 <label class="tog"><input type="checkbox" id="hideinv" checked onchange="render();renderExtra()" title="Hide matches that failed their check (bad checksum, IP with no host) or that the local AI judged a false positive"> Hide invalid / AI false positives</label>
  <label class="tog"><input type="checkbox" id="showdis" onchange="render()"> Show dismissed</label>
  <label class="repctl" id="pickctl" style="display:none;align-items:center;gap:6px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none">
   <input type="checkbox" id="pickonly" onchange="render()"> Show only picked<span id="pickcount"></span>
  </label>
  <button class="btn repctl" id="pickclear" style="display:none" onclick="clearPicks()" title="Unpick everything">Clear picks</button>
  <span class="sep noreport"></span>
  <button class="btn" onclick="copyLive()">Copy live creds</button>
  <button class="btn noreport" onclick="dismissFiltered()" title="Mark every finding matching the current filters as false positive">Dismiss filtered</button>
  <button class="btn noreport" onclick="exportReviewed()">Export reviewed CSV</button>
  <button class="btn noreport danger" onclick="restoreAll()">Restore all</button>
  <span class="count" id="count"></span>
 </div>

 <div class="tablewrap"><table>
  <thead><tr><th style="width:26px"></th>
   <th class="sortable" onclick="toggleSort('severity')">Severity<span class="sortarrow" id="sa-severity"></span></th>
   <th>Verified</th>
   <th class="sortable" onclick="toggleSort('detector')">Detector<span class="sortarrow" id="sa-detector"></span></th>
   <th class="sortable" onclick="toggleSort('loc')">Location<span class="sortarrow" id="sa-loc"></span></th>
   <th>Value</th><th class="fpcol" style="width:34px"></th></tr></thead>
  <tbody id="rows"></tbody>
 </table></div>

 <div class="pager" id="pager"></div>
 <div id="extra"></div>
</main>
<footer>Generated by Exhume v__VERSION__ · secrets discovery &amp; verification</footer>
<div class="toast" id="toast"></div>
__DATA__
<script>
const DATA = {findings:[],databases:[],assets:{}};
document.querySelectorAll('script.chunk').forEach(s=>{
 const d=JSON.parse(s.textContent);
 if(d.findings) for(let i=0;i<d.findings.length;i++) DATA.findings.push(d.findings[i]);
 if(d.databases) DATA.databases=d.databases;
 if(d.assets) DATA.assets=d.assets;
});
const PAGE=100; let page=0, view=[];
const ROOT=(document.querySelector('.tgt')||{}).dataset?document.querySelector('.tgt').dataset.real:'';
// The header's height isn't fixed (a long target path, coverage notes or the AI-engine line can
// wrap it to several lines), so the table header's sticky offset must track it live instead of
// assuming a constant — a stale offset left a gap where already-scrolled rows peeked through above it.
(function(){
 const hdr=document.querySelector('header');
 const sync=()=>document.documentElement.style.setProperty('--hdrH',hdr.offsetHeight+'px');
 sync();
 if(window.ResizeObserver) new ResizeObserver(sync).observe(hdr); else window.addEventListener('resize',sync);
})();
let fSev='all', REPORT=false;
const SEVLBL={3:'CRITICAL',2:'HIGH',1:'MEDIUM'};
const SKEY='exhume-dismissed:'+ROOT;
let DIS=new Set(); try{DIS=new Set(JSON.parse(localStorage.getItem(SKEY)||'[]'));}catch(e){}
function saveDis(){try{localStorage.setItem(SKEY,JSON.stringify([...DIS]));}catch(e){}}
// ---- picking (report mode): choose exactly which findings show on screen, e.g. 2 highs + 1 medium,
// independent of the severity tab/search/detector filters, so a screenshot shows precisely that mix.
const PKEY='exhume-picked:'+ROOT;
let PICK=new Set(); try{PICK=new Set(JSON.parse(localStorage.getItem(PKEY)||'[]'));}catch(e){}
function savePick(){try{localStorage.setItem(PKEY,JSON.stringify([...PICK]));}catch(e){}}
function updatePickCount(){
 const n=PICK.size, c=document.getElementById('pickcount'); if(c) c.textContent=n?(' ('+n+')'):'';
 const b=document.getElementById('pickclear'); if(b) b.style.display=(REPORT&&n)?'inline-block':'none';
}
function clearPicks(){
 if(!PICK.size) return;
 if(!confirm('Clear all '+PICK.size.toLocaleString()+' picked finding(s)?')) return;
 PICK=new Set(); savePick(); updatePickCount(); render(false);
}
// ---- column sorting ----
let sortKey=null, sortDir=1;
function sortVal(f,key){
 if(key==='severity') return f.severity;
 if(key==='detector') return f.detector;
 if(key==='loc') return f.path+':'+String(f.line).padStart(10,'0');
 return 0;
}
function toggleSort(key){
 if(sortKey===key) sortDir=-sortDir; else { sortKey=key; sortDir=1; }
 document.querySelectorAll('.sortarrow').forEach(s=>s.textContent='');
 const el=document.getElementById('sa-'+key); if(el) el.textContent=sortDir>0?'▲':'▼';
 render(false);
}
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function vbadge(f){
 const ai=f.ai==='real'?' <span class="vbadge v-valid" title="'+esc(f.ai_note||'')+'">AI: real</span>'
  :(f.ai==='false'?' <span class="vbadge v-invalid" title="'+esc(f.ai_note||'')+'">AI: false positive</span>':'');
 // "unknown" means this detector has no deterministic check at all (a password, a generic secret,
 // a phone number — there's no checksum or live host to test), so only the AI judges it. Showing
 // nothing here (the old behavior) looked like a missing/broken badge next to rows that DO have a
 // VALID/invalid one; an explicit dash makes the difference a fact about the data type, not a glitch.
 return ({live:'<span class="vbadge v-live">● LIVE</span>',dead:'<span class="vbadge v-dead">● dead</span>',
  valid:'<span class="vbadge v-valid" title="Passed its check (checksum OK / host answers)">● VALID</span>',
  invalid:'<span class="vbadge v-invalid" title="Failed its check (bad checksum / no host answered)">● invalid</span>',
  unknown:'<span class="vbadge v-unknown" title="This type has no automated check (e.g. a password or '
         +'generic secret has no checksum, no host to contact) — only the AI judges it">— n/a</span>'
  }[f.verified]||'')+ai;
}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1300);}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied')).catch(()=>toast('Copy failed'));}
// ---- censoring (report mode) ----
function maskVal(v){v=v||'';return v.length<=2?'••••':v.slice(0,2)+'•'.repeat(Math.min(10,Math.max(4,v.length-2)));}
function showVal(f){return REPORT?maskVal(f.value):f.value;}
function relPath(p){
 if(!REPORT||!ROOT) return p;
 return p.startsWith(ROOT)?('…'+p.slice(ROOT.length)):p;
}
function censorLine(line,f){
 if(!REPORT) return line;
 let t=line;
 if(f.value) t=t.split(f.value).join(maskVal(f.value));
 // also hide values of other assignments that appear in the surrounding lines
 return t.replace(/([:=]\s*['"]?)([^\s'";,•]{4,})/g,(m,a,b)=>a+maskVal(b));
}
function hi(line,f){
 const shown=showVal(f);
 let e=esc(censorLine(line,f)); const ev=esc(shown);
 if(ev) e=e.split(ev).join('<mark>'+ev+'</mark>');
 return e;
}
function visible(f){return REPORT? !DIS.has(f.fingerprint) : true;}
function setSev(s){fSev=s;
 document.querySelectorAll('#sevseg button').forEach(b=>b.classList.toggle('active',b.dataset.sev===s));
 document.querySelectorAll('#cards .card').forEach(c=>c.classList.toggle('sel',c.dataset.sev===s&&s!=='all'));
 render();}
document.querySelectorAll('#cards .card').forEach(c=>c.addEventListener('click',()=>setSev(c.dataset.sev)));
function matchBase(f){
 // Every filter EXCEPT the detector dropdown and the free-text search — this is also what decides
 // which detectors are worth offering in the dropdown at all, so "Medium" never lists a detector
 // that has no Medium findings, and a detector hidden entirely behind "Hide invalid" doesn't show
 // up with a count that then shows zero rows when picked.
 const liveonly=document.getElementById('liveonly').checked;
 const showdis=document.getElementById('showdis').checked&&!REPORT;
 if(!showdis && DIS.has(f.fingerprint)) return false;
 if((document.getElementById('hideinv').checked||REPORT) && (f.verified==='invalid'||f.ai==='false')) return false;
 if(fSev==='live'){ if(f.verified!=='live') return false; }
 else if(fSev!=='all'){ if(String(f.severity)!==fSev) return false; }
 if(liveonly && f.verified!=='live') return false;
 return true;
}
function match(f){
 if(REPORT && document.getElementById('pickonly').checked) return PICK.has(f.fingerprint);
 if(!matchBase(f)) return false;
 const det=document.getElementById('detsel').value;
 if(det && f.detector!==det) return false;
 const q=document.getElementById('q').value.toLowerCase();
 if(q){ const hay=f._h||(f._h=(f.detector+' '+f.path+' '+f.value+' '+f.context+' '+(f.detail||'')).toLowerCase());
        if(!hay.includes(q)) return false; }
 return true;
}
function rebuildDetectorOptions(){
 const sel=document.getElementById('detsel');
 const prev=sel.value;
 const counts={};
 DATA.findings.forEach(f=>{ if(matchBase(f)) counts[f.detector]=(counts[f.detector]||0)+1; });
 const entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1));
 sel.innerHTML='<option value="">All detectors</option>'+entries.map(([d,c])=>
  '<option value="'+esc(d)+'">'+esc(d)+' ('+c.toLocaleString()+')</option>').join('');
 sel.value=(prev && counts[prev]) ? prev : '';
}
function locsHTML(f){
 const locs=f.locations||[{path:f.path,line:f.line,col:f.col}];
 const CAP=50;
 let h='<ul class="locs">'+locs.slice(0,CAP).map(l=>'<li>'+esc(relPath(l.path))+':'+l.line+(l.col?(':'+l.col):'')+'</li>').join('');
 const extra=(f.locations_truncated||0)+Math.max(0,locs.length-CAP);
 if(extra>0) h+='<li class="more">… and '+extra.toLocaleString()+' more location(s) (see the CSV/JSON export)</li>';
 return h+'</ul>';
}
function detailHTML(f,i){
 const loc=esc(relPath(f.path))+':'+f.line+(f.col?(':'+f.col):'');
 let code='';
 (f.context_block||[]).forEach(([n,t])=>{
   const hit = n===f.line ? ' hit':'';
   code+='<div class="ln'+hit+'"><span class="gutter">'+n+'</span><span class="src">'+hi(t,f)+'</span></div>';
 });
 if(!code) code='<div class="ln"><span class="src">'+hi(f.context,f)+'</span></div>';
 const vb = vbadge(f)||'unknown';
 const dis=DIS.has(f.fingerprint);
 const occ=f.occurrences||1;
 return '<div class="detailbox">'
  +'<div class="dgrid">'
  +'<div><span class="k">'+(occ>1?'First location':'Location')+'</span><span class="loc">'+loc+'</span></div>'
  +'<div><span class="k">Detector</span>'+esc(f.detector)+'</div>'
  +'<div><span class="k">Verified</span>'+vb+'</div>'
  +(f.detail?('<div><span class="k">Detail</span>'+esc(f.detail)+'</div>'):'')
  +'</div>'
  +(occ>1?('<div><span class="k">Seen in '+occ.toLocaleString()+' places</span></div>'+locsHTML(f)):'')
  +'<div class="detailbtns">'
  +'<button class="btn" onclick="copy(DATA.findings['+i+'].value)">Copy value</button>'
  +'<button class="btn" onclick="copy((DATA.findings['+i+'].locations||[]).map(l=>l.path+\':\'+l.line).join(\'\\n\'))">Copy all locations</button>'
  +(dis?'<button class="btn" onclick="setDis(['+i+'],false)">Restore</button>'
       :'<button class="btn danger" onclick="setDis(['+i+'],true)">Not real — dismiss</button>'
        +'<button class="btn danger" onclick="dismissWhere('+i+',\'detector\')">Dismiss whole detector</button>')
  +'</div>'
  +'<div class="code">'+code+'</div>'
  +'</div>';
}
function rowFor(f,i){
 const tr=document.createElement('tr');
 tr.className='row'+(DIS.has(f.fingerprint)?' dis':'')+(f.verified==='invalid'||f.ai==='false'?' inv':'')
  +(REPORT&&PICK.has(f.fingerprint)?' picked':'');
 const vb=vbadge(f);
 const occ=f.occurrences||1;
 const occBadge=occ>1?'<span class="occ" title="This exact value appears in '+occ.toLocaleString()+' places">×'+occ.toLocaleString()+'</span>':'';
 const locText=esc(relPath(f.path))+':'+f.line+(f.col?(':'+f.col):'');
 const loc='<span class="locpath" title="'+(REPORT?'':'Click to copy · ')+locText+'">'+locText+'</span>'+occBadge;
 const dis=DIS.has(f.fingerprint);
 const picked=PICK.has(f.fingerprint);
 const fpcell=REPORT
  ?'<td class="fpcol"><input type="checkbox" class="pickbox" '+(picked?'checked':'')+' title="Pick this one for the screenshot"></td>'
  :'<td class="fpcol"><button class="x" title="'+(dis?'Restore':'Not a real finding — dismiss')+'">'+(dis?'↺':'✕')+'</button></td>';
 tr.innerHTML='<td><span class="caret">▸</span></td>'
  +'<td><span class="pill p'+f.severity+'">'+SEVLBL[f.severity]+'</span></td>'
  +'<td>'+vb+'</td><td class="det">'+esc(f.detector)+'</td>'
  +'<td class="loc">'+loc+'</td>'
  +'<td><span class="val" title="'+(REPORT?'':'Click to copy')+'">'+esc(showVal(f))+'</span></td>'
  +fpcell;
 let dtr=null;
 tr.addEventListener('click',()=>{
  if(!dtr){ dtr=document.createElement('tr'); dtr.className='detail';
   dtr.innerHTML='<td colspan="7">'+detailHTML(f,i)+'</td>'; tr.after(dtr); tr.classList.add('open'); return; }
  const o=dtr.style.display==='none'; dtr.style.display=o?'':'none'; tr.classList.toggle('open',o);});
 tr.querySelector('.val').addEventListener('click',ev=>{ev.stopPropagation();if(!REPORT)copy(f.value);});
 tr.querySelector('.locpath').addEventListener('click',ev=>{ev.stopPropagation();if(!REPORT)copy(relPath(f.path)+':'+f.line);});
 if(REPORT){
  tr.querySelector('.pickbox').addEventListener('change',ev=>{
   ev.stopPropagation();
   if(ev.target.checked) PICK.add(f.fingerprint); else PICK.delete(f.fingerprint);
   tr.classList.toggle('picked',ev.target.checked);
   savePick(); updatePickCount();
   if(document.getElementById('pickonly').checked) render(false);
  });
  tr.querySelector('.pickbox').addEventListener('click',ev=>ev.stopPropagation());
 } else {
  tr.querySelector('.x').addEventListener('click',ev=>{ev.stopPropagation();setDis([i],!dis);});
 }
 return tr;
}
function render(resetPage){
 if(resetPage!==false) page=0;
 rebuildDetectorOptions();
 view=[]; DATA.findings.forEach((f,i)=>{ if(match(f)) view.push(i); });
 if(sortKey) view.sort((a,b)=>{
  const va=sortVal(DATA.findings[a],sortKey), vb=sortVal(DATA.findings[b],sortKey);
  return va<vb?-sortDir:(va>vb?sortDir:0);
 });
 const pages=Math.max(1,Math.ceil(view.length/PAGE));
 if(page>=pages) page=pages-1;
 const tb=document.getElementById('rows'); tb.innerHTML='';
 const frag=document.createDocumentFragment();
 view.slice(page*PAGE,(page+1)*PAGE).forEach(i=>frag.appendChild(rowFor(DATA.findings[i],i)));
 tb.appendChild(frag);
 if(!view.length) tb.innerHTML='<tr><td colspan="7" class="empty">No findings match the current filters.</td></tr>';
 let ninv=0; if(document.getElementById('hideinv').checked||REPORT) DATA.findings.forEach(f=>{if(f.verified==='invalid'||f.ai==='false')ninv++;});
 const ni=ninv?(' · '+ninv.toLocaleString()+' hidden'):'';
 const nd=DIS.size?(' · '+DIS.size.toLocaleString()+' dismissed'):'';
 document.getElementById('count').textContent=view.length.toLocaleString()+' / '+DATA.findings.length.toLocaleString()+' unique value(s)'+ni+nd;
 renderPager(pages); updateCards();
}
function updateCards(){ // totals minus dismissed (dismissed ones can only be among the embedded findings)
 const d={1:0,2:0,3:0,live:0,all:0};
 DATA.findings.forEach(f=>{ if(DIS.has(f.fingerprint)){d[f.severity]++;d.all++;if(f.verified==='live')d.live++;} });
 document.querySelectorAll('#cards .card').forEach(c=>{
  const k=c.dataset.sev, n=c.querySelector('.n');
  if(n.dataset.base===undefined) n.dataset.base=n.textContent;
  n.textContent=(Math.max(0,(+n.dataset.base)-(d[k]||0))).toLocaleString();
 });
}
function setDis(idx,on){
 idx.forEach(i=>{const fp=DATA.findings[i].fingerprint; on?DIS.add(fp):DIS.delete(fp);});
 saveDis(); render(false);
}
function dismissWhere(i,kind){
 const f=DATA.findings[i]; const hit=[];
 DATA.findings.forEach((g,j)=>{ if(kind==='detector' && g.detector===f.detector) hit.push(j); });
 if(hit.length>1 && !confirm('Dismiss '+hit.length.toLocaleString()+' unique value(s)?')) return;
 setDis(hit,true);
}
function dismissFiltered(){
 if(!view.length){toast('Nothing to dismiss');return;}
 if(!confirm('Mark '+view.length.toLocaleString()+' filtered findings as NOT real?\nYou can undo it with "Show dismissed" or "Restore all".')) return;
 setDis(view.slice(),true);
}
function restoreAll(){ if(!DIS.size||!confirm('Restore all '+DIS.size+' dismissed findings?')) return; DIS=new Set(); saveDis(); render(false); }
function csvCell(v){v=String(v==null?'':v);return '"'+v.replace(/"/g,'""')+'"';}
function exportReviewed(){
 const rows=[['severity','verified','detector','occurrences','path','line','value','detail']];
 DATA.findings.forEach(f=>{ if(DIS.has(f.fingerprint)) return;
  rows.push([SEVLBL[f.severity],f.verified==='live'?'LIVE':(f.verified==='dead'?'DEAD':''),f.detector,
             f.occurrences||1,f.path,f.line,f.value,f.detail||'']); });
 const blob=new Blob(['﻿'+rows.map(r=>r.map(csvCell).join(',')).join('\n')],{type:'text/csv'});
 const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='exhume_reviewed.csv'; a.click();
 toast((rows.length-1)+' findings exported');
}
function toggleReport(){
 REPORT=!REPORT; document.body.classList.toggle('report',REPORT);
 const b=document.getElementById('rmode'); b.textContent=REPORT?'Exit report mode':'📷 Report mode'; b.classList.toggle('on',REPORT);
 const t=document.querySelector('.tgt'); if(t) t.textContent=REPORT?'[target hidden]':t.dataset.real;
 document.getElementById('pickctl').style.display=REPORT?'inline-flex':'none';
 if(!REPORT) document.getElementById('pickonly').checked=false;
 updatePickCount();
 render(); renderExtra();
}
function goPage(p){page=p;render(false);window.scrollTo({top:0});}
function renderPager(pages){
 const el=document.getElementById('pager');
 if(pages<=1){el.innerHTML='';return;}
 el.innerHTML='<button class="btn" '+(page===0?'disabled':'')+' onclick="goPage(0)">«</button>'
  +'<button class="btn" '+(page===0?'disabled':'')+' onclick="goPage('+(page-1)+')">‹ Prev</button>'
  +'<span>Page <input type="number" min="1" max="'+pages+'" value="'+(page+1)+'" onchange="goPage(Math.min(Math.max(0,this.value-1),'+(pages-1)+'))"> of '+pages.toLocaleString()+'</span>'
  +'<button class="btn" '+(page>=pages-1?'disabled':'')+' onclick="goPage('+(page+1)+')">Next ›</button>'
  +'<button class="btn" '+(page>=pages-1?'disabled':'')+' onclick="goPage('+(pages-1)+')">»</button>';
}
function toggleAll(on){
 document.querySelectorAll('#rows tr.row').forEach(r=>{
  const open=r.classList.contains('open');
  if(on!==open) r.click();
 });}
function copyLive(){
 const live=DATA.findings.filter(f=>f.verified==='live'&&!DIS.has(f.fingerprint));
 if(!live.length){toast('No verified-live credentials');return;}
 copy(live.map(f=>{
  const locs=(f.locations||[{path:f.path,line:f.line}]).map(l=>l.path+':'+l.line).join(', ');
  return f.detector+'\t'+locs+'\t'+f.value;
 }).join('\n'));
}
// ---- assets: collapsible folder tree, built lazily ----
function human(n){const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(1)+u[i];}
function buildTrie(items){
 const root={d:{},f:[],n:0};
 items.forEach(it=>{
  let p=it.path; if(ROOT&&p.startsWith(ROOT)) p=p.slice(ROOT.length);
  const parts=p.split('/').filter(Boolean); const name=parts.pop()||p;
  let node=root; node.n++;
  parts.forEach(seg=>{ node=node.d[seg]||(node.d[seg]={d:{},f:[],n:0}); node.n++; });
  node.f.push({name:name,size:it.size,path:it.path});
 });
 return root;
}
function renderNode(node,box){
 const MAXF=200;
 Object.keys(node.d).sort().forEach(k=>{
  let label=k, cur=node.d[k];
  while(!cur.f.length && Object.keys(cur.d).length===1){ const nk=Object.keys(cur.d)[0]; label+='/'+nk; cur=cur.d[nk]; }
  const det=document.createElement('details');
  det.innerHTML='<summary>📁 '+esc(label)+'<span class="cnt">'+cur.n.toLocaleString()+'</span></summary><div class="kids"></div>';
  let built=false;
  det.addEventListener('toggle',()=>{ if(det.open&&!built){built=true;renderNode(cur,det.querySelector('.kids'));} });
  box.appendChild(det);
 });
 const files=node.f.slice().sort((a,b)=>a.name<b.name?-1:1);
 const addFiles=(from)=>{
  files.slice(from,from+MAXF).forEach(f=>{
   const d=document.createElement('div'); d.className='file';
   d.innerHTML='<span>'+esc(f.name)+'</span><span class="sz">'+human(f.size)+'</span>'; d.title=f.path; box.appendChild(d);});
  if(files.length>from+MAXF){
   const b=document.createElement('button'); b.className='btn more'; b.textContent='Show '+Math.min(MAXF,files.length-from-MAXF)+' more of '+(files.length-from-MAXF).toLocaleString();
   b.onclick=()=>{b.remove();addFiles(from+MAXF);}; box.appendChild(b);}
 };
 addFiles(0);
}
function renderExtra(){
 const meta={key_material:['Key material','🔑','Certificates, keystores and private-key files'],
  sensitive_name:['Sensitive filenames','👁️','Named like something worth a closer look (backup, dump, secrets…)'],
  database:['Databases','🗄️','Opened to list tables and sensitive-looking columns'],
  executable:['Executables','⚙️','Compiled binaries and scripts'],
  archive:['Archives','📦','Zip/tar/7z and similar — unpacked and scanned inside'],
  config:['Config files','🧾','.env, .yml, .conf and other configuration'],
  git_history:['Git history','🕐','Found only in a commit, not the working tree']};
 const as=DATA.assets||{};
 const hideAI=document.getElementById('hideinv').checked||REPORT;
 const cats=[]; let totalItems=0;
 for(const k in meta){ const items=(as[k]||[]).filter(i=>!(hideAI&&i.ai==='false')); if(items.length){cats.push([k,items]); totalItems+=items.length;} }
 const ex=document.getElementById('extra'); ex.innerHTML='';
 if(!cats.length) return;
 const wrap=document.createElement('div'); wrap.id='assetsec'; wrap.className='assetpanel';
 wrap.innerHTML='<div class="hd"><span class="t">Detected assets</span>'
  +'<span class="tag">non-secret, worth a look</span>'
  +'<span class="by">'+totalItems.toLocaleString()+' item(s) in '+cats.length+' categor'+(cats.length===1?'y':'ies')+'</span></div>'
  +'<div class="bd tree"></div>';
 const box=wrap.querySelector('.bd');
 cats.forEach(([k,items])=>{
  const [title,icon,desc]=meta[k];
  const det=document.createElement('details'); det.className='cat';
  det.innerHTML='<summary><span class="icon">'+icon+'</span><span class="catlabel">'+esc(title)
   +'<span class="catdesc">'+esc(desc)+'</span></span><span class="cnt">'+items.length.toLocaleString()+'</span></summary>'
   +'<div class="kids"></div>';
  let built=false;
  det.addEventListener('toggle',()=>{ if(det.open&&!built){built=true;
   const kids=det.querySelector('.kids');
   if(k==='database') dbHTML(kids,items);
   renderNode(buildTrie(items),kids); } });
  box.appendChild(det); });
 ex.appendChild(wrap);
}
function dbHTML(kids,items){
 const paths=new Set(items.map(i=>i.path)); let h='';
 (DATA.databases||[]).forEach(d=>{ if(!paths.has(d.path)) return;
  h+='<h3 class="loc">'+esc(d.path)+'</h3>';
  const sc=(d.sensitive_columns||[]); if(sc.length) h+='<p class="susp">⚠ sensitive columns: '+esc(sc.join(', '))+'</p>';
  if(d.ai_insight) h+='<p class="aiinsight">🤖 '+esc(d.ai_insight)+'</p>';
  const tb=(d.tables||[]); if(tb.length){ h+='<table class="subt"><thead><tr><th>Table</th><th>Rows</th><th>Columns</th></tr></thead><tbody>';
   tb.forEach(t=>{h+='<tr><td>'+esc(t.name)+'</td><td>'+(t.rows==null?'':t.rows)+'</td><td class="loc">'+esc((t.columns||[]).join(', '))+'</td></tr>';});
   h+='</tbody></table>'; } });
 if(h){const d=document.createElement('div'); d.innerHTML='<div style="margin:6px 0 10px 22px">'+h+'</div>'; kids.appendChild(d);}
}
document.addEventListener('keydown',e=>{
 const q=document.getElementById('q');
 if(e.key==='/' && document.activeElement!==q){e.preventDefault();q.focus();}
 else if(e.key==='Escape' && document.activeElement===q){q.value='';render();q.blur();}
});
document.addEventListener('click',e=>{
 document.querySelectorAll('.covdetails[open]').forEach(d=>{ if(!d.contains(e.target)) d.open=false; });
});
updatePickCount();
render(); renderExtra();
</script></body></html>"""


_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _inline_md(escaped: str) -> str:
    """``**bold**`` -> ``<strong>bold</strong>``, applied AFTER escaping (the `*`s survive
    html.escape untouched, so this is still safe against anything the model wrote)."""
    return _BOLD_RE.sub(r"<strong>\1</strong>", escaped)


def _md_to_html(text: str) -> str:
    """Minimal, safe Markdown-ish rendering (headings, lists, paragraphs, **bold**)."""
    import html as _h
    out, in_list = [], False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        esc = _inline_md(_h.escape(line.strip()))
        if line.lstrip().startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{_inline_md(_h.escape(line.lstrip()[3:]))}</h3>")
        elif line.lstrip()[:2] in ("- ", "* ") or (line.lstrip()[:2].rstrip() == "-"):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline_md(_h.escape(line.lstrip()[2:]))}</li>")
        elif line.lstrip()[:3].strip().rstrip(".").isdigit():
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{esc}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{esc}</p>")
    if in_list:
        out.append("</ul>")
    return "".join(out)


def _ai_section(meta: dict) -> str:
    summary = meta.get("ai_summary") or ""
    if not summary.strip():
        return ""
    import html as _h
    model = _h.escape(meta.get("ai_model", ""))
    return (
        '<div class="ai">'
        '<div class="hd"><span class="t">Triage summary</span>'
        '<span class="tag">prioritization</span>'
        f'<span class="by">local model · {model}</span></div>'
        f'<div class="bd">{_md_to_html(summary)}</div>'
        '</div>'
    )


HTML_MAX_DEFAULT = 50_000
_CHUNK = 5_000
_FIELD_CAP = 400


_LOC_EMBED_CAP = 50  # locations embedded per group in the HTML (the JSON export has them all)


def _compact(f: dict, keep_block: bool) -> dict:
    """Trim a finding for embedding in HTML (the JSON/CSV keep the full data)."""
    out = {k: f[k] for k in ("detector", "severity", "line", "col", "path", "verified", "detail",
                             "fingerprint", "ai", "ai_note", "occurrences")}
    out["value"] = f["value"][:_FIELD_CAP] if f["value"] else f["value"]
    out["context"] = (f["context"] or "")[:_FIELD_CAP]
    if keep_block and f.get("context_block"):
        out["context_block"] = [[n, t[:_FIELD_CAP]] for n, t in f["context_block"]]
    locs = f.get("locations") or []
    if f["occurrences"] > 1:
        out["locations"] = locs[:_LOC_EMBED_CAP]
        out["locations_truncated"] = f.get("locations_truncated", 0) + max(0, len(locs) - _LOC_EMBED_CAP)
    return out


def write_html(payload: dict, path: str, max_findings: int = HTML_MAX_DEFAULT) -> int:
    """Write the HTML report. Returns how many findings were left out (0 = all embedded).

    The browser cannot realistically hold hundreds of thousands of rows, so past
    ``max_findings`` (ordered by severity) the rest stay in the JSON/CSV exports.
    """
    import html as _h
    m, rs = payload["meta"], payload["summary"]
    sev = rs["by_severity"]
    c3, c2, c1 = sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"]
    inv = rs.get("hidden", rs.get("invalid", 0))
    shown_total = rs["total_findings"] - inv      # cards/bar exclude matches that failed validation
    total = shown_total or 1
    bar = (f"<i style='width:{c3 / total * 100:.1f}%;background:var(--crit)'></i>"
           f"<i style='width:{c2 / total * 100:.1f}%;background:var(--high)'></i>"
           f"<i style='width:{c1 / total * 100:.1f}%;background:var(--med)'></i>")
    supp = rs.get("suppressed_by_baseline", 0)

    def chip(value: str, label: str, title: str = "", cls: str = "") -> str:
        t = f' title="{_h.escape(title, quote=True)}"' if title else ""
        c = f" {cls}" if cls else ""
        return f'<span class="mchip{c}"{t}><b>{_h.escape(value)}</b>{_h.escape(label)}</span>'

    chips = [chip(f"{m['files_scanned']:,}/{m['files_seen']:,}", " scanned",
                 "Files whose content was actually read and scanned, out of every file/entry seen")]
    if m["nested"]:
        chips.append(chip(f"{m['nested']:,}", " nested", "Found inside an archive or container"))
    if m["git_blobs"]:
        chips.append(chip(f"{m['git_blobs']:,}", " in git history"))
    if rs.get("total_occurrences", 0) > rs["total_findings"]:
        chips.append(chip(f"{rs['total_occurrences']:,}→{rs['total_findings']:,}", " deduped",
                          "That many raw occurrences collapsed to this many unique values"))
    if supp:
        chips.append(chip(f"{supp:,}", " hidden by baseline", "Already known from a previous scan's baseline"))
    chips.append(chip(f"{m['seconds']}s", " elapsed"))

    cov = m.get("coverage") or {}
    # (label, hint shown under the count — None when there's nothing the user can do about it).
    _cov_meta = {
        "scanned": ("content scanned", None),
        "archives": ("archives unpacked", None),
        "binary_skipped": ("binary files skipped", "include them: --strings (or --deep)"),
        "media_skipped": ("media files skipped", "include them: --strings (or --deep)"),
        "ocr_unavailable": ("images without OCR", "install the tesseract program (see console output), "
                            "then re-run"),
        "too_big": ("files too big, skipped", "raise or remove the cap: --max-size 0 (or --deep)"),
        "document_failed": ("documents unreadable", "corrupt, encrypted, or an unsupported format"),
        "timeout": ("timed out", "raise the per-file limit: --file-timeout"),
        "error": ("read errors", None),
    }
    _cov_groups = [
        ("Processed", ("scanned", "archives")),
        ("Skipped by default", ("binary_skipped", "media_skipped", "ocr_unavailable", "too_big")),
        ("Failed", ("document_failed", "timeout", "error")),
    ]

    def cov_group(title: str, keys: tuple) -> str:
        rows = []
        for k in keys:
            v = cov.get(k, 0)
            if not v:
                continue
            label, hint = _cov_meta.get(k, (k, None))
            hint_html = f'<span class="covhint">{_h.escape(hint)}</span>' if hint else ""
            rows.append(f'<li><b>{v:,}</b> {_h.escape(label)}{hint_html}</li>')
        if not rows:
            return ""
        return f'<div class="covgroup"><h4>{_h.escape(title)}</h4><ul class="covlist">{"".join(rows)}</ul></div>'

    cov_body = "".join(cov_group(title, keys) for title, keys in _cov_groups)
    cov_html = (f'<details class="covdetails"><summary>Coverage breakdown</summary>'
               f'<div class="covpanel">{cov_body}</div></details>') if cov_body else ""

    hidden_html = ""
    if inv:
        ai_false = rs.get("ai_false", 0)
        checksum_fail = inv - ai_false
        hidden_html = (
            f'<div class="mnote warn" title="These are excluded from the counts and table above by '
            f'default — turn on &quot;Show dismissed&quot; / untick &quot;Hide invalid&quot; to see them">'
            f'<b>{inv:,}</b> hidden by default: <b>{checksum_fail:,}</b> failed their check '
            f'(bad checksum / no host answered)'
            + (f', <b>{ai_false:,}</b> judged false positive by the local AI' if ai_false else "")
            + "</div>"
        )
    ai_html = (f'<div class="mnote ai">AI filter: <b>{_h.escape(m["ai_engine"])}</b></div>'
              if m.get("ai_engine") else "")
    # A flex row, not two loose inline-block siblings: inline-block's baseline alignment put these
    # two notes on visibly different, overlapping lines in testing (reported as looking broken,
    # with a stray gap below) whenever their combined width didn't leave obvious room to spare.
    notes_html = (f'<div class="mnoterow">{hidden_html}{ai_html}</div>' if (hidden_html or ai_html) else "")

    metaline = (
        f'Target: <b class="tgt" data-real="{_h.escape(m["target"], quote=True)}">{_h.escape(m["target"])}</b>'
        f'<span class="mgen">generated {_h.escape(m["generated"])} · v{m["version"]}</span>'
        f'<div class="metachips">{"".join(chips)}{cov_html}</div>'
        f'{notes_html}'
    )
    mask_badge = '<span class="badge-mask">MASKED</span>' if m.get("masked") else ""

    all_f = payload["findings"]
    embedded = all_f[:max_findings] if max_findings and max_findings > 0 else all_f
    omitted = len(all_f) - len(embedded)
    chunks = []
    for i in range(0, len(embedded), _CHUNK):
        part = [_compact(f, f["severity"] >= 2 or len(embedded) <= 20_000) for f in embedded[i:i + _CHUNK]]
        chunks.append({"findings": part})
    chunks.append({"databases": payload.get("databases", []), "assets": payload.get("assets", {})})
    data = "\n".join(
        '<script class="chunk" type="application/json">'
        + json.dumps(c, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
        + "</script>" for c in chunks)
    trunc = (f'<div class="trunc">Showing the {len(embedded):,} highest-severity unique values of '
             f'{len(all_f):,}. The full list is in the accompanying .csv / .json export '
             f'(or re-run with <code>--html-max 0</code> to embed everything).</div>') if omitted else ""

    doc = (_TEMPLATE
           .replace("__TARGET__", _h.escape(m["target"]))
           .replace("__MASKBADGE__", mask_badge)
           .replace("__METALINE__", metaline)
           .replace("__C3__", str(c3)).replace("__C2__", str(c2)).replace("__C1__", str(c1))
           .replace("__LIVE__", str(rs["verified_live"])).replace("__TOTAL__", str(shown_total))
           .replace("__BAR__", bar)
           .replace("__AISECTION__", _ai_section(m))
           .replace("__VERSION__", str(m["version"]))
           .replace("__TRUNCNOTE__", trunc)
           .replace("__DATA__", data))
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return omitted
