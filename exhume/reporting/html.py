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
 --crit:#f43f5e;--high:#f59e0b;--med:#38bdf8;--live:#22c55e;--accent:#8b5cf6;--mark:#fde047;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
 font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;font-size:14px}
a{color:var(--med)}
header{padding:20px 28px;background:linear-gradient(180deg,#141b29,#0c1019);border-bottom:1px solid var(--line);
 position:sticky;top:0;z-index:30}
.brand{display:flex;align-items:center;gap:10px;font-size:19px;font-weight:800;letter-spacing:.2px}
.brand .paw{font-size:22px}
.brand .tag{color:var(--mut);font-weight:500;font-size:13px}
.meta{color:var(--mut);font-size:12.5px;margin-top:6px}
.badge-mask{background:#2a1d10;color:#ffcf99;border:1px solid #5a3d1a;border-radius:6px;padding:1px 7px;font-size:11px;margin-left:8px}
main{padding:22px 28px;max-width:1600px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 17px;cursor:pointer;
 transition:transform .08s,border-color .12s}
.card:hover{transform:translateY(-2px)}
.card.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.card .n{font-size:28px;font-weight:800;line-height:1}
.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-top:7px}
.card.crit .n{color:var(--crit)}.card.high .n{color:var(--high)}.card.med .n{color:var(--med)}
.card.live .n{color:var(--live)}
.bar{height:7px;border-radius:6px;overflow:hidden;display:flex;margin:2px 0 18px;background:var(--panel2)}
.bar i{display:block;height:100%}
.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:12px}
.toolbar input[type=text],.toolbar select{padding:9px 12px;background:var(--panel);border:1px solid var(--line);
 color:var(--txt);border-radius:9px;font-size:13.5px}
.toolbar input[type=text]{flex:1;min-width:240px}
.seg{display:flex;border:1px solid var(--line);border-radius:9px;overflow:hidden}
.seg button{padding:8px 13px;background:var(--panel);color:var(--mut);border:0;cursor:pointer;font-size:13px;font-weight:600}
.seg button.active{background:var(--panel2);color:var(--txt)}
.tog{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none}
.count{color:var(--mut);font-size:13px;margin-left:auto}
table{border-collapse:collapse;width:100%}
thead th{position:sticky;top:73px;background:#0f1420;z-index:10;text-align:left;color:var(--mut);
 font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:9px 12px;border-bottom:1px solid var(--line)}
tbody td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr.row{cursor:pointer}
tbody tr.row:hover{background:#121a28}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.03em}
.p3{background:#3a1420;color:#fda4af}.p2{background:#3a2c12;color:#fcd34d}.p1{background:#0e2c3f;color:#7dd3fc}
.vbadge{font-weight:800;font-size:12px}.v-live,.v-valid{color:var(--live)}.v-dead,.v-invalid{color:#64748b}
.det{color:var(--txt)}
.loc{color:var(--mut);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.loc{word-break:break-all}
.val{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#fef08a;max-width:360px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom;cursor:pointer}
.val:hover{text-decoration:underline;text-decoration-style:dotted}
.occ{display:inline-block;background:var(--panel2);color:var(--mut);border:1px solid var(--line);
 border-radius:999px;padding:0 7px;font-size:10.5px;font-weight:700;margin-left:7px;vertical-align:1px}
.locs{list-style:none;margin:6px 0 0;padding:0;max-height:220px;overflow:auto;
 font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.locs li{padding:3px 0;border-bottom:1px solid var(--line);word-break:break-all;color:#cbd5e1}
.locs .more{color:var(--mut);padding-top:5px}
.caret{color:var(--mut);transition:transform .12s;display:inline-block}
tr.open .caret{transform:rotate(90deg)}
.detail td{background:#0c1119;padding:0}
.detailbox{padding:14px 16px;border-left:3px solid var(--accent);margin:2px 0}
.dgrid{display:flex;flex-wrap:wrap;gap:18px;margin-bottom:10px;font-size:12.5px}
.dgrid .k{color:var(--mut);margin-right:6px}
.btn{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:7px;padding:5px 10px;
 cursor:pointer;font-size:12px;font-weight:600;margin-right:6px}
.btn:hover{border-color:var(--accent)}
.code{background:#0a0e16;border:1px solid var(--line);border-radius:10px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;margin-top:8px}
.code .ln{display:flex;white-space:pre}
.code .ln.hit{background:rgba(139,92,246,.14)}
.code .gutter{color:#475569;text-align:right;padding:1px 12px;user-select:none;min-width:52px;border-right:1px solid var(--line);background:#0b1017}
.code .src{padding:1px 14px;color:#cbd5e1;white-space:pre}
mark{background:var(--mark);color:#111;border-radius:3px;padding:0 2px;font-weight:700}
h2{font-size:15px;margin:26px 0 6px}
h3{margin:16px 0 4px;color:#cbd5e1;font-size:13.5px}
.sz{color:#5b6677}
.asset ul{columns:2;gap:22px;padding-left:18px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.asset li{margin:3px 0;break-inside:avoid}
.susp{color:var(--high);font-size:12.5px;margin:4px 0}
.aiinsight{color:#c4b5fd;font-size:12.5px;margin:4px 0;font-style:italic}
.subt{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:6px}
.subt th,.subt td{border:1px solid var(--line);padding:5px 9px;text-align:left}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:14px 0;color:var(--mut);font-size:13px}
.pager button:disabled{opacity:.4;cursor:default}
.pager input{width:64px;padding:5px 7px;background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:7px}
.trunc{background:#2a1d10;color:#ffcf99;border:1px solid #5a3d1a;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}

.hdrrow{display:flex;align-items:flex-start;gap:14px;justify-content:space-between}
.hdrbtns{display:flex;gap:8px;flex-shrink:0}
.btn.on{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.danger:hover{border-color:var(--crit);color:#fda4af}
.x{background:none;border:0;color:#64748b;cursor:pointer;font-size:15px;padding:2px 7px;border-radius:6px}
.x:hover{background:#3a1420;color:#fda4af}
tr.row.dis,tr.row.inv{opacity:.5}
tr.row.dis .det,tr.row.dis .val,tr.row.dis .loc{text-decoration:line-through}
.rbanner{display:none;background:#10231a;border:1px solid #1f5a3a;color:#86efac;border-radius:10px;padding:9px 14px;margin-bottom:14px;font-size:13px}
body.report .rbanner{display:block}
body.report .noreport,body.report .toolbar .tog,body.report #pager,body.report .x,body.report .detailbtns,
body.report #assetsec,body.report .trunc,body.report .ai,body.report .card[data-sev=live]{display:none!important}
body.report .val{cursor:default}
body.report .meta .tgt{letter-spacing:.1em}
body.report .code .src{white-space:pre-wrap;word-break:break-all}
.tree details{margin:2px 0}
.tree summary{cursor:pointer;padding:3px 6px;border-radius:6px;list-style:none;font-size:13px}
.tree summary::-webkit-details-marker{display:none}
.tree summary::before{content:"▸";display:inline-block;width:16px;color:var(--mut);transition:transform .1s}
.tree details[open]>summary::before{transform:rotate(90deg)}
.tree summary:hover{background:var(--panel2)}
.tree .kids{margin-left:14px;border-left:1px solid var(--line);padding-left:8px}
.tree .file{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;padding:2px 6px 2px 22px;color:#cbd5e1;
 display:flex;justify-content:space-between;gap:14px;word-break:break-all}
.tree .cnt{color:var(--mut);font-size:12px;margin-left:6px}
.tree .more{margin:4px 0 4px 22px}
.cat>summary{font-weight:700;font-size:14px;background:var(--panel);border:1px solid var(--line);padding:9px 12px;margin-top:8px}
.cat .kids{margin-top:4px}
.empty{color:var(--mut);padding:26px;text-align:center}
footer{color:#48525f;font-size:12px;text-align:center;padding:26px}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--accent);color:#fff;
 padding:9px 16px;border-radius:9px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:50}
.toast.show{opacity:1}
.ai{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:18px;overflow:hidden}
.ai .hd{display:flex;align-items:center;gap:10px;padding:12px 18px;border-bottom:1px solid var(--line);background:#10151e}
.ai .hd .t{font-weight:700;font-size:14px;color:var(--txt)}
.ai .hd .tag{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);
 border:1px solid var(--line);border-radius:999px;padding:2px 9px}
.ai .hd .by{color:#5b6677;font-size:11.5px;margin-left:auto}
.ai .bd{padding:4px 18px 14px}
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
 <div class="rbanner">REPORT MODE · values are censored, paths are relative and dismissed findings are excluded. Check the box on any row to pick it, then “Show only picked” to curate exactly what's visible for a screenshot. Click “Exit report mode” to go back.</div>
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
  <label class="tog"><input type="checkbox" id="liveonly" onchange="render()"> Verified only</label>
  <label class="tog"><input type="checkbox" id="expall" onchange="toggleAll(this.checked)"> Expand all</label>
 <label class="tog"><input type="checkbox" id="hideinv" checked onchange="render();renderExtra()" title="Hide matches that failed their check (bad checksum, IP with no host) or that the local AI judged a false positive"> Hide invalid / AI false positives</label>
  <label class="tog"><input type="checkbox" id="showdis" onchange="render()"> Show dismissed</label>
  <label class="repctl" id="pickctl" style="display:none;align-items:center;gap:6px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none">
   <input type="checkbox" id="pickonly" onchange="render()"> Show only picked<span id="pickcount"></span>
  </label>
  <button class="btn repctl" id="pickclear" style="display:none" onclick="clearPicks()" title="Unpick everything">Clear picks</button>
  <button class="btn" onclick="copyLive()">Copy live creds</button>
  <button class="btn noreport" onclick="dismissFiltered()" title="Mark every finding matching the current filters as false positive">Dismiss filtered</button>
  <button class="btn noreport" onclick="exportReviewed()">Export reviewed CSV</button>
  <button class="btn noreport danger" onclick="restoreAll()">Restore all</button>
  <span class="count" id="count"></span>
 </div>

 <table>
  <thead><tr><th style="width:26px"></th><th>Severity</th><th>Verified</th><th>Detector</th><th>Location</th><th>Value</th><th class="fpcol" style="width:34px"></th></tr></thead>
  <tbody id="rows"></tbody>
 </table>

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
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function vbadge(f){
 const ai=f.ai==='real'?' <span class="vbadge v-valid" title="'+esc(f.ai_note||'')+'">AI: real</span>'
  :(f.ai==='false'?' <span class="vbadge v-invalid" title="'+esc(f.ai_note||'')+'">AI: false positive</span>':'');
 return ({live:'<span class="vbadge v-live">● LIVE</span>',dead:'<span class="vbadge v-dead">● dead</span>',
  valid:'<span class="vbadge v-valid" title="Passed its check (checksum OK / host answers)">● VALID</span>',
  invalid:'<span class="vbadge v-invalid" title="Failed its check (bad checksum / no host answered)">● invalid</span>'}[f.verified]||'')+ai;
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
 const tr=document.createElement('tr'); tr.className='row'+(DIS.has(f.fingerprint)?' dis':'')+(f.verified==='invalid'||f.ai==='false'?' inv':'');
 const vb=vbadge(f);
 const occ=f.occurrences||1;
 const occBadge=occ>1?'<span class="occ" title="This exact value appears in '+occ.toLocaleString()+' places">×'+occ.toLocaleString()+'</span>':'';
 const loc=esc(relPath(f.path))+':'+f.line+(f.col?(':'+f.col):'')+occBadge;
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
 if(REPORT){
  tr.querySelector('.pickbox').addEventListener('change',ev=>{
   ev.stopPropagation();
   if(ev.target.checked) PICK.add(f.fingerprint); else PICK.delete(f.fingerprint);
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
 const titles={key_material:'Key material',sensitive_name:'Sensitive filenames',database:'Databases',
  executable:'Executables',archive:'Archives',config:'Config files',git_history:'Git history'};
 const as=DATA.assets||{}; const box=document.createElement('div'); box.id='assetsec'; box.className='tree';
 let any=false;
 const hideAI=document.getElementById('hideinv').checked||REPORT;
 for(const k in titles){ const items=(as[k]||[]).filter(i=>!(hideAI&&i.ai==='false')); if(!items.length) continue; any=true;
  const det=document.createElement('details'); det.className='cat';
  det.innerHTML='<summary>'+titles[k]+'<span class="cnt">'+items.length.toLocaleString()+'</span></summary><div class="kids"></div>';
  let built=false;
  det.addEventListener('toggle',()=>{ if(det.open&&!built){built=true;
   const kids=det.querySelector('.kids');
   if(k==='database') dbHTML(kids,items);
   renderNode(buildTrie(items),kids); } });
  box.appendChild(det); }
 const ex=document.getElementById('extra'); ex.innerHTML='';
 if(any){ const h=document.createElement('h2'); h.textContent='Detected assets'; ex.appendChild(h); ex.appendChild(box); }
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
    supp_note = f" · {supp} hidden by baseline" if supp else ""
    occ_note = f" ({rs['total_occurrences']:,} occurrences, deduplicated by value)" if rs.get(
        "total_occurrences", 0) > rs["total_findings"] else ""
    metaline = (f"Target: <b class=\"tgt\" data-real=\"{_h.escape(m['target'], quote=True)}\">{_h.escape(m['target'])}</b>"
                f" · {m['files_scanned']} scanned / "
                f"{m['files_seen']} seen · {m['nested']} nested · {m['git_blobs']} git-history · "
                f"{m['seconds']}s{supp_note} · {_h.escape(m['generated'])} · v{m['version']}{occ_note}")
    cov = m.get("coverage") or {}
    _lbl = {"scanned": "content scanned", "archives": "archives unpacked", "media_skipped": "media skipped",
            "binary_skipped": "binary skipped", "document_failed": "documents unreadable",
            "ocr_unavailable": "images without OCR",
            "too_big": "too big", "timeout": "timed out", "error": "errors"}
    cov_parts = [f"{v:,} {_lbl.get(k, k)}" for k, v in cov.items() if v]
    if cov_parts:
        metaline += "<br>Coverage: " + " · ".join(cov_parts)
    if inv:
        metaline += (f"<br>{inv:,} matches hidden by default: failed validation (checksum / no host) "
                     f"or judged false positives by the local AI ({rs.get('ai_false', 0):,})")
    if m.get("ai_engine"):
        metaline += f"<br>AI filter: {_h.escape(m['ai_engine'])}"
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
