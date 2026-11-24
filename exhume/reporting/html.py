"""Self-contained, interactive HTML report.

Data-driven: findings are embedded as JSON and rendered client-side, giving
expandable rows with highlighted multi-line context, copy buttons and rich
filtering. No external dependencies; works offline.
"""
from __future__ import annotations

import json

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
.vbadge{font-weight:800;font-size:12px}.v-live{color:var(--live)}.v-dead{color:#64748b}
.det{color:var(--txt)}
.loc{color:var(--mut);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.loc{word-break:break-all}
.val{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#fef08a;max-width:360px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom;cursor:pointer}
.val:hover{text-decoration:underline;text-decoration-style:dotted}
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
.subt{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:6px}
.subt th,.subt td{border:1px solid var(--line);padding:5px 9px;text-align:left}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:14px 0;color:var(--mut);font-size:13px}
.pager button:disabled{opacity:.4;cursor:default}
.pager input{width:64px;padding:5px 7px;background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:7px}
.trunc{background:#2a1d10;color:#ffcf99;border:1px solid #5a3d1a;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}
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
 <div class="brand">Exhume <span class="tag">audit report</span>__MASKBADGE__</div>
 <div class="meta">__METALINE__</div>
</header>
<main>
 <div class="cards" id="cards">
  <div class="card crit" data-sev="3"><div class="n">__C3__</div><div class="l">Critical</div></div>
  <div class="card high" data-sev="2"><div class="n">__C2__</div><div class="l">High</div></div>
  <div class="card med"  data-sev="1"><div class="n">__C1__</div><div class="l">Medium</div></div>
  <div class="card live" data-sev="live"><div class="n">__LIVE__</div><div class="l">Verified live</div></div>
  <div class="card" data-sev="all"><div class="n">__TOTAL__</div><div class="l">Total findings</div></div>
 </div>
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
  <select id="detsel" onchange="render()"><option value="">All detectors</option>__DETOPTS__</select>
  <label class="tog"><input type="checkbox" id="liveonly" onchange="render()"> Verified only</label>
  <label class="tog"><input type="checkbox" id="expall" onchange="toggleAll(this.checked)"> Expand all</label>
  <button class="btn" onclick="copyLive()">Copy live creds</button>
  <span class="count" id="count"></span>
 </div>

 <table>
  <thead><tr><th style="width:26px"></th><th>Severity</th><th>Verified</th><th>Detector</th><th>Location</th><th>Value</th></tr></thead>
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
let fSev='all';
const SEVLBL={3:'CRITICAL',2:'HIGH',1:'MEDIUM'};
function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function hi(line,val){ // escape then highlight occurrences of val
 let e=esc(line); if(val){const ev=esc(val); if(ev) e=e.split(ev).join('<mark>'+ev+'</mark>');} return e;
}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1300);}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied')).catch(()=>toast('Copy failed'));}
function setSev(s){fSev=s;
 document.querySelectorAll('#sevseg button').forEach(b=>b.classList.toggle('active',b.dataset.sev===s));
 document.querySelectorAll('#cards .card').forEach(c=>c.classList.toggle('sel',c.dataset.sev===s&&s!=='all'));
 render();}
document.querySelectorAll('#cards .card').forEach(c=>c.addEventListener('click',()=>setSev(c.dataset.sev)));
function match(f){
 const q=document.getElementById('q').value.toLowerCase();
 const det=document.getElementById('detsel').value;
 const liveonly=document.getElementById('liveonly').checked;
 if(fSev==='live'){ if(f.verified!=='live') return false; }
 else if(fSev!=='all'){ if(String(f.severity)!==fSev) return false; }
 if(liveonly && f.verified!=='live') return false;
 if(det && f.detector!==det) return false;
 if(q){ const hay=f._h||(f._h=(f.detector+' '+f.path+' '+f.value+' '+f.context+' '+(f.detail||'')).toLowerCase());
        if(!hay.includes(q)) return false; }
 return true;
}
function detailHTML(f,i){
 const loc=esc(f.path)+':'+f.line+(f.col?(':'+f.col):'');
 let code='';
 (f.context_block||[]).forEach(([n,t])=>{
   const hit = n===f.line ? ' hit':'';
   code+='<div class="ln'+hit+'"><span class="gutter">'+n+'</span><span class="src">'+hi(t,f.value)+'</span></div>';
 });
 if(!code) code='<div class="ln"><span class="src">'+hi(f.context,f.value)+'</span></div>';
 const vb = f.verified==='live'?'<span class="vbadge v-live">● LIVE</span>':(f.verified==='dead'?'<span class="vbadge v-dead">● dead</span>':'unknown');
 return '<div class="detailbox">'
  +'<div class="dgrid">'
  +'<div><span class="k">Location</span><span class="loc">'+loc+'</span></div>'
  +'<div><span class="k">Detector</span>'+esc(f.detector)+'</div>'
  +'<div><span class="k">Verified</span>'+vb+'</div>'
  +(f.detail?('<div><span class="k">Detail</span>'+esc(f.detail)+'</div>'):'')
  +'<div><span class="k">Fingerprint</span><span class="loc">'+esc(f.fingerprint)+'</span></div>'
  +'</div>'
  +'<button class="btn" onclick="copy(DATA.findings['+i+'].value)">Copy value</button>'
  +'<button class="btn" onclick="copy(DATA.findings['+i+'].path)">Copy path</button>'
  +'<div class="code">'+code+'</div>'
  +'</div>';
}
function rowFor(f,i){
 const tr=document.createElement('tr'); tr.className='row';
 const vb=f.verified==='live'?'<span class="vbadge v-live">● LIVE</span>':(f.verified==='dead'?'<span class="vbadge v-dead">● dead</span>':'');
 const loc=esc(f.path)+':'+f.line+(f.col?(':'+f.col):'');
 tr.innerHTML='<td><span class="caret">▸</span></td>'
  +'<td><span class="pill p'+f.severity+'">'+SEVLBL[f.severity]+'</span></td>'
  +'<td>'+vb+'</td><td class="det">'+esc(f.detector)+'</td>'
  +'<td class="loc">'+loc+'</td>'
  +'<td><span class="val" title="Click to copy">'+esc(f.value)+'</span></td>';
 let dtr=null;
 tr.addEventListener('click',()=>{
  if(!dtr){ dtr=document.createElement('tr'); dtr.className='detail';
   dtr.innerHTML='<td colspan="6">'+detailHTML(f,i)+'</td>'; tr.after(dtr); tr.classList.add('open'); return; }
  const o=dtr.style.display==='none'; dtr.style.display=o?'':'none'; tr.classList.toggle('open',o);});
 tr.querySelector('.val').addEventListener('click',ev=>{ev.stopPropagation();copy(f.value);});
 return tr;
}
function render(resetPage){
 if(resetPage!==false) page=0;
 view=[]; DATA.findings.forEach((f,i)=>{ if(match(f)) view.push(i); });
 const pages=Math.max(1,Math.ceil(view.length/PAGE));
 if(page>=pages) page=pages-1;
 const tb=document.getElementById('rows'); tb.innerHTML='';
 const frag=document.createDocumentFragment();
 view.slice(page*PAGE,(page+1)*PAGE).forEach(i=>frag.appendChild(rowFor(DATA.findings[i],i)));
 tb.appendChild(frag);
 if(!view.length) tb.innerHTML='<tr><td colspan="6" class="empty">No findings match the current filters.</td></tr>';
 document.getElementById('count').textContent=view.length.toLocaleString()+' / '+DATA.findings.length.toLocaleString()+' findings';
 renderPager(pages);
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
 const live=DATA.findings.filter(f=>f.verified==='live');
 if(!live.length){toast('No verified-live credentials');return;}
 copy(live.map(f=>f.detector+'\t'+f.path+':'+f.line+'\t'+f.value).join('\n'));
}
function renderExtra(){
 let h='';
 const db=DATA.databases||[];
 if(db.length){ h+='<h2>Databases</h2>';
  db.forEach(d=>{ h+='<h3 class="loc">'+esc(d.path)+'</h3>';
   const sc=(d.sensitive_columns||[]); if(sc.length) h+='<p class="susp">⚠ sensitive columns: '+esc(sc.join(', '))+'</p>';
   const tb=(d.tables||[]); if(tb.length){ h+='<table class="subt"><thead><tr><th>Table</th><th>Rows</th><th>Columns</th></tr></thead><tbody>';
    tb.forEach(t=>{h+='<tr><td>'+esc(t.name)+'</td><td>'+(t.rows==null?'':t.rows)+'</td><td class="loc">'+esc((t.columns||[]).join(', '))+'</td></tr>';});
    h+='</tbody></table>'; } });
 }
 const titles={database:'Databases',key_material:'Key material',sensitive_name:'Sensitive filenames',
  executable:'Executables',archive:'Archives',config:'Config files',git_history:'Git history'};
 const as=DATA.assets||{}; let any=false;
 let ah='';
 for(const k in titles){ const items=as[k]||[]; if(!items.length) continue; any=true;
  ah+='<h3>'+titles[k]+' <span class="sz">('+items.length+')</span></h3><div class="asset"><ul>';
  items.forEach(i=>{ah+='<li>'+esc(i.path)+' <span class="sz">('+human(i.size)+')</span></li>';}); ah+='</ul></div>'; }
 if(any) h+='<h2>Detected assets</h2>'+ah;
 document.getElementById('extra').innerHTML=h;
}
function human(n){const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(1)+u[i];}
document.addEventListener('keydown',e=>{
 const q=document.getElementById('q');
 if(e.key==='/' && document.activeElement!==q){e.preventDefault();q.focus();}
 else if(e.key==='Escape' && document.activeElement===q){q.value='';render();q.blur();}
});
render(); renderExtra();
</script></body></html>"""


def _severity_options(by_type: dict) -> str:
    return "".join(f"<option value=\"{d}\">{d} ({c})</option>"
                   for d, c in sorted(by_type.items(), key=lambda x: -x[1]))


def _md_to_html(text: str) -> str:
    """Minimal, safe Markdown-ish rendering (headings, lists, paragraphs)."""
    import html as _h
    out, in_list = [], False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        esc = _h.escape(line.strip())
        if line.lstrip().startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{_h.escape(line.lstrip()[3:])}</h3>")
        elif line.lstrip()[:2] in ("- ", "* ") or (line.lstrip()[:2].rstrip() == "-"):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_h.escape(line.lstrip()[2:])}</li>")
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


def _compact(f: dict, keep_block: bool) -> dict:
    """Trim a finding for embedding in HTML (the JSON/CSV keep the full data)."""
    out = {k: f[k] for k in ("detector", "severity", "line", "col", "path", "verified", "detail", "fingerprint")}
    out["value"] = f["value"][:_FIELD_CAP] if f["value"] else f["value"]
    out["context"] = (f["context"] or "")[:_FIELD_CAP]
    if keep_block and f.get("context_block"):
        out["context_block"] = [[n, t[:_FIELD_CAP]] for n, t in f["context_block"]]
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
    total = rs["total_findings"] or 1
    bar = (f"<i style='width:{c3 / total * 100:.1f}%;background:var(--crit)'></i>"
           f"<i style='width:{c2 / total * 100:.1f}%;background:var(--high)'></i>"
           f"<i style='width:{c1 / total * 100:.1f}%;background:var(--med)'></i>")
    supp = rs.get("suppressed_by_baseline", 0)
    supp_note = f" · {supp} hidden by baseline" if supp else ""
    metaline = (f"Target: <b>{_h.escape(m['target'])}</b> · {m['files_scanned']} scanned / "
                f"{m['files_seen']} seen · {m['nested']} nested · {m['git_blobs']} git-history · "
                f"{m['seconds']}s{supp_note} · {_h.escape(m['generated'])} · v{m['version']}")
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
    trunc = (f'<div class="trunc">Showing the {len(embedded):,} highest-severity findings of '
             f'{len(all_f):,}. The full list is in the accompanying .csv / .json export '
             f'(or re-run with <code>--html-max 0</code> to embed everything).</div>') if omitted else ""

    doc = (_TEMPLATE
           .replace("__TARGET__", _h.escape(m["target"]))
           .replace("__MASKBADGE__", mask_badge)
           .replace("__METALINE__", metaline)
           .replace("__C3__", str(c3)).replace("__C2__", str(c2)).replace("__C1__", str(c1))
           .replace("__LIVE__", str(rs["verified_live"])).replace("__TOTAL__", str(rs["total_findings"]))
           .replace("__BAR__", bar)
           .replace("__AISECTION__", _ai_section(m))
           .replace("__DETOPTS__", _severity_options(rs["by_type"]))
           .replace("__VERSION__", str(m["version"]))
           .replace("__TRUNCNOTE__", trunc)
           .replace("__DATA__", data))
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return omitted
