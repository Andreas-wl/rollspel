// node build.mjs  →  dist/<id>.html
// Hemligheter krypteras med AES-GCM (nyckel via PBKDF2 från koden). Klartext hamnar aldrig i dist/.
import { webcrypto as crypto } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { characters, shared, maps } from './data.mjs';

const ITER = 60000;
const b64 = (u8) => Buffer.from(u8).toString('base64');
const norm = (c) => c.trim().toUpperCase().replace(/\s+/g, '-');

async function encrypt(code, payload) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(payload))));
  return { s: b64(salt), i: b64(iv), c: b64(ct) };
}

// Minimal markdown: **fet**, stycken, > ruta
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const md = (s) => s.split(/\n\n+/).map((p) => {
  const quote = p.startsWith('> ');
  const h = esc(quote ? p.slice(2) : p).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  return quote ? `<aside class="note">${h}</aside>` : `<p>${h}</p>`;
}).join('');

const ATTRS = [
  ['STY', 'Styrka', 'Råstyrka och fysisk tålighet.', ['Tunga maskiner', 'Närstrid', 'Uthållighet']],
  ['SMI', 'Smidighet', 'Kroppskontroll, snabbhet och motorik.', ['Avståndsstrid', 'Rörlighet', 'Pilot']],
  ['SKA', 'Skarpsinne', 'Uppfattning, intelligens och mental skärpa.', ['Observation', 'Överlevnad', 'Teknik']],
  ['EMP', 'Empati', 'Personlig utstrålning och förmåga att påverka andra.', ['Befäl', 'Manipulation', 'Sjukvård']],
];
const SKILL_HELP = {
  'Tunga maskiner': 'Köra Power Loader, lyfta tungt, bända upp dörrar, reparera grova maskiner.',
  'Närstrid': 'Slåss med knytnävar, knivar och tillhyggen.',
  'Uthållighet': 'Stå emot kyla, svält, hårt arbete och smärta. Används när du är nära att dö.',
  'Avståndsstrid': 'Skjuta med pistoler, gevär, eldkastare och bultpistoler.',
  'Rörlighet': 'Fly, klättra, smyga, ta skydd, ta sig loss ur grepp.',
  'Pilot': 'Flyga skepp och köra fordon under press.',
  'Observation': 'Upptäcka faror, lyssna, läsa av rörelsedetektorn, upptäcka smygande fiender.',
  'Överlevnad': 'Klara sig i fientliga miljöer, hitta vägen, hantera vakuum och gifter.',
  'Teknik': 'Reparera elektronik, hacka system, använda datorer och MOTHER.',
  'Befäl': 'Ge order, få andra att agera i kris, hjälpa någon som har panik.',
  'Manipulation': 'Övertala, ljuga, hota och förhandla.',
  'Sjukvård': 'Ge första hjälpen, stoppa blödningar, behandla kritiska skador.',
};

const CSS = `:root{--bg:#0b100d;--panel:#121a15;--line:#24382b;--fg:#d9e4dc;--muted:#8aa394;--accent:#7dffa8;--warn:#ffb547;--danger:#ff6b5e;
--mono:"Share Tech Mono",ui-monospace,Consolas,monospace;--serif:"Source Serif 4",Georgia,serif;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.55 var(--serif);-webkit-text-size-adjust:100%}
.wrap{max-width:640px;margin:0 auto;padding:0 max(16px,env(safe-area-inset-left)) calc(40px + env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-right))}
h1,h2,h3,.mono{font-family:var(--mono);font-weight:400;letter-spacing:.08em}
h2{font-size:1rem;text-transform:uppercase;color:var(--accent);margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
p{margin:.6em 0}
strong{color:#fff}
.top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(6px);border-bottom:1px solid var(--line);padding:calc(10px + env(safe-area-inset-top)) 16px 10px;font:12px var(--mono);letter-spacing:.2em;color:var(--muted);text-transform:uppercase;display:flex;justify-content:space-between;gap:8px}
.top b{color:var(--accent);font-weight:400}
.hero{padding:24px 0 4px}
.hero h1{font-size:2.2rem;margin:0;color:var(--accent);line-height:1.1}
.hero .sub{font:14px var(--mono);color:var(--muted);letter-spacing:.1em;margin-top:4px}
.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:16px 0 0}
.facts div{background:var(--panel);border:1px solid var(--line);padding:8px 10px}
.facts dt{font:11px var(--mono);letter-spacing:.15em;text-transform:uppercase;color:var(--muted)}
.facts dd{margin:0}
/* trackers */
.track{background:var(--panel);border:1px solid var(--line);padding:12px 14px;margin-bottom:12px}
.track .row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.track .lbl{font:14px var(--mono);letter-spacing:.12em;text-transform:uppercase}
.track .ctl{display:flex;align-items:center;gap:6px}
.track button{all:unset;cursor:pointer;width:48px;height:48px;display:grid;place-items:center;border:1px solid var(--line);font:24px var(--mono);color:var(--fg);touch-action:manipulation}
.track button:active{background:var(--line)}
.track output{font:30px var(--mono);min-width:56px;text-align:center}
.pips{display:flex;gap:4px;margin-top:10px}
.pips i{flex:1;height:10px;border:1px solid var(--line)}
.health .pips i.on{background:var(--accent);border-color:var(--accent)}
.stress .lbl,.stress output{color:var(--warn)}
.stress .pips i.on{background:var(--warn);border-color:var(--warn)}
.stress.high .pips i.on{background:var(--danger);border-color:var(--danger)}
.track .hint{font-size:.9rem;color:var(--muted);margin:10px 0 0}
/* attributes */
.attr{background:var(--panel);border:1px solid var(--line);margin-bottom:10px}
.attr header{display:flex;justify-content:space-between;align-items:baseline;padding:10px 14px 0}
.an{font:15px var(--mono);letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}
.av{font:28px var(--mono);color:var(--accent)}
.ah{margin:0;padding:0 14px 6px;color:var(--muted);font-size:.92rem}
.attr ul{list-style:none;margin:0;padding:0}
.attr li{border-top:1px solid var(--line)}
.attr summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:1fr 28px 52px;gap:8px;align-items:center;padding:12px 14px;min-height:48px}
.attr summary::-webkit-details-marker{display:none}
.attr summary span::after{content:" ›";color:var(--muted)}
.attr details[open] summary span::after{content:" ⌄"}
.attr summary b{font:18px var(--mono);font-weight:400;text-align:right}
.attr summary em{font:14px var(--mono);font-style:normal;color:var(--muted);text-align:right}
.attr li.zero summary{color:var(--muted)}
.attr details p{margin:0;padding:0 14px 12px;color:var(--muted);font-size:.95rem}
/* cards */
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);padding:6px 16px 10px;margin-bottom:12px}
.card h3{font-size:.95rem;text-transform:uppercase;color:var(--accent);margin:8px 0 0}
.card .en{font:12px var(--mono);color:var(--muted)}
details.rule{border-top:1px solid var(--line)}
details.rule:last-of-type{border-bottom:1px solid var(--line)}
details.rule summary{cursor:pointer;padding:12px 0;font:14px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--warn);min-height:44px}
details.rule ul{padding-left:1.2em;margin:0 0 12px}
details.rule li{margin:4px 0}
.note{display:block;margin:.8em 0;padding:10px 12px;border:1px solid var(--line);border-left:3px solid var(--warn);background:var(--bg);font-size:.95rem}
textarea{width:100%;min-height:120px;background:var(--panel);color:var(--fg);border:1px solid var(--line);padding:10px;font:16px var(--serif);resize:vertical}
/* secrets */
.unlock{display:flex;gap:8px}
.unlock input{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);color:var(--fg);font:18px var(--mono);letter-spacing:.12em;text-transform:uppercase;padding:10px 12px}
.unlock button{font:14px var(--mono);letter-spacing:.12em;text-transform:uppercase;background:var(--accent);color:var(--bg);border:0;padding:0 16px;cursor:pointer}
.msg{font:13px var(--mono);min-height:1.4em;margin:6px 0 12px;color:var(--muted)}
.msg.bad{color:var(--danger)} .msg.ok{color:var(--accent)}
.secret{scroll-margin-top:70px;border-left-color:var(--danger);animation:in .5s ease-out}
.secret .stamp{font:11px var(--mono);letter-spacing:.2em;color:var(--danger);text-transform:uppercase;margin-top:8px}
.secret.infected{border-left-color:#c33;background:#1a0f0f}
@keyframes in{from{opacity:0;transform:translateY(6px)}}
button:focus-visible,input:focus-visible,summary:focus-visible,textarea:focus-visible{outline:2px solid var(--warn);outline-offset:2px}
.foot{margin-top:28px;font:12px var(--mono);color:var(--muted);text-align:center}
.foot button{all:unset;cursor:pointer;text-decoration:underline}`;
const UNLOCK_JS = `const ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const norm=c=>c.trim().toUpperCase().replace(/\\s+/g,'-');
async function tryOpen(code,b){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(code),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:ub(b.s),iterations:ITER,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  try{return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(b.i)},key,ub(b.c))))}catch{return null}
}
const box=document.getElementById('secrets'),msg=document.getElementById('msg');
function show(s){
  const d=document.createElement('div');d.className='card secret'+(s.kind==='infected'?' infected':'');d.id='sec-'+s.n;
  d.innerHTML='<div class="stamp">'+({infected:'⚠ Biologisk varning',map:'Kartdata · MU/TH/UR',sl:'Spelledare'}[s.kind]||'Endast för dina ögon')+'</div><h3></h3>'+s.html;
  d.querySelector('h3').textContent=s.title;
  const all=[...box.children];const after=all.find(x=>+x.id.slice(4)>s.n);box.insertBefore(d,after||null);return d;
}
async function find(code){for(const b of BLOBS){const s=await tryOpen(code,b);if(s)return s}return null}
let codes=ls.get('codes',[]);
(async()=>{for(const c of codes){const s=await find(c);if(s&&!document.getElementById('sec-'+s.n))show(s)}})();
document.getElementById('unlock').onsubmit=async e=>{
  e.preventDefault();const inp=document.getElementById('code');const code=norm(inp.value);if(!code)return;
  msg.className='msg';msg.textContent='Kontaktar MOTHER…';
  const s=await find(code);
  if(!s){msg.className='msg bad';msg.textContent='ÅTKOMST NEKAD. Okänd kod.';return}
  inp.value='';
  if(document.getElementById('sec-'+s.n)){msg.className='msg ok';msg.textContent='Redan öppnad.';document.getElementById('sec-'+s.n)?.scrollIntoView({behavior:'smooth'});return}
  codes.push(code);ls.set('codes',codes);
  msg.className='msg ok';msg.textContent='Meddelande mottaget.';
  show(s).scrollIntoView({behavior:'smooth',block:'start'});
};`;

function page(id, ch, blobs) {
  const skillRows = ATTRS.map(([k, name, help, skills]) => `
    <section class="attr">
      <header><span class="an">${name}</span><span class="av">${ch.attrs[k]}</span></header>
      <p class="ah">${help}</p>
      <ul>${skills.map((s) => {
        const v = ch.skills[s] || 0;
        return `<li class="${v ? '' : 'zero'}"><details><summary><span>${s}</span><b>${v}</b><em title="Tärningar att slå">${ch.attrs[k] + v} T6</em></summary><p>${SKILL_HELP[s]}</p></details></li>`;
      }).join('')}</ul>
    </section>`).join('');

  return `<!doctype html>
<html lang="sv"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex">
<title>${ch.name} – USCSS Montero</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<style>
${CSS}
</style></head><body>
<div class="top"><span>USCSS Montero</span><b>${ch.career}</b></div>
<main class="wrap">
  <section class="hero">
    <h1>${ch.name.toUpperCase()}</h1>
    <div class="sub">${ch.fullName} · ${ch.role}</div>
    <dl class="facts">
      <div><dt>Ålder</dt><dd>${ch.age}</dd></div>
      <div><dt>Personlighet</dt><dd>${ch.personality}</dd></div>
      <div><dt>Vän</dt><dd>${ch.buddy || '–'}</dd></div>
      <div><dt>Rival</dt><dd>${ch.rival || '–'}</dd></div>
    </dl>
  </section>

  <h2>Status</h2>
  <div class="track health" data-k="health" data-max="${ch.health}">
    <div class="row"><span class="lbl">Hälsa</span><span class="ctl"><button aria-label="Minska hälsa">−</button><output>${ch.health}</output><button aria-label="Öka hälsa">+</button></span></div>
    <div class="pips"></div>
    <p class="hint">Max ${ch.health}. Når du 0 är du <strong>bruten</strong> och slår på tabellen för kritiska skador.</p>
  </div>
  <div class="track stress" data-k="stress" data-max="10">
    <div class="row"><span class="lbl">Stress</span><span class="ctl"><button aria-label="Minska stress">−</button><output>0</output><button aria-label="Öka stress">+</button></span></div>
    <div class="pips"></div>
    <p class="hint">Lägg till lika många <strong>stresstärningar</strong> som din stress när du slår. Visar någon stresstärning en <strong>1:a</strong> får du göra ett panikslag.</p>
  </div>

  <h2>Vem du är</h2>
  ${md(ch.bio)}

  <h2>Att slå tärning</h2>
  <details class="rule"><summary>Så funkar ett slag</summary><ul>
    <li>Slå lika många T6 som <strong>grundegenskap + färdighet</strong> (T6-siffran längst till höger nedan).</li>
    <li>Varje <strong>6:a</strong> är ett lyckat resultat. Du behöver minst en.</li>
    <li>Fler 6:or ger extra effekter, till exempel mer skada eller snabbare.</li>
  </ul></details>
  <details class="rule"><summary>Pressa slaget</summary><ul>
    <li>Misslyckades du? Du får slå om alla tärningar som inte visar 6.</li>
    <li>Det kostar <strong>+1 stress</strong> först, och du slår med den nya stressnivån.</li>
  </ul></details>
  <details class="rule"><summary>Stress och panik</summary><ul>
    <li>Du får stress när du pressar slag, skjuter med automatvapen, ser hemska saker och när SL säger det.</li>
    <li>Stresstärningar ger fler chanser till 6:or men varje <strong>1:a</strong> = panikslag (T6 + din stress).</li>
    <li>Stress sjunker när du vilar på en säker plats eller med SL:s tillåtelse.</li>
  </ul></details>

  <h2>Grundegenskaper &amp; färdigheter</h2>
  <p class="mono" style="font-size:13px;color:var(--muted)">Tryck på en färdighet för att läsa vad den används till.</p>
  ${skillRows}

  <h2>Talang</h2>
  <div class="card"><h3>${ch.talent.name}</h3><div class="en">${ch.talent.en}</div>${md(ch.talent.text)}</div>

  <h2>Personligt föremål</h2>
  <div class="card"><p>${ch.item}</p></div>

  <h2>Från MOTHER</h2>
  <p>Ibland får du en kod av spelledaren. Skriv in den här för att läsa meddelandet. Visa det inte för de andra.</p>
  <form class="unlock" id="unlock" autocomplete="off"><input id="code" aria-label="Kod" placeholder="KOD" autocapitalize="characters" spellcheck="false"><button>Öppna</button></form>
  <div class="msg" id="msg" role="status"></div>
  <div id="secrets"></div>

  <h2>Anteckningar</h2>
  <textarea id="notes" placeholder="Saker du vill komma ihåg..."></textarea>

  <div class="foot">Sparas bara i den här telefonen · <button id="reset">Nollställ sidan</button></div>
</main>
<script>
const ID=${JSON.stringify(id)},KEY='alien:'+ID+':',ITER=${ITER};
const BLOBS=${JSON.stringify(blobs)};
const ls={get(k,d){try{const v=localStorage.getItem(KEY+k);return v===null?d:JSON.parse(v)}catch{return d}},set(k,v){try{localStorage.setItem(KEY+k,JSON.stringify(v))}catch{}}};
// trackers
document.querySelectorAll('.track').forEach(t=>{
  const k=t.dataset.k,max=+t.dataset.max,out=t.querySelector('output'),pips=t.querySelector('.pips');
  let v=ls.get(k,k==='health'?max:0);
  pips.innerHTML='<i></i>'.repeat(max);
  const draw=()=>{out.textContent=v;[...pips.children].forEach((p,i)=>p.classList.toggle('on',i<v));if(k==='stress')t.classList.toggle('high',v>=7);ls.set(k,v)};
  const [minus,plus]=t.querySelectorAll('button');
  minus.onclick=()=>{v=Math.max(0,v-1);draw()};plus.onclick=()=>{v=Math.min(max,v+1);draw()};
  draw();
});
// notes
const notes=document.getElementById('notes');notes.value=ls.get('notes','');notes.oninput=()=>ls.set('notes',notes.value);
// secrets
${UNLOCK_JS}
document.getElementById('reset').onclick=()=>{if(!confirm('Nollställa hälsa, stress, anteckningar och öppnade meddelanden?'))return;
  try{Object.keys(localStorage).filter(k=>k.startsWith(KEY)).forEach(k=>localStorage.removeItem(k))}catch{};location.reload()};
</script>
</body></html>`;
}

const SL_KOD = process.env.SL_KOD;
if (!SL_KOD) { console.error('Sätt SL_KOD (spelledarens lösenord), t.ex.  SL_KOD=xxx node build.mjs'); process.exit(1); }
mkdirSync('dist', { recursive: true });
for (const [id, ch] of Object.entries(characters)) {
  const list = [...ch.secrets, ...shared];
  const blobs = [];
  for (const [n, s] of list.entries()) blobs.push(await encrypt(s.code, { n, title: s.title, kind: s.kind, html: md(s.body) }));
  // blanda ordningen så att antalet/ordningen inte avslöjar vad som är vad
  blobs.sort(() => Math.random() - 0.5);
  writeFileSync(`dist/${id}.html`, page(id, ch, blobs));
  console.log(`dist/${id}.html  (${list.length} låsta meddelanden)`);
}

// Enkel låst sida (kartor, SL-koder)
function lockPage({ id, title, intro, blobs, wide }) {
  return `<!doctype html><html lang="sv"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex">
<title>${title} – USCSS Montero</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<style>${CSS}
.secret img{display:block;width:100%;height:auto;margin:8px 0;border:1px solid var(--line)}
.back{color:var(--muted);text-decoration:none}
${wide ? '.wrap{max-width:900px}' : ''}</style></head><body>
<div class="top"><a class="back" href="index.html">‹ Besättning</a><b>${title}</b></div>
<main class="wrap">
  <h2>${title}</h2>
  <p>${intro}</p>
  <form class="unlock" id="unlock" autocomplete="off"><input id="code" aria-label="Kod" placeholder="KOD" autocapitalize="characters" spellcheck="false"><button>Öppna</button></form>
  <div class="msg" id="msg" role="status"></div>
  <div id="secrets"></div>
</main>
<script>
const KEY='alien:${id}:',ITER=${ITER};
const BLOBS=${JSON.stringify(blobs)};
const ls={get(k,d){try{const v=localStorage.getItem(KEY+k);return v===null?d:JSON.parse(v)}catch{return d}},set(k,v){try{localStorage.setItem(KEY+k,JSON.stringify(v))}catch{}}};
${UNLOCK_JS}
</script></body></html>`;
}

const mapBlobs = [];
for (const [n, m] of maps.entries()) {
  const html = m.images.map((f) => `<img alt="${m.title}" src="data:image/jpeg;base64,${readFileSync('maps/' + f).toString('base64')}">`).join('');
  mapBlobs.push(await encrypt(m.code, { n, title: m.title, kind: 'map', html }));
}
writeFileSync('dist/kartor.html', lockPage({ id: 'kartor', title: 'Kartor', wide: true, blobs: mapBlobs.sort(() => Math.random() - 0.5),
  intro: 'Skeppsritningar från MU/TH/UR. Spelledaren ger er en kod när ni får tillgång till en karta. Nyp för att zooma.' }));
console.log(`dist/kartor.html  (${maps.length} låsta kartor)`);

// Startsida
const cards = Object.entries(characters).map(([id, c]) =>
  `<a href="${id}.html"><b>${c.name.toUpperCase()}</b><span>${c.role}</span></a>`).join('');
writeFileSync('dist/index.html', `<!doctype html><html lang="sv"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>USCSS Montero – Besättning</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap">
<style>:root{color-scheme:dark}body{margin:0;background:#0b100d;color:#d9e4dc;font:16px "Share Tech Mono",ui-monospace,monospace}
main{max-width:520px;margin:0 auto;padding:calc(32px + env(safe-area-inset-top)) 16px 40px}
h1{color:#7dffa8;font-weight:400;letter-spacing:.15em;margin:0}p{color:#8aa394;letter-spacing:.05em}
a{display:flex;flex-direction:column;gap:2px;padding:16px;margin-bottom:10px;background:#121a15;border:1px solid #24382b;border-left:3px solid #7dffa8;color:inherit;text-decoration:none}
a b{color:#7dffa8;font-weight:400;font-size:1.3rem;letter-spacing:.15em}a span{color:#8aa394;font-size:.85rem}a:active{background:#24382b}</style></head>
<body><main><h1>MU/TH/UR 6000</h1><p>USCSS MONTERO · BESÄTTNINGSREGISTER<br>Välj din profil.</p>${cards}<a href="kartor.html" style="border-left-color:#ffb547;margin-top:24px"><b style="color:#ffb547">KARTOR</b><span>Skeppsritningar</span></a></main></body></html>`);

// Kodlista för SL – krypterad med SL_KOD, publiceras som dist/sl.html
const li = (list) => '<ul>' + list.map((x) => `<li>${esc(x.title)}: <strong>${esc(x.code)}</strong></li>`).join('') + '</ul>';
let sl = '';
for (const c of Object.values(characters)) sl += `<h3>${c.name}</h3>${li(c.secrets)}`;
sl += `<h3>Gemensamma (alla sidor)</h3><p>Ge bara till den som blir Lucas / smittas.</p>${li(shared)}<h3>Kartor</h3>${li(maps)}`;
writeFileSync('dist/sl.html', lockPage({ id: 'sl', title: 'Spelledare', intro: 'Ange spelledarkoden.',
  blobs: [await encrypt(SL_KOD, { n: 0, title: 'Alla koder', kind: 'sl', html: sl })] }));
console.log('dist/index.html, dist/sl.html');
