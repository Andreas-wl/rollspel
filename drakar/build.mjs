// SL_KOD=xxx node build.mjs  →  dist/
// Kartor, reservrollpersoner och kodlistan krypteras med AES-GCM (nyckel via PBKDF2 från koden).
import { webcrypto as crypto } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { characters, reserves, maps } from './data.mjs';

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
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

const ATTRS = [
  ['STY', 'Styrka', 'Rå kroppslig muskelkraft.', 'Utmattad'],
  ['FYS', 'Fysik', 'Fysisk kondition och motståndskraft.', 'Krasslig'],
  ['SMI', 'Smidighet', 'Kroppskontroll, snabbhet och finmotorik.', 'Omtöcknad'],
  ['INT', 'Intelligens', 'Sinnesskärpa, logik och förnuft.', 'Arg'],
  ['PSY', 'Psyke', 'Viljestyrka och mentalt fokus.', 'Rädd'],
  ['KAR', 'Karisma', 'Personlig utstrålning och empati.', 'Uppgiven'],
];
const SKILLS = [
  ['Bestiologi', 'INT', 'Känna till monster och djur, och deras svagheter.'],
  ['Bluffa', 'KAR', 'Ljuga och lura någon.'],
  ['Fingerfärdighet', 'SMI', 'Dyrka lås, desarmera fällor, stjäla ur fickor. Lirka upp lönndörrar.'],
  ['Finna dolda ting', 'INT', 'Leta upp det som är gömt: lönndörrar, fällor, skatter.'],
  ['Främmande språk', 'INT', 'Tyda okända språk och gamla skrifter.'],
  ['Hantverk', 'STY', 'Bygga och laga saker, till exempel ett trasigt vapen.'],
  ['Hoppa & klättra', 'SMI', 'Klättra, hoppa långt och mildra fall.'],
  ['Jakt & fiske', 'SMI', 'Skaffa mat i naturen.'],
  ['Köpslå', 'KAR', 'Pruta och göra affärer.'],
  ['Läkekonst', 'INT', 'Rädda den som är på noll KP, och vårda under kort vila.'],
  ['Myter & legender', 'INT', 'Minnas sagor, historia och gamla berättelser.'],
  ['Rida', 'SMI', 'Hantera riddjur.'],
  ['Simma', 'SMI', 'Hålla dig flytande, dyka och hitta rätt under vatten.'],
  ['Sjökunnighet', 'INT', 'Segla, navigera och kunna allt om skepp.'],
  ['Smyga', 'SMI', 'Röra dig tyst och obemärkt, och göra smygattacker.'],
  ['Undvika', 'SMI', 'Ducka för attacker och slippa frislag.'],
  ['Uppträda', 'KAR', 'Sjunga, spela och underhålla.'],
  ['Upptäcka fara', 'INT', 'Märka bakhåll och faror i tid. Hitta fienden i mörker.'],
  ['Vildmarksvana', 'INT', 'Hitta rätt, göra upp eld och stå emot kyla.'],
  ['Övertala', 'KAR', 'Få andra med på din linje. Få en kamrat på noll KP att kämpa på.'],
];
const WEAPONS = [['Armborst', 'SMI'], ['Hammare', 'STY'], ['Kniv', 'SMI'], ['Pilbåge', 'SMI'], ['Slagsmål', 'STY'], ['Slunga', 'SMI'], ['Spjut', 'STY'], ['Stav', 'SMI'], ['Svärd', 'STY'], ['Yxa', 'STY']];
const WEAPON_HELP = (n) => `Attackera och parera med ${n.toLowerCase()}. Kastvapen slås också mot vapenfärdigheten.`;

const SPELLS = `
  <h2>Besvärjelser</h2>
  <p>Slå mot <strong>Elementalism (FV 14)</strong> och betala VP. Det kostar <strong>2 VP per effektgrad</strong> (1–3). Misslyckas slaget är VP ändå förbrukade.</p>
  <div class="card"><h3>Trolleritrick</h3><div class="en">1 VP · lyckas alltid · handling i strid</div>
    <p><strong>Rökpuff:</strong> En imponerande rökpuff slår upp precis framför dig. Kan ge fördel på SMYGA i vissa lägen. SL avgör.</p>
    <p><strong>Tända:</strong> Du tänder eller släcker ett ljus, en fackla eller en lykta inom 10 meter.</p>
    <p><strong>Värma/kyla:</strong> Området inom 10 meter från dig blir behagligt varmt eller svalt. Skyddar mot kyla i ett skift.</p></div>
  <div class="card"><h3>Flamma</h3><div class="en">Ord, gest · 20 meter · omedelbar</div>
    <p>En flamma far från din hand eller fokus till målet. Kan duckas eller pareras som en avståndsattack. Träff ger <strong>2T6</strong> i skada och sätter eld på lättantändliga föremål. Varje effektgrad utöver den första ökar skadan med T6, eller skapar en till flamma mot ett annat mål inom räckvidden.</p></div>
  <div class="card"><h3>Pelare</h3><div class="en">Ord, gest · 10 meter · skift</div>
    <p>Drar upp en tre meter hög och en meter bred pelare ur marken eller ett stengolv. Den som står där måste klara HOPPA &amp; KLÄTTRA (ej handling) för att inte falla av. Under lågt tak ger ett misslyckat slag i stället 2T6 krosskada. Varje extra effektgrad höjer pelaren tre meter.</p></div>
  <div class="card"><h3>Vindpust</h3><div class="en">Ord, gest · 10 meter (kon) · omedelbar</div>
    <p>Lösa föremål och varelser upp till människostorlek i konen knuffas <strong>2T4</strong> meter bort från dig och tar lika mycket i krosskada. Varje extra effektgrad ger en tärning till.</p></div>
  <details class="rule"><summary>Drakslag och demonslag med magi</summary><ul>
    <li><strong>Drakslag:</strong> Det krävs drakslag för att motstå, parera eller ducka. Välj också en effekt: dubbel skada eller räckvidd, gratis besvärjelse, eller en besvärjelse till med nackdel.</li>
    <li><strong>Demonslag:</strong> Slaget får inte pressas.</li>
  </ul></details>`;

const RULES = `
  <h2>Regler</h2>
  <details class="rule"><summary>Att slå tärning</summary><ul>
    <li>Slå <strong>T20</strong>. Lika med eller under ditt FV lyckas.</li>
    <li><strong>1 = drakslag:</strong> extra lyckat. <strong>20 = demonslag:</strong> misslyckas alltid och kan inte pressas.</li>
    <li><strong>Fördel:</strong> slå två T20, räkna den lägsta. <strong>Nackdel:</strong> räkna den högsta. En fördel tar ut en nackdel.</li>
    <li><strong>Hjälpa:</strong> säg till innan tärningen slås. Den du hjälper får en fördel. Bara en person kan hjälpa per slag, och i strid kostar det din handling.</li>
    <li>Du har som regel en chans på samma sak. Prova något annat, eller låt någon annan försöka.</li>
  </ul></details>
  <details class="rule"><summary>Pressa slaget</summary><ul>
    <li>Misslyckades du? Slå om. Det nya resultatet gäller, vad det än visar.</li>
    <li>Direkt efter tar du ett <strong>tillstånd</strong> du inte redan har, och förklarar hur det uppstod.</li>
    <li>Ett tillstånd ger nackdel på allt som bygger på dess grundegenskap.</li>
    <li>Demonslag kan inte pressas. Inte dödsslag heller.</li>
  </ul></details>
  <details class="rule"><summary>Din tur i strid</summary><ul>
    <li>Alla drar ett initiativkort varje runda. Lägst börjar. Du får <strong>förflytta dig och göra en handling</strong>, i valfri ordning.</li>
    <li><strong>Avvakta:</strong> byt kort med någon som ligger efter dig.</li>
    <li><strong>Handlingar:</strong> sprinta (dubbel förflyttning), attackera, plocka upp något, hjälpa, första hjälpen, kämpa på, dyrka lås, använda föremål, aktivera förmåga, lägga besvärjelse, snabb vila.</li>
    <li><strong>Fria handlingar</strong> (en av varje på din tur): dra vapen, kasta dig ner eller resa dig, släppa något, ropa några ord.</li>
    <li><strong>Frislag:</strong> går du frivilligt bort från en fiende inom 2 m slår du UNDVIKA. Misslyckas du får fienden en extra attack.</li>
    <li>En ruta på kartan är 2×2 meter.</li>
  </ul></details>
  <details class="rule"><summary>Attackera</summary><ul>
    <li><strong>Närstrid:</strong> inom 2 m (4 m med långt vapen). Slå mot vapenfärdigheten och lägg till skadebonus vid träff.</li>
    <li><strong>Avstånd:</strong> nackdel om fienden står inom 2 m eller är delvis skymd. Dubbel räckvidd går med nackdel.</li>
    <li><strong>Drakslag = kritisk träff:</strong> krävs drakslag för att parera eller ducka. Välj dubbla skadetärningar, eller att stickskada går förbi rustningen. I närstrid kan du i stället attackera en annan fiende direkt.</li>
    <li><strong>Liggande fiende:</strong> fördel och T6 extra i skada.</li>
    <li><strong>Knuffa:</strong> är din STY-skadebonus minst lika hög som fiendens kan du knuffa den 2 m vid träff (inte monster).</li>
    <li><strong>Smygattack:</strong> slå SMYGA (nackdel för att komma inom 2 m). Lyckas du får du välja initiativkort och fördel, och målet kan inte ducka eller parera. Smidigt vapen ger en skadetärning extra.</li>
  </ul></details>
  <details class="rule"><summary>Parera och ducka</summary><ul>
    <li>Bägge sker <strong>utanför din tur</strong> och ersätter den, så du måste ha turen kvar. Säg till innan skadan slås.</li>
    <li><strong>Parera:</strong> slå mot vapnets FV, med draget vapen eller sköld. Är skadan högre än brytvärdet går vapnet sönder. Avståndsattacker kräver sköld. Monster kan som regel inte pareras.</li>
    <li><strong>Ducka:</strong> slå UNDVIKA. Lyckas du kan du även flytta dig 2 m utan frislag. Går oftast att göra mot monster.</li>
  </ul></details>
  <details class="rule"><summary>Noll KP och dödsslag</summary><ul>
    <li>På noll KP faller du. På din tur slår du <strong>dödsslag</strong> mot FYS varje runda.</li>
    <li><strong>Tre lyckade:</strong> du får T6 KP. <strong>Tre misslyckade:</strong> du dör. Drakslag räknas som två lyckade, demonslag som två misslyckade.</li>
    <li>Mer skada på noll KP = ett automatiskt misslyckat dödsslag.</li>
    <li><strong>Rädda liv:</strong> någon intill slår LÄKEKONST (handling). Du får T6 KP.</li>
    <li><strong>Kämpa på:</strong> någon inom 10 m kan ÖVERTALA dig att fortsätta slåss. Du slår dödsslag ändå.</li>
    <li>Går en enda skada ner till minus ditt hela KP-värde dör du direkt.</li>
  </ul></details>
  <details class="rule"><summary>Vila</summary><ul>
    <li><strong>Snabb vila</strong> (en runda): T6 VP. En gång per skift.</li>
    <li><strong>Kort vila</strong> (en kvart): T6 KP (2T6 om någon vårdar dig och klarar LÄKEKONST), T6 VP och ett valfritt tillstånd. En gång per skift. Minnessaken ger ett extra tillstånd en gång per spelmöte.</li>
    <li><strong>Lång vila</strong> (ett skift, säker plats): allt läks.</li>
  </ul></details>
  <details class="rule"><summary>Mörker, vatten och fall</summary><ul>
    <li><strong>Mörker:</strong> ingen sprint och inga avståndsattacker. För närstrid måste du först klara UPPTÄCKA FARA.</li>
    <li><strong>Fackla:</strong> lyser 10 m, kräver en hand, tänds med en handling. Efter varje kvart slår du T6, på en etta slocknar den.</li>
    <li><strong>Vatten:</strong> halv förflyttning, nackdel i närstrid, inga avståndsattacker. Ringbrynja eller plåt ger nackdel på SIMMA och slag varje runda för att hålla dig flytande.</li>
    <li><strong>Under vatten:</strong> slå FYS varje runda för att hålla andan. Misslyckas du tar du T6 skada per runda.</li>
    <li><strong>Fall:</strong> T6 krosskada per 2 meter, avrundat nedåt. HOPPA &amp; KLÄTTRA halverar. Rustning skyddar inte.</li>
  </ul></details>
  <details class="rule"><summary>Skräck</summary>
    <p>Slå mot PSY (går att pressa). Misslyckas du, slå T8:</p><ol>
    <li><strong>Kraftlös:</strong> förlorar 2T6 VP och blir Uppgiven.</li>
    <li><strong>Skakis:</strong> blir Rädd.</li>
    <li><strong>Flämtar:</strong> blir Utmattad.</li>
    <li><strong>Blek:</strong> du och alla rollpersoner inom 10 m och synhåll blir Rädda.</li>
    <li><strong>Skrik:</strong> alla som hör dig utsätts också för en skräckattack.</li>
    <li><strong>Vredesmod:</strong> du måste angripa källan på din nästa tur, och blir Arg.</li>
    <li><strong>Paralyserad:</strong> ingen handling eller förflyttning nästa tur. Slå PSY inför varje tur för att bryta det.</li>
    <li><strong>Vild panik:</strong> du måste sprinta bort nästa tur. Slå PSY inför varje tur för att sluta fly.</li>
  </ol></details>`;

const FONTS = 'https://fonts.googleapis.com/css2?family=Cinzel:wght@500;700&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap';
const CSS = `:root{--bg:#14120e;--panel:#211c15;--line:#3d3426;--fg:#eee4d0;--muted:#ad9f88;--accent:#62c9b2;--warn:#e7b65c;--danger:#ef6a58;--on:#14120e;
--head:"Cinzel",Georgia,serif;--serif:"Source Serif 4",Georgia,serif;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.55 var(--serif);-webkit-text-size-adjust:100%}
a{color:inherit}
.wrap{max-width:640px;margin:0 auto;padding:0 max(16px,env(safe-area-inset-left)) calc(40px + env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-right))}
h1,h2,h3{font-family:var(--head);font-weight:700}
h2{font-size:1rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
p{margin:.6em 0}
strong{color:#fff}
.top{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);padding:calc(10px + env(safe-area-inset-top)) 16px 10px;font:600 13px var(--head);letter-spacing:.06em;color:var(--muted);display:flex;justify-content:space-between;gap:8px}
.top a{text-decoration:none;min-height:24px}.top b{color:var(--accent)}
.hero{padding:24px 0 4px}
.hero h1{font-size:1.9rem;margin:0;color:var(--accent);line-height:1.15}
.hero .sub{color:var(--muted);margin-top:4px}
.facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:16px 0 0}
.facts div{background:var(--panel);border:1px solid var(--line);padding:8px 10px;min-width:0}
.facts dt{font-size:12px;color:var(--muted)}
.facts dd{margin:0;font-weight:600;font-size:1.15rem}
.track{background:var(--panel);border:1px solid var(--line);padding:12px 14px;margin-bottom:12px}
.track .row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.track .lbl{font:700 15px var(--head)}
.track .ctl{display:flex;align-items:center;gap:6px}
.track button{all:unset;cursor:pointer;width:48px;height:48px;display:grid;place-items:center;border:1px solid var(--line);font-size:24px;touch-action:manipulation}
.track button:active{background:var(--line)}
.track output{font-size:28px;font-weight:600;min-width:52px;text-align:center}
.pips{display:flex;gap:3px;margin-top:10px}
.pips i{flex:1;height:10px;border:1px solid var(--line)}
.kp .pips i.on{background:var(--danger);border-color:var(--danger)}.kp .lbl{color:var(--danger)}
.vp .pips i.on{background:var(--accent);border-color:var(--accent)}.vp .lbl{color:var(--accent)}
.silver .lbl{color:var(--warn)}
.chips{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:12px}
.chip{all:unset;cursor:pointer;box-sizing:border-box;display:flex;justify-content:space-between;align-items:center;gap:6px;min-height:48px;padding:8px 12px;background:var(--panel);border:1px solid var(--line);touch-action:manipulation}
.chip small{color:var(--muted)}
.chip[aria-pressed=true]{background:var(--warn);border-color:var(--warn);color:var(--on)}
.chip[aria-pressed=true] small{color:var(--on)}
.death{background:var(--panel);border:1px solid var(--line);padding:12px 14px;margin-bottom:12px}
.death .row{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:6px}
.death .lbl{font:700 15px var(--head)}
.boxes{display:flex;gap:6px}
.box{all:unset;cursor:pointer;width:44px;height:44px;border:1px solid var(--line);display:grid;place-items:center;font-size:20px;touch-action:manipulation}
.box[aria-pressed=true]{background:var(--fg);color:var(--on)}
.bad .box[aria-pressed=true]{background:var(--danger)}
.attr{background:var(--panel);border:1px solid var(--line);margin-bottom:10px}
.attr header{display:flex;justify-content:space-between;align-items:baseline;gap:8px;padding:10px 14px 0}
.an{font:700 15px var(--head);color:var(--accent)}
.av{font-size:26px;font-weight:600;color:var(--accent)}
.ah{margin:0;padding:0 14px 6px;color:var(--muted);font-size:.92rem}
.attr .state{display:none;margin:0 14px 8px;font-size:.88rem;color:var(--on);background:var(--warn);padding:2px 8px}
.attr.dis .state{display:block}
.attr ul{list-style:none;margin:0;padding:0}
.attr li{border-top:1px solid var(--line)}
.attr summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:1fr 36px;gap:8px;align-items:center;padding:11px 14px;min-height:48px}
.attr summary::-webkit-details-marker{display:none}
.attr summary span::after{content:" ›";color:var(--muted)}
.attr details[open] summary span::after{content:" ⌄"}
.attr summary b{font-size:19px;text-align:right}
.attr summary em{display:block;font-style:normal;font-size:.8rem;color:var(--warn)}
.attr details p{margin:0;padding:0 14px 12px;color:var(--muted);font-size:.95rem}
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);padding:6px 16px 10px;margin-bottom:12px}
.card h3{font-size:1rem;color:var(--accent);margin:8px 0 0}
.card .en{font-size:.88rem;color:var(--muted)}
.wpn h3{color:var(--fg)}
.wpn dl{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:4px;margin:8px 0 4px}
.wpn dt{font-size:12px;color:var(--muted)}.wpn dd{margin:0;font-weight:600}
.wpn p{margin:4px 0;color:var(--muted);font-size:.95rem}
details.rule{border-top:1px solid var(--line)}
details.rule:last-of-type{border-bottom:1px solid var(--line)}
details.rule summary{cursor:pointer;padding:12px 0;font:700 14px var(--head);color:var(--warn);min-height:44px}
details.rule ul,details.rule ol{padding-left:1.3em;margin:0 0 12px}
details.rule li{margin:4px 0}
textarea{width:100%;min-height:120px;background:var(--panel);color:var(--fg);border:1px solid var(--line);padding:10px;font:16px var(--serif);resize:vertical}
.unlock{display:flex;gap:8px}
.unlock input{flex:1;min-width:0;min-height:48px;background:var(--panel);border:1px solid var(--line);color:var(--fg);font:18px var(--serif);letter-spacing:.08em;text-transform:uppercase;padding:10px 12px}
.unlock button{font:700 14px var(--head);background:var(--accent);color:var(--on);border:0;padding:0 16px;cursor:pointer}
.msg{font-size:15px;min-height:1.5em;margin:6px 0 12px;color:var(--muted)}
.msg.bad{color:var(--danger)}.msg.ok{color:var(--accent)}
.secret{scroll-margin-top:60px;animation:in .4s ease-out}
.secret img{display:block;width:100%;height:auto;margin:8px 0;border:1px solid var(--line)}
@keyframes in{from{opacity:0;transform:translateY(6px)}}
.again{all:unset;cursor:pointer;display:block;box-sizing:border-box;width:100%;padding:14px 16px;margin-bottom:10px;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--warn);font:700 16px var(--head);color:var(--warn)}
button:focus-visible,input:focus-visible,summary:focus-visible,textarea:focus-visible,a:focus-visible{outline:2px solid var(--warn);outline-offset:2px}
.foot{margin-top:28px;font-size:13px;color:var(--muted);text-align:center}
.foot button{all:unset;cursor:pointer;text-decoration:underline}
@media (prefers-reduced-motion:reduce){.secret{animation:none}}`;

const head = (title, extra = '') => `<!doctype html>
<html lang="sv"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex">
<title>${title} – Det sjunkande tornet</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<style>${CSS}${extra}</style></head><body>`;

function page(id, ch) {
  const dis = ch.armor?.dis || [];
  const skillLi = ([name, , help]) => {
    const i = SKILLS.findIndex((s) => s[0] === name);
    return `<li><details><summary><span>${esc(name)}${dis.includes(name) ? `<em>Nackdel: ${esc(ch.armor.name.toLowerCase())}</em>` : ''}</span><b>${ch.fv.a[i]}</b></summary><p>${esc(help)}</p></details></li>`;
  };
  const attrSections = ATTRS.map(([k, name, help, cond]) => {
    const skills = SKILLS.filter((s) => s[1] === k).map(skillLi);
    const wpns = WEAPONS.map((w, i) => [w, i]).filter(([w]) => w[1] === k).map(([w, i]) =>
      `<li><details><summary><span>${w[0]} <small style="color:var(--muted)">(vapen)</small></span><b>${ch.fv.w[i]}</b></summary><p>${esc(WEAPON_HELP(w[0]))}</p></details></li>`);
    const extra = ch.fv.extra.filter((e) => e[1] === k).map((e) => `<li><details><summary><span>${e[0]}</span><b>${e[2]}</b></summary><p>Din magiskola. Slå mot den när du lägger en besvärjelse.</p></details></li>`);
    const rows = [...skills, ...extra, ...wpns];
    return `<section class="attr" data-a="${k}">
      <header><span class="an">${name}</span><span class="av">${ch.attrs[k]}</span></header>
      <p class="ah">${help}</p><p class="state">${cond}: nackdel på allt här</p>
      ${rows.length ? `<ul>${rows.join('')}</ul>` : ''}
    </section>`;
  }).join('');
  const weapons = ch.weapons.map(([n, g, r, d, b, e]) => `<div class="card wpn"><h3>${n}</h3>
    <dl><div><dt>Skada</dt><dd>${d}</dd></div><div><dt>Räckvidd</dt><dd>${r}</dd></div><div><dt>Grepp</dt><dd>${g}</dd></div><div><dt>Brytvärde</dt><dd>${b}</dd></div></dl><p>${e}</p></div>`).join('');
  const abilities = ch.abilities.map((a) => `<div class="card"><h3>${a.name}</h3><div class="en">Viljepoäng: ${a.vp}</div><p>${esc(a.text)}</p></div>`).join('');
  const pips = (k, cls, label, max, hint) => `<div class="track ${cls}" data-k="${k}" data-max="${max}">
    <div class="row"><span class="lbl">${label}</span><span class="ctl"><button aria-label="Minska ${label}">−</button><output>${max}</output><button aria-label="Öka ${label}">+</button></span></div>
    <div class="pips"></div>${hint ? `<p style="margin:8px 0 0;color:var(--muted);font-size:.9rem">${hint}</p>` : ''}</div>`;

  return `${head(esc(ch.short))}
<div class="top"><a href="index.html">‹ Alla</a><b>${esc(ch.short)}</b></div>
<main class="wrap">
  <section class="hero">
    <h1>${esc(ch.name)}</h1>
    <div class="sub">${esc(ch.kin)} · ${esc(ch.job)} · ${esc(ch.age)}</div>
    <dl class="facts">
      <div><dt>Förflyttning</dt><dd>${ch.move} m</dd></div>
      <div><dt>Skadebonus STY</dt><dd>${ch.sbSty}</dd></div>
      <div><dt>Skadebonus SMI</dt><dd>${ch.sbSmi}</dd></div>
    </dl>
  </section>

  <h2>Status</h2>
  ${pips('kp', 'kp', 'Kroppspoäng', ch.attrs.FYS, '')}
  ${pips('vp', 'vp', 'Viljepoäng', ch.attrs.PSY, '')}
  <div class="death">
    <span class="lbl">Dödsslag</span>
    <div class="row"><span>Lyckade</span><span class="boxes" data-k="dsOk"><button class="box" aria-label="Lyckat dödsslag 1">✓</button><button class="box" aria-label="Lyckat dödsslag 2">✓</button><button class="box" aria-label="Lyckat dödsslag 3">✓</button></span></div>
    <div class="row bad"><span>Misslyckade</span><span class="boxes" data-k="dsNo"><button class="box" aria-label="Misslyckat dödsslag 1">✕</button><button class="box" aria-label="Misslyckat dödsslag 2">✕</button><button class="box" aria-label="Misslyckat dödsslag 3">✕</button></span></div>
  </div>
  <h2>Tillstånd</h2>
  <div class="chips">${ATTRS.map(([k, , , c]) => `<button class="chip" data-cond="${k}" aria-pressed="false">${c} <small>${k}</small></button>`).join('')}</div>
  <div class="chips"><button class="chip" data-rest="quick" aria-pressed="false">Snabb vila tagen</button><button class="chip" data-rest="short" aria-pressed="false">Kort vila tagen</button></div>

  <h2>Vem du är</h2>
  <p>${esc(ch.bio)}</p>
  <p><strong>Utseende:</strong> ${esc(ch.looks)}</p>
  <p><strong>Svaghet:</strong> ${esc(ch.weakness)}</p>

  <h2>Vapen &amp; rustning</h2>
  ${weapons}
  ${ch.armor ? `<div class="card wpn"><h3>${ch.armor.name}</h3><dl><div><dt>Skydd</dt><dd>${ch.armor.sv}</dd></div></dl>${ch.armor.dis.length ? `<p>Nackdel på: ${ch.armor.dis.join(', ')}.</p>` : ''}</div>` : '<p>Du bär ingen rustning.</p>'}

  <h2>Förmågor</h2>
  ${abilities}
  ${ch.magic ? SPELLS : ''}

  <h2>Grundegenskaper &amp; färdigheter</h2>
  <p style="color:var(--muted);font-size:.95rem">Slå T20, lika med eller under siffran lyckas. Tryck på en färdighet för att läsa vad den används till.</p>
  ${attrSections}
  ${RULES}

  <h2>Utrustning</h2>
  <div class="card">
    <p><strong>Packning</strong> (bär ${ch.carry}): ${ch.pack.map(esc).join(', ')}.</p>
    ${ch.small ? `<p><strong>Småsaker:</strong> ${esc(ch.small)}.</p>` : ''}
    <p><strong>Minnessak:</strong> ${esc(ch.keepsake)}</p>
  </div>
  <div class="track silver" data-k="silver" data-max="9999" data-start="${ch.silver}">
    <div class="row"><span class="lbl">Silvermynt</span><span class="ctl"><button aria-label="Minska silvermynt">−</button><output>${ch.silver}</output><button aria-label="Öka silvermynt">+</button></span></div>
  </div>
  <div class="track silver" data-k="skatt" data-max="9999" data-start="0">
    <div class="row"><span class="lbl">Skattkort</span><span class="ctl"><button aria-label="Minska skattkort">−</button><output>0</output><button aria-label="Öka skattkort">+</button></span></div>
  </div>

  <h2>Anteckningar</h2>
  <textarea id="notes" aria-label="Anteckningar" placeholder="Saker du hittat, gåtor, vilka som skadat dig..."></textarea>

  <div class="foot">Sparas bara i den här telefonen · <button id="reset">Nollställ sidan</button></div>
</main>
<script>
(function(){
const KEY='dod:${id}:';
const ls={get(k,d){try{const v=localStorage.getItem(KEY+k);return v===null?d:JSON.parse(v)}catch{return d}},set(k,v){try{localStorage.setItem(KEY+k,JSON.stringify(v))}catch{}}};
document.querySelectorAll('.track').forEach(t=>{
  const k=t.dataset.k,max=+t.dataset.max,out=t.querySelector('output'),pips=t.querySelector('.pips');
  let v=ls.get(k,t.dataset.start!==undefined?+t.dataset.start:max);
  if(pips)pips.innerHTML='<i></i>'.repeat(max);
  const draw=()=>{out.textContent=v;if(pips)[...pips.children].forEach((p,i)=>p.classList.toggle('on',i<v));ls.set(k,v)};
  const [minus,plus]=t.querySelectorAll('button');
  minus.onclick=()=>{v=Math.max(0,v-1);draw()};plus.onclick=()=>{v=Math.min(max,v+1);draw()};
  draw();
});
document.querySelectorAll('.boxes').forEach(b=>{
  const k=b.dataset.k,bs=[...b.children];let v=ls.get(k,0);
  const draw=()=>{bs.forEach((x,i)=>x.setAttribute('aria-pressed',i<v));ls.set(k,v)};
  bs.forEach((x,i)=>x.onclick=()=>{v=(v===i+1)?i:i+1;draw()});
  draw();
});
const conds=ls.get('conds',{});
document.querySelectorAll('[data-cond]').forEach(c=>{
  const a=c.dataset.cond,sec=document.querySelector('.attr[data-a='+a+']');
  const draw=()=>{c.setAttribute('aria-pressed',!!conds[a]);sec.classList.toggle('dis',!!conds[a])};
  c.onclick=()=>{conds[a]=!conds[a];ls.set('conds',conds);draw()};draw();
});
const rest=ls.get('rest',{});
document.querySelectorAll('[data-rest]').forEach(c=>{
  const a=c.dataset.rest,draw=()=>c.setAttribute('aria-pressed',!!rest[a]);
  c.onclick=()=>{rest[a]=!rest[a];ls.set('rest',rest);draw()};draw();
});
const notes=document.getElementById('notes');notes.value=ls.get('notes','');notes.oninput=()=>ls.set('notes',notes.value);
document.getElementById('reset').onclick=()=>{if(!confirm('Nollställa den här rollpersonen?'))return;
  try{Object.keys(localStorage).filter(k=>k.startsWith(KEY)).forEach(k=>localStorage.removeItem(k))}catch{};location.reload()};
})();
</script>
</body></html>`;
}

const CRYPT_JS = `const ITER=${ITER};
const ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const norm=c=>c.trim().toUpperCase().replace(/\\s+/g,'-');
async function tryOpen(code,b){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(code),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:ub(b.s),iterations:ITER,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  try{return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(b.i)},key,ub(b.c))))}catch{return null}
}
async function find(code){for(const b of BLOBS){const s=await tryOpen(code,b);if(s)return s}return null}`;
const lsFor = (id) => `const KEY='dod:${id}:';
const ls={get(k,d){try{const v=localStorage.getItem(KEY+k);return v===null?d:JSON.parse(v)}catch{return d}},set(k,v){try{localStorage.setItem(KEY+k,JSON.stringify(v))}catch{}}};`;

function lockPage({ id, title, intro, blobs, okMsg }) {
  return `${head(title, '.wrap{max-width:900px}')}
<div class="top"><a href="index.html">‹ Alla</a><b>${title}</b></div>
<main class="wrap">
  <h2>${title}</h2>
  <p>${intro}</p>
  <form class="unlock" id="unlock" autocomplete="off"><input id="code" aria-label="Kod" placeholder="KOD" autocapitalize="characters" spellcheck="false"><button>Öppna</button></form>
  <div class="msg" id="msg" role="status"></div>
  <div id="secrets"></div>
</main>
<script>
const BLOBS=${JSON.stringify(blobs)};
${lsFor(id)}
${CRYPT_JS}
const box=document.getElementById('secrets'),msg=document.getElementById('msg');
function show(s){
  const d=document.createElement('div');d.className='card secret';d.id='sec-'+s.n;
  d.innerHTML='<h3></h3>'+s.html;d.querySelector('h3').textContent=s.title;
  const after=[...box.children].find(x=>+x.id.slice(4)>s.n);box.insertBefore(d,after||null);return d;
}
let codes=ls.get('codes',[]);
(async()=>{for(const c of codes){const s=await find(c);if(s&&!document.getElementById('sec-'+s.n))show(s)}})();
document.getElementById('unlock').onsubmit=async e=>{
  e.preventDefault();const inp=document.getElementById('code');const code=norm(inp.value);if(!code)return;
  msg.className='msg';msg.textContent='Letar…';
  const s=await find(code);
  if(!s){msg.className='msg bad';msg.textContent='Fel kod.';return}
  inp.value='';
  const old=document.getElementById('sec-'+s.n);
  if(old){msg.className='msg ok';msg.textContent='Redan öppen.';old.scrollIntoView({behavior:'smooth'});return}
  codes.push(code);ls.set('codes',codes);
  msg.className='msg ok';msg.textContent='${okMsg}';
  show(s).scrollIntoView({behavior:'smooth',block:'start'});
};
</script></body></html>`;
}

// Ersättningsrollperson: hela sidan ligger krypterad och skrivs in i dokumentet när koden stämmer.
function reservePage(blobs) {
  return `${head('Ny rollperson')}
<div class="top"><a href="index.html">‹ Alla</a><b>Ny rollperson</b></div>
<main class="wrap">
  <h2>Ny rollperson</h2>
  <p>Har din rollperson stupat? Spelledaren ger dig en kod till din nya.</p>
  <div id="saved"></div>
  <form class="unlock" id="unlock" autocomplete="off"><input id="code" aria-label="Kod" placeholder="KOD" autocapitalize="characters" spellcheck="false"><button>Öppna</button></form>
  <div class="msg" id="msg" role="status"></div>
</main>
<script>
const BLOBS=${JSON.stringify(blobs)};
${lsFor('ny')}
${CRYPT_JS}
const msg=document.getElementById('msg');
function open_(s){document.open();document.write(s.page);document.close()}
let saved=ls.get('saved',[]);
saved.forEach(x=>{const b=document.createElement('button');b.className='again';b.textContent=x.name;
  b.onclick=async()=>{b.textContent='Öppnar…';const s=await find(x.code);if(s)open_(s)};
  document.getElementById('saved').append(b)});
document.getElementById('unlock').onsubmit=async e=>{
  e.preventDefault();const code=norm(document.getElementById('code').value);if(!code)return;
  msg.className='msg';msg.textContent='Letar…';
  const s=await find(code);
  if(!s){msg.className='msg bad';msg.textContent='Fel kod.';return}
  if(!saved.some(x=>x.code===code)){saved.push({code,name:s.name});ls.set('saved',saved)}
  open_(s);
};
</script></body></html>`;
}

const SL_KOD = process.env.SL_KOD;
if (!SL_KOD) { console.error('Sätt SL_KOD (spelledarens lösenord), t.ex.  SL_KOD=xxx node build.mjs'); process.exit(1); }
mkdirSync('dist', { recursive: true });

for (const [id, ch] of Object.entries(characters)) {
  writeFileSync(`dist/${id}.html`, page(id, ch));
  console.log(`dist/${id}.html`);
}

const reserveBlobs = [];
for (const [id, ch] of Object.entries(reserves)) reserveBlobs.push(await encrypt(ch.code, { name: ch.name, page: page(id, ch) }));
writeFileSync('dist/ny.html', reservePage(reserveBlobs.sort(() => Math.random() - 0.5)));

const mapBlobs = [];
for (const [n, m] of maps.entries()) {
  const html = m.images.map((f) => `<img alt="Karta över ${esc(m.title)}" src="data:image/jpeg;base64,${readFileSync('maps/' + f).toString('base64')}">`).join('');
  mapBlobs.push(await encrypt(m.code, { n, title: m.title, html }));
}
writeFileSync('dist/kartor.html', lockPage({ id: 'kartor', title: 'Kartor', okMsg: 'Kartan är öppen.', blobs: mapBlobs.sort(() => Math.random() - 0.5),
  intro: 'Spelledaren ger er en kod när ni kommer till en ny våning. En ruta är 2×2 meter. Nyp för att zooma.' }));

const cards = Object.entries(characters).map(([id, c]) => `<a href="${id}.html"><b>${esc(c.name)}</b><span>${esc(c.kin)} · ${esc(c.job)}</span></a>`).join('');
writeFileSync('dist/index.html', `${head('Äventyrare', `main{max-width:520px;margin:0 auto;padding:calc(32px + env(safe-area-inset-top)) 16px 40px}
h1{color:var(--accent);margin:0;font-size:1.8rem;line-height:1.15}main>p{color:var(--muted)}
main>a{display:flex;flex-direction:column;gap:2px;padding:16px;margin-bottom:10px;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);text-decoration:none}
main>a b{color:var(--accent);font:700 1.05rem var(--head)}main>a span{color:var(--muted);font-size:.9rem}main>a:active{background:var(--line)}
main>a.alt{border-left-color:var(--warn)}main>a.alt b{color:var(--warn)}`)}
<main><h1>Det sjunkande tornet</h1><p>Drakar och Demoner. Välj din rollperson.</p>${cards}
<a class="alt" href="kartor.html" style="margin-top:24px"><b>Kartor</b><span>Tornets våningar</span></a>
<a class="alt" href="ny.html"><b>Ny rollperson</b><span>Om din rollperson stupar</span></a></main></body></html>`);

const li = (list) => '<ul>' + list.map((x) => `<li>${esc(x.title)}: <strong>${esc(x.code)}</strong></li>`).join('') + '</ul>';
const sl = `<h3>Kartor</h3><p>Ge koden när gruppen når våningen.</p>${li(maps)}
<h3>Ersättningsrollpersoner</h3><p>Ge koden till en spelare vars rollperson har stupat. Sidan öppnas under Ny rollperson.</p>${li(Object.values(reserves).map((r) => ({ title: r.name, code: r.code })))}`;
writeFileSync('dist/sl.html', lockPage({ id: 'sl', title: 'Spelledare', okMsg: 'Upplåst.', intro: 'Ange spelledarkoden.',
  blobs: [await encrypt(SL_KOD, { n: 0, title: 'Alla koder', html: sl })] }));
console.log('dist/ klar');
