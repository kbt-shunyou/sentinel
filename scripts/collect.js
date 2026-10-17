/**
 * Sentinel collector — runs 2x/day via GitHub Actions, writes data/collected.json.
 * Pre-collects WORLDWIDE news (JP + EN) + security (NVD/CISA/arXiv) + filings, with
 * source URLs and a one-point mitigation (対策) for security items. Node 18+/20, zero deps.
 */
const fs = require("fs");
const path = require("path");
const UA = "SentinelCollector/1.0";

const TECH_CATS = [
  { id:"ai",    q:'("artificial intelligence" OR "generative AI" OR LLM OR ロボット OR ヒューマノイド)' },
  { id:"space", q:'(宇宙 OR ロケット OR 衛星 OR "space launch" OR rocket OR satellite OR SpaceX OR JAXA)' },
  { id:"auto",  q:'(自動車 OR EV OR "electric vehicle" OR 自動運転 OR "self-driving")' },
  { id:"semi",  q:'(半導体 OR semiconductor OR チップ OR TSMC OR "chip export")' },
  { id:"energy",q:'(エネルギー OR 原油 OR "crude oil" OR 電力 OR 原子力 OR LNG)' },
  { id:"geo",   q:'(戦争 OR 紛争 OR 制裁 OR war OR conflict OR sanctions OR military)' },
  { id:"econ",  q:'(利上げ OR インフレ OR "central bank" OR inflation OR 株式市場)' },
  { id:"academ",q:'(研究 OR 論文 OR 大学 OR "research breakthrough" OR university)' }
];
const SEC_PANELS = [
  { id:"infect", type:"gdelt", q:'(ランサムウェア OR マルウェア OR ウイルス感染 OR ransomware OR malware OR サイバー攻撃)' },
  { id:"kev",    type:"kev" },
  { id:"cve",    type:"nvd" },
  { id:"patch",  type:"gdelt", q:'("security update" OR "patch released" OR 緊急アップデート OR 脆弱性 修正 OR 更新プログラム)' },
  { id:"jp",     type:"gdelt", q:'(日本 (サイバー攻撃 OR 情報漏洩 OR 不正アクセス OR ランサムウェア) OR JPCERT OR IPA 注意喚起)' },
  { id:"dark",   type:"gdelt", q:'("dark web" OR データ漏洩 OR 情報流出 OR "data breach" OR ダークウェブ)' },
  { id:"acad",   type:"arxiv" },
  { id:"media",  type:"gdelt", q:'(サイバーセキュリティ OR "zero trust" OR AI security OR セキュリティ対策)' }
];
const TIPS = [
  [/ransom|ランサム/i,"オフライン保管のバックアップ＋多要素認証(MFA)＋EDRで早期検知。復旧手順を事前演習。"],
  [/phish|フィッシング|詐欺メール/i,"送信ドメイン認証(DMARC)＋MFA＋添付/リンクの隔離。利用者教育を定期実施。"],
  [/breach|漏洩|流出|leak/i,"該当アカウントのパスワード変更と失効、漏洩監視、最小権限・ログ監査を実施。"],
  [/zero[- ]?day|ゼロデイ/i,"ベンダー回避策の即時適用、該当機能の無効化、侵害痕跡(IOC)の調査。"],
  [/vpn|rce|remote code|認証回避|auth bypass/i,"対象機器を即パッチ、管理画面の公開停止、MFAと接続元制限を徹底。"],
  [/ddos/i,"CDN/WAFでの緩和、レート制限、上流プロバイダと連携した遮断。"],
  [/malware|ウイルス|マルウェア|trojan/i,"EDRでの隔離・駆除、感染端末の分離、全社スキャンと資格情報の再発行。"],
  [/supply chain|サプライチェーン|依存|dependency/i,"SBOMで依存を棚卸し、署名検証、固定バージョン運用と更新監視。"]
];
const tipFor = (t) => { const s=String(t||""); for(const [re,v] of TIPS) if(re.test(s)) return v;
  return "最新更新の適用・最小権限・ログ監視を徹底。"; };

const fmt = (s)=>{const m=String(s||"").match(/(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})/);return m?`${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}`:(s||"");};
async function gj(url,h={}){const r=await fetch(url,{headers:{"User-Agent":UA,...h}});if(!r.ok)throw new Error(url+" "+r.status);return r.json();}
async function gt(url,h={}){const r=await fetch(url,{headers:{"User-Agent":UA,...h}});if(!r.ok)throw new Error(url+" "+r.status);return r.text();}
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));

async function gdelt(query, lang, max){
  const url="https://api.gdeltproject.org/api/v2/doc/doc?query="+encodeURIComponent(query+" sourcelang:"+lang)+
    "&mode=artlist&maxrecords="+max+"&sort=datedesc&format=json&timespan=2w";
  try{const j=await gj(url); return (j.articles||[]).map(x=>({src:x.domain||"news",title:x.title||"",time:fmt(x.seendate),url:x.url,lang:x.language||lang}));}catch(e){return [];}
}
async function gdeltWorld(query, tag, max){
  const [en,ja]=await Promise.all([gdelt(query,"english",max),gdelt(query,"japanese",Math.ceil(max/2))]);
  const seen=new Set(), out=[];
  for(const a of [...ja,...en]){ if(a.url&&!seen.has(a.url)){ seen.add(a.url); out.push({tag,...a}); } }
  return out.slice(0,max);
}
// NVD: ~1 year, fetched in 120-day windows (NVD caps each request at 120 days)
async function nvd(perWin){
  const out=[]; const now=Date.now();
  for(let w=0; w<3; w++){
    const e=new Date(now-w*120*864e5).toISOString().slice(0,23);
    const s=new Date(now-(w*120+119)*864e5).toISOString().slice(0,23);
    try{const j=await gj(`https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${perWin}&pubStartDate=${s}&pubEndDate=${e}`);
      (j.vulnerabilities||[]).forEach(v=>{const c=v.cve||{};const d=((c.descriptions||[]).find(x=>x.lang==="en")||{}).value||"";
        out.push({tag:"sec",src:"NVD",title:c.id||"CVE",summary:d.slice(0,300),time:(c.published||"").slice(0,10),url:"https://nvd.nist.gov/vuln/detail/"+(c.id||"")});});
    }catch(e){}
    await sleep(1500); // NVD rate limit (no key)
  }
  return out;
}
async function cisa(n){ try{const j=await gj("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const cut=Date.now()-365*864e5;
  return (j.vulnerabilities||[]).filter(v=>new Date(v.dateAdded||0)>=cut).reverse().slice(0,n).map(v=>({tag:"sec",src:"CISA KEV",
    title:v.cveID+" — "+(v.vulnerabilityName||""),summary:(v.shortDescription||""),requiredAction:v.requiredAction||"",
    time:v.dateAdded||"",url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}));}catch(e){return [];}}
async function arxiv(cats,n){ try{const q=cats.map(c=>"cat:"+c).join("+OR+");
  const xml=await gt(`http://export.arxiv.org/api/query?search_query=${q}&sortBy=submittedDate&sortOrder=descending&max_results=${n}`);
  const pick=(b,t)=>{const m=b.match(new RegExp("<"+t+"[^>]*>([\\s\\S]*?)</"+t+">"));return m?m[1].replace(/\s+/g," ").trim():"";};
  const out=[];const re=/<entry>([\s\S]*?)<\/entry>/g;let m;
  while((m=re.exec(xml))&&out.length<n){const b=m[1];out.push({tag:"paper",src:"arXiv",title:pick(b,"title"),summary:pick(b,"summary").slice(0,360),time:(pick(b,"published")||"").slice(0,10),url:pick(b,"id")});}
  return out;}catch(e){return [];}}
async function edgar(n){ try{const end=new Date().toISOString().slice(0,10),start=new Date(Date.now()-90*864e5).toISOString().slice(0,10);
  const j=await gj(`https://efts.sec.gov/LATEST/search-index?forms=8-K,10-Q,10-K&startdt=${start}&enddt=${end}`);
  return ((j.hits&&j.hits.hits)||[]).slice(0,n).map(h=>{const s=h._source||{};return {tag:"earn",src:"SEC EDGAR",
    title:(s.display_names&&s.display_names[0]||"Filing")+" — "+(s.root_forms&&s.root_forms[0]||""),summary:s.file_type||"",
    time:s.file_date||"",url:"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany"};});}catch(e){return [];}}

(async () => {
  const news={}, sec={};
  for(const c of TECH_CATS){ news[c.id]=await gdeltWorld(c.q,"ai",16); await sleep(1200); }
  for(const p of SEC_PANELS){
    let d=[];
    if(p.type==="gdelt"){ d=await gdeltWorld(p.q,"sec",24); await sleep(1200); }
    else if(p.type==="kev") d=await cisa(40);
    else if(p.type==="nvd") d=await nvd(30);
    else if(p.type==="arxiv") d=await arxiv(["cs.CR","cs.AI"],18);
    sec[p.id]=d.map(x=>({ ...x, tip: tipFor((x.title||"")+" "+(x.summary||"")+" "+(x.requiredAction||"")) }));
  }
  const [filings, papers] = await Promise.all([edgar(18), arxiv(["cs.AI","cs.LG","cs.CR"],18)]);
  const out = { ts: Date.now(), generated: new Date().toISOString(), news, sec, filings, papers };
  const dir = path.join(__dirname, "..", "data");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "collected.json"), JSON.stringify(out));
  const nn=Object.values(news).reduce((a,b)=>a+b.length,0), sn=Object.values(sec).reduce((a,b)=>a+b.length,0);
  console.log(`collected: news=${nn} sec=${sn} filings=${filings.length} papers=${papers.length}`);
})();
