/*
 * panel/subdomain.js - certificate-transparency subdomain discovery.
 *
 *   window.XraySubdomain.deriveRoot(host)  -> which domain to search
 *   window.XraySubdomain.search(root, opts) -> the names
 *
 * WHY THERE IS A DOMAIN-STRIPPING STEP AT ALL
 * -------------------------------------------
 * Certificate transparency is indexed by the REGISTERED DOMAIN, not by
 * whatever host the browser happens to be on. Asking for subdomains of
 * "news.example.com" is a category error: there is no such index, and
 * "subdomains of a subdomain" is not a thing that can be looked up.
 *
 * So the host the tester is on has to be reduced to its registered domain -
 * the eTLD+1 - before anything is queried:
 *
 *   csi-india.org          -> csi-india.org   (already the registered domain)
 *   ess.cehrd.gov.np       -> cehrd.gov.np    (gov.np is a public suffix, so
 *                                             cehrd.gov.np is registered)
 *   news.csi-india.org     -> csi-india.org
 *
 * The hard part is that "the last two labels" is wrong in a way that is
 * invisible until it is not. For "ess.cehrd.gov.np" the last two labels are
 * "gov.np" - a PUBLIC SUFFIX, not a domain - and searching it would return
 * the government of Nepal's own subdomains, which is both useless and
 * somebody else's attack surface. A list of multi-label public suffixes is
 * therefore needed, and the rule has to be applied longest-match first.
 *
 * The public suffix list is large and changes. This carries the multi-label
 * suffixes that actually occur in practice, and the server is treated as the
 * authority: it rejects a non-eTLD+1 apex and says what the real one is, so
 * a domain this list does not know about is corrected by the response rather
 * than silently searched as the wrong thing.
 *
 * WHAT THIS DOES NOT DO
 * ---------------------
 * It reads PUBLIC certificate logs. It does not resolve names, connect to
 * anything, or probe a host. A name in a CT log means a certificate was
 * issued for it - by a public CA, for a name the applicant asked for. It
 * does not mean the host is alive, does not mean it belongs to the target
 * (a CA can issue for a name the applicant does not own), and does not mean
 * it is in scope. A name that is absent from CT does not mean the host does
 * not exist: private CAs, internal names and hosts that never needed a
 * certificate never appear.
 */
(function (global) {
  "use strict";

  // ---------------------------------------------------------------------
  // Public suffixes that are more than one label.
  //
  // A host whose last two labels are one of these is a domain UNDER that
  // suffix, not the suffix itself. Written out because the list is the
  // difference between searching cehrd.gov.np and searching gov.np.
  // ---------------------------------------------------------------------
  const MULTI_LABEL_SUFFIXES = new Set((
    // United Kingdom
    "co.uk org.uk me.uk net.uk ltd.uk plc.uk sch.uk ac.uk gov.uk nhs.uk police.uk mod.uk " +
    // Isle of Man / Jersey / Guernsey
    "co.im net.im org.im ac.im gov.im com.je net.je org.je co.je " +
    // Australia
    "com.au net.au org.au edu.au gov.au asn.au id.au act.au nsw.au nt.au qld.au sa.au tas.au vic.au wa.au " +
    // New Zealand
    "co.nz net.nz org.nz govt.nz ac.nz geek.nz kiwi.nz school.nz " +
    // India
    "co.in net.in org.in gen.in firm.in ind.in ac.in edu.in res.in gov.in mil.in nic.in " +
    // Nepal
    "com.np net.np org.np gov.np edu.np ac.np mil.np " +
    // Japan
    "co.jp ne.jp or.jp ac.jp ad.jp ed.jp go.jp gr.jp lg.jp " +
    // China
    "com.cn net.cn org.cn gov.cn edu.cn ac.cn " +
    // Hong Kong
    "com.hk net.hk org.hk edu.hk gov.hk idv.hk " +
    // Taiwan
    "com.tw net.tw org.tw gov.tw edu.tw idv.tw " +
    // Korea
    "co.kr ne.kr or.kr re.kr pe.kr go.kr mil.kr ac.kr " +
    // Brazil
    "com.br net.br org.br gov.br edu.br art.br blog.br " +
    // South Africa
    "co.za net.za org.za gov.za ac.za web.za " +
    // Mexico
    "com.mx net.mx org.mx gob.mx edu.mx " +
    // Argentina / Chile / Colombia / Peru / Ecuador
    "com.ar net.ar org.ar gob.ar edu.ar " +
    "com.cl gob.cl gov.cl mil.cl " +
    "com.co net.co org.co gov.co edu.co " +
    "com.pe net.pe org.pe gob.pe edu.pe " +
    "com.ec net.ec org.ec gov.ec edu.ec med.ec fin.ec info.ec pro.ec " +
    // Venezuela / Bolivia / Paraguay / Uruguay
    "com.ve net.ve org.ve web.ve gob.ve edu.ve " +
    "com.bo net.bo org.bo gov.bo edu.bo mil.bo tv.bo " +
    "com.py net.py org.py gov.py edu.py " +
    "com.uy net.uy org.uy edu.uy gub.uy " +
    // Central America
    "com.gt net.gt org.gt edu.gt gob.gt mil.gt ind.gt " +
    "com.pa net.pa org.pa edu.pa gob.pa sld.pa " +
    "com.do net.do org.do gob.do edu.do sld.do web.do " +
    "or.cr go.cr ed.cr fi.cr sa.cr " +
    // Southeast Asia
    "com.sg net.sg org.sg edu.sg gov.sg " +
    "com.my net.my org.my gov.my edu.my " +
    "com.ph net.ph org.ph gov.ph edu.ph " +
    "com.vn net.vn org.vn edu.vn gov.vn int.vn ac.vn biz.vn info.vn name.vn pro.vn health.vn gen.vn " +
    "co.th in.th or.th net.th ac.th go.th mi.th " +
    "co.id or.id ac.id go.id web.id sch.id mil.id my.id biz.id net.id " +
    "com.kh edu.kh gov.kh org.kh net.kh per.kh int.kh " +
    "com.la net.la org.la int.la edu.la gov.la per.la " +
    "com.mm net.mm org.mm edu.mm gov.mm " +
    "com.kh com.la com.bd com.tj com.kg com.uz com.tm " +
    // South and Central Asia
    "com.pk net.pk org.pk gov.pk edu.pk " +
    "com.bd net.bd org.bd gov.bd edu.bd ac.bd " +
    "com.lk net.lk org.lk gov.lk edu.lk ac.lk assn.lk grp.lk hotel.lk int.lk ltd.lk plc.lk sld.lk web.lk " +
    "com.kz net.kz org.kz gov.kz edu.kz mil.kz " +
    "com.uz net.uz org.uz co.uz " +
    "com.tj net.tj org.tj gov.tj edu.tj " +
    "com.kg net.kg org.kg gov.kg edu.kg " +
    "com.tm net.tm org.tm gov.tm edu.tm " +
    "com.af net.af org.af gov.af edu.af " +
    "com.az net.az org.az gov.az edu.az " +
    "com.ge net.ge org.ge gov.ge edu.ge pvt.ge " +
    "com.mk net.mk org.mk gov.mk edu.mk " +
    "com.al net.al org.al gov.al edu.al " +
    // Middle East
    "co.il net.il org.il ac.il gov.il muni.il k12.il " +
    "com.sa net.sa org.sa gov.sa edu.sa med.sa sch.sa " +
    "co.ae net.ae org.ae gov.ae ac.ae sch.ae mil.ae " +
    "com.qa net.qa org.qa gov.qa edu.qa " +
    "com.kw edu.kw gov.kw net.kw org.kw " +
    "co.ir ac.ir gov.ir id.ir net.ir org.ir sch.ir " +
    "com.tr net.tr org.tr gov.tr edu.tr bel.tr " +
    "com.jo net.jo org.jo gov.jo edu.jo " +
    "com.lb net.lb org.lb gov.lb edu.lb " +
    "com.sy net.sy org.sy gov.sy edu.sy " +
    "com.ye net.ye org.ye gov.ye edu.ye " +
    "com.om net.om org.om gov.om edu.om " +
    "com.bh net.bh org.bh gov.bh edu.bh " +
    // Africa
    "co.za co.ke or.ke ne.ke go.ke ac.ke sc.ke me.ke mobi.ke info.ke " +
    "com.gh edu.gh gov.gh org.gh mil.gh " +
    "com.ng net.ng org.ng gov.ng edu.ng ngo.ng " +
    "co.ma net.ma org.ma gov.ma ac.ma press.ma " +
    "com.eg net.eg org.eg gov.eg edu.eg sci.eg " +
    "co.tz net.tz org.tz go.tz ac.tz " +
    "co.zw net.zw org.zw ac.zw gov.zw " +
    "co.ug or.ug ne.ug ac.ug go.ug " +
    "com.zm org.zm co.zm " +
    // Europe
    "co.at or.at ac.at gv.at priv.at " +
    "co.ch org.ch net.ch gov.ch ac.ch " +
    "com.be org.be net.be gov.be ac.be int.be " +
    "co.dk org.dk net.dk gov.dk edu.dk " +
    "com.se org.se net.se gov.se edu.se pp.se " +
    "com.pt org.pt net.pt gov.pt edu.pt nome.pt " +
    "com.gr net.gr org.gr gov.gr edu.gr " +
    "gov.ie com.es org.es nom.es gob.es edu.es " +
    "co.hu org.hu info.hu priv.hu sport.hu tm.hu " +
    "com.ro org.ro tm.ro nt.ro nom.ro info.ro rec.ro store.ro www.ro " +
    "com.bg net.bg org.bg gov.bg edu.bg " +
    "com.rs org.rs edu.rs gov.rs ac.rs " +
    "com.hr from.hr iz.hr name.hr " +
    "com.ru net.ru org.ru msk.ru spb.ru " +
    "com.pl net.pl org.pl edu.pl gov.pl waw.pl " +
    "com.ua net.ua org.ua gov.ua edu.ua in.ua kiev.ua " +
    "com.by net.by " +
    "com.cz org.cz net.cz " +
    "com.is net.is org.is edu.is gov.is int.is " +
    "com.ee org.ee fie.ee pri.ee " +
    "com.lv edu.lv gov.lv org.lv mil.lv id.lv net.lv asn.lv " +
    "com.lt net.lt org.lt gov.lt " +
    "com.ba net.ba org.ba gov.ba edu.ba " +
    "com.cy net.cy org.cy ac.cy gov.cy " +
    "com.mt net.mt org.mt " +
    "asn.lu com.lu org.lu net.lu " +
    "com.si org.si gov.si " +
    "com.hr com.mk com.me com.rs com.al " +
    "co.hu co.at co.rs co.ug co.tz co.zm co.zw " +
    // Americas
    "com.br com.co com.ar com.pe com.ve com.ec com.bo com.py com.uy com.do com.pa com.gt com.cr " +
    "com.mx com.br org.br net.br " +
    "ca.on ca.gc ab.ca bc.ca mb.ca nb.ca nf.ca ns.ca nt.ca on.ca pe.ca qc.ca sk.ca yk.ca " +
    "us.ca us.ny us.nj us.ma us.mn us.md us.va us.dc us.gu us.pr us.vi " +
    "com.pr net.pr org.pr gob.pr edu.pr " +
    "com.tt net.tt org.tt co.tt gov.tt edu.tt " +
    "com.bs net.bs org.bs com.ai net.ai org.ai " +
    "com.ag net.ag org.ag co.ag nom.ag " +
    "com.bm net.bm org.bm edu.bm gov.bm " +
    "com.ky net.ky org.ky edu.ky gov.ky " +
    "com.gi net.gi org.gi ltd.gi " +
    "co.im com.je gov.je " +
    "com.fj net.fj org.fj gov.fj ac.fj " +
    "com.mt co.mt " +
    // Pacific / other
    "com.pg net.pg org.pg ac.pg " +
    "com.sb net.sb org.sb edu.sb gov.sb " +
    "com.to net.to org.to gov.to ac.to " +
    "com.vu net.vu org.vu ac.vu edu.vu gov.vu " +
    "co.ws com.ws net.ws org.ws gov.ws edu.ws " +
    "com.nu net.nu org.nu " +
    "com.tn net.tn org.tn gov.tn edu.tn " +
    "com.ly net.ly org.ly gov.ly edu.ly " +
    "com.sd net.sd org.sd edu.sd med.sd gov.sd " +
    "com.mo net.mo org.mo edu.mo gov.mo " +
    "com.mm com.la " +
    // Generic second-level suffixes that are also public suffixes
    "blog.sh wiki.sh hosting.sh " +
    "blogspot.com github.io herokuapp.com cloudfront.net appspot.com " +
    "s3.amazonaws.com elasticbeanstalk.com " +
    "azurewebsites.net cloudapp.net trafficmanager.net " +
    "web.app firebaseapp.com netlify.app vercel.app pages.dev workers.dev " +
    "ngrok.io ngrok.app trycloudflare.com " +
    "readthedocs.io pythonanywhere.com " +
    "repl.co glitch.me codesandbox.io " +
    "surrogate.id "
  ).split(/\s+/).filter(Boolean));

  // A hostname that is a public suffix itself, and one that is an IP, cannot
  // be reduced further. These two lists are what make "the registered domain
  // of this host" a question with an answer.
  const SINGLE_LABEL_SUFFIXES = new Set((
    "com net org edu gov mil int arpa info biz name pro aero coop museum jobs mobi travel " +
    "tel asia cat post xxx " +
    "academy agency apartments app associates bargains boutique build buzz capital care " +
    "cash center ceo chat church claims cleaning clinic clothing cloud coach codes coffee " +
    "community company computer condos construction consulting contractors cooking cool " +
    "country coupons credit cricket dance date dating deals degree delivery democrat " +
    "dental diamonds digital directory discount domains download education email energy " +
    "engineer engineering enterprises equipment estate events exchange expert exposed express " +
    "fail faith family fans farm fashion film finance financial fish fitness flights florist " +
    "flowers football forsale foundation fun fund furniture futbol gallery game games garden " +
    "gifts gives glass global gold golf graphics gratis green gripe guide guitars guru " +
    "health healthcare help hiphop hockey holdings holiday host hosting house how ice " +
    "immo immobilien industries ink institute insurance international investments jetzt " +
    "jewelry juegos kaufen kim kitchen kiwi land lawyer lease legal life lighting limited " +
    "limo link live loan loans lol love ltd luxury management market marketing media " +
    "memorial men menu moda moe money mortgage movie network ninja observer one onl online " +
    "page partners parts party pet photo photography photos pics pictures pizza place plumbing " +
    "plus poker press productions properties property pub qpon racing realestate recipes reise " +
    "reisen rent rentals repair report republican rest restaurant review reviews rich rip " +
    "rocks rodeo run sale salon sarl school schule science services sexy shiksha shoes shop " +
    "shopping show singles site ski soccer social software solar solutions space store stream " +
    "studio study style sucks supplies supply support surf surgery systems tattoo tax taxi " +
    "team tech technology tennis theater theatre tickets tienda tips tires today tokyo tools " +
    "top tours town toys trade trading training tube university uno vacations vegas ventures " +
    "vet viajes video villas vin vip vision vodka vote voting voyage watch webcam website " +
    "wedding wiki win wine work works world wtf xyz yoga zone"
  ).split(/\s+/).filter(Boolean));

  // ---------------------------------------------------------------------
  // Deriving the registered domain.
  // ---------------------------------------------------------------------
  function normalizeHost(input) {
    let h = String(input == null ? "" : input).trim().toLowerCase();
    if (!h) return "";
    // A URL was passed instead of a hostname.
    if (/^[a-z][a-z0-9+.-]*:\/\//.test(h)) {
      try { h = new URL(h).hostname; }
      catch (_) { h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/)[0]; }
    }
    h = h.split("/")[0].split("?")[0].split("#")[0];
    // A port is not part of a hostname.
    h = h.replace(/:\d+$/, "");
    // A trailing dot is the same name.
    h = h.replace(/\.$/, "");
    // Credentials in a URL are not part of a hostname.
    if (h.indexOf("@") >= 0) h = h.slice(h.lastIndexOf("@") + 1);
    if (h.charAt(0) === "[" && h.charAt(h.length - 1) === "]") h = h.slice(1, -1);
    return h;
  }

  const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  const IPV6_RE = /^[0-9a-f:]+$/;

  /**
   * Reduce a host to the domain that certificate transparency is indexed by.
   *
   * @returns {{ok:true, host:string, root:string, suffix:string,
   *            isSubdomain:boolean, depth:number} |
   *           {ok:false, host:string, reason:string, message:string}}
   */
  function deriveRoot(input) {
    const host = normalizeHost(input);
    if (!host) {
      return { ok: false, host: "", reason: "no-host",
        message: "No page is open, so there is no host to derive a domain from." };
    }
    if (IP_RE.test(host) || (IPV6_RE.test(host) && host.indexOf(":") >= 0)) {
      return { ok: false, host: host, reason: "ip",
        message: "This is an IP address, not a domain. A certificate can be issued for " +
          "an IP, but certificate transparency is indexed by domain name, so there is " +
          "nothing here to search." };
    }
    // "indexOf(...) < 0", not "!indexOf(...)". A bare hostname has indexOf
    // return -1, and !(-1) is false - so the check never fired, and
    // "intranet" fell through to the suffix logic and came back as a domain
    // called "intranet" with a suffix called "intranet".
    if (host.indexOf(".") < 0) {
      return { ok: false, host: host, reason: "single-label",
        message: "This host has no domain part (" + host + "). It is either a local " +
          "name or a machine on a local network, and neither appears in a public " +
          "certificate log." };
    }
    if (host === "localhost" || /\.localhost$/.test(host) || /\.local$/.test(host) ||
        /\.internal$/.test(host) || /\.test$/.test(host) || /\.invalid$/.test(host) ||
        /\.example$/.test(host)) {
      return { ok: false, host: host, reason: "local",
        message: "This looks like a local or reserved name (" + host + "), not a " +
          "public domain." };
    }

    const labels = host.split(".");
    const last = labels[labels.length - 1];

    // The public suffix, longest match first.
    //
    // The candidate may be the WHOLE host, and it has to be: "gov.np" is
    // itself a public suffix, so it has no registrable domain under it and
    // must be refused rather than searched. Starting the loop at
    // labels.length - 1 meant the whole-host case was never considered, and
    // "gov.np" came back as a searchable domain - which is a search of
    // somebody else's namespace.
    let suffix = last;
    let suffixLabels = 1;
    for (let n = Math.min(4, labels.length); n >= 2; n--) {
      const cand = labels.slice(labels.length - n).join(".");
      if (MULTI_LABEL_SUFFIXES.has(cand)) { suffix = cand; suffixLabels = n; break; }
    }

    if (labels.length <= suffixLabels) {
      return { ok: false, host: host, reason: "is-suffix",
        message: "\"" + host + "\" is a public suffix (" + suffix + "), not a " +
          "registered domain. There is no domain here to look for subdomains of." };
    }

    // The public suffix list's default rule is "*": anything not in the list
    // is treated as a suffix. So an ending this list has never heard of is
    // still a suffix, and the registered domain is the label above it. The
    // only thing the list buys is knowing the endings that take MORE than one
    // label, which is the case that matters - and the case that is silently
    // wrong without it.
    const suffixAssumed = !MULTI_LABEL_SUFFIXES.has(suffix) &&
      !SINGLE_LABEL_SUFFIXES.has(last) && !/^[a-z]{2}$/.test(last);

    const root = labels.slice(labels.length - (suffixLabels + 1)).join(".");
    const isSubdomain = labels.length > suffixLabels + 1;
    return {
      ok: true,
      host: host,
      root: root,
      suffix: suffix,
      isSubdomain: isSubdomain,
      // True when the ending is not in the bundled list and was assumed to be
      // a suffix. The service checks the same thing against the full list, so
      // this is a note, not an error.
      suffixAssumed: suffixAssumed,
      // How many labels sit above the registered domain.
      depth: labels.length - (suffixLabels + 1)
    };
  }

  // ---------------------------------------------------------------------
  // The query.
  //
  // The response is one name per line, and for a large domain it is large:
  // google.com answers with about 169,000 names and seven megabytes. Reading
  // all of it to show the first few thousand is a waste of the tester's
  // bandwidth and of the service's, so the body is read as a stream and
  // stopped at the cap.
  // ---------------------------------------------------------------------
  const DEFAULT_CAP = 5000;

  function parseNames(text) {
    const seen = new Set();
    const out = [];
    for (let line of String(text || "").split("\n")) {
      line = line.trim().toLowerCase();
      if (!line) continue;
      // A wildcard certificate covers every name under it, and the log may
      // record it that way. "*.example.com" means the wildcard, not a host
      // called "*", so it is kept as a marker rather than as a name.
      if (line.indexOf("*.") === 0) line = "*." + line.slice(2);
      if (seen.has(line)) continue;
      seen.add(line);
      out.push(line);
    }
    return out;
  }

  // How many names to let pass between progress reports. It grows with the
  // count, so the number on screen moves smoothly at the start - where a
  // tester is watching for it - and costs nothing on a domain with a
  // hundred thousand names.
  function reportStep(seen) {
    if (seen < 10) return 1;
    if (seen < 100) return 5;
    if (seen < 1000) return 25;
    if (seen < 10000) return 100;
    return 250;
  }

  // The request is made by the extension's service worker when there is one.
  //
  // The certificate service answers with "access-control-allow-origin: null",
  // which suits a file:// preview and does not name an extension page's
  // origin. An extension page can ignore that with its host permissions, but
  // the worker is where those permissions are meant to be used, and it is
  // also the only context here that can hold a long request open without the
  // panel being torn down. A direct fetch is kept as the fallback so the
  // module still works in the preview and in a test harness.
  //
  // The worker call is on a DEADLINE, and that is not defensive decoration.
  // An MV3 service worker that is asleep, restarting or shutting down can
  // leave sendMessage pending forever: nothing rejects and nothing resolves,
  // so a catch never fires and the await never returns. This codebase has
  // already been bitten by exactly that - the Security tab stayed empty on a
  // page full of findings because a worker call was awaited with no
  // deadline - and the symptom there was the same one here: a tab that
  // spins forever and says nothing.
  //
  // So the worker gets 8 seconds, and the direct request takes over.
  async function fetchViaWorker(root, cap, timeoutMs, onProgress, reqId) {
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
      return null;
    }
    let res;
    try {
      res = await Promise.race([
        chrome.runtime.sendMessage({
          __xre: 1,
          kind: "ctFetch",
          host: "crt.name",
          path: "/v1/search?apex=" + encodeURIComponent(root),
          cap: cap,
          reqId: reqId || ""
        }),
        new Promise((_, reject) => setTimeout(() =>
          reject(new Error("the service worker did not answer")), timeoutMs || 8000))
      ]);
    } catch (_) {
      return null;   // no answer, a dead worker, or a timeout - use the direct request
    }
    if (!res) return null;   // no answer - fall back to a direct request
    if (res.ok !== true) {
      // A refusal from the worker is a configuration problem and is worth
      // saying. A MISSING answer is not: that is a service worker running an
      // older build, and it should fall back rather than break the tab.
      if (/refused/i.test(String(res.error || ""))) {
        return { ok: false, reason: "worker", message: String(res.error) };
      }
      return null;
    }
    return res.result;
  }

  async function search(root, opts) {
    opts = opts || {};
    const cap = Math.max(1, Math.min(opts.cap || DEFAULT_CAP, 20000));
    const timeoutMs = opts.timeoutMs || 45000;
    const endpoint = opts.endpoint || "https://crt.name/v1/search";
    // How many names have arrived so far. The log does not say how many it
    // has, so this is a count and not a percentage - the one number here
    // that is true while the request is still running.
    const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
    const report = n => { if (onProgress) { try { onProgress(n); } catch (_) {} } };

    const url = endpoint + "?apex=" + encodeURIComponent(root);

    // The worker does its own reading, capping and error handling. It gets a
    // deadline, because a pending worker call never settles.
    //
    // The worker streams, so the count of names that have arrived is known
    // DURING the request - and it is the one thing on screen that is
    // neither a guess nor a spinner. The worker relays it.
    const viaWorker = await fetchViaWorker(root, cap, opts.workerTimeoutMs || 8000, report, opts.reqId).catch(() => null);
    if (viaWorker) {
      if (!viaWorker.ok) {
        const body = String(viaWorker.body || "");
        const m = /eTLD\+1 is ([A-Za-z0-9.-]+)/.exec(body);
        if (m) {
          return {
            ok: false, root: root, reason: "not-an-apex", corrected: m[1],
            message: "\"" + root + "\" is a subdomain, not a registered domain. " +
              "Subdomains of a subdomain are not something certificate " +
              "transparency can answer - the index is by registered domain. " +
              "Using " + m[1] + " instead."
          };
        }
        return {
          ok: false, root: root, reason: "http", status: viaWorker.status,
          message: "The certificate transparency service answered " + viaWorker.status +
            (body ? ": " + body.slice(0, 200) : "")
        };
      }
      const names = parseNames(viaWorker.text);
      return {
        ok: true, root: root, names: names, count: names.length,
        total: viaWorker.seen, truncated: !!viaWorker.truncated, cap: cap
      };
    }

    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;

    try {
      const res = await fetch(url, {
        signal: ctrl ? ctrl.signal : undefined,
        credentials: "omit",
        redirect: "follow"
      });

      if (!res.ok) {
        const body = await res.text().catch(() => "");
        // The service enforces the same rule this module does, and says what
        // the real registered domain is. When the two disagree, the service is
        // right - it is reading the full public suffix list.
        const m = /eTLD\+1 is ([A-Za-z0-9.-]+)/.exec(body);
        if (m) {
          return {
            ok: false, root: root, reason: "not-an-apex", corrected: m[1],
            message: "\"" + root + "\" is a subdomain, not a registered domain. " +
              "Subdomains of a subdomain are not something certificate " +
              "transparency can answer - the index is by registered domain. " +
              "Using " + m[1] + " instead."
          };
        }
        const nosuffix = /cannot derive eTLD\+1/.test(body);
        return {
          ok: false, root: root, reason: nosuffix ? "no-root" : "http",
          status: res.status,
          message: nosuffix
            ? "No registered domain could be derived from \"" + root + "\"."
            : ("The certificate transparency service answered " + res.status +
               (body ? ": " + body.slice(0, 200) : ""))
        };
      }

      let text = "";
      let truncated = false;
      let seen = 0;

      const reader = res.body && res.body.getReader ? res.body.getReader() : null;
      if (reader) {
        const decoder = new TextDecoder();
        let buf = "";
        let lastReported = 0;
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          buf += decoder.decode(chunk.value, { stream: true });
          const lines = buf.split("\n");
          buf = lines.pop();
          for (const l of lines) {
            const v = l.trim().toLowerCase();
            if (!v) continue;
            seen++;
            // The cap counts NAMES. An earlier version compared the length of
            // the accumulated text against the cap, which made a cap of 5000
            // mean "about 170 names" - because a name is roughly thirty
            // characters long. The list was silently a third of what the
            // number said it was.
            if (seen <= cap) text += v + "\n";
            else { truncated = true; break; }
          }
          // Report the count as it grows, but not on every single name: a
          // message per name is a message per name, and the panel redraws on
          // each one.
          //
          // The step grows with the count, so the number moves smoothly at
          // the start rather than jumping 0 -> 25 -> 50, which is what a
          // fixed step looks like on a small domain.
          if (seen - lastReported >= reportStep(seen)) { lastReported = seen; report(seen); }
          if (truncated) { try { await reader.cancel(); } catch (_) {} break; }
        }
        if (!truncated && buf.trim()) {
          seen++;
          if (seen <= cap) text += buf.trim().toLowerCase() + "\n";
        }
        report(seen);
      } else {
        const body = await res.text();
        const lines = parseNames(body);
        seen = lines.length;
        truncated = lines.length > cap;
        text = lines.slice(0, cap).join("\n");
      }

      const names = parseNames(text);
      return {
        ok: true, root: root, names: names, count: names.length,
        // How many names the service sent before the cap stopped the read.
        // When the list was truncated this is NOT the full count, and the
        // panel says so rather than presenting it as one.
        total: seen, truncated: truncated, cap: cap
      };
    } catch (e) {
      const aborted = e && (e.name === "AbortError" || /abort/i.test(String(e.message || "")));
      return {
        ok: false, root: root, reason: aborted ? "timeout" : "network",
        message: aborted
          ? "The certificate transparency service did not answer within " +
            Math.round(timeoutMs / 1000) + "s. The domain may be very large - " +
            "try again, or search a smaller one."
          : "The request failed: " + String(e && e.message || e)
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------------
  // Is a name alive?
  //
  // This is the only part of the extension that contacts hosts it was not
  // asked to contact, so it is a separate, explicit, opt-in call - never
  // something that happens because a tab was opened.
  //
  // The work is done by the service worker: it has the host permissions,
  // and a panel that starts requests and is then closed leaves them
  // orphaned. The worker checks ONE name at a time and reports it before
  // starting the next, so the table fills in row by row instead of
  // appearing all at once at the end.
  //
  // The listener lives HERE, in the transport module, rather than in the
  // panel. The panel was missing the results: it had its own listener, and
  // a result that arrived while the panel was busy went nowhere, so the
  // count sat on zero and the table stayed empty until the whole run
  // finished. The module that owns the transport owns the listener.
  // ---------------------------------------------------------------------
  const hostCheckListeners = [];
  let hostCheckListenerReady = false;

  // The listener is registered LAZILY, on the first check, rather than when
  // this file loads.
  //
  // Registering it at load time assumes chrome.runtime already exists. In
  // the extension it does - but in the preview harness, where this module is
  // loaded before the harness installs its chrome stub, it does not, and the
  // listener was never registered. The result was a check that ran to
  // completion and reported nothing until the end: every per-name result
  // had gone to a listener that was not there.
  function ensureHostCheckListener() {
    if (hostCheckListenerReady) return;
    hostCheckListenerReady = true;
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.onMessage ||
        typeof chrome.runtime.onMessage.addListener !== "function") return;
    chrome.runtime.onMessage.addListener(msg => {
      if (!msg || msg.kind !== "hostCheckResult" || !msg.result) return undefined;
      for (const fn of hostCheckListeners) {
        try { fn(msg.reqId, msg.result); } catch (_) {}
      }
      return undefined;
    });
  }

  async function checkHosts(hosts, opts) {
    opts = opts || {};
    const list = (hosts || []).slice(0, 200);
    const onResult = typeof opts.onResult === "function" ? opts.onResult : null;
    if (!list.length) return { ok: true, results: {} };

    ensureHostCheckListener();

    const reqId = opts.reqId || ("chk-" + Date.now());
    // One listener per call, removed when the call ends, so a second check
    // does not deliver its results to the first one's callback.
    const listener = (rid, result) => {
      if (String(rid) !== String(reqId)) return;
      if (onResult) { try { onResult(result); } catch (_) {} }
    };
    hostCheckListeners.push(listener);

    try {
      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        const res = await chrome.runtime.sendMessage({
          __xre: 1,
          kind: "hostCheck",
          hosts: list,
          reqId: reqId
        });
        if (res && res.ok) return { ok: true, results: res.results || {} };
        if (res && res.error) {
          return { ok: false, error: String(res.error) };
        }
      }
      return { ok: false, error: "the service worker did not answer" };
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e) };
    } finally {
      const i = hostCheckListeners.indexOf(listener);
      if (i >= 0) hostCheckListeners.splice(i, 1);
    }
  }

  global.XraySubdomain = {
    deriveRoot: deriveRoot,
    search: search,
    checkHosts: checkHosts,
    parseNames: parseNames,
    normalizeHost: normalizeHost,
    MULTI_LABEL_SUFFIXES: MULTI_LABEL_SUFFIXES,
    SINGLE_LABEL_SUFFIXES: SINGLE_LABEL_SUFFIXES
  };
})(typeof window !== "undefined" ? window : globalThis);
