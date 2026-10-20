  
                                                               
  
                                                                   
                                                                              
                                                                            
                                                                  
  
                                                                           
                                                                             
                                                                          
                                                                             
            
  
                                                                               
                                                                             
                                                                              
                                   
   
(() => {
  "use strict";

  const REQ = "__xrext_req__";
  const RES = "__xrext_res__";
  const TIMEOUT_MS = 45000;
  const isTop = (() => { try { return window.top === window; } catch (_) { return false; } })();

                                                                              
                                                                              
                                                                            
  if (window.__xrextRelay) return;
  window.__xrextRelay = true;

  let seq = 0;

  function callMainWorld(cmd, args) {
    return new Promise(resolve => {
      const id = ++seq;
      let settled = false;

      const finish = payload => {
        if (settled) return;
        settled = true;
        window.removeEventListener(RES, onRes);
        clearTimeout(timer);
        resolve(payload);
      };

      const onRes = ev => {
        let d = null;
        try { d = JSON.parse(ev && ev.detail); } catch (_) { return; }
                                                                         
        if (!d || d.id !== id) return;
        finish(d);
      };

                                                                           
                                    
      window.addEventListener(RES, onRes, false);

      const timer = setTimeout(() => finish({
        id, ok: false,
        error: "No answer from the page scanner. It may not have injected on this URL."
      }), TIMEOUT_MS);

      try {
        window.dispatchEvent(new CustomEvent(REQ, {
          detail: JSON.stringify({ id, cmd, args: args || {} })
        }));
      } catch (e) {
        finish({ id, ok: false, error: "dispatch failed: " + String((e && e.message) || e) });
      }
    });
  }

                                                                                
                                                                          
                                                            
try {
  const rt = chrome && chrome.runtime;
  if (rt && typeof rt.onMessage.addListener === "function") {
    rt.onMessage.addListener((msg, sender, sendResponse) => {
      if (!isTop) return undefined;                                                 
      if (!msg || msg.__xre !== 1) return undefined;

      callMainWorld(msg.cmd, msg.args).then(sendResponse, e =>
        sendResponse({ ok: false, error: String((e && e.message) || e) })
      );
      return true;                                                   
    });
  }
} catch (e) {
                                                                        
}
})();