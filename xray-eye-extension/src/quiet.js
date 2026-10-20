  
                                                
  
                                                                        
                                                                            
                                                                              
                               
  
                                                                             
                                                                           
                                                                             
                                                                          
                                                           
   
(() => {
  "use strict";

  if (window.__xreQuiet) return;
  window.__xreQuiet = { original: {}, silent: {} };

                                                                            
                                                                          
                                                                             
                                                                              
                                                                              
  window.__XRE_EXTENSION__ = true;

  const METHODS = ["log", "info", "warn", "error", "debug", "table", "trace",
    "group", "groupCollapsed", "groupEnd", "dir", "dirxml", "count", "timeEnd",
    "assert", "profile", "profileEnd"];

  for (const m of METHODS) {
    window.__xreQuiet.original[m] = console[m];
                                                                               
                                                                
    const noop = function () {};
    window.__xreQuiet.silent[m] = noop;
  }

  for (const m of METHODS) {
    try { console[m] = window.__xreQuiet.silent[m]; } catch (_) {}
  }
})();