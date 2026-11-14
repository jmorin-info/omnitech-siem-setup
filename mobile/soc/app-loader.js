function loadScript(src){loadScript._c=loadScript._c||{};if(loadScript._c[src])return loadScript._c[src];
  return loadScript._c[src]=new Promise(function(res,rej){var s=document.createElement("script");s.src=src;s.async=true;s.onload=res;s.onerror=rej;document.head.appendChild(s);});}
