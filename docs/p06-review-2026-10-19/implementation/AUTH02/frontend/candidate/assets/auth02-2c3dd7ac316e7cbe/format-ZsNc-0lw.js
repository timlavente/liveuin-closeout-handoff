const s=(t,e="USD")=>{const n=Math.abs(t),o=t<0?"-":"",r=new Intl.NumberFormat("en-US",{style:"currency",currency:e,maximumFractionDigits:n>=1e3?0:2}).format(n);return`${o}${r}`};export{s as m};
