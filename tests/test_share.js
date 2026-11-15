'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const elements=new Map();
let downloaded,blob,copied;
function element(selector){
 if(!elements.has(selector))elements.set(selector,{hidden:true,textContent:'',innerHTML:'',attributes:{},setAttribute(k,v){this.attributes[k]=v;},replaceChildren(){this.innerHTML='';},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}});
 return elements.get(selector);
}
class TestURL extends URL{
 static createObjectURL(value){blob=value;return 'blob:test';}
 static revokeObjectURL(){}
}
const context=vm.createContext({
 document:{baseURI:'https://example.test/admin/',querySelector:element,querySelectorAll:()=>[],addEventListener(){},createElement(){return {click(){downloaded=this.download;}};}},
 window:{addEventListener(){}},location:{origin:'https://example.test',hash:''},
 navigator:{clipboard:{writeText:async value=>{copied=value;}}},
 fetch:async()=>({ok:false,status:401,json:async()=>({error:'login'})}),
 qrcode:require('../static/qrcode.js'),TextEncoder,Blob,URL:TestURL,
 setTimeout(){},setInterval(){},console,
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8'),context);
assert.equal(vm.runInContext(`state.protocols=[{id:'vless',name:'VLESS'}];connectionName({protocol:'vless',transport:'xhttp',self_sni:true},'NL')`,context),'🇳🇱 VLESS · XHTTP · SELF');

(async()=>{
 await vm.runInContext(`state={services:[{id:'s',protocol:'vless'}],users:[{id:'u',name:'User',service_id:'s',person_id:'p'}],people:[{id:'p',name:'User',token:'secret-token'}],protocols:[],events:[]};
 api=async()=>({content:'vless://secret-profile'});
 openModal=(title,description,body)=>{globalThis.modalBody=body;};
 showProfile('u')`,context);
 assert(!context.modalBody.includes('secret-token'));
 assert(!context.modalBody.includes('secret-profile'));
 const profile=element('#profile-share-text'),subscription=element('#subscription-share-text');
 assert(profile.hidden && subscription.hidden);
 await element('#profile-share-copy').onclick();
 assert.equal(copied,'vless://secret-profile');
 assert(profile.hidden);
 element('#profile-share-show').onclick();
 assert.equal(profile.textContent,'vless://secret-profile');
 element('#profile-share-show').onclick();
 assert.equal(profile.textContent,'');
 element('#subscription-share-qr').onclick();
 assert.match(element('#subscription-share-qr-code').innerHTML,/<svg/);
 element('#subscription-share-qr').onclick();
 assert.equal(element('#subscription-share-qr-code').innerHTML,'');
 element('#subscription-share-download').onclick();
 assert.equal(downloaded,'yptun-subscription.txt');
 assert.equal(await blob.text(),'https://example.test/subscription/secret-token');
 await vm.runInContext(`peopleAction('person-sub','p')`,context);
 assert(!context.modalBody.includes('secret-token'));
 await element('#subscription-share-copy').onclick();
 assert.equal(copied,'https://example.test/subscription/secret-token');
 vm.runInContext(`bindShare('large','x'.repeat(2954),'large.txt')`,context);
 element('#large-qr').onclick();
 assert.equal(element('#large-qr-code').innerHTML,'');
 assert.match(element('#toast').textContent,/слишком большая/);
 console.log('Share controls: OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
