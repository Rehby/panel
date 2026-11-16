'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const elements=new Map(),handlers={};
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
 document:{baseURI:'https://example.test/admin/',querySelector:element,querySelectorAll:()=>[],addEventListener(name,fn){(handlers[name]||=[]).push(fn);},createElement(){return {click(){downloaded=this.download;}};}},
 window:{addEventListener(){},confirm:()=>true},location:{origin:'https://example.test',hash:''},
 FormData:class{constructor(form){this.values=form.values;}getAll(name){return this.values[name]||[];}*[Symbol.iterator](){for(const [name,values] of Object.entries(this.values))for(const value of values)yield [name,value];}},
 navigator:{clipboard:{writeText:async value=>{copied=value;}}},
 fetch:async()=>({ok:false,status:401,json:async()=>({error:'login'})}),
 qrcode:require('../static/qrcode.js'),TextEncoder,Blob,URL:TestURL,
 setTimeout(){},setInterval(){},console,
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8'),context);
assert.equal(vm.runInContext(`state.protocols=[{id:'vless',name:'VLESS'}];connectionName({protocol:'vless',transport:'xhttp',self_sni:true},'NL')`,context),'🇳🇱 VLESS · XHTTP · SELF');
assert.equal(vm.runInContext(`connectionName({protocol:'vless',transport:'tcp'},'')`,context),'VLESS · TCP');

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
 await vm.runInContext(`state={services:[
  {id:'normal',name:'VPN <one>',host:'vpn.example',port:443,protocol:'vless'},
  {id:'turn',name:'TURN',host:'turn.example',port:56000,protocol:'wdtt',capacity:{used:10,limit:10,free:0}},
  {id:'available',name:'TURN 2',host:'turn.example',port:56001,protocol:'wdtt',capacity:{used:2,limit:10,free:8}}
 ],users:[{id:'u',name:'Access',service_id:'available',person_id:'p',enabled:true,expires_at:0}],people:[{id:'p',name:'Alice'}],protocols:[{id:'vless',name:'VLESS'},{id:'wdtt',name:'VK-TURN / qWDTT'}],events:[]};
 peopleAction('person-grant','p')`,context);
 assert.match(context.modalBody,/VPN &lt;one&gt;/);
 assert.match(context.modalBody,/name="add" value="normal"/);
 assert.match(context.modalBody,/data-action="turn-limit" data-id="turn"/);
 assert.match(context.modalBody,/name="keep" value="u" checked/);
 vm.runInContext(`globalThis.requests=[];api=async(path,data)=>{requests.push([path,data]);return {};};load=async()=>{};`,context);
 const form={id:'person-connections-form',dataset:{id:'p'},values:{add:['normal'],keep:[]},querySelectorAll:()=>[{value:'u'}]};
 await handlers.submit[handlers.submit.length-1]({target:form,preventDefault(){}});
 assert.equal(context.requests[0][0],'people/p/grant');
 assert.equal(context.requests[0][1].service_id,'normal');
 assert.equal(context.requests[1][0],'users/u/delete');
 vm.runInContext(`api=async(path)=>{if(path.startsWith('users/'))throw Error('ошибка удаления');};`,context);
 await handlers.submit[handlers.submit.length-1]({target:form,preventDefault(){}});
 assert.match(element('#connections-error').textContent,/ошибка удаления/);
 assert.match(element('#connections-error').textContent,/Выполнено операций: 1/);
 element('#connections-error').textContent='';
 const turn=vm.runInContext('turnPage()',context);
 assert.match(turn,/data-action="turn-hashes"/);
 assert.match(turn,/data-protocol="wdtt"/);
 assert.match(turn,/data-action="turn-edit-user" data-id="u"/);
 assert.match(turn,/Активен/);
 vm.runInContext(`page='turn';render()`,context);
 assert.equal(element('#breadcrumb').textContent,'Службы');
 assert.match(element('#content').innerHTML,/data-action="turn-hashes"/);
 assert.match(element('#content').innerHTML,/data-action="turn-edit-user" data-id="u"/);
 await vm.runInContext(`state.services=[];state.users=[];peopleAction('person-grant','p')`,context);
 assert.match(context.modalBody,/Сначала создайте службу/);
 vm.runInContext(`globalThis.requests=[];api=async(path,data)=>{requests.push([path,data]);return {};};`,context);
 await handlers.submit[0]({target:{id:'user-form',dataset:{countryPending:'true'},values:{name:['VLESS · TCP'],country:['']}},preventDefault(){}});
 assert.equal(context.requests[0][0],'users');
 assert.equal(context.requests[0][1].name,'VLESS · TCP');
 assert.equal(context.requests[0][1].country,'');
 console.log('Share controls: OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
