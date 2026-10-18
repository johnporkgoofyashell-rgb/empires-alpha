import http from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scrypt=promisify(scryptCallback),root=path.dirname(fileURLToPath(import.meta.url)),port=Number(process.env.PORT||8835);
const dataDir=process.env.DATA_DIR||path.join(root,'data'),usersFile=path.join(dataDir,'users.json'),sessions=new Map(),rooms=new Map(),worlds=new Map();
const json=(res,status,body)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});res.end(JSON.stringify(body));};
const body=req=>new Promise((resolve,reject)=>{let raw='';req.on('data',part=>{raw+=part;if(raw.length>100000)reject(Error('Request too large'));});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(Error('Invalid JSON'));}});});
async function users(){try{return JSON.parse(await readFile(usersFile,'utf8'));}catch{return []}}
async function saveUsers(value){await mkdir(dataDir,{recursive:true});await writeFile(usersFile,JSON.stringify(value,null,2));}
async function passwordHash(password,salt=randomBytes(16).toString('hex')){return {salt,hash:(await scrypt(password,salt,64)).toString('hex')}}
async function authenticate(req,url){const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'')||url?.searchParams.get('token')||'';const id=sessions.get(token);return id?(await users()).find(user=>user.id===id):null;}
function sendRoom(room,event){for(const client of rooms.get(room)||[])client.write('event: room\ndata: '+JSON.stringify(event)+'\n\n');}
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');
 if(req.method==='POST'&&url.pathname==='/api/auth/register'){
  const {username,password}=await body(req),name=String(username||'').trim();if(!/^[a-zA-Z0-9_]{3,24}$/.test(name)||String(password||'').length<8)return json(res,400,{error:'Use a 3–24 character username and an 8+ character password.'});
  const all=await users();if(all.some(user=>user.username.toLowerCase()===name.toLowerCase()))return json(res,409,{error:'Username already exists.'});const credential=await passwordHash(password),user={id:randomBytes(12).toString('hex'),username:name,...credential,createdAt:Date.now()};all.push(user);await saveUsers(all);const token=randomBytes(32).toString('hex');sessions.set(token,user.id);return json(res,201,{token,user:{id:user.id,username:user.username}});
 }
 if(req.method==='POST'&&url.pathname==='/api/auth/login'){
  const {username,password}=await body(req),user=(await users()).find(item=>item.username.toLowerCase()===String(username||'').toLowerCase());if(!user)return json(res,401,{error:'Invalid username or password.'});const candidate=await passwordHash(password,user.salt);if(!timingSafeEqual(Buffer.from(candidate.hash,'hex'),Buffer.from(user.hash,'hex')))return json(res,401,{error:'Invalid username or password.'});const token=randomBytes(32).toString('hex');sessions.set(token,user.id);return json(res,200,{token,user:{id:user.id,username:user.username}});
 }
 if(req.method==='GET'&&url.pathname==='/api/me'){const user=await authenticate(req);return user?json(res,200,{user:{id:user.id,username:user.username}}):json(res,401,{error:'Sign in required.'});}
 if(req.method==='GET'&&url.pathname==='/api/world'){const user=await authenticate(req),room=url.searchParams.get('room')||'public';if(!user)return json(res,401,{error:'Sign in required.'});return json(res,200,{countries:[...((worlds.get(room)||new Map()).values())]});}
 if(req.method==='POST'&&url.pathname==='/api/world/publish'){const user=await authenticate(req);if(!user)return json(res,401,{error:'Sign in required.'});const {room='public',country={}}=await body(req);const world=worlds.get(room)||new Map();const safe={playerId:user.id,name:String(country.name||user.username).slice(0,32),color:country.color||'#557799',flag:Array.isArray(country.flag)?country.flag.slice(0,192):[],tiles:Array.isArray(country.tiles)?country.tiles.slice(0,400):[],population:Math.max(0,Number(country.population)||0),government:String(country.government||'Tribal Council').slice(0,40),army:Math.max(0,Number(country.army)||0),alliances:Array.isArray(country.alliances)?country.alliances.slice(0,20):[]};world.set(user.id,safe);worlds.set(room,world);sendRoom(room,{type:'world',country:safe});return json(res,200,{ok:true,countries:[...world.values()]});}
 if(req.method==='POST'&&url.pathname==='/api/world/alliance'){const user=await authenticate(req);if(!user)return json(res,401,{error:'Sign in required.'});const {room='public',targetId}=await body(req),world=worlds.get(room)||new Map(),mine=world.get(user.id),theirs=world.get(targetId);if(!mine||!theirs)return json(res,404,{error:'Both countries must be online.'});mine.alliances=[...new Set([...mine.alliances,theirs.playerId])];theirs.alliances=[...new Set([...theirs.alliances,mine.playerId])];sendRoom(room,{type:'alliance',a:mine.playerId,b:theirs.playerId});return json(res,200,{ok:true});}
 if(req.method==='GET'&&url.pathname==='/api/rooms/events'){const user=await authenticate(req,url),room=url.searchParams.get('room')||'public';if(!user)return json(res,401,{error:'Sign in required.'});res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache','connection':'keep-alive'});res.write('event: room\ndata: '+JSON.stringify({type:'presence',user:{id:user.id,username:user.username}})+'\n\n');const clients=rooms.get(room)||new Set();clients.add(res);rooms.set(room,clients);sendRoom(room,{type:'join',user:{id:user.id,username:user.username}});req.on('close',()=>{clients.delete(res);sendRoom(room,{type:'leave',user:{id:user.id,username:user.username}});});return;}
 if(req.method==='POST'&&url.pathname==='/api/rooms/event'){const user=await authenticate(req);if(!user)return json(res,401,{error:'Sign in required.'});const {room='public',event={}}=await body(req);sendRoom(room,{type:'game',user:{id:user.id,username:user.username},event,at:Date.now()});return json(res,202,{ok:true});}
 if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'content-type':'text/html; charset=utf-8'});return res.end(await readFile(path.join(root,'index.html')));}
 if(req.method==='GET'&&url.pathname.startsWith('/assets/')){const file=path.normalize(path.join(root,url.pathname));if(!file.startsWith(path.join(root,'assets')))return json(res,403,{error:'Forbidden'});return res.end(await readFile(file));}
 return json(res,404,{error:'Not found'});
 }catch(error){console.error(error);return json(res,500,{error:'Server error'});}
});
server.listen(port,'0.0.0.0',()=>console.log('EMPIRES server listening on '+port));
