import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const db = new Database('privmessenger.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';

db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 number TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL,
 receiver_id INTEGER NOT NULL,
 text TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, created_at);
`);

app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(__dirname,'public')));

function tokenFor(user){ return jwt.sign({id:user.id,number:user.number}, JWT_SECRET,{expiresIn:'30d'}); }
function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    const t=h.startsWith('Bearer ')?h.slice(7):'';
    req.user=jwt.verify(t,JWT_SECRET);
    next();
  }catch{res.status(401).json({error:'Необходим вход'});}
}
function safeUser(u){return {id:u.id,number:u.number,name:u.name};}

app.post('/api/register', async (req,res)=>{
  const number=String(req.body.number||'').trim();
  const name=String(req.body.name||'').trim();
  const password=String(req.body.password||'');
  if(!/^[0-9]{4,20}$/.test(number)) return res.status(400).json({error:'Номер должен содержать 4–20 цифр'});
  if(name.length<2 || name.length>40) return res.status(400).json({error:'Имя: от 2 до 40 символов'});
  if(password.length<6) return res.status(400).json({error:'Пароль: минимум 6 символов'});
  if(db.prepare('SELECT id FROM users WHERE number=?').get(number)) return res.status(409).json({error:'Этот номер уже зарегистрирован'});
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare('INSERT INTO users(number,name,password_hash,created_at) VALUES(?,?,?,?)').run(number,name,hash,Date.now());
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  res.json({token:tokenFor(user),user:safeUser(user)});
});

app.post('/api/login', async (req,res)=>{
  const number=String(req.body.number||'').trim(), password=String(req.body.password||'');
  const user=db.prepare('SELECT * FROM users WHERE number=?').get(number);
  if(!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'Неверный номер или пароль'});
  res.json({token:tokenFor(user),user:safeUser(user)});
});

app.get('/api/me',auth,(req,res)=>{
  const u=db.prepare('SELECT id,number,name FROM users WHERE id=?').get(req.user.id);
  res.json({user:u});
});

app.get('/api/users',auth,(req,res)=>{
  const q=String(req.query.q||'').trim();
  const rows=q
    ? db.prepare("SELECT id,number,name FROM users WHERE id<>? AND (number LIKE ? OR name LIKE ?) ORDER BY name LIMIT 50").all(req.user.id,`%${q}%`,`%${q}%`)
    : db.prepare("SELECT id,number,name FROM users WHERE id<>? ORDER BY name LIMIT 50").all(req.user.id);
  res.json({users:rows});
});

app.get('/api/messages/:userId',auth,(req,res)=>{
  const other=Number(req.params.userId);
  const rows=db.prepare(`
    SELECT id,sender_id AS senderId,receiver_id AS receiverId,text,created_at AS createdAt
    FROM messages
    WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
    ORDER BY id ASC LIMIT 500
  `).all(req.user.id,other,other,req.user.id);
  res.json({messages:rows});
});

const online=new Map(); // userId -> Set<WebSocket>
function send(ws,obj){ if(ws.readyState===1) ws.send(JSON.stringify(obj)); }
function broadcastUser(userId,obj){
  for(const ws of (online.get(userId)||[])) send(ws,obj);
}
wss.on('connection',(ws)=>{
  let uid=null;
  ws.on('message',(raw)=>{
    try{
      const msg=JSON.parse(raw.toString());
      if(msg.type==='auth'){
        const p=jwt.verify(msg.token,JWT_SECRET); uid=p.id;
        if(!online.has(uid)) online.set(uid,new Set());
        online.get(uid).add(ws);
        send(ws,{type:'ready'});
        return;
      }
      if(!uid) return;
      if(msg.type==='message'){
        const receiverId=Number(msg.receiverId);
        const text=String(msg.text||'').trim();
        if(!receiverId || !text || text.length>5000) return;
        const receiver=db.prepare('SELECT id FROM users WHERE id=?').get(receiverId);
        if(!receiver) return;
        const createdAt=Date.now();
        const info=db.prepare('INSERT INTO messages(sender_id,receiver_id,text,created_at) VALUES(?,?,?,?)')
          .run(uid,receiverId,text,createdAt);
        const out={type:'message',message:{id:info.lastInsertRowid,senderId:uid,receiverId,text,createdAt}};
        broadcastUser(uid,out); broadcastUser(receiverId,out);
      }
    }catch{}
  });
  ws.on('close',()=>{
    if(uid && online.has(uid)){
      online.get(uid).delete(ws);
      if(!online.get(uid).size) online.delete(uid);
    }
  });
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
const port=Number(process.env.PORT||3000);
server.listen(port,()=>console.log(`PrivMessenger online: http://localhost:${port}`));
