import express from "express";
import helmet from "helmet";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();
const required = ["JWT_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD"];
for (const k of required) if (!process.env[k]) throw new Error(`Missing required environment variable: ${k}`);
if (process.env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(process.env.DB_FILE || path.join(__dirname, "fast-recharge.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS packages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, price INTEGER NOT NULL CHECK(price > 0),
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 package_id INTEGER REFERENCES packages(id), package_title TEXT NOT NULL, price INTEGER NOT NULL,
 imo_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const count = db.prepare("SELECT COUNT(*) n FROM packages").get().n;
if (!count) {
 const insert = db.prepare("INSERT INTO packages(title,price) VALUES(?,?)");
 for (const p of [["100 Diamond",120],["310 Diamond",350],["520 Diamond",580],["1060 Diamond",1150]]) insert.run(...p);
}
db.exec(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);`);
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
db.prepare(`INSERT INTO admins(username,password_hash) VALUES(?,?)
 ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash`).run(process.env.ADMIN_USERNAME, adminHash);
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || false }));
app.use(express.json({limit:"30kb"}));
app.use("/api", rateLimit({windowMs:15*60*1000,limit:180,standardHeaders:true,legacyHeaders:false}));
function tokenFor(claims){return jwt.sign(claims,process.env.JWT_SECRET,{expiresIn:"12h"});}
function auth(role){return (req,res,next)=>{
 const h=req.headers.authorization||"";
 try { const t=h.startsWith("Bearer ")?h.slice(7):""; const payload=jwt.verify(t,process.env.JWT_SECRET);
 if(role && payload.role!==role) return res.status(403).json({error:"অনুমতি নেই"});
 req.actor=payload; next();
 } catch { return res.status(401).json({error:"আবার লগইন করুন"}); }
};}
const cleanPhone = v => String(v||"").replace(/[^\d+]/g,"").slice(0,20);
app.post("/api/customer/signup", async (req,res)=>{
 const name=String(req.body.name||"").trim().slice(0,80), phone=cleanPhone(req.body.phone), password=String(req.body.password||"");
 if(!name||phone.length<8||password.length<8) return res.status(400).json({error:"নাম, সঠিক মোবাইল নম্বর ও কমপক্ষে ৮ অক্ষরের পাসওয়ার্ড দিন"});
 try {
 const hash=await bcrypt.hash(password,12);
 const r=db.prepare("INSERT INTO users(name,phone,password_hash) VALUES(?,?,?)").run(name,phone,hash);
 const token=tokenFor({sub:r.lastInsertRowid,role:"customer",phone});
 res.status(201).json({token,user:{name,phone}});
 } catch(e){ if(String(e).includes("UNIQUE")) return res.status(409).json({error:"এই নম্বরে অ্যাকাউন্ট আছে"}); throw e; }
});
app.post("/api/customer/login",async(req,res)=>{
 const phone=cleanPhone(req.body.phone), row=db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
 if(!row||!(await bcrypt.compare(String(req.body.password||""),row.password_hash))) return res.status(401).json({error:"মোবাইল বা পাসওয়ার্ড ভুল"});
 res.json({token:tokenFor({sub:row.id,role:"customer",phone}),user:{name:row.name,phone:row.phone}});
});
app.post("/api/admin/login",async(req,res)=>{
 const row=db.prepare("SELECT * FROM admins WHERE username=?").get(String(req.body.username||""));
 if(!row||!(await bcrypt.compare(String(req.body.password||""),row.password_hash))) return res.status(401).json({error:"অ্যাডমিন ইউজারনেম বা পাসওয়ার্ড ভুল"});
 res.json({token:tokenFor({sub:row.id,role:"admin",username:row.username}),user:{username:row.username}});
});
app.get("/api/packages",(req,res)=>res.json(db.prepare("SELECT id,title,price FROM packages WHERE active=1 ORDER BY id DESC").all()));
app.post("/api/packages",auth("admin"),(req,res)=>{
 const title=String(req.body.title||"").trim().slice(0,100),price=Number(req.body.price);
 if(!title||!Number.isSafeInteger(price)||price<1) return res.status(400).json({error:"প্যাকেজের নাম ও সঠিক দাম দিন"});
 const r=db.prepare("INSERT INTO packages(title,price) VALUES(?,?)").run(title,price);
 res.status(201).json({id:r.lastInsertRowid,title,price});
});
app.delete("/api/packages/:id",auth("admin"),(req,res)=>{
 const r=db.prepare("UPDATE packages SET active=0 WHERE id=?").run(Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"প্যাকেজ পাওয়া যায়নি"});
 res.json({ok:true});
});
app.post("/api/orders",auth("customer"),(req,res)=>{
 const packageId=Number(req.body.packageId),imoId=String(req.body.imoId||"").trim().slice(0,80);
 const p=db.prepare("SELECT * FROM packages WHERE id=? AND active=1").get(packageId);
 if(!p||!imoId)return res.status(400).json({error:"প্যাকেজ নির্বাচন করুন এবং IMO ID দিন"});
 const r=db.prepare("INSERT INTO orders(user_id,package_id,package_title,price,imo_id) VALUES(?,?,?,?,?)").run(Number(req.actor.sub),p.id,p.title,p.price,imoId);
 res.status(201).json({id:r.lastInsertRowid,status:"Pending"});
});
app.get("/api/orders/mine",auth("customer"),(req,res)=>{
 res.json(db.prepare("SELECT id,package_title AS package,price,imo_id AS imoId,status,created_at AS createdAt FROM orders WHERE user_id=? ORDER BY id DESC").all(Number(req.actor.sub)));
});
app.get("/api/admin/orders",auth("admin"),(req,res)=>{
 res.json(db.prepare(`SELECT o.id,o.package_title AS package,o.price,o.imo_id AS imoId,o.status,o.created_at AS createdAt,u.name,u.phone
 FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC`).all());
});
app.patch("/api/admin/orders/:id",auth("admin"),(req,res)=>{
 const status=String(req.body.status||"");
 if(!["Pending","Processing","Completed","Rejected"].includes(status))return res.status(400).json({error:"অবস্থা সঠিক নয়"});
 const r=db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"অর্ডার পাওয়া যায়নি"});
 res.json({ok:true});
});
app.get("/api/health",(req,res)=>res.json({ok:true,service:"FAST RECHARGE API"}));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","customer.html")));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`FAST RECHARGE server listening on ${port}`));
