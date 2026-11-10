
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const DATA_FILE = path.join(__dirname, "fast-recharge-data.json");

let data = {
  customers: [],
  orders: [],
  packages: [
    { id: "p1", name: "100 Diamonds", price: 100 },
    { id: "p2", name: "250 Diamonds", price: 250 },
    { id: "p3", name: "500 Diamonds", price: 500 }
  ]
};

if (fs.existsSync(DATA_FILE)) {
  try {
    data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (error) {
    console.error("ডেটা ফাইল পড়া যায়নি:", error);
  }
}

function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

const sessions = new Map();

function getCustomer(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  return sessions.get(token) || null;
}

function makePassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, salt, hash) {
  const testHash = crypto.scryptSync(password, salt, 64);
  const originalHash = Buffer.from(hash, "hex");

  return originalHash.length === testHash.length &&
    crypto.timingSafeEqual(testHash, originalHash);
}

app.post("/api/customer/signup", (req, res) => {
  const { name, phone, password } = req.body;

  if (!name || !phone || !password) {
    return res.status(400).json({ message: "সব তথ্য পূরণ করুন।" });
  }

  if (String(password).length < 6) {
    return res.status(400).json({
      message: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।"
    });
  }

  if (data.customers.some(c => c.phone === String(phone))) {
    return res.status(409).json({
      message: "এই নম্বরে আগে থেকেই অ্যাকাউন্ট আছে।"
    });
  }

  const passwordData = makePassword(String(password));

  data.customers.push({
    id: crypto.randomUUID(),
    name: String(name),
    phone: String(phone),
    salt: passwordData.salt,
    passwordHash: passwordData.hash
  });

  saveData();

  res.json({ message: "অ্যাকাউন্ট তৈরি হয়েছে। এখন লগইন করুন।" });
});

app.post("/api/customer/login", (req, res) => {
  const { phone, password } = req.body;

  const customer = data.customers.find(
    c => c.phone === String(phone)
  );

  if (
    !customer ||
    !checkPassword(
      String(password || ""),
      customer.salt,
      customer.passwordHash
    )
  ) {
    return res.status(401).json({
      message: "মোবাইল নম্বর অথবা পাসওয়ার্ড ভুল।"
    });
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, customer.id);

  res.json({
    token,
    customer: {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    }
  });
});

app.get("/api/customer/me", (req, res) => {
  const customerId = getCustomer(req);

  if (!customerId) {
    return res.status(401).json({ message: "আবার লগইন করুন।" });
  }

  const customer = data.customers.find(c => c.id === customerId);

  if (!customer) {
    return res.status(401).json({ message: "কাস্টমার পাওয়া যায়নি।" });
  }

  res.json({
    customer: {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    }
  });
});

app.get("/api/packages", (req, res) => {
  res.json({ packages: data.packages });
});

app.post("/api/orders", (req, res) => {
  const customerId = getCustomer(req);

  if (!customerId) {
    return res.status(401).json({ message: "আগে লগইন করুন।" });
  }

  const { packageId, imoId } = req.body;

  const selectedPackage = data.packages.find(
    p => p.id === String(packageId)
  );

  if (!selectedPackage || !imoId) {
    return res.status(400).json({
      message: "সঠিক প্যাকেজ ও IMO ID দিন।"
    });
  }

  const order = {
    id: "FR" + Date.now(),
    customerId,
    packageId: selectedPackage.id,
    packageName: selectedPackage.name,
    price: selectedPackage.price,
    imoId: String(imoId),
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  data.orders.push(order);
  saveData();

  res.json({
    message: "অর্ডার জমা হয়েছে। পেমেন্ট ও রিচার্জ যাচাই করা হবে।",
    order
  });
});

app.get("/api/orders", (req, res) => {
  const customerId = getCustomer(req);

  if (!customerId) {
    return res.status(401).json({ message: "আগে লগইন করুন।" });
  }

  const orders = data.orders.filter(
    order => order.customerId === customerId
  );

  res.json({ orders });
});

app.listen(PORT, () => {
  console.log(`FAST RECHARGE server running on port ${PORT}`);
});
