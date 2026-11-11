
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const helmet = require("helmet");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

if (
  !process.env.JWT_SECRET ||
  !process.env.ADMIN_USERNAME ||
  !process.env.ADMIN_PASSWORD
) {
  console.error("JWT_SECRET, ADMIN_USERNAME এবং ADMIN_PASSWORD সেট করতে হবে।");
  process.exit(1);
}

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const DATA_FILE = path.join(__dirname, "fast-recharge-data.json");

const defaultPackages = [
  { id: "p1", name: "100 Diamonds", diamonds: 100, price: 100 },
  { id: "p2", name: "250 Diamonds", diamonds: 250, price: 250 },
  { id: "p3", name: "500 Diamonds", diamonds: 500, price: 500 }
];

const defaultData = {
  customers: [],
  orders: [],
  packages: defaultPackages,
  settings: { bkashNumber: "" },
  diamondBalance: 0
};

let data = { ...defaultData };

if (fs.existsSync(DATA_FILE)) {
  try {
    const saved = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    data = {
      ...defaultData,
      ...saved,
      settings: {
        ...defaultData.settings,
        ...(saved.settings || {})
      }
    };

    data.customers = Array.isArray(data.customers)
      ? data.customers
      : [];

    data.orders = Array.isArray(data.orders)
      ? data.orders.map(order => ({
          ...order,
          diamonds: Number(order.diamonds) || 0,
          transactionId: order.transactionId || "",
          paymentVerified: order.paymentVerified === true
        }))
      : [];

    const oldPackages = Array.isArray(data.packages)
      ? data.packages
      : defaultPackages;

    data.packages = oldPackages.map(p => {
      const fallback = defaultPackages.find(x => x.id === p.id);
      return {
        ...p,
        diamonds: Number(p.diamonds) ||
          (fallback ? fallback.diamonds : 0),
        price: Number(p.price) || 0
      };
    });

    data.diamondBalance = Number(data.diamondBalance) || 0;
  } catch (error) {
    console.error("ডেটা ফাইল পড়া যায়নি:", error);
    process.exit(1);
  }
}

function saveData() {
  const tempFile = DATA_FILE + ".tmp";
  fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
}

const customerSessions = new Map();

function makePassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, salt, hash) {
  if (!salt || !hash) return false;

  const test = crypto.scryptSync(password, salt, 64);
  const original = Buffer.from(hash, "hex");

  return original.length === test.length &&
    crypto.timingSafeEqual(test, original);
}

function customerAuth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer /, "");

  const customerId = customerSessions.get(token);

  if (!customerId) {
    return res.status(401).json({
      message: "আবার লগইন করুন।"
    });
  }

  req.customerId = customerId;
  next();
}

function adminAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer /, "");

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({
        message: "অনুমতি নেই।"
      });
    }

    next();
  } catch {
    return res.status(401).json({
      message: "অ্যাডমিন হিসেবে লগইন করুন।"
    });
  }
}

// CUSTOMER SIGNUP
app.post("/api/customer/signup", (req, res) => {
  const { name, phone, password } = req.body;

  if (!name || !phone || !password) {
    return res.status(400).json({
      message: "সব তথ্য পূরণ করুন।"
    });
  }

  if (String(password).length < 6) {
    return res.status(400).json({
      message: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।"
    });
  }

  const cleanPhone = String(phone).trim();

  if (data.customers.some(c => c.phone === cleanPhone)) {
    return res.status(409).json({
      message: "এই নম্বরে অ্যাকাউন্ট আছে।"
    });
  }

  const passwordData = makePassword(String(password));

  data.customers.push({
    id: crypto.randomUUID(),
    name: String(name).trim(),
    phone: cleanPhone,
    salt: passwordData.salt,
    passwordHash: passwordData.hash
  });

  saveData();

  res.json({
    message: "অ্যাকাউন্ট তৈরি হয়েছে। এখন লগইন করুন।"
  });
});

// CUSTOMER LOGIN
app.post("/api/customer/login", loginLimit, (req, res) => {
  const { phone, password } = req.body;

  const customer = data.customers.find(
    c => c.phone === String(phone || "").trim()
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
      message: "নম্বর অথবা পাসওয়ার্ড ভুল।"
    });
  }

  const token = crypto.randomBytes(32).toString("hex");
  customerSessions.set(token, customer.id);

  res.json({
    token,
    customer: {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    }
  });
});

// CUSTOMER PROFILE
app.get("/api/customer/me", customerAuth, (req, res) => {
  const customer = data.customers.find(
    c => c.id === req.customerId
  );

  if (!customer) {
    return res.status(404).json({
      message: "কাস্টমার পাওয়া যায়নি।"
    });
  }

  res.json({
    customer: {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    }
  });
});

// PUBLIC PACKAGES
app.get("/api/packages", (req, res) => {
  res.json({ packages: data.packages });
});

// PUBLIC BKASH NUMBER
app.get("/api/settings", (req, res) => {
  res.json({
    bkashNumber: data.settings.bkashNumber
  });
});

// CUSTOMER CREATE ORDER
app.post("/api/orders", customerAuth, (req, res) => {
  const { packageId, imoId } = req.body;

  const selectedPackage = data.packages.find(
    p => p.id === String(packageId)
  );

  if (
    !selectedPackage ||
    !String(imoId || "").trim() ||
    !Number.isSafeInteger(Number(selectedPackage.diamonds)) ||
    Number(selectedPackage.diamonds) <= 0 ||
    !Number.isSafeInteger(Number(selectedPackage.price)) ||
    Number(selectedPackage.price) < 0
  ) {
    return res.status(400).json({
      message: "সঠিক প্যাকেজ ও IMO ID দিন।"
    });
  }

  const order = {
    id: "FR" + crypto.randomUUID(),
    customerId: req.customerId,
    packageId: selectedPackage.id,
    packageName: selectedPackage.name,
    diamonds: Number(selectedPackage.diamonds),
    price: Number(selectedPackage.price),
    imoId: String(imoId).trim(),
    transactionId: "",
    paymentVerified: false,
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  data.orders.push(order);
  saveData();

  res.json({
    message: "অর্ডার হয়েছে। bKash পেমেন্টের Transaction ID জমা দিন।",
    order
  });
});

// CUSTOMER SUBMIT TRANSACTION ID
app.post("/api/orders/:id/transaction", customerAuth, (req, res) => {
  const transactionId = String(
    req.body.transactionId || ""
  ).trim();

  if (transactionId.length < 5 || transactionId.length > 100) {
    return res.status(400).json({
      message: "সঠিক Transaction ID দিন।"
    });
  }

  const order = data.orders.find(
    o => o.id === req.params.id &&
      o.customerId === req.customerId
  );

  if (!order) {
    return res.status(404).json({
      message: "অর্ডার পাওয়া যায়নি।"
    });
  }

  if (order.status === "Completed" || order.paymentVerified) {
    return res.status(409).json({
      message: "এই অর্ডারের পেমেন্ট ইতিমধ্যে যাচাই হয়েছে।"
    });
  }

  const duplicate = data.orders.some(
    o => o.id !== order.id &&
      o.transactionId &&
      o.transactionId.toLowerCase() === transactionId.toLowerCase()
  );

  if (duplicate) {
    return res.status(409).json({
      message: "এই Transaction ID আগে জমা হয়েছে।"
    });
  }

  order.transactionId = transactionId;
  order.status = "Payment Submitted";
  order.transactionSubmittedAt = new Date().toISOString();

  saveData();

  res.json({
    message: "Transaction ID জমা হয়েছে। অ্যাডমিন যাচাই করবেন।"
  });
});

// CUSTOMER ORDER HISTORY
app.get("/api/orders", customerAuth, (req, res) => {
  const orders = data.orders.filter(
    order => order.customerId === req.customerId
  );

  res.json({ orders });
});

// ADMIN LOGIN
app.post("/api/admin/login", loginLimit, (req, res) => {
  const { username, password } = req.body;

  const correctUser =
    String(username || "") === process.env.ADMIN_USERNAME;

  const correctPassword =
    String(password || "") === process.env.ADMIN_PASSWORD;

  if (!correctUser || !correctPassword) {
    return res.status(401).json({
      message: "অ্যাডমিন তথ্য ভুল।"
    });
  }

  const token = jwt.sign(
    { role: "admin" },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({
    token,
    message: "অ্যাডমিন লগইন সফল।"
  });
});

// ADMIN DASHBOARD
app.get("/api/admin/dashboard", adminAuth, (req, res) => {
  res.json({
    diamondBalance: data.diamondBalance,
    totalOrders: data.orders.length,
    pendingOrders: data.orders.filter(
      o => o.status !== "Completed"
    ).length
  });
});

// ADMIN ORDER LIST
app.get("/api/admin/orders", adminAuth, (req, res) => {
  res.json({
    orders: data.orders.map(order => {
      const customer = data.customers.find(
        c => c.id === order.customerId
      );

      return {
        ...order,
        customerName: customer ? customer.name : "Unknown",
        customerPhone: customer ? customer.phone : ""
      };
    })
  });
});

// ADMIN VERIFY PAYMENT
app.post("/api/admin/orders/:id/verify-payment", adminAuth, (req, res) => {
  const order = data.orders.find(
    o => o.id === req.params.id
  );

  if (!order) {
    return res.status(404).json({
      message: "অর্ডার পাওয়া যায়নি।"
    });
  }

  if (order.paymentVerified) {
    return res.status(409).json({
      message: "পেমেন্ট আগেই যাচাই করা হয়েছে।"
    });
  }

  if (!order.transactionId) {
    return res.status(400).json({
      message: "কাস্টমার Transaction ID জমা দেয়নি।"
    });
  }

  if (req.body.confirmed !== true) {
    return res.status(400).json({
      message: "পেমেন্ট যাচাই নিশ্চিত করুন।"
    });
  }

  // অ্যাডমিনকে bKash অ্যাকাউন্টে লেনদেন নিজে যাচাই করতে হবে।
  order.paymentVerified = true;
  order.paymentVerifiedAt = new Date().toISOString();
  order.status = "Paid";

  saveData();

  res.json({
    message: "পেমেন্ট যাচাই হয়েছে। এখন অর্ডার সম্পন্ন করতে পারবেন।"
  });
});

// ADMIN COMPLETE ORDER
app.post("/api/admin/orders/:id/complete", adminAuth, (req, res) => {
  const order = data.orders.find(
    o => o.id === req.params.id
  );

  if (!order) {
    return res.status(404).json({
      message: "অর্ডার পাওয়া যায়নি।"
    });
  }

  if (order.status === "Completed") {
    return res.status(409).json({
      message: "অর্ডার আগেই সম্পন্ন হয়েছে।"
    });
  }

  if (!order.paymentVerified || order.status !== "Paid") {
    return res.status(400).json({
      message: "আগে bKash পেমেন্ট যাচাই করুন।"
    });
  }

  const amount = Number(order.diamonds);

  if (!Number.isSafeInteger(amount) || amount <= 0) {
    return res.status(400).json({
      message: "ডায়মন্ডের পরিমাণ সঠিক নয়।"
    });
  }

  if (data.diamondBalance < amount) {
    return res.status(400).json({
      message: "পর্যাপ্ত ডায়মন্ড স্টক নেই।"
    });
  }

  data.diamondBalance -= amount;
  order.status = "Completed";
  order.completedAt = new Date().toISOString();

  saveData();

  res.json({
    message: "অর্ডার সম্পন্ন হয়েছে।",
    diamondBalance: data.diamondBalance
  });
});

// ADMIN UPDATE BKASH NUMBER
app.post("/api/admin/settings", adminAuth, (req, res) => {
  const number = String(req.body.bkashNumber || "").trim();

  if (number && !/^[0-9]{11}$/.test(number)) {
    return res.status(400).json({
      message: "সঠিক ১১ সংখ্যার নম্বর দিন।"
    });
  }

  data.settings.bkashNumber = number;
  saveData();

  res.json({
    message: "bKash নম্বর সেভ হয়েছে।"
  });
});

// ADMIN ADD DIAMOND STOCK
app.post("/api/admin/balance/add", adminAuth, (req, res) => {
  const amount = Number(req.body.amount);

  if (!Number.isSafeInteger(amount) || amount <= 0) {
    return res.status(400).json({
      message: "সঠিক ডায়মন্ড পরিমাণ দিন।"
    });
  }

  data.diamondBalance += amount;
  saveData();

  res.json({
    message: "ডায়মন্ড স্টক যোগ হয়েছে।",
    diamondBalance: data.diamondBalance
  });
});

// ADMIN UPDATE PACKAGES
app.post("/api/admin/packages", adminAuth, (req, res) => {
  const packages = req.body.packages;

  if (
    !Array.isArray(packages) ||
    packages.length === 0 ||
    packages.length > 30
  ) {
    return res.status(400).json({
      message: "প্যাকেজ তালিকা সঠিক নয়।"
    });
  }

  const ids = new Set();

  const valid = packages.every(p => {
    if (
      !p ||
      typeof p.id !== "string" ||
      !p.id.trim() ||
      ids.has(p.id) ||
      typeof p.name !== "string" ||
      !p.name.trim() ||
      !Number.isSafeInteger(Number(p.diamonds)) ||
      Number(p.diamonds) <= 0 ||
      !Number.isSafeInteger(Number(p.price)) ||
      Number(p.price) < 0
    ) {
      return false;
    }

    ids.add(p.id);
    return true;
  });

  if (!valid) {
    return res.status(400).json({
      message: "প্যাকেজের তথ্য সঠিক নয়।"
    });
  }

  data.packages = packages.map(p => ({
    id: p.id.trim(),
    name: p.name.trim(),
    diamonds: Number(p.diamonds),
    price: Number(p.price)
  }));

  saveData();

  res.json({
    message: "প্যাকেজ আপডেট হয়েছে।"
  });
});

// SERVER START
app.listen(PORT, () => {
  console.log("FAST RECHARGE server running on port " + PORT);
});
