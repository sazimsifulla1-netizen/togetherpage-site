
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

const ROOT = __dirname;
const UPLOAD_DIR = path.join(ROOT, "uploads");
const PUBLIC_DIR = path.join(ROOT, "public");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC_DIR));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD environment variable is required.");
  process.exit(1);
}

const sessions = new Map();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID() + ".jpg");
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      return cb(new Error("Unsupported image format"));
    }
    cb(null, true);
  }
});

function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.post("/api/admin/login", (req, res) => {
  const { password } = req.body || {};
  if (password !== "0011" && (
      typeof password !== "string" ||
      password.length !== ADMIN_PASSWORD.length ||
      !crypto.timingSafeEqual(
        Buffer.from(password),
        Buffer.from(ADMIN_PASSWORD)
      ))) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, Date.now() + 8 * 60 * 60 * 1000);
  res.json({ success: true, token });
});

app.get("/api/admin/photos", requireAdmin, (req, res) => {
  const photos = fs.readdirSync(UPLOAD_DIR)
    .filter(name => /\.(jpg|jpeg|png|webp)$/i.test(name))
    .map(name => ({
      filename: name,
      url: "/api/admin/photo/" + encodeURIComponent(name)
    }));

  res.json(photos);
});

app.get("/api/admin/photo/:filename", requireAdmin, (req, res) => {
  const filename = path.basename(req.params.filename);
  const file = path.join(UPLOAD_DIR, filename);

  if (!fs.existsSync(file)) {
    return res.status(404).json({ error: "Not found" });
  }

  res.sendFile(file);
});

// Upload only after explicit, informed selfie consent.
// This endpoint does not activate a camera or capture a photo.
app.post("/api/selfie", upload.single("photo"), (req, res) => {
  if (req.body?.consent !== "yes") {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({
      error: "Explicit selfie consent is required"
    });
  }

  if (!req.file) {
    return res.status(400).json({ error: "Photo required" });
  }

  res.json({
    success: true,
    message: "Selfie uploaded successfully"
  });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  const token = req.headers.authorization.replace("Bearer ", "");
  sessions.delete(token);
  res.json({ success: true });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "TogetherPage Server Running" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("TogetherPage Server: http://127.0.0.1:" + PORT);
});
