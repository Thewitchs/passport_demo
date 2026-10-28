// server.js
// Minimal Passport (local strategy) + role-based auth demo
// Run: npm i express express-session passport passport-local bcryptjs
// Start: node server.js  → open http://localhost:3000

import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- In-memory users (demo only) -------------------------------------------
// Passwords here are bcrypt-hashed for realism. Plaintext: adminpass, teacherpass
const users = [
  {
    id: "1",
    username: "admin",
    passwordHash: bcrypt.hashSync("adminpass", 10),
    roles: ["admin"],
    name: "Ada Admin",
  },
  {
    id: "2",
    username: "teacher",
    passwordHash: bcrypt.hashSync("teacherpass", 10),
    roles: ["teacher"],
    name: "Terry Teacher",
  },
  {
    id: "3",
    username: "student",
    passwordHash: bcrypt.hashSync("studentpass", 10),
    roles: ["student"],
    name: "Sue Student",
  },
];

// --- Passport Local Strategy (username/password) ---------------------------
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = users.find((u) => u.username === username);
      if (!user) return done(null, false, { message: "Invalid credentials" });
      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return done(null, false, { message: "Invalid credentials" });
      return done(null, {
        id: user.id,
        username: user.username,
        roles: user.roles,
        name: user.name,
      });
    } catch (err) {
      return done(err);
    }
  }),
);

// --- Passport session glue -------------------------------------------------
passport.serializeUser((user, done) => {
  // Store the minimal identifier in the session
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // Hydrate full user from our in-memory store
  const user = users.find((u) => u.id === id);
  if (!user) return done(null, false);
  done(null, {
    id: user.id,
    username: user.username,
    roles: user.roles,
    name: user.name,
  });
});

// --- Middleware ------------------------------------------------------------
app.use(express.urlencoded({ extended: false })); // handle form posts
app.use(express.json()); // handle JSON posts (optional)
app.use(
  session({
    secret: "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }, // secure:true in prod with HTTPS
  }),
);
app.use(passport.initialize());
app.use(passport.session());

// --- Auth helpers ----------------------------------------------------------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, error: "Not authenticated" });
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user)
      return res.status(401).json({ ok: false, error: "Not authenticated" });
    const has = req.user.roles?.some((r) => allowed.includes(r));
    if (!has)
      return res
        .status(403)
        .json({ ok: false, error: "Forbidden: insufficient role" });
    next();
  };
}

// --- Routes: static page ---------------------------------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Auth routes -----------------------------------------------------------
app.post("/login", passport.authenticate("local"), (req, res) => {
  res.json({
    ok: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      roles: req.user.roles,
      name: req.user.name,
    },
  });
});

app.post("/logout", (req, res, next) => {
  // Passport 0.6+ logout is async
  req.logout(function (err) {
    if (err) return next(err);
    res.json({ ok: true });
  });
});

// --- Session/user info -----------------------------------------------------
app.get("/me", (req, res) => {
  if (!req.user) return res.json({ ok: true, user: null });
  res.json({ ok: true, user: req.user });
});

// --- Protected APIs --------------------------------------------------------
// Admin-only
app.get(
  "/admin/secret",
  ensureAuthenticated,
  requireRole("admin"),
  (req, res) => {
    res.json({
      ok: true,
      who: req.user.name,
      message: "Welcome, admin. Here are your admin APIs.",
    });
  },
);

// Teacher-only
app.get(
  "/teacher/secret",
  ensureAuthenticated,
  requireRole("teacher"),
  (req, res) => {
    res.json({
      ok: true,
      who: req.user.name,
      message: "Welcome, teacher. Here are your teacher APIs.",
    });
  },
);

// Example of multi-role allow-list (admin OR teacher)
app.get(
  "/shared/for-staff",
  ensureAuthenticated,
  requireRole("admin", "teacher"),
  (req, res) => {
    res.json({
      ok: true,
      who: req.user.name,
      message: "Both admins and teachers can see this.",
    });
  },
);

app.get(
  "/shared/for-student",
  ensureAuthenticated,
  requireRole("student", "teacher"),
  (req, res) => {
    res.json({
      ok: true,
      who: req.user.name,
      message: "Both students and teachers can see this.",
    });
  },
);
// --- Start server ----------------------------------------------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
