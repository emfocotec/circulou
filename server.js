require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const multer = require("multer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const { GridFSBucket } = require("mongodb");
const { Readable } = require("stream");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:"],
    },
  },
}));

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["http://localhost:3000"];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error("Origem não permitida pelo CORS"));
  },
  credentials: true,
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(mongoSanitize());

const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 100, standardHeaders: true, legacyHeaders: false, message: { message: "Muitas requisições." } });
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { message: "Muitas tentativas." } });
app.use(globalLimiter);

app.use(express.static(path.join(__dirname, "public")));

let bucket;
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB conectado");
    bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "photos" });
  })
  .catch((err) => console.error("Erro MongoDB:", err));

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5*1024*1024, files: 4 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg","image/png","image/webp"];
    allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error("Apenas imagens JPEG, PNG ou WebP."));
  },
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, match: [/^\S+@\S+\.\S+$/, "Email inválido"] },
  password: { type: String, required: true, select: false },
  skills: [{ type: String, trim: true, maxlength: 50 }],
  courses: [{ type: String, trim: true, maxlength: 80 }],
  goals: { type: String, trim: true, maxlength: 300 },
  personality: { type: String, trim: true, maxlength: 100 },
  availability: { type: String, trim: true, maxlength: 100 },
  instagram: { type: String, trim: true, maxlength: 100 },
  photoIds: [{ type: mongoose.Schema.Types.ObjectId }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  dislikes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const messageSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, index: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true, trim: true, maxlength: 1000 },
  readAt: { type: Date, default: null },
}, { timestamps: true });

const Message = mongoose.model("Message", messageSchema);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error("ERRO CRÍTICO: JWT_SECRET não definido"); process.exit(1); }

function authenticateToken(req, res, next) {
  const token = (req.headers["authorization"] || "").split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token não fornecido" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido ou expirado" });
    req.user = user;
    next();
  });
}

function getConversationId(idA, idB) {
  return [idA.toString(), idB.toString()].sort().join("_");
}

async function isMutualMatch(userIdA, userIdB) {
  const [a, b] = await Promise.all([User.findById(userIdA), User.findById(userIdB)]);
  if (!a || !b) return false;
  return a.likes.some(id => id.toString() === userIdB.toString()) &&
         b.likes.some(id => id.toString() === userIdA.toString());
}

const uploadToGridFS = (fileBuffer, filename, mimetype) =>
  new Promise((resolve, reject) => {
    const stream = bucket.openUploadStream(filename, { contentType: mimetype });
    Readable.from(fileBuffer).pipe(stream);
    stream.on("finish", () => resolve(stream.id));
    stream.on("error", reject);
  });

// ===== SOCKET.IO =====
const io = new Server(server, { cors: { origin: allowedOrigins, methods: ["GET","POST"], credentials: true } });

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Token não fornecido"));
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error("Token inválido"));
    socket.user = user;
    next();
  });
});

io.on("connection", (socket) => {
  const userId = socket.user.id;
  socket.join(`user:${userId}`);

  socket.on("join_conversation", ({ otherUserId }) => {
    socket.join(getConversationId(userId, otherUserId));
  });

  socket.on("send_message", async ({ receiverId, text }) => {
    try {
      if (!receiverId || !text || !text.trim() || text.trim().length > 1000) return;
      const matched = await isMutualMatch(userId, receiverId);
      if (!matched) { socket.emit("error_msg", { message: "Sem match para conversar." }); return; }

      const conversationId = getConversationId(userId, receiverId);
      const message = await Message.create({ conversationId, senderId: userId, receiverId, text: text.trim() });
      const sender = await User.findById(userId).select("name photoIds");

      const payload = {
        _id: message._id,
        conversationId,
        senderId: userId,
        senderName: sender.name,
        senderPhoto: sender.photoIds.length > 0 ? `/photo/${sender.photoIds[0]}` : null,
        receiverId,
        text: message.text,
        createdAt: message.createdAt,
      };

      io.to(conversationId).emit("new_message", payload);
      io.to(`user:${receiverId}`).emit("message_notification", { from: userId, fromName: sender.name, text: message.text });
    } catch (err) { console.error("Erro socket send_message:", err.message); }
  });
});

// ===== ROTAS HTTP =====

app.get("/photo/:id", async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const files = await bucket.find({ _id: fileId }).toArray();
    if (!files.length) return res.status(404).json({ message: "Foto não encontrada" });
    res.set("Content-Type", files[0].contentType || "image/jpeg");
    res.set("Cache-Control", "public, max-age=86400");
    bucket.openDownloadStream(fileId).pipe(res);
  } catch { res.status(400).json({ message: "ID inválido" }); }
});

app.post("/register", authLimiter, upload.array("photos", 4), async (req, res) => {
  try {
    const { name, email, password, skills, courses, goals, personality, availability, instagram } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Nome, email e senha são obrigatórios" });
    if (password.length < 8) return res.status(400).json({ message: "Senha deve ter ao menos 8 caracteres" });
    if (await User.findOne({ email: email.toLowerCase().trim() })) return res.status(400).json({ message: "Email já cadastrado" });

    const hashedPassword = await bcrypt.hash(password, 12);
    let photoIds = [];
    for (const file of (req.files || [])) photoIds.push(await uploadToGridFS(file.buffer, `${Date.now()}-${file.originalname}`, file.mimetype));

    const user = new User({
      name: name.trim(), email: email.toLowerCase().trim(), password: hashedPassword,
      skills: skills ? skills.split(",").map(s=>s.trim()).filter(Boolean).slice(0,10) : [],
      courses: courses ? courses.split(",").map(c=>c.trim()).filter(Boolean).slice(0,10) : [],
      goals: goals?.trim(), personality: personality?.trim(), availability: availability?.trim(),
      instagram: instagram?.trim(), photoIds,
    });

    await user.save();
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ message: "Usuário registrado com sucesso", userId: user._id, token });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao registrar usuário" }); }
});

app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email e senha são obrigatórios" });
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select("+password");
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: "Credenciais inválidas" });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login bem-sucedido", userId: user._id, token });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao fazer login" }); }
});

app.get("/users/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.id !== req.params.id) return res.status(403).json({ message: "Acesso negado" });
    const currentUser = await User.findById(req.params.id);
    if (!currentUser) return res.status(404).json({ message: "Usuário não encontrado" });
    const users = await User.find({ _id: { $ne: currentUser._id, $nin: [...currentUser.likes, ...currentUser.dislikes] } }).select("-password -likes -dislikes");
    res.json(users.map(u => ({ _id: u._id, name: u.name, courses: u.courses, goals: u.goals, skills: u.skills, personality: u.personality, availability: u.availability, photos: u.photoIds.map(id=>`/photo/${id}`) })));
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao buscar usuários" }); }
});

app.get("/profile/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.id !== req.params.id) return res.status(403).json({ message: "Acesso negado" });
    const user = await User.findById(req.params.id).select("-password -likes -dislikes");
    if (!user) return res.status(404).json({ message: "Usuário não encontrado" });
    const obj = user.toObject();
    obj.photos = user.photoIds.map(id=>`/photo/${id}`);
    delete obj.photoIds;
    res.json(obj);
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao buscar perfil" }); }
});

app.put("/profile/:id", authenticateToken, upload.array("photos", 4), async (req, res) => {
  try {
    if (req.user.id !== req.params.id) return res.status(403).json({ message: "Acesso negado" });
    const { name, email, skills, courses, goals, personality, availability, instagram } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "Usuário não encontrado" });
    if (email && email.toLowerCase().trim() !== user.email) {
      if (await User.findOne({ email: email.toLowerCase().trim() })) return res.status(400).json({ message: "Email já em uso" });
      user.email = email.toLowerCase().trim();
    }
    if (name) user.name = name.trim();
    if (skills !== undefined) user.skills = skills.split(",").map(s=>s.trim()).filter(Boolean).slice(0,10);
    if (courses !== undefined) user.courses = courses.split(",").map(c=>c.trim()).filter(Boolean).slice(0,10);
    if (goals !== undefined) user.goals = goals.trim();
    if (personality !== undefined) user.personality = personality.trim();
    if (availability !== undefined) user.availability = availability.trim();
    if (instagram !== undefined) user.instagram = instagram.trim();
    if (req.files && req.files.length > 0) {
      for (const oldId of user.photoIds) try { await bucket.delete(new mongoose.Types.ObjectId(oldId)); } catch(_){}
      user.photoIds = [];
      for (const file of req.files) user.photoIds.push(await uploadToGridFS(file.buffer, `${Date.now()}-${file.originalname}`, file.mimetype));
    }
    await user.save();
    res.json({ message: "Perfil atualizado com sucesso" });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao atualizar perfil" }); }
});

app.post("/like", authenticateToken, async (req, res) => {
  try {
    const { userId, likedUserId } = req.body;
    if (req.user.id !== userId) return res.status(403).json({ message: "Acesso negado" });
    if (!likedUserId || userId === likedUserId) return res.status(400).json({ message: "Requisição inválida" });
    const [user, likedUser] = await Promise.all([User.findById(userId), User.findById(likedUserId)]);
    if (!user || !likedUser) return res.status(404).json({ message: "Usuário não encontrado" });
    if (!user.likes.includes(likedUserId)) {
      user.likes.push(likedUserId);
      user.dislikes = user.dislikes.filter(id=>id.toString()!==likedUserId);
      await user.save();
    }
    const isMatch = likedUser.likes.some(id=>id.toString()===userId);
    res.json({ message: "Usuário curtido", match: isMatch, likedUserInstagram: isMatch ? likedUser.instagram : null });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao curtir usuário" }); }
});

app.post("/dislike", authenticateToken, async (req, res) => {
  try {
    const { userId, dislikedUserId } = req.body;
    if (req.user.id !== userId) return res.status(403).json({ message: "Acesso negado" });
    if (!dislikedUserId) return res.status(400).json({ message: "dislikedUserId é obrigatório" });
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "Usuário não encontrado" });
    if (!user.dislikes.includes(dislikedUserId)) {
      user.dislikes.push(dislikedUserId);
      user.likes = user.likes.filter(id=>id.toString()!==dislikedUserId);
      await user.save();
    }
    res.json({ message: "Usuário descurtido" });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao descurtir usuário" }); }
});

// Lista matches para o chat
app.get("/matches/:userId", authenticateToken, async (req, res) => {
  try {
    if (req.user.id !== req.params.userId) return res.status(403).json({ message: "Acesso negado" });
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "Usuário não encontrado" });

    const theyLikedMe = await User.find({ likes: user._id }).select("_id");
    const theyLikedMeIds = theyLikedMe.map(u=>u._id.toString());
    const matchIds = user.likes.map(id=>id.toString()).filter(id=>theyLikedMeIds.includes(id));
    if (!matchIds.length) return res.json([]);

    const matchUsers = await User.find({ _id: { $in: matchIds } }).select("name photoIds");
    const result = await Promise.all(matchUsers.map(async m => {
      const cid = getConversationId(req.params.userId, m._id.toString());
      const lastMsg = await Message.findOne({ conversationId: cid }).sort({ createdAt: -1 }).select("text createdAt");
      const unread = await Message.countDocuments({ conversationId: cid, receiverId: req.params.userId, readAt: null });
      return { _id: m._id, name: m.name, photo: m.photoIds.length > 0 ? `/photo/${m.photoIds[0]}` : null, lastMessage: lastMsg?.text || null, lastMessageAt: lastMsg?.createdAt || null, unreadCount: unread };
    }));

    result.sort((a,b) => (!a.lastMessageAt ? 1 : !b.lastMessageAt ? -1 : new Date(b.lastMessageAt)-new Date(a.lastMessageAt)));
    res.json(result);
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao buscar matches" }); }
});

// Mensagens de uma conversa
app.get("/messages/:otherUserId", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { otherUserId } = req.params;
    if (!(await isMutualMatch(userId, otherUserId))) return res.status(403).json({ message: "Sem match para conversar." });
    const cid = getConversationId(userId, otherUserId);
    const messages = await Message.find({ conversationId: cid }).sort({ createdAt: 1 }).select("senderId text createdAt readAt");
    await Message.updateMany({ conversationId: cid, receiverId: userId, readAt: null }, { readAt: new Date() });
    res.json(messages);
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao buscar mensagens" }); }
});

// Deletar conversa (para os dois)
app.delete("/conversation/:otherUserId", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { otherUserId } = req.params;
    if (!(await isMutualMatch(userId, otherUserId))) return res.status(403).json({ message: "Conversa não encontrada." });
    const cid = getConversationId(userId, otherUserId);
    await Message.deleteMany({ conversationId: cid });
    io.to(`user:${otherUserId}`).emit("conversation_deleted", { by: userId });
    res.json({ message: "Conversa deletada para os dois." });
  } catch (err) { console.error(err.message); res.status(500).json({ message: "Erro ao deletar conversa" }); }
});

app.use((err, req, res, next) => {
  if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ message: "Arquivo muito grande. Máximo 5MB." });
  if (err.message) return res.status(400).json({ message: err.message });
  res.status(500).json({ message: "Erro interno do servidor" });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));