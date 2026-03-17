
require("dotenv").config();

const cors = require("cors");
const express = require("express");
const helmet = require("helmet");
const http = require("http");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");
const bcrypt = require("bcryptjs");

const {
  USER_WELCOME_COINS,
  createSeedState,
  normalizeState,
  normalizePhone,
  parseAmount,
  makeId,
  nowIso,
  avatarById,
} = require("./state");

const PORT = Number(process.env.PORT || 4000);
const DATABASE_URL = process.env.DATABASE_URL || "";
const DATABASE_SSL = process.env.DATABASE_SSL === "true";
const JWT_SECRET = process.env.JWT_SECRET || "change-me-user-jwt";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change-me-admin-jwt";
const DEMO_MODE = process.env.DEMO_MODE !== "false";
const DEMO_FIXED_OTP = String(process.env.DEMO_FIXED_OTP || "123456");

const VALID_CALL_STATES = new Set([
  "calling",
  "ringing",
  "connecting",
  "connected",
  "ended",
  "missed",
  "failed",
]);
const ACTIVE_CALL_STATES = new Set(["calling", "ringing", "connecting", "connected"]);
const TERMINAL_CALL_STATES = new Set(["ended", "missed", "failed"]);
const VALID_AVAILABILITY = new Set(["online", "offline", "busy"]);

if (!DATABASE_URL) {
  console.error("DATABASE_URL is required for backend startup.");
  process.exit(1);
}

const allowedOrigins = [
  process.env.CLIENT_USER_APP_URL,
  process.env.CLIENT_HOST_APP_URL,
  process.env.CLIENT_ADMIN_URL,
].filter(Boolean);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_SSL ? { rejectUnauthorized: false } : false,
});

let state = createSeedState();
let persistQueue = Promise.resolve();

const socketsByParticipantId = new Map();
const callTimers = new Map();

function toMillis(value) {
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function sendError(res, status, message) {
  return res.status(status).json({ message });
}

function parsePagination(req, fallbackLimit = 20) {
  const limitRaw = Number(req.query.limit || fallbackLimit);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 50)) : fallbackLimit;
  const cursor = req.query.cursor ? String(req.query.cursor) : null;
  return { limit, cursor };
}

function paginateOffset(items, cursor, limit) {
  const start = Number.isFinite(Number(cursor)) ? Math.max(Number(cursor), 0) : 0;
  return {
    items: items.slice(start, start + limit),
    nextCursor: start + limit < items.length ? String(start + limit) : null,
  };
}

function paginateMessages(messagesAsc, cursor, limit) {
  if (!cursor) {
    const end = messagesAsc.length;
    const start = Math.max(0, end - limit);
    return { items: messagesAsc.slice(start, end), nextCursor: start > 0 ? String(start) : null };
  }
  const end = Math.max(parseAmount(cursor, 0), 0);
  const start = Math.max(0, end - limit);
  return { items: messagesAsc.slice(start, end), nextCursor: start > 0 ? String(start) : null };
}

function signUserToken(userId, role) {
  return jwt.sign({ sub: userId, role, type: "app" }, JWT_SECRET, { expiresIn: "7d" });
}

function signAdminToken(adminId, role) {
  return jwt.sign({ sub: adminId, role, type: "admin" }, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}

function getAuthorizationToken(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return "";
  }
  return header.slice(7).trim();
}

function requireAdmin(req, res, next) {
  try {
    const token = getAuthorizationToken(req);
    if (!token) {
      return sendError(res, 401, "Missing admin token.");
    }
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    const admin = state.admins.find((entry) => entry.id === payload.sub && entry.isActive);
    if (!admin) {
      return sendError(res, 401, "Admin session invalid.");
    }
    req.admin = admin;
    return next();
  } catch {
    return sendError(res, 401, "Admin token invalid.");
  }
}

function requireAnyAdminRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.admin.role)) {
      return sendError(res, 403, "Permission denied.");
    }
    return next();
  };
}

function findUserById(userId) {
  return state.users.find((entry) => entry.id === userId) || null;
}

function findHostById(hostId) {
  return state.hosts.find((entry) => entry.id === hostId) || null;
}

function findUserByPhone(phone) {
  return state.users.find((entry) => entry.phone === phone) || null;
}

function findHostByPhone(phone) {
  return state.hosts.find((entry) => entry.phone === phone) || null;
}

function getWallet(ownerType, ownerId) {
  return state.wallets.find((entry) => entry.ownerType === ownerType && entry.ownerId === ownerId) || null;
}

function ensureWallet(ownerType, ownerId) {
  let wallet = getWallet(ownerType, ownerId);
  if (!wallet) {
    wallet = {
      ownerType,
      ownerId,
      balance: ownerType === "user" ? USER_WELCOME_COINS : 0,
      updatedAt: nowIso(),
    };
    state.wallets.push(wallet);
    if (ownerType === "user") {
      state.walletTransactions.unshift({
        id: makeId("tx"),
        ownerType: "user",
        ownerId,
        amount: USER_WELCOME_COINS,
        balanceAfter: USER_WELCOME_COINS,
        type: "refund",
        description: "Welcome balance credit",
        createdAt: nowIso(),
      });
    }
  }
  return wallet;
}

function applyWalletDelta(ownerType, ownerId, type, amount, description, relatedEntityId) {
  const wallet = ensureWallet(ownerType, ownerId);
  wallet.balance = parseAmount(wallet.balance, 0) + parseAmount(amount, 0);
  wallet.updatedAt = nowIso();
  const transaction = {
    id: makeId("tx"),
    ownerType,
    ownerId,
    amount: parseAmount(amount, 0),
    balanceAfter: wallet.balance,
    type,
    description,
    relatedEntityId: relatedEntityId || undefined,
    createdAt: nowIso(),
  };
  state.walletTransactions.unshift(transaction);
  return { wallet, transaction };
}

function appendAudit(admin, action, payload = {}) {
  state.adminAuditLogs.unshift({
    id: makeId("audit"),
    adminId: admin.id,
    adminEmail: admin.email,
    adminRole: admin.role,
    action,
    payload,
    createdAt: nowIso(),
  });
}

function appendNotification(targetType, targetId, kind, payload = {}) {
  state.notifications.unshift({
    id: makeId("notify"),
    targetType,
    targetId,
    kind,
    payload,
    createdAt: nowIso(),
    readAt: null,
  });
}

function isBlocked(userId, hostId) {
  return state.blocks.some((entry) => entry.userId === userId && entry.hostId === hostId);
}

function isHostBlockingUser(hostId, userId) {
  return state.hostBlocks.some((entry) => entry.hostId === hostId && entry.userId === userId);
}

function hasConversationMessages(conversationId) {
  return state.messages.some((entry) => entry.conversationId === conversationId);
}

function getConversationById(conversationId) {
  return state.conversations.find((entry) => entry.id === conversationId) || null;
}

function getConversationMessages(conversationId) {
  return state.messages
    .filter((entry) => entry.conversationId === conversationId)
    .sort((left, right) => toMillis(left.createdAt) - toMillis(right.createdAt));
}

function serializeHost(host) {
  return {
    id: host.id,
    name: host.name,
    age: host.age,
    languages: host.languages,
    interests: host.interests,
    isOnline: host.availability === "online",
    availability: host.availability,
    verified: host.verified !== false,
    about: host.about,
    avatarUrl: host.avatarUrl || avatarById(host.id),
    status: host.status || "active",
  };
}

function serializeCall(call) {
  const user = findUserById(call.userId);
  const host = findHostById(call.hostId);
  return {
    id: call.id,
    userId: call.userId,
    userName: user?.displayName || `User ${call.userId.slice(-4)}`,
    userAvatarUrl: user?.avatarUrl || avatarById(call.userId),
    hostId: call.hostId,
    hostName: host?.name || "Host",
    hostAvatarUrl: host?.avatarUrl || avatarById(call.hostId),
    initiatedByRole: call.initiatedByRole === "host" ? "host" : "user",
    state: call.state,
    startedAt: call.startedAt,
    connectedAt: call.connectedAt || null,
    endedAt: call.endedAt || null,
    durationSec: call.durationSec || 0,
  };
}

function buildConversationPreview(conversation, roleView) {
  const user = findUserById(conversation.userId);
  const host = findHostById(conversation.hostId);
  const hostName = host?.name || "Host";
  const userName = user?.displayName || "User";
  const hostAvatarUrl = host?.avatarUrl || avatarById(conversation.hostId);
  const userAvatarUrl = user?.avatarUrl || avatarById(conversation.userId);
  const counterpartIsHost = roleView === "user";
  return {
    id: conversation.id,
    hostId: conversation.hostId,
    hostName,
    hostAvatarUrl,
    hostOnline: host?.availability === "online",
    hostVerified: host?.verified !== false,
    userId: conversation.userId,
    userName,
    userAvatarUrl,
    counterpartId: counterpartIsHost ? conversation.hostId : conversation.userId,
    counterpartName: counterpartIsHost ? hostName : userName,
    counterpartAvatarUrl: counterpartIsHost ? hostAvatarUrl : userAvatarUrl,
    counterpartOnline: counterpartIsHost ? host?.availability === "online" : isParticipantConnected(conversation.userId),
    counterpartVerified: counterpartIsHost ? host?.verified !== false : true,
    roleView,
    lastMessage: conversation.lastMessage,
    lastMessageAt: conversation.lastMessageAt,
    unreadCount: roleView === "user" ? conversation.userUnread : conversation.hostUnread,
  };
}

function ensureConversation(userId, hostId) {
  let conversation = state.conversations.find((entry) => entry.userId === userId && entry.hostId === hostId);
  if (!conversation) {
    conversation = {
      id: makeId("convo"),
      userId,
      hostId,
      createdAt: nowIso(),
      lastMessage: "Conversation started",
      lastMessageAt: nowIso(),
      userUnread: 0,
      hostUnread: 0,
    };
    state.conversations.push(conversation);
  }
  return conversation;
}
function createMessage({ conversation, senderType, senderId, text, kind = "text", gift = null }) {
  const message = {
    id: makeId("msg"),
    conversationId: conversation.id,
    senderType,
    senderId,
    kind,
    text: String(text || ""),
    gift: gift || null,
    deliveryState: "delivered",
    createdAt: nowIso(),
    readBy: [senderId],
  };
  state.messages.push(message);
  conversation.lastMessage =
    kind === "gift" && gift ? `${senderType === "user" ? "Gift sent" : "Gift received"}: ${gift.name}` : message.text;
  conversation.lastMessageAt = message.createdAt;
  if (senderType === "user") {
    conversation.userUnread = 0;
    conversation.hostUnread += 1;
  } else {
    conversation.hostUnread = 0;
    conversation.userUnread += 1;
  }
  return message;
}

function markConversationRead(conversation, role) {
  const participantId = role === "host" ? conversation.hostId : conversation.userId;
  for (const message of state.messages) {
    if (message.conversationId !== conversation.id) {
      continue;
    }
    if (!message.readBy.includes(participantId)) {
      message.readBy.push(participantId);
    }
    if (message.readBy.includes(conversation.userId) && message.readBy.includes(conversation.hostId)) {
      message.deliveryState = "read";
    }
  }
  if (role === "host") {
    conversation.hostUnread = 0;
  } else {
    conversation.userUnread = 0;
  }
}

function isParticipantConnected(participantId) {
  return Boolean(socketsByParticipantId.get(participantId)?.size);
}

function emitEventToSocket(socket, event) {
  if (!socket || socket.readyState !== 1) {
    return;
  }
  try {
    socket.send(JSON.stringify(event));
  } catch {
    // ignore noisy transport errors
  }
}

function emitToParticipant(participantId, event) {
  const sockets = socketsByParticipantId.get(participantId);
  if (!sockets) {
    return;
  }
  for (const socket of sockets) {
    emitEventToSocket(socket, event);
  }
}

function emitToParticipants(participantIds, event) {
  const seen = new Set();
  for (const participantId of participantIds) {
    if (!participantId || seen.has(participantId)) {
      continue;
    }
    seen.add(participantId);
    emitToParticipant(participantId, event);
  }
}

function emitConversationUpdates(conversation) {
  emitToParticipant(conversation.userId, {
    type: "conversation.updated",
    payload: buildConversationPreview(conversation, "user"),
  });
  emitToParticipant(conversation.hostId, {
    type: "conversation.updated",
    payload: buildConversationPreview(conversation, "host"),
  });
}

function emitWalletEvents(wallet, transaction) {
  emitToParticipant(wallet.ownerId, { type: "wallet.updated", payload: wallet });
  if (transaction) {
    emitToParticipant(wallet.ownerId, { type: "wallet.transaction", payload: transaction });
  }
}

function clearCallTimers(callId) {
  const timer = callTimers.get(callId);
  if (!timer) {
    return;
  }
  for (const timeoutId of timer.timeouts) {
    clearTimeout(timeoutId);
  }
  if (timer.intervalId) {
    clearInterval(timer.intervalId);
  }
  callTimers.delete(callId);
}

function ensureCallTimer(callId) {
  if (!callTimers.has(callId)) {
    callTimers.set(callId, { timeouts: [], intervalId: null });
  }
  return callTimers.get(callId);
}

function emitCallUpdate(call) {
  emitToParticipants([call.userId, call.hostId], { type: "call.updated", payload: serializeCall(call) });
}

function startCallDurationTicker(call) {
  const timer = ensureCallTimer(call.id);
  if (timer.intervalId) {
    clearInterval(timer.intervalId);
  }
  timer.intervalId = setInterval(() => {
    const current = state.calls.find((entry) => entry.id === call.id);
    if (!current || current.state !== "connected") {
      clearCallTimers(call.id);
      return;
    }
    const elapsed = Math.max(Math.floor((Date.now() - toMillis(current.connectedAt || current.startedAt)) / 1000), 0);
    if (elapsed !== current.durationSec) {
      current.durationSec = elapsed;
      schedulePersist({ eventType: "call.tick", payload: { callId: current.id, durationSec: elapsed } });
      emitCallUpdate(current);
    }
  }, 1000);
}

function transitionCallState(call, nextState) {
  if (!VALID_CALL_STATES.has(nextState) || call.state === nextState) {
    return false;
  }
  if (TERMINAL_CALL_STATES.has(call.state) && !TERMINAL_CALL_STATES.has(nextState)) {
    return false;
  }
  call.state = nextState;
  if (nextState === "connected" && !call.connectedAt) {
    call.connectedAt = nowIso();
    startCallDurationTicker(call);
  }
  if (TERMINAL_CALL_STATES.has(nextState)) {
    call.endedAt = call.endedAt || nowIso();
    if (call.connectedAt) {
      call.durationSec = Math.max(call.durationSec, Math.floor((toMillis(call.endedAt) - toMillis(call.connectedAt)) / 1000));
    }
    clearCallTimers(call.id);
  }
  return true;
}

function scheduleCallLifecycle(call) {
  const timer = ensureCallTimer(call.id);
  const steps = [
    { waitMs: 900, expected: "calling", next: "ringing" },
    { waitMs: 1800, expected: "ringing", next: "connecting" },
    { waitMs: 2800, expected: "connecting", next: "connected" },
  ];
  for (const step of steps) {
    const timeoutId = setTimeout(() => {
      const current = state.calls.find((entry) => entry.id === call.id);
      if (!current || current.state !== step.expected) {
        return;
      }
      if (transitionCallState(current, step.next)) {
        schedulePersist({ eventType: "call.state.changed", payload: { callId: current.id, state: current.state } });
        emitCallUpdate(current);
      }
    }, step.waitMs);
    timer.timeouts.push(timeoutId);
  }
}

function resolveCallParticipants(body) {
  if (body?.requesterId && body?.counterpartId) {
    const requesterRole = body.requesterRole === "host" ? "host" : "user";
    return requesterRole === "host"
      ? { userId: String(body.counterpartId), hostId: String(body.requesterId), initiatedByRole: "host" }
      : { userId: String(body.requesterId), hostId: String(body.counterpartId), initiatedByRole: "user" };
  }
  if (body?.userId && body?.hostId) {
    return {
      userId: String(body.userId),
      hostId: String(body.hostId),
      initiatedByRole: body.requesterRole === "host" ? "host" : "user",
    };
  }
  return null;
}

function getSeedOtpForPhone(phone) {
  if (!DEMO_MODE) {
    return "";
  }
  const demoPhone = ["9000000001", "9000000002", "8000000001", "8000000002"];
  return demoPhone.includes(phone) ? DEMO_FIXED_OTP : "";
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_state (
      id SMALLINT PRIMARY KEY DEFAULT 1,
      state JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_events (
      id BIGSERIAL PRIMARY KEY,
      event_type TEXT NOT NULL,
      actor_id TEXT,
      actor_role TEXT,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function loadState() {
  await ensureSchema();
  const { rows } = await pool.query("SELECT state FROM platform_state WHERE id = 1 LIMIT 1");
  if (rows.length === 0) {
    const seeded = createSeedState();
    state = normalizeState(seeded);
    await pool.query(
      "INSERT INTO platform_state (id, state, updated_at) VALUES (1, $1::jsonb, NOW())",
      [JSON.stringify(state)]
    );
    return;
  }
  state = normalizeState(rows[0].state);
}

function schedulePersist(meta = {}) {
  persistQueue = persistQueue
    .then(async () => {
      await pool.query("UPDATE platform_state SET state = $1::jsonb, updated_at = NOW() WHERE id = 1", [JSON.stringify(state)]);
      if (meta.eventType) {
        await pool.query(
          "INSERT INTO platform_events (event_type, actor_id, actor_role, payload) VALUES ($1, $2, $3, $4::jsonb)",
          [
            meta.eventType,
            meta.actorId || null,
            meta.actorRole || null,
            JSON.stringify(meta.payload || {}),
          ]
        );
      }
    })
    .catch((error) => {
      console.error("Persist error:", error.message);
    });
  return persistQueue;
}

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error("Origin not allowed"));
  },
}));
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

app.get("/health", asyncRoute(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({
    ok: true,
    serverTime: nowIso(),
    users: state.users.length,
    hosts: state.hosts.length,
    conversations: state.conversations.length,
    calls: state.calls.length,
  });
}));
const ADMIN_ROLES = new Set(["super_admin", "support_admin", "finance_admin", "moderation_admin"]);
const FINANCE_ROLES = ["super_admin", "finance_admin"];
const MODERATION_ROLES = ["super_admin", "moderation_admin", "support_admin"];

function ensureUserById(userId) {
  const user = findUserById(userId);
  if (!user || user.status !== "active") {
    return null;
  }
  ensureWallet("user", user.id);
  return user;
}

function ensureHostById(hostId) {
  const host = findHostById(hostId);
  if (!host || host.status !== "active") {
    return null;
  }
  ensureWallet("host", host.id);
  return host;
}

function getOrCreateUserByPhone(phone) {
  let user = findUserByPhone(phone);
  if (!user) {
    user = {
      id: makeId("user"),
      phone,
      displayName: `User ${phone.slice(-4)}`,
      avatarUrl: avatarById(phone),
      role: "user",
      status: "active",
      createdAt: nowIso(),
    };
    state.users.push(user);
  }
  ensureWallet("user", user.id);
  return user;
}

function getOrCreateHostByPhone(phone) {
  let host = findHostByPhone(phone);
  if (!host) {
    host = {
      id: makeId("host"),
      phone,
      name: `Host ${phone.slice(-4)}`,
      age: 27,
      languages: ["English"],
      interests: ["Support"],
      availability: "offline",
      isOnline: false,
      verified: false,
      about: "Supportive host profile.",
      avatarUrl: avatarById(phone),
      role: "host",
      status: "active",
      createdAt: nowIso(),
    };
    state.hosts.push(host);
  }
  ensureWallet("host", host.id);
  return host;
}

function activeUsersCount() {
  return state.users.filter((entry) => entry.status === "active").length;
}

function activeHostsCount() {
  return state.hosts.filter((entry) => entry.status === "active").length;
}

function hostConversationIds(hostId) {
  return new Set(state.conversations.filter((entry) => entry.hostId === hostId).map((entry) => entry.id));
}

function userConversationIds(userId) {
  return new Set(state.conversations.filter((entry) => entry.userId === userId).map((entry) => entry.id));
}

function getGiftById(giftId) {
  return state.gifts.find((gift) => gift.id === giftId && gift.isEnabled !== false) || null;
}

function mapTopupIntent(intent) {
  return {
    intentId: intent.intentId,
    status: intent.status,
    amountInr: intent.amountInr,
    coins: intent.coins,
    createdAt: intent.createdAt,
  };
}

function mapUserSession(user) {
  return {
    id: user.id,
    phone: user.phone,
    displayName: user.displayName,
    role: "user",
    avatarUrl: user.avatarUrl || avatarById(user.id),
  };
}

function mapHostSession(host) {
  return {
    id: host.id,
    phone: host.phone,
    displayName: host.name,
    role: "host",
    avatarUrl: host.avatarUrl || avatarById(host.id),
  };
}

function serializeWithdrawal(withdrawal) {
  const host = findHostById(withdrawal.hostId);
  return {
    ...withdrawal,
    hostName: host?.name || "Host",
    hostPhone: host?.phone || "",
  };
}

function adminCanAccessRole(adminRole, allowedRoles) {
  return allowedRoles.includes(adminRole);
}

app.post("/auth/request-otp", asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  const role = req.body?.role === "host" ? "host" : "user";

  if (phone.length < 8) {
    return sendError(res, 400, "Please enter a valid phone number.");
  }

  const seededOtp = getSeedOtpForPhone(phone);
  const otp = seededOtp || String(Math.floor(100000 + Math.random() * 900000));

  const otpSession = {
    sessionId: makeId("otp"),
    phone,
    otp,
    role,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    createdAt: nowIso(),
  };

  state.otpSessions = state.otpSessions
    .filter((entry) => toMillis(entry.expiresAt) > Date.now())
    .slice(0, 300);
  state.otpSessions.unshift(otpSession);

  await schedulePersist({
    eventType: "auth.otp.requested",
    actorRole: role,
    actorId: phone,
    payload: { sessionId: otpSession.sessionId, role },
  });

  return res.json({
    sessionId: otpSession.sessionId,
    phone: otpSession.phone,
    otp: otpSession.otp,
    expiresAt: otpSession.expiresAt,
    role,
  });
}));

app.post("/auth/verify-otp", asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  const otp = String(req.body?.otp || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const role = req.body?.role === "host" ? "host" : "user";

  if (!phone || !otp || !sessionId) {
    return sendError(res, 400, "Phone, OTP, and session are required.");
  }

  const otpSession = state.otpSessions.find(
    (entry) => entry.sessionId === sessionId && entry.phone === phone
  );

  if (!otpSession) {
    return sendError(res, 400, "OTP session not found or expired.");
  }
  if (toMillis(otpSession.expiresAt) < Date.now()) {
    state.otpSessions = state.otpSessions.filter((entry) => entry.sessionId !== sessionId);
    await schedulePersist({ eventType: "auth.otp.expired", actorRole: role, actorId: phone });
    return sendError(res, 400, "OTP expired. Please request a new code.");
  }
  if (otpSession.role !== role) {
    return sendError(res, 400, "OTP role mismatch. Please request OTP again.");
  }
  if (otpSession.otp !== otp) {
    return sendError(res, 400, "Invalid OTP.");
  }

  let sessionUser;
  let wallet;

  if (role === "host") {
    const host = getOrCreateHostByPhone(phone);
    sessionUser = mapHostSession(host);
    wallet = ensureWallet("host", host.id);
  } else {
    const user = getOrCreateUserByPhone(phone);
    sessionUser = mapUserSession(user);
    wallet = ensureWallet("user", user.id);
  }

  state.otpSessions = state.otpSessions.filter((entry) => entry.sessionId !== sessionId);

  const token = signUserToken(sessionUser.id, role);

  await schedulePersist({
    eventType: "auth.login.success",
    actorRole: role,
    actorId: sessionUser.id,
    payload: { role },
  });

  return res.json({
    token,
    user: sessionUser,
    role,
    wallet,
  });
}));

app.get("/hosts", asyncRoute(async (req, res) => {
  const userId = String(req.query.userId || "");
  const user = ensureUserById(userId);
  if (!user) {
    return sendError(res, 404, "User not found.");
  }

  const hosts = state.hosts
    .filter((host) => host.status === "active")
    .filter((host) => !isBlocked(user.id, host.id) && !isHostBlockingUser(host.id, user.id))
    .map((host) => serializeHost(host));

  return res.json(hosts);
}));

app.get("/hosts/:hostId", asyncRoute(async (req, res) => {
  const host = findHostById(req.params.hostId);
  if (!host || host.status !== "active") {
    return sendError(res, 404, "Host not found.");
  }

  return res.json(serializeHost(host));
}));

app.post("/conversations/start", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const hostId = String(req.body?.hostId || "");
  const user = ensureUserById(userId);
  const host = ensureHostById(hostId);

  if (!user || !host) {
    return sendError(res, 404, "User or host not found.");
  }
  if (isBlocked(userId, hostId) || isHostBlockingUser(hostId, userId)) {
    return sendError(res, 403, "Conversation unavailable due to safety settings.");
  }

  const conversation = ensureConversation(userId, hostId);
  await schedulePersist({
    eventType: "conversation.started",
    actorRole: "user",
    actorId: userId,
    payload: { conversationId: conversation.id, hostId },
  });

  return res.json(buildConversationPreview(conversation, "user"));
}));

app.get("/conversations", asyncRoute(async (req, res) => {
  const userId = String(req.query.userId || "");
  const user = ensureUserById(userId);
  if (!user) {
    return sendError(res, 404, "User not found.");
  }

  const { limit, cursor } = parsePagination(req, 30);
  const items = state.conversations
    .filter((conversation) => conversation.userId === userId)
    .filter((conversation) => hasConversationMessages(conversation.id))
    .filter((conversation) => !isBlocked(userId, conversation.hostId) && !isHostBlockingUser(conversation.hostId, userId))
    .sort((left, right) => toMillis(right.lastMessageAt) - toMillis(left.lastMessageAt))
    .map((conversation) => buildConversationPreview(conversation, "user"));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.get("/conversations/:conversationId/messages", asyncRoute(async (req, res) => {
  const conversationId = String(req.params.conversationId || "");
  const userId = String(req.query.userId || "");
  const conversation = getConversationById(conversationId);

  if (!conversation || conversation.userId !== userId) {
    return sendError(res, 404, "Conversation not found.");
  }

  const { limit, cursor } = parsePagination(req, 40);
  const messages = getConversationMessages(conversationId);
  return res.json(paginateMessages(messages, cursor, limit));
}));

app.post("/conversations/:conversationId/messages", asyncRoute(async (req, res) => {
  const conversation = getConversationById(req.params.conversationId);
  if (!conversation) {
    return sendError(res, 404, "Conversation not found.");
  }

  const senderId = String(req.body?.senderId || "");
  const senderType = req.body?.senderType === "host" ? "host" : "user";
  const text = String(req.body?.text || "").trim();

  if (!text) {
    return sendError(res, 400, "Message text cannot be empty.");
  }
  if (senderType !== "user" || senderId !== conversation.userId) {
    return sendError(res, 403, "Invalid sender for this endpoint.");
  }
  if (isBlocked(conversation.userId, conversation.hostId) || isHostBlockingUser(conversation.hostId, conversation.userId)) {
    return sendError(res, 403, "Conversation unavailable due to safety settings.");
  }

  const message = createMessage({
    conversation,
    senderType: "user",
    senderId,
    text,
    kind: "text",
  });

  await schedulePersist({
    eventType: "message.created",
    actorRole: "user",
    actorId: senderId,
    payload: { conversationId: conversation.id, messageId: message.id },
  });

  emitToParticipants([conversation.userId, conversation.hostId], {
    type: "message.created",
    payload: message,
  });
  emitConversationUpdates(conversation);

  return res.json(message);
}));

app.post("/conversations/:conversationId/read", asyncRoute(async (req, res) => {
  const conversation = getConversationById(req.params.conversationId);
  const userId = String(req.body?.userId || "");

  if (!conversation || conversation.userId !== userId) {
    return sendError(res, 404, "Conversation not found.");
  }

  markConversationRead(conversation, "user");
  await schedulePersist({
    eventType: "conversation.read",
    actorRole: "user",
    actorId: userId,
    payload: { conversationId: conversation.id },
  });

  emitConversationUpdates(conversation);
  return res.json({ ok: true });
}));
app.get("/host/dashboard", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const hostConversations = state.conversations.filter((conversation) => conversation.hostId === hostId);
  const activeConversations = hostConversations.filter((conversation) => hasConversationMessages(conversation.id)).length;
  const unreadMessages = hostConversations.reduce((sum, conversation) => sum + parseAmount(conversation.hostUnread, 0), 0);
  const ongoingCalls = state.calls.filter((call) => call.hostId === hostId && ACTIVE_CALL_STATES.has(call.state)).length;
  const earningTx = state.walletTransactions.filter((tx) => tx.ownerType === "host" && tx.ownerId === hostId && tx.amount > 0);
  const totalEarnings = earningTx.reduce((sum, tx) => sum + tx.amount, 0);
  const todayPrefix = nowIso().slice(0, 10);
  const todayEarnings = earningTx
    .filter((tx) => String(tx.createdAt).startsWith(todayPrefix))
    .reduce((sum, tx) => sum + tx.amount, 0);

  const conversationIds = hostConversationIds(hostId);
  const giftsReceived = state.messages.filter((message) => message.kind === "gift" && conversationIds.has(message.conversationId)).length;

  return res.json({
    hostId,
    availability: host.availability,
    activeConversations,
    unreadMessages,
    ongoingCalls,
    totalEarnings,
    todayEarnings,
    giftsReceived,
  });
}));

app.post("/host/availability", asyncRoute(async (req, res) => {
  const hostId = String(req.body?.hostId || "");
  const availability = String(req.body?.availability || "");
  const host = ensureHostById(hostId);

  if (!host) {
    return sendError(res, 404, "Host not found.");
  }
  if (!VALID_AVAILABILITY.has(availability)) {
    return sendError(res, 400, "Invalid availability state.");
  }

  host.availability = availability;
  host.isOnline = availability === "online";

  await schedulePersist({
    eventType: "host.availability.updated",
    actorRole: "host",
    actorId: host.id,
    payload: { availability },
  });

  const availabilityEvent = {
    type: "host.availability.updated",
    payload: { hostId: host.id, availability: host.availability },
  };
  for (const participantId of socketsByParticipantId.keys()) {
    emitToParticipant(participantId, availabilityEvent);
  }
  for (const conversation of state.conversations.filter((entry) => entry.hostId === host.id)) {
    emitConversationUpdates(conversation);
  }

  return res.json(serializeHost(host));
}));

app.get("/host/conversations", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);

  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const { limit, cursor } = parsePagination(req, 30);
  const items = state.conversations
    .filter((conversation) => conversation.hostId === hostId)
    .filter((conversation) => hasConversationMessages(conversation.id))
    .filter((conversation) => !isBlocked(conversation.userId, hostId) && !isHostBlockingUser(hostId, conversation.userId))
    .sort((left, right) => toMillis(right.lastMessageAt) - toMillis(left.lastMessageAt))
    .map((conversation) => buildConversationPreview(conversation, "host"));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/host/conversations/start", asyncRoute(async (req, res) => {
  const hostId = String(req.body?.hostId || "");
  const userId = String(req.body?.userId || "");
  const host = ensureHostById(hostId);
  const user = ensureUserById(userId);

  if (!host || !user) {
    return sendError(res, 404, "Host or user not found.");
  }
  if (isBlocked(userId, hostId) || isHostBlockingUser(hostId, userId)) {
    return sendError(res, 403, "Conversation unavailable due to safety settings.");
  }

  const conversation = ensureConversation(userId, hostId);
  await schedulePersist({
    eventType: "conversation.started",
    actorRole: "host",
    actorId: hostId,
    payload: { conversationId: conversation.id, userId },
  });

  return res.json(buildConversationPreview(conversation, "host"));
}));

app.get("/host/conversations/:conversationId/messages", asyncRoute(async (req, res) => {
  const conversationId = String(req.params.conversationId || "");
  const hostId = String(req.query.hostId || "");
  const conversation = getConversationById(conversationId);

  if (!conversation || conversation.hostId !== hostId) {
    return sendError(res, 404, "Conversation not found.");
  }

  const { limit, cursor } = parsePagination(req, 40);
  return res.json(paginateMessages(getConversationMessages(conversationId), cursor, limit));
}));

app.post("/host/conversations/:conversationId/messages", asyncRoute(async (req, res) => {
  const conversation = getConversationById(req.params.conversationId);
  if (!conversation) {
    return sendError(res, 404, "Conversation not found.");
  }

  const hostId = String(req.body?.hostId || "");
  const text = String(req.body?.text || "").trim();
  if (!text) {
    return sendError(res, 400, "Message text cannot be empty.");
  }
  if (hostId !== conversation.hostId) {
    return sendError(res, 403, "Invalid host sender.");
  }
  if (isBlocked(conversation.userId, conversation.hostId) || isHostBlockingUser(conversation.hostId, conversation.userId)) {
    return sendError(res, 403, "Conversation unavailable due to safety settings.");
  }

  const message = createMessage({
    conversation,
    senderType: "host",
    senderId: hostId,
    text,
    kind: "text",
  });

  await schedulePersist({
    eventType: "message.created",
    actorRole: "host",
    actorId: hostId,
    payload: { conversationId: conversation.id, messageId: message.id },
  });

  emitToParticipants([conversation.userId, conversation.hostId], {
    type: "message.created",
    payload: message,
  });
  emitConversationUpdates(conversation);

  return res.json(message);
}));

app.post("/host/conversations/:conversationId/read", asyncRoute(async (req, res) => {
  const conversation = getConversationById(req.params.conversationId);
  const hostId = String(req.body?.hostId || "");
  if (!conversation || conversation.hostId !== hostId) {
    return sendError(res, 404, "Conversation not found.");
  }

  markConversationRead(conversation, "host");
  await schedulePersist({
    eventType: "conversation.read",
    actorRole: "host",
    actorId: hostId,
    payload: { conversationId: conversation.id },
  });

  emitConversationUpdates(conversation);
  return res.json({ ok: true });
}));

app.get("/host/users", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const blockedUserIds = new Set(
    state.hostBlocks.filter((entry) => entry.hostId === hostId).map((entry) => entry.userId)
  );

  const userIdsInConversations = state.conversations
    .filter((conversation) => conversation.hostId === hostId)
    .sort((left, right) => toMillis(right.lastMessageAt) - toMillis(left.lastMessageAt))
    .map((conversation) => conversation.userId);

  const orderedUserIds = [];
  const seen = new Set();
  for (const userId of userIdsInConversations) {
    if (!seen.has(userId) && !blockedUserIds.has(userId)) {
      seen.add(userId);
      orderedUserIds.push(userId);
    }
  }
  for (const user of state.users) {
    if (!seen.has(user.id) && !blockedUserIds.has(user.id) && !isBlocked(user.id, hostId)) {
      seen.add(user.id);
      orderedUserIds.push(user.id);
    }
  }

  const users = orderedUserIds
    .map((userId) => findUserById(userId))
    .filter(Boolean)
    .map((user) => ({
      id: user.id,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl || avatarById(user.id),
    }));

  return res.json(users);
}));

app.get("/host/earnings/wallet", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const wallet = ensureWallet("host", hostId);
  await schedulePersist({ eventType: "host.wallet.read", actorRole: "host", actorId: hostId });
  return res.json(wallet);
}));

app.get("/host/earnings/transactions", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const { limit, cursor } = parsePagination(req, 20);
  const items = state.walletTransactions
    .filter((tx) => tx.ownerType === "host" && tx.ownerId === hostId)
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.get("/host/gifts/history", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const { limit, cursor } = parsePagination(req, 20);
  const conversationIds = hostConversationIds(hostId);
  const items = state.messages
    .filter((message) => message.kind === "gift" && conversationIds.has(message.conversationId))
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/host/safety/report", asyncRoute(async (req, res) => {
  const hostId = String(req.body?.hostId || "");
  const userId = String(req.body?.userId || "");
  const reason = String(req.body?.reason || "").trim() || "Not specified";

  if (!ensureHostById(hostId) || !ensureUserById(userId)) {
    return sendError(res, 404, "Host or user not found.");
  }

  const report = {
    id: makeId("report"),
    reporterRole: "host",
    hostId,
    userId,
    reason,
    status: "open",
    adminNote: "",
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  state.reports.unshift(report);
  appendNotification("admin", "global", "report.created", { reportId: report.id, reporterRole: "host" });

  await schedulePersist({
    eventType: "safety.report.created",
    actorRole: "host",
    actorId: hostId,
    payload: { reportId: report.id, userId },
  });

  return res.json({ ok: true, reportId: report.id });
}));

app.post("/host/safety/block", asyncRoute(async (req, res) => {
  const hostId = String(req.body?.hostId || "");
  const userId = String(req.body?.userId || "");

  if (!ensureHostById(hostId) || !ensureUserById(userId)) {
    return sendError(res, 404, "Host or user not found.");
  }

  if (!isHostBlockingUser(hostId, userId)) {
    state.hostBlocks.unshift({ hostId, userId, createdAt: nowIso() });
    await schedulePersist({
      eventType: "safety.block.created",
      actorRole: "host",
      actorId: hostId,
      payload: { userId },
    });
  }

  return res.json({ ok: true });
}));

app.post("/host/withdrawals/request", asyncRoute(async (req, res) => {
  const hostId = String(req.body?.hostId || "");
  const amountCoins = parseAmount(req.body?.amountCoins, 0);
  const host = ensureHostById(hostId);

  if (!host) {
    return sendError(res, 404, "Host not found.");
  }
  if (amountCoins <= 0) {
    return sendError(res, 400, "Withdrawal amount must be greater than zero.");
  }

  const minimum = parseAmount(state.appSettings?.withdrawalMinCoins, 500);
  if (amountCoins < minimum) {
    return sendError(res, 400, `Minimum withdrawal is ${minimum} coins.`);
  }

  const wallet = ensureWallet("host", hostId);
  if (wallet.balance < amountCoins) {
    return sendError(res, 400, "Insufficient earnings balance.");
  }

  const request = {
    id: makeId("wd"),
    hostId,
    amountCoins,
    status: "pending",
    adminNote: "",
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  state.withdrawalRequests.unshift(request);
  appendNotification("admin", "finance", "withdrawal.requested", {
    withdrawalId: request.id,
    hostId,
    amountCoins,
  });

  await schedulePersist({
    eventType: "withdrawal.requested",
    actorRole: "host",
    actorId: hostId,
    payload: { withdrawalId: request.id, amountCoins },
  });

  return res.json(serializeWithdrawal(request));
}));

app.get("/host/withdrawals", asyncRoute(async (req, res) => {
  const hostId = String(req.query.hostId || "");
  const host = ensureHostById(hostId);
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }

  const { limit, cursor } = parsePagination(req, 20);
  const items = state.withdrawalRequests
    .filter((entry) => entry.hostId === hostId)
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt))
    .map((entry) => serializeWithdrawal(entry));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/safety/report", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const hostId = String(req.body?.hostId || "");
  const reason = String(req.body?.reason || "").trim() || "Not specified";

  if (!ensureUserById(userId) || !ensureHostById(hostId)) {
    return sendError(res, 404, "User or host not found.");
  }

  const report = {
    id: makeId("report"),
    reporterRole: "user",
    userId,
    hostId,
    reason,
    status: "open",
    adminNote: "",
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  state.reports.unshift(report);
  appendNotification("admin", "global", "report.created", { reportId: report.id, reporterRole: "user" });

  await schedulePersist({
    eventType: "safety.report.created",
    actorRole: "user",
    actorId: userId,
    payload: { reportId: report.id, hostId },
  });

  return res.json({ ok: true, reportId: report.id });
}));

app.post("/safety/block", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const hostId = String(req.body?.hostId || "");

  if (!ensureUserById(userId) || !ensureHostById(hostId)) {
    return sendError(res, 404, "User or host not found.");
  }

  if (!isBlocked(userId, hostId)) {
    state.blocks.unshift({ userId, hostId, createdAt: nowIso() });
    await schedulePersist({
      eventType: "safety.block.created",
      actorRole: "user",
      actorId: userId,
      payload: { hostId },
    });
  }

  return res.json({ ok: true });
}));

app.get("/wallet", asyncRoute(async (req, res) => {
  const userId = String(req.query.userId || "");
  const user = ensureUserById(userId);
  if (!user) {
    return sendError(res, 404, "User not found.");
  }

  const wallet = ensureWallet("user", userId);
  await schedulePersist({ eventType: "wallet.read", actorRole: "user", actorId: userId });
  return res.json(wallet);
}));

app.get("/wallet/transactions", asyncRoute(async (req, res) => {
  const userId = String(req.query.userId || "");
  const user = ensureUserById(userId);
  if (!user) {
    return sendError(res, 404, "User not found.");
  }

  const { limit, cursor } = parsePagination(req, 20);
  const items = state.walletTransactions
    .filter((tx) => tx.ownerType === "user" && tx.ownerId === userId)
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/wallet/topup-intent", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const amountInr = parseAmount(req.body?.amountInr, 0);
  const coins = parseAmount(req.body?.coins, 0);
  const user = ensureUserById(userId);

  if (!user) {
    return sendError(res, 404, "User not found.");
  }
  if (amountInr <= 0 || coins <= 0) {
    return sendError(res, 400, "Amount and coins must be greater than zero.");
  }

  const intent = {
    intentId: makeId("pay"),
    userId,
    amountInr,
    coins,
    status: "pending",
    provider: "mock_gateway",
    createdAt: nowIso(),
  };

  state.topupIntents.unshift(intent);
  await schedulePersist({
    eventType: "wallet.topup.intent.created",
    actorRole: "user",
    actorId: userId,
    payload: { intentId: intent.intentId, amountInr, coins },
  });

  return res.json(mapTopupIntent(intent));
}));

app.post("/wallet/topup-confirm", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const intentId = String(req.body?.intentId || "");
  const success = Boolean(req.body?.success);

  if (!ensureUserById(userId)) {
    return sendError(res, 404, "User not found.");
  }

  const intent = state.topupIntents.find((entry) => entry.intentId === intentId && entry.userId === userId);
  if (!intent) {
    return sendError(res, 404, "Top-up intent not found.");
  }

  let wallet = ensureWallet("user", userId);
  let transaction = null;

  if (intent.status === "pending") {
    if (success) {
      intent.status = "success";
      ({ wallet, transaction } = applyWalletDelta(
        "user",
        userId,
        "topup_success",
        intent.coins,
        `Top-up success (INR ${intent.amountInr})`,
        intent.intentId
      ));
    } else {
      intent.status = "failed";
      ({ wallet, transaction } = applyWalletDelta(
        "user",
        userId,
        "topup_failed",
        0,
        `Top-up failed (INR ${intent.amountInr})`,
        intent.intentId
      ));
    }

    await schedulePersist({
      eventType: "wallet.topup.confirmed",
      actorRole: "user",
      actorId: userId,
      payload: { intentId: intent.intentId, status: intent.status },
    });

    emitWalletEvents(wallet, transaction);
  }

  return res.json(mapTopupIntent(intent));
}));

app.get("/gifts/catalog", asyncRoute(async (_req, res) => {
  const catalog = [...state.gifts]
    .filter((gift) => gift.isEnabled !== false)
    .sort((left, right) => parseAmount(left.sortOrder, 999) - parseAmount(right.sortOrder, 999));

  return res.json(catalog);
}));

app.post("/gifts/send", asyncRoute(async (req, res) => {
  const userId = String(req.body?.userId || "");
  const conversationId = String(req.body?.conversationId || "");
  const giftId = String(req.body?.giftId || "");
  const note = String(req.body?.note || "").trim() || "Sent with care";

  const user = ensureUserById(userId);
  const conversation = getConversationById(conversationId);
  if (!user || !conversation || conversation.userId !== userId) {
    return sendError(res, 404, "Conversation not found.");
  }
  if (isBlocked(conversation.userId, conversation.hostId) || isHostBlockingUser(conversation.hostId, conversation.userId)) {
    return sendError(res, 403, "Conversation unavailable due to safety settings.");
  }

  const gift = getGiftById(giftId);
  if (!gift) {
    return sendError(res, 404, "Gift not found.");
  }

  const userWallet = ensureWallet("user", userId);
  if (userWallet.balance < gift.coinCost) {
    return sendError(res, 400, "Insufficient coins. Please top-up wallet.");
  }

  const userTxResult = applyWalletDelta(
    "user",
    userId,
    "gift_sent",
    -gift.coinCost,
    `Gift sent: ${gift.name}`,
    gift.id
  );
  const hostTxResult = applyWalletDelta(
    "host",
    conversation.hostId,
    "gift_received",
    gift.coinCost,
    `Gift received: ${gift.name}`,
    gift.id
  );

  const message = createMessage({
    conversation,
    senderType: "user",
    senderId: userId,
    text: note,
    kind: "gift",
    gift,
  });

  await schedulePersist({
    eventType: "gift.sent",
    actorRole: "user",
    actorId: userId,
    payload: { giftId: gift.id, conversationId: conversation.id, messageId: message.id },
  });

  emitWalletEvents(userTxResult.wallet, userTxResult.transaction);
  emitWalletEvents(hostTxResult.wallet, hostTxResult.transaction);
  emitToParticipants([conversation.userId, conversation.hostId], {
    type: "message.created",
    payload: message,
  });
  emitConversationUpdates(conversation);

  return res.json(message);
}));

app.get("/calls", asyncRoute(async (req, res) => {
  const userId = req.query.userId ? String(req.query.userId) : "";
  const hostId = req.query.hostId ? String(req.query.hostId) : "";

  if (!userId && !hostId) {
    return sendError(res, 400, "userId or hostId is required.");
  }

  const { limit, cursor } = parsePagination(req, 30);
  const items = state.calls
    .filter((call) => (userId ? call.userId === userId : true) && (hostId ? call.hostId === hostId : true))
    .sort((left, right) => toMillis(right.startedAt) - toMillis(left.startedAt))
    .map((call) => serializeCall(call));

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/calls/start", asyncRoute(async (req, res) => {
  const participants = resolveCallParticipants(req.body);
  if (!participants) {
    return sendError(res, 400, "Invalid call payload.");
  }

  const user = ensureUserById(participants.userId);
  const host = ensureHostById(participants.hostId);
  if (!user || !host) {
    return sendError(res, 404, "User or host not found.");
  }
  if (isBlocked(participants.userId, participants.hostId) || isHostBlockingUser(participants.hostId, participants.userId)) {
    return sendError(res, 403, "Call unavailable due to safety settings.");
  }

  const call = {
    id: makeId("call"),
    userId: participants.userId,
    hostId: participants.hostId,
    initiatedByRole: participants.initiatedByRole,
    state: "calling",
    startedAt: nowIso(),
    connectedAt: null,
    endedAt: null,
    durationSec: 0,
  };

  state.calls.unshift(call);
  await schedulePersist({
    eventType: "call.started",
    actorRole: participants.initiatedByRole,
    actorId: participants.initiatedByRole === "host" ? participants.hostId : participants.userId,
    payload: { callId: call.id, userId: call.userId, hostId: call.hostId },
  });

  emitCallUpdate(call);
  scheduleCallLifecycle(call);

  return res.json(serializeCall(call));
}));

app.post("/calls/:callId/state", asyncRoute(async (req, res) => {
  const callId = String(req.params.callId || "");
  const call = state.calls.find((entry) => entry.id === callId);
  if (!call) {
    return sendError(res, 404, "Call not found.");
  }

  const nextState = String(req.body?.state || "");
  if (!VALID_CALL_STATES.has(nextState)) {
    return sendError(res, 400, "Invalid call state.");
  }

  const actorId = String(req.body?.actorId || req.body?.userId || req.body?.hostId || "");
  if (!actorId || (actorId !== call.userId && actorId !== call.hostId)) {
    return sendError(res, 403, "Actor is not part of this call.");
  }

  const changed = transitionCallState(call, nextState);
  if (changed) {
    await schedulePersist({
      eventType: "call.state.changed",
      actorRole: actorId === call.hostId ? "host" : "user",
      actorId,
      payload: { callId: call.id, state: call.state },
    });
    emitCallUpdate(call);
  }

  return res.json(serializeCall(call));
}));
app.post("/admin/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!email || !password) {
    return sendError(res, 400, "Email and password are required.");
  }

  const admin = state.admins.find((entry) => entry.email === email && entry.isActive);
  if (!admin) {
    return sendError(res, 401, "Invalid admin credentials.");
  }

  const isValid = await bcrypt.compare(password, admin.passwordHash || "");
  if (!isValid) {
    return sendError(res, 401, "Invalid admin credentials.");
  }

  if (!ADMIN_ROLES.has(admin.role)) {
    return sendError(res, 403, "Admin role is not allowed.");
  }

  const token = signAdminToken(admin.id, admin.role);
  appendAudit(admin, "admin.login", { email });
  await schedulePersist({
    eventType: "admin.login.success",
    actorRole: admin.role,
    actorId: admin.id,
    payload: { email },
  });

  return res.json({
    token,
    admin: {
      id: admin.id,
      email: admin.email,
      displayName: admin.displayName,
      role: admin.role,
    },
  });
}));

app.get("/admin/me", requireAdmin, asyncRoute(async (req, res) => {
  return res.json({
    id: req.admin.id,
    email: req.admin.email,
    displayName: req.admin.displayName,
    role: req.admin.role,
  });
}));

app.get("/admin/dashboard", requireAdmin, asyncRoute(async (req, res) => {
  const pendingWithdrawals = state.withdrawalRequests.filter((entry) => entry.status === "pending").length;
  const completedWithdrawals = state.withdrawalRequests.filter((entry) => entry.status === "paid").length;

  const walletVolume = state.walletTransactions
    .filter((entry) => entry.ownerType === "user")
    .reduce((sum, entry) => sum + Math.max(entry.amount, 0), 0);

  const topupVolume = state.topupIntents
    .filter((entry) => entry.status === "success")
    .reduce((sum, entry) => sum + entry.amountInr, 0);

  const giftVolume = state.walletTransactions
    .filter((entry) => entry.type === "gift_sent")
    .reduce((sum, entry) => sum + Math.abs(entry.amount), 0);

  const activeChats = state.conversations.filter((conversation) => hasConversationMessages(conversation.id)).length;
  const activeCalls = state.calls.filter((call) => ACTIVE_CALL_STATES.has(call.state)).length;

  const recentActivity = [
    ...state.reports.slice(0, 8).map((entry) => ({
      id: entry.id,
      type: "report",
      label: `${entry.reporterRole} report`,
      createdAt: entry.createdAt,
      status: entry.status,
    })),
    ...state.withdrawalRequests.slice(0, 8).map((entry) => ({
      id: entry.id,
      type: "withdrawal",
      label: `Withdrawal ${entry.status}`,
      createdAt: entry.createdAt,
      status: entry.status,
    })),
    ...state.topupIntents.slice(0, 8).map((entry) => ({
      id: entry.intentId,
      type: "topup",
      label: `Top-up ${entry.status}`,
      createdAt: entry.createdAt,
      status: entry.status,
    })),
  ]
    .sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt))
    .slice(0, 20);

  return res.json({
    totals: {
      users: activeUsersCount(),
      hosts: activeHostsCount(),
      activeChats,
      activeCalls,
      walletVolume,
      topupVolume,
      giftVolume,
      pendingWithdrawals,
      completedWithdrawals,
      openReports: state.reports.filter((entry) => entry.status === "open").length,
    },
    recentActivity,
  });
}));

app.get("/admin/users", requireAdmin, asyncRoute(async (req, res) => {
  const query = String(req.query.query || "").trim().toLowerCase();
  const status = String(req.query.status || "").trim();
  const { limit, cursor } = parsePagination(req, 25);

  let items = state.users.map((user) => {
    const wallet = ensureWallet("user", user.id);
    const conversationCount = state.conversations.filter((conversation) => conversation.userId === user.id).length;
    const callCount = state.calls.filter((call) => call.userId === user.id).length;
    const reports = state.reports.filter((report) => report.userId === user.id).length;
    return {
      ...user,
      walletBalance: wallet.balance,
      conversationCount,
      callCount,
      reports,
    };
  });

  if (query) {
    items = items.filter((item) =>
      [item.id, item.displayName, item.phone].some((field) => String(field).toLowerCase().includes(query))
    );
  }

  if (status) {
    items = items.filter((item) => item.status === status);
  }

  items.sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
  return res.json(paginateOffset(items, cursor, limit));
}));

app.patch("/admin/users/:userId/status", requireAdmin, requireAnyAdminRole(MODERATION_ROLES), asyncRoute(async (req, res) => {
  const user = findUserById(req.params.userId);
  const status = String(req.body?.status || "").trim();
  if (!user) {
    return sendError(res, 404, "User not found.");
  }
  if (!["active", "blocked", "suspended"].includes(status)) {
    return sendError(res, 400, "Invalid user status.");
  }

  user.status = status;
  appendAudit(req.admin, "admin.user.status.updated", { userId: user.id, status });

  await schedulePersist({
    eventType: "admin.user.status.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { userId: user.id, status },
  });

  return res.json(user);
}));

app.get("/admin/hosts", requireAdmin, asyncRoute(async (req, res) => {
  const query = String(req.query.query || "").trim().toLowerCase();
  const status = String(req.query.status || "").trim();
  const { limit, cursor } = parsePagination(req, 25);

  let items = state.hosts.map((host) => {
    const wallet = ensureWallet("host", host.id);
    const conversationCount = state.conversations.filter((conversation) => conversation.hostId === host.id).length;
    const callCount = state.calls.filter((call) => call.hostId === host.id).length;
    const reports = state.reports.filter((report) => report.hostId === host.id).length;
    const withdrawalsPending = state.withdrawalRequests.filter((entry) => entry.hostId === host.id && entry.status === "pending").length;

    return {
      ...serializeHost(host),
      phone: host.phone,
      status: host.status,
      walletBalance: wallet.balance,
      conversationCount,
      callCount,
      reports,
      withdrawalsPending,
      createdAt: host.createdAt,
    };
  });

  if (query) {
    items = items.filter((item) =>
      [item.id, item.name, item.phone].some((field) => String(field).toLowerCase().includes(query))
    );
  }

  if (status) {
    items = items.filter((item) => item.status === status);
  }

  items.sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
  return res.json(paginateOffset(items, cursor, limit));
}));

app.patch("/admin/hosts/:hostId/status", requireAdmin, requireAnyAdminRole(MODERATION_ROLES), asyncRoute(async (req, res) => {
  const host = findHostById(req.params.hostId);
  const status = String(req.body?.status || "").trim();
  if (!host) {
    return sendError(res, 404, "Host not found.");
  }
  if (!["active", "blocked", "suspended"].includes(status)) {
    return sendError(res, 400, "Invalid host status.");
  }

  host.status = status;
  if (status !== "active") {
    host.availability = "offline";
    host.isOnline = false;
  }

  appendAudit(req.admin, "admin.host.status.updated", { hostId: host.id, status });

  await schedulePersist({
    eventType: "admin.host.status.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { hostId: host.id, status },
  });

  return res.json(serializeHost(host));
}));

app.get("/admin/withdrawals", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const status = String(req.query.status || "").trim();
  const { limit, cursor } = parsePagination(req, 30);

  let items = state.withdrawalRequests
    .map((entry) => serializeWithdrawal(entry))
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt));

  if (status) {
    items = items.filter((entry) => entry.status === status);
  }

  return res.json(paginateOffset(items, cursor, limit));
}));

app.patch("/admin/withdrawals/:withdrawalId", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const withdrawal = state.withdrawalRequests.find((entry) => entry.id === req.params.withdrawalId);
  const status = String(req.body?.status || "").trim();
  const adminNote = String(req.body?.adminNote || "").trim();

  if (!withdrawal) {
    return sendError(res, 404, "Withdrawal request not found.");
  }

  const allowed = ["pending", "approved", "rejected", "paid"];
  if (!allowed.includes(status)) {
    return sendError(res, 400, "Invalid withdrawal status.");
  }

  const previousStatus = withdrawal.status;
  withdrawal.status = status;
  withdrawal.adminNote = adminNote;
  withdrawal.updatedAt = nowIso();

  if (status === "paid" && previousStatus !== "paid") {
    const hostWallet = ensureWallet("host", withdrawal.hostId);
    if (hostWallet.balance < withdrawal.amountCoins) {
      withdrawal.status = previousStatus;
      return sendError(res, 400, "Host wallet has insufficient balance for payout.");
    }

    applyWalletDelta(
      "host",
      withdrawal.hostId,
      "withdrawal_paid",
      -withdrawal.amountCoins,
      `Withdrawal paid (${withdrawal.amountCoins} coins)`,
      withdrawal.id
    );

    state.payoutHistory.unshift({
      id: makeId("payout"),
      withdrawalId: withdrawal.id,
      hostId: withdrawal.hostId,
      amountCoins: withdrawal.amountCoins,
      paidByAdminId: req.admin.id,
      createdAt: nowIso(),
    });
  }

  appendAudit(req.admin, "admin.withdrawal.updated", {
    withdrawalId: withdrawal.id,
    previousStatus,
    status,
    adminNote,
  });

  await schedulePersist({
    eventType: "admin.withdrawal.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: {
      withdrawalId: withdrawal.id,
      previousStatus,
      status,
      adminNote,
    },
  });

  return res.json(serializeWithdrawal(withdrawal));
}));

app.get("/admin/wallet/transactions", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const ownerType = req.query.ownerType === "host" ? "host" : req.query.ownerType === "user" ? "user" : "";
  const ownerId = String(req.query.ownerId || "").trim();
  const { limit, cursor } = parsePagination(req, 40);

  let items = [...state.walletTransactions].sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
  if (ownerType) {
    items = items.filter((entry) => entry.ownerType === ownerType);
  }
  if (ownerId) {
    items = items.filter((entry) => entry.ownerId === ownerId);
  }

  return res.json(paginateOffset(items, cursor, limit));
}));

app.post("/admin/wallet/adjust", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const ownerType = req.body?.ownerType === "host" ? "host" : "user";
  const ownerId = String(req.body?.ownerId || "").trim();
  const amount = parseAmount(req.body?.amount, 0);
  const reason = String(req.body?.reason || "").trim() || "Manual wallet adjustment";

  if (!ownerId || amount === 0) {
    return sendError(res, 400, "ownerId and non-zero amount are required.");
  }

  if (ownerType === "user" && !findUserById(ownerId)) {
    return sendError(res, 404, "User not found.");
  }
  if (ownerType === "host" && !findHostById(ownerId)) {
    return sendError(res, 404, "Host not found.");
  }

  const type = amount > 0 ? "admin_credit" : "admin_debit";
  const { wallet, transaction } = applyWalletDelta(
    ownerType,
    ownerId,
    type,
    amount,
    `${reason} (by ${req.admin.email})`,
    req.admin.id
  );

  appendAudit(req.admin, "admin.wallet.adjusted", {
    ownerType,
    ownerId,
    amount,
    reason,
    transactionId: transaction.id,
  });

  await schedulePersist({
    eventType: "admin.wallet.adjusted",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { ownerType, ownerId, amount, transactionId: transaction.id },
  });

  emitWalletEvents(wallet, transaction);
  return res.json({ wallet, transaction });
}));

app.get("/admin/reports", requireAdmin, requireAnyAdminRole(MODERATION_ROLES), asyncRoute(async (req, res) => {
  const status = String(req.query.status || "").trim();
  const { limit, cursor } = parsePagination(req, 30);

  let items = state.reports
    .map((report) => ({
      ...report,
      userName: findUserById(report.userId)?.displayName || "User",
      hostName: findHostById(report.hostId)?.name || "Host",
    }))
    .sort((left, right) => toMillis(right.createdAt) - toMillis(left.createdAt));

  if (status) {
    items = items.filter((item) => item.status === status);
  }

  return res.json(paginateOffset(items, cursor, limit));
}));

app.patch("/admin/reports/:reportId", requireAdmin, requireAnyAdminRole(MODERATION_ROLES), asyncRoute(async (req, res) => {
  const report = state.reports.find((entry) => entry.id === req.params.reportId);
  const status = String(req.body?.status || "").trim();
  const adminNote = String(req.body?.adminNote || "").trim();

  if (!report) {
    return sendError(res, 404, "Report not found.");
  }
  if (!["open", "resolved", "dismissed"].includes(status)) {
    return sendError(res, 400, "Invalid report status.");
  }

  report.status = status;
  report.adminNote = adminNote;
  report.updatedAt = nowIso();

  appendAudit(req.admin, "admin.report.updated", {
    reportId: report.id,
    status,
    adminNote,
  });

  await schedulePersist({
    eventType: "admin.report.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { reportId: report.id, status },
  });

  return res.json(report);
}));

app.get("/admin/gifts", requireAdmin, asyncRoute(async (_req, res) => {
  const items = [...state.gifts].sort((a, b) => parseAmount(a.sortOrder, 999) - parseAmount(b.sortOrder, 999));
  return res.json(items);
}));

app.post("/admin/gifts", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const category = String(req.body?.category || "").trim();
  const coinCost = parseAmount(req.body?.coinCost, 0);
  const icon = String(req.body?.icon || "").trim() || "??";

  if (!name || !["small", "premium", "luxury"].includes(category) || coinCost <= 0) {
    return sendError(res, 400, "Invalid gift payload.");
  }

  const gift = {
    id: makeId("gift"),
    name,
    category,
    coinCost,
    icon,
    isEnabled: true,
    sortOrder: state.gifts.length + 1,
  };

  state.gifts.push(gift);
  appendAudit(req.admin, "admin.gift.created", { giftId: gift.id, name, category, coinCost });

  await schedulePersist({
    eventType: "admin.gift.created",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { giftId: gift.id },
  });

  return res.status(201).json(gift);
}));

app.patch("/admin/gifts/:giftId", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const gift = state.gifts.find((entry) => entry.id === req.params.giftId);
  if (!gift) {
    return sendError(res, 404, "Gift not found.");
  }

  if (typeof req.body?.name === "string") {
    gift.name = req.body.name.trim() || gift.name;
  }
  if (["small", "premium", "luxury"].includes(req.body?.category)) {
    gift.category = req.body.category;
  }
  if (req.body?.coinCost !== undefined) {
    const nextCost = parseAmount(req.body.coinCost, gift.coinCost);
    if (nextCost <= 0) {
      return sendError(res, 400, "Gift cost must be greater than zero.");
    }
    gift.coinCost = nextCost;
  }
  if (typeof req.body?.icon === "string" && req.body.icon.trim()) {
    gift.icon = req.body.icon.trim();
  }
  if (typeof req.body?.isEnabled === "boolean") {
    gift.isEnabled = req.body.isEnabled;
  }
  if (req.body?.sortOrder !== undefined) {
    gift.sortOrder = Math.max(parseAmount(req.body.sortOrder, gift.sortOrder), 1);
  }

  appendAudit(req.admin, "admin.gift.updated", { giftId: gift.id });

  await schedulePersist({
    eventType: "admin.gift.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { giftId: gift.id },
  });

  return res.json(gift);
}));

app.delete("/admin/gifts/:giftId", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const index = state.gifts.findIndex((entry) => entry.id === req.params.giftId);
  if (index === -1) {
    return sendError(res, 404, "Gift not found.");
  }

  const [removed] = state.gifts.splice(index, 1);
  appendAudit(req.admin, "admin.gift.deleted", { giftId: removed.id });

  await schedulePersist({
    eventType: "admin.gift.deleted",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: { giftId: removed.id },
  });

  return res.json({ ok: true, deletedGiftId: removed.id });
}));

app.get("/admin/settings", requireAdmin, asyncRoute(async (_req, res) => {
  return res.json(state.appSettings || {});
}));

app.patch("/admin/settings", requireAdmin, requireAnyAdminRole(FINANCE_ROLES), asyncRoute(async (req, res) => {
  const next = state.appSettings || {};

  if (Array.isArray(req.body?.topupPackages)) {
    next.topupPackages = req.body.topupPackages
      .map((entry) => ({
        amountInr: parseAmount(entry.amountInr, 0),
        coins: parseAmount(entry.coins, 0),
      }))
      .filter((entry) => entry.amountInr > 0 && entry.coins > 0);
  }

  if (req.body?.withdrawalMinCoins !== undefined) {
    const value = parseAmount(req.body.withdrawalMinCoins, next.withdrawalMinCoins || 500);
    next.withdrawalMinCoins = Math.max(value, 1);
  }

  if (req.body?.hostCommissionPercent !== undefined) {
    const value = parseAmount(req.body.hostCommissionPercent, next.hostCommissionPercent || 0);
    next.hostCommissionPercent = Math.max(0, Math.min(value, 100));
  }

  if (typeof req.body?.supportEmail === "string" && req.body.supportEmail.trim()) {
    next.supportEmail = req.body.supportEmail.trim();
  }

  state.appSettings = next;

  appendAudit(req.admin, "admin.settings.updated", {
    topupPackages: Boolean(req.body?.topupPackages),
    withdrawalMinCoins: req.body?.withdrawalMinCoins,
    hostCommissionPercent: req.body?.hostCommissionPercent,
    supportEmail: req.body?.supportEmail,
  });

  await schedulePersist({
    eventType: "admin.settings.updated",
    actorRole: req.admin.role,
    actorId: req.admin.id,
    payload: {},
  });

  return res.json(state.appSettings);
}));

app.get("/admin/audit-logs", requireAdmin, asyncRoute(async (req, res) => {
  const { limit, cursor } = parsePagination(req, 30);
  const items = [...state.adminAuditLogs].sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
  return res.json(paginateOffset(items, cursor, limit));
}));

app.get("/admin/chat-calls/overview", requireAdmin, asyncRoute(async (req, res) => {
  const { limit, cursor } = parsePagination(req, 25);

  const conversationRows = state.conversations
    .filter((entry) => hasConversationMessages(entry.id))
    .map((entry) => ({
      id: entry.id,
      userId: entry.userId,
      userName: findUserById(entry.userId)?.displayName || "User",
      hostId: entry.hostId,
      hostName: findHostById(entry.hostId)?.name || "Host",
      lastMessage: entry.lastMessage,
      lastMessageAt: entry.lastMessageAt,
      userUnread: entry.userUnread,
      hostUnread: entry.hostUnread,
    }))
    .sort((a, b) => toMillis(b.lastMessageAt) - toMillis(a.lastMessageAt));

  const callRows = state.calls
    .map((entry) => serializeCall(entry))
    .sort((a, b) => toMillis(b.startedAt) - toMillis(a.startedAt));

  return res.json({
    conversations: paginateOffset(conversationRows, cursor, limit),
    calls: callRows.slice(0, limit),
  });
}));

app.use((req, res) => {
  sendError(res, 404, `Route ${req.method} ${req.path} not found.`);
});

app.use((error, _req, res, _next) => {
  console.error("Backend error:", error);
  const message = error?.message || "Internal server error.";
  sendError(res, 500, message);
});

wss.on("connection", (socket, request) => {
  const hostHeader = request.headers.host || "localhost";
  const url = new URL(request.url || "", `http://${hostHeader}`);
  const participantId = String(url.searchParams.get("userId") || "").trim();

  if (!participantId) {
    socket.close(1008, "Missing userId");
    return;
  }

  let sockets = socketsByParticipantId.get(participantId);
  if (!sockets) {
    sockets = new Set();
    socketsByParticipantId.set(participantId, sockets);
  }
  sockets.add(socket);

  emitEventToSocket(socket, {
    type: "connected",
    payload: { userId: participantId },
  });

  socket.on("close", () => {
    const participantSockets = socketsByParticipantId.get(participantId);
    if (!participantSockets) {
      return;
    }
    participantSockets.delete(socket);
    if (participantSockets.size === 0) {
      socketsByParticipantId.delete(participantId);
    }
  });

  socket.on("error", () => {
    // close handler will cleanup
  });
});

async function bootstrap() {
  await loadState();

  state = normalizeState(state);

  for (const user of state.users) {
    ensureWallet("user", user.id);
  }
  for (const host of state.hosts) {
    ensureWallet("host", host.id);
  }

  for (const call of state.calls) {
    if (call.state === "connected") {
      startCallDurationTicker(call);
      continue;
    }
    if (call.state === "calling" || call.state === "ringing" || call.state === "connecting") {
      transitionCallState(call, "ended");
    }
  }

  await schedulePersist({ eventType: "server.bootstrap" });

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Feely backend listening on http://0.0.0.0:${PORT}`);
  });
}

bootstrap().catch((error) => {
  console.error("Failed to bootstrap backend:", error);
  process.exit(1);
});
