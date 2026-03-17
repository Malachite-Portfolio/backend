const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const USER_WELCOME_COINS = 299;

const SEEDED_HOSTS = [
  {
    id: "host_demo_1",
    phone: "8000000001",
    name: "Host Maya",
    age: 28,
    languages: ["English", "Hindi"],
    interests: ["Anxiety", "Career"],
    availability: "online",
    verified: true,
    about: "Friendly, supportive, and non-judgmental.",
    avatarUrl: "https://i.pravatar.cc/300?img=32",
    status: "active",
  },
  {
    id: "host_demo_2",
    phone: "8000000002",
    name: "Host Alex",
    age: 27,
    languages: ["English"],
    interests: ["Stress", "Relationships"],
    availability: "busy",
    verified: true,
    about: "Calm listener for difficult moments.",
    avatarUrl: "https://i.pravatar.cc/300?img=12",
    status: "active",
  },
];

const SEEDED_USERS = [
  {
    id: "user_demo_1",
    phone: "9000000001",
    displayName: "Demo User 1",
    avatarUrl: "https://i.pravatar.cc/300?img=41",
    status: "active",
  },
  {
    id: "user_demo_2",
    phone: "9000000002",
    displayName: "Demo User 2",
    avatarUrl: "https://i.pravatar.cc/300?img=53",
    status: "active",
  },
];

const SEEDED_GIFTS = [
  { id: "gift_flower", name: "Flower", category: "small", coinCost: 99, icon: "\uD83C\uDF38", isEnabled: true, sortOrder: 1 },
  { id: "gift_heart_note", name: "Heart Note", category: "small", coinCost: 149, icon: "\uD83D\uDC8C", isEnabled: true, sortOrder: 2 },
  { id: "gift_care_box", name: "Care Box", category: "premium", coinCost: 299, icon: "\uD83C\uDF81", isEnabled: true, sortOrder: 3 },
  { id: "gift_sunlight", name: "Sunlight", category: "premium", coinCost: 399, icon: "\uD83C\uDF1E", isEnabled: true, sortOrder: 4 },
  { id: "gift_crown", name: "Crown of Gratitude", category: "luxury", coinCost: 999, icon: "\uD83D\uDC51", isEnabled: true, sortOrder: 5 },
];

const SEEDED_ADMIN = {
  id: "admin_super_1",
  email: "admin@feelytalk.com",
  displayName: "Super Admin",
  role: "super_admin",
  isActive: true,
  passwordHash: bcrypt.hashSync("Admin@12345", 10),
};

function nowIso() {
  return new Date().toISOString();
}

function normalizePhone(value) {
  return String(value || "").replace(/[^\d]/g, "");
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function parseAmount(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function avatarById(seed) {
  let hash = 0;
  for (let index = 0; index < String(seed).length; index += 1) {
    hash = (hash << 5) - hash + String(seed).charCodeAt(index);
    hash |= 0;
  }
  const numeric = Math.abs(hash) % 70;
  return `https://i.pravatar.cc/300?img=${numeric + 1}`;
}

function makeWallet(ownerType, ownerId, balance = 0) {
  return {
    ownerId,
    ownerType,
    balance,
    updatedAt: nowIso(),
  };
}

function makeWalletTx(ownerType, ownerId, amount, balanceAfter, type, description, relatedEntityId) {
  return {
    id: makeId("tx"),
    ownerType,
    ownerId,
    amount,
    balanceAfter,
    type,
    description,
    relatedEntityId: relatedEntityId || undefined,
    createdAt: nowIso(),
  };
}

function createSeedState() {
  const createdAt = nowIso();
  const users = SEEDED_USERS.map((user) => ({
    ...user,
    role: "user",
    phone: normalizePhone(user.phone),
    createdAt,
  }));
  const hosts = SEEDED_HOSTS.map((host) => ({
    ...host,
    role: "host",
    phone: normalizePhone(host.phone),
    isOnline: host.availability === "online",
    createdAt,
  }));

  const wallets = [];
  const walletTransactions = [];
  for (const user of users) {
    wallets.push(makeWallet("user", user.id, USER_WELCOME_COINS));
    walletTransactions.push(
      makeWalletTx("user", user.id, USER_WELCOME_COINS, USER_WELCOME_COINS, "refund", "Welcome balance credit")
    );
  }
  for (const host of hosts) {
    wallets.push(makeWallet("host", host.id, 0));
  }

  return {
    users,
    hosts,
    admins: [{ ...SEEDED_ADMIN, createdAt }],
    gifts: [...SEEDED_GIFTS],
    wallets,
    walletTransactions,
    topupIntents: [],
    otpSessions: [],
    conversations: [],
    messages: [],
    calls: [],
    reports: [],
    blocks: [],
    hostBlocks: [],
    withdrawalRequests: [],
    payoutHistory: [],
    notifications: [],
    adminAuditLogs: [],
    appSettings: {
      topupPackages: [
        { amountInr: 49, coins: 100 },
        { amountInr: 99, coins: 220 },
        { amountInr: 199, coins: 500 },
        { amountInr: 499, coins: 1400 },
      ],
      withdrawalMinCoins: 500,
      hostCommissionPercent: 0,
      supportEmail: "support@feelytalk.com",
    },
  };
}

function normalizeState(raw) {
  const state = raw && typeof raw === "object" ? raw : {};

  state.users = asArray(state.users).map((user) => ({
    id: String(user.id || makeId("user")),
    phone: normalizePhone(user.phone),
    displayName: String(user.displayName || `User ${String(user.phone || "").slice(-4)}`),
    avatarUrl: String(user.avatarUrl || avatarById(user.id)),
    role: "user",
    status: ["active", "blocked", "suspended"].includes(user.status) ? user.status : "active",
    createdAt: String(user.createdAt || nowIso()),
  }));

  state.hosts = asArray(state.hosts).map((host) => ({
    id: String(host.id || makeId("host")),
    phone: normalizePhone(host.phone),
    name: String(host.name || "Host"),
    age: parseAmount(host.age, 27),
    languages: asArray(host.languages).length ? asArray(host.languages) : ["English"],
    interests: asArray(host.interests).length ? asArray(host.interests) : ["Support"],
    availability: ["online", "busy", "offline"].includes(host.availability) ? host.availability : "offline",
    isOnline: host.availability === "online",
    verified: host.verified !== false,
    about: String(host.about || "Supportive host profile."),
    avatarUrl: String(host.avatarUrl || avatarById(host.id)),
    status: ["active", "blocked", "suspended"].includes(host.status) ? host.status : "active",
    createdAt: String(host.createdAt || nowIso()),
  }));

  state.admins = asArray(state.admins).map((admin) => ({
    id: String(admin.id || makeId("admin")),
    email: String(admin.email || "").toLowerCase(),
    displayName: String(admin.displayName || "Admin"),
    role: String(admin.role || "support_admin"),
    isActive: admin.isActive !== false,
    passwordHash: String(admin.passwordHash || ""),
    createdAt: String(admin.createdAt || nowIso()),
  }));

  state.gifts = asArray(state.gifts).map((gift, index) => ({
    id: String(gift.id || makeId("gift")),
    name: String(gift.name || "Gift"),
    category: ["small", "premium", "luxury"].includes(gift.category) ? gift.category : "small",
    coinCost: parseAmount(gift.coinCost, 99),
    icon: String(gift.icon || "\uD83C\uDF81"),
    isEnabled: gift.isEnabled !== false,
    sortOrder: parseAmount(gift.sortOrder, index + 1),
  }));

  state.wallets = asArray(state.wallets).map((wallet) => ({
    ownerType: wallet.ownerType === "host" ? "host" : "user",
    ownerId: String(wallet.ownerId || ""),
    balance: parseAmount(wallet.balance, 0),
    updatedAt: String(wallet.updatedAt || nowIso()),
  }));

  state.walletTransactions = asArray(state.walletTransactions).map((tx) => ({
    id: String(tx.id || makeId("tx")),
    ownerType: tx.ownerType === "host" ? "host" : "user",
    ownerId: String(tx.ownerId || ""),
    amount: parseAmount(tx.amount, 0),
    balanceAfter: parseAmount(tx.balanceAfter, 0),
    type: String(tx.type || "refund"),
    description: String(tx.description || "Wallet transaction"),
    relatedEntityId: tx.relatedEntityId ? String(tx.relatedEntityId) : undefined,
    createdAt: String(tx.createdAt || nowIso()),
  }));

  state.topupIntents = asArray(state.topupIntents).map((intent) => ({
    intentId: String(intent.intentId || makeId("pay")),
    userId: String(intent.userId || ""),
    amountInr: parseAmount(intent.amountInr, 0),
    coins: parseAmount(intent.coins, 0),
    status: ["pending", "success", "failed"].includes(intent.status) ? intent.status : "pending",
    createdAt: String(intent.createdAt || nowIso()),
  }));

  state.otpSessions = asArray(state.otpSessions).map((session) => ({
    sessionId: String(session.sessionId || makeId("otp")),
    role: session.role === "host" ? "host" : "user",
    phone: normalizePhone(session.phone),
    otp: String(session.otp || "").slice(0, 6),
    expiresAt: String(session.expiresAt || nowIso()),
    createdAt: String(session.createdAt || nowIso()),
  }));

  state.conversations = asArray(state.conversations).map((conversation) => ({
    id: String(conversation.id || makeId("convo")),
    userId: String(conversation.userId || ""),
    hostId: String(conversation.hostId || ""),
    createdAt: String(conversation.createdAt || nowIso()),
    lastMessage: String(conversation.lastMessage || "Conversation started"),
    lastMessageAt: String(conversation.lastMessageAt || nowIso()),
    userUnread: parseAmount(conversation.userUnread, 0),
    hostUnread: parseAmount(conversation.hostUnread, 0),
  }));

  state.messages = asArray(state.messages).map((message) => ({
    id: String(message.id || makeId("msg")),
    conversationId: String(message.conversationId || ""),
    senderType: message.senderType === "host" ? "host" : "user",
    senderId: String(message.senderId || ""),
    kind: message.kind === "gift" ? "gift" : message.kind === "system" ? "system" : "text",
    text: String(message.text || ""),
    gift: message.gift || null,
    deliveryState: ["sent", "delivered", "read"].includes(message.deliveryState)
      ? message.deliveryState
      : "delivered",
    createdAt: String(message.createdAt || nowIso()),
    readBy: asArray(message.readBy).map((entry) => String(entry)),
  }));

  state.calls = asArray(state.calls).map((call) => ({
    id: String(call.id || makeId("call")),
    userId: String(call.userId || ""),
    hostId: String(call.hostId || ""),
    initiatedByRole: call.initiatedByRole === "host" ? "host" : "user",
    state: ["calling", "ringing", "connecting", "connected", "ended", "missed", "failed"].includes(call.state)
      ? call.state
      : "ended",
    startedAt: String(call.startedAt || nowIso()),
    connectedAt: call.connectedAt ? String(call.connectedAt) : null,
    endedAt: call.endedAt ? String(call.endedAt) : null,
    durationSec: Math.max(parseAmount(call.durationSec, 0), 0),
  }));

  state.reports = asArray(state.reports).map((report) => ({
    id: String(report.id || makeId("report")),
    reporterRole: report.reporterRole === "host" ? "host" : "user",
    userId: String(report.userId || ""),
    hostId: String(report.hostId || ""),
    reason: String(report.reason || "Not specified"),
    status: ["open", "resolved", "dismissed"].includes(report.status) ? report.status : "open",
    adminNote: String(report.adminNote || ""),
    createdAt: String(report.createdAt || nowIso()),
    updatedAt: String(report.updatedAt || nowIso()),
  }));

  state.blocks = asArray(state.blocks).map((entry) => ({
    userId: String(entry.userId || ""),
    hostId: String(entry.hostId || ""),
    createdAt: String(entry.createdAt || nowIso()),
  }));

  state.hostBlocks = asArray(state.hostBlocks).map((entry) => ({
    hostId: String(entry.hostId || ""),
    userId: String(entry.userId || ""),
    createdAt: String(entry.createdAt || nowIso()),
  }));

  state.withdrawalRequests = asArray(state.withdrawalRequests).map((request) => ({
    id: String(request.id || makeId("wd")),
    hostId: String(request.hostId || ""),
    amountCoins: parseAmount(request.amountCoins, 0),
    status: ["pending", "approved", "rejected", "paid"].includes(request.status) ? request.status : "pending",
    adminNote: String(request.adminNote || ""),
    createdAt: String(request.createdAt || nowIso()),
    updatedAt: String(request.updatedAt || nowIso()),
  }));

  state.payoutHistory = asArray(state.payoutHistory);
  state.notifications = asArray(state.notifications);
  state.adminAuditLogs = asArray(state.adminAuditLogs);
  state.appSettings = state.appSettings && typeof state.appSettings === "object"
    ? state.appSettings
    : createSeedState().appSettings;

  const ensureAdmin = state.admins.find((entry) => entry.email === SEEDED_ADMIN.email);
  if (!ensureAdmin) {
    state.admins.push({
      ...SEEDED_ADMIN,
      createdAt: nowIso(),
    });
  }

  for (const seedUser of SEEDED_USERS) {
    if (!state.users.some((user) => user.phone === seedUser.phone)) {
      state.users.push({
        ...seedUser,
        role: "user",
        createdAt: nowIso(),
      });
    }
  }
  for (const seedHost of SEEDED_HOSTS) {
    if (!state.hosts.some((host) => host.phone === seedHost.phone)) {
      state.hosts.push({
        ...seedHost,
        role: "host",
        isOnline: seedHost.availability === "online",
        createdAt: nowIso(),
      });
    }
  }

  return state;
}

module.exports = {
  USER_WELCOME_COINS,
  SEEDED_USERS,
  SEEDED_HOSTS,
  SEEDED_ADMIN,
  SEEDED_GIFTS,
  createSeedState,
  normalizeState,
  normalizePhone,
  parseAmount,
  makeId,
  nowIso,
  avatarById,
};
