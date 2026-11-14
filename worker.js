const APP_NAME = "SM Earn API";
const VERSION = "4.1";

const GROUP_ID = "@tiktokaccountbaysell";
const CHANNEL_ID = "@SMEarn2026";

const REFERRAL_REWARD = 5;
const MIN_WITHDRAW = 500;

const WEB_ORIGIN =
  "https://mexhekar78-code.github.io";

const CORS = {
  "Access-Control-Allow-Origin": WEB_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type,Authorization,X-Bot-Secret,X-Admin-Secret",
  "Access-Control-Max-Age": "86400"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type":
        "application/json; charset=UTF-8",
      "Cache-Control": "no-store",
      ...CORS
    }
  });
}

function html(content) {
  return new Response(content, {
    headers: {
      "Content-Type":
        "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer"
    }
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function safeText(value, max = 100) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

function validId(value) {
  const id = Number(value);

  return (
    Number.isSafeInteger(id) &&
    id > 0
  );
}

function validPhone(value) {
  return /^01\d{9}$/.test(
    String(value || "")
  );
}

function money(value) {
  const number = Number(value || 0);

  if (!Number.isFinite(number)) {
    return 0;
  }

  return (
    Math.round(number * 100) / 100
  );
}

function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |=
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return result === 0;
}

function bytesToHex(bytes) {
  return Array
    .from(bytes)
    .map(byte =>
      byte
        .toString(16)
        .padStart(2, "0")
    )
    .join("");
}

async function hmacSha256(
  key,
  message,
  keyIsBytes = false
) {
  const encoder =
    new TextEncoder();

  const rawKey =
    keyIsBytes
      ? key
      : encoder.encode(key);

  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      rawKey,
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      encoder.encode(message)
    );

  return new Uint8Array(signature);
}

/*
  TELEGRAM MINI APP AUTHENTICATION

  সংশোধন:
  data-check string তৈরি করার সময়
  শুধু hash বাদ যাবে।

  signature থাকলে data-check string-এর
  মধ্যে থাকবে।
*/

async function telegramUser(
  request,
  env
) {
  if (!env.BOT_TOKEN) {
    throw new Error(
      "BOT_TOKEN পাওয়া যায়নি।"
    );
  }

  const authorization =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    !authorization.startsWith("tma ")
  ) {
    throw new Error(
      "Telegram authentication পাওয়া যায়নি।"
    );
  }

  const rawInitData =
    authorization
      .slice(4)
      .trim();

  if (!rawInitData) {
    throw new Error(
      "Telegram initData খালি।"
    );
  }

  const params =
    new URLSearchParams(
      rawInitData
    );

  const receivedHash =
    String(
      params.get("hash") || ""
    ).toLowerCase();

  const authDate =
    Number(
      params.get("auth_date")
    );

  const userText =
    params.get("user");

  if (
    !receivedHash ||
    !Number.isFinite(authDate) ||
    !userText
  ) {
    throw new Error(
      "Telegram initData অসম্পূর্ণ।"
    );
  }

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    authDate > now + 60 ||
    now - authDate > 86400
  ) {
    throw new Error(
      "Telegram session শেষ। Bot থেকে Web App আবার খুলুন।"
    );
  }

  const lines = [];

  for (
    const [key, value]
    of params.entries()
  ) {
    if (key !== "hash") {
      lines.push(
        `${key}=${value}`
      );
    }
  }

  lines.sort();

  const dataCheckString =
    lines.join("\n");

  const secretKey =
    await hmacSha256(
      "WebAppData",
      env.BOT_TOKEN
    );

  const calculatedHash =
    bytesToHex(
      await hmacSha256(
        secretKey,
        dataCheckString,
        true
      )
    );

  if (
    !safeEqual(
      calculatedHash,
      receivedHash
    )
  ) {
    throw new Error(
      "Telegram authentication সঠিক নয়।"
    );
  }

  let user;

  try {
    user =
      JSON.parse(userText);
  } catch {
    throw new Error(
      "Telegram user data সঠিক নয়।"
    );
  }

  if (!validId(user?.id)) {
    throw new Error(
      "Telegram user ID সঠিক নয়।"
    );
  }

  return {
    id: Number(user.id),

    firstName:
      safeText(
        user.first_name,
        100
      ),

    lastName:
      safeText(
        user.last_name,
        100
      ),

    username:
      safeText(
        user.username,
        100
      )
  };
}

function botAllowed(
  request,
  env
) {
  const supplied =
    request.headers.get(
      "X-Bot-Secret"
    ) || "";

  return (
    Boolean(env.BOT_API_SECRET) &&
    safeEqual(
      supplied,
      env.BOT_API_SECRET
    )
  );
}

function adminAllowed(
  request,
  env
) {
  const supplied =
    request.headers.get(
      "X-Admin-Secret"
    ) || "";

  return (
    Boolean(env.ADMIN_SECRET) &&
    safeEqual(
      supplied,
      env.ADMIN_SECRET
    )
  );
}

async function telegramApi(
  env,
  method,
  body
) {
  const response =
    await fetch(
      "https://api.telegram.org/bot" +
      env.BOT_TOKEN +
      "/" +
      method,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify(body)
      }
    );

  const result =
    await response.json();

  if (
    !response.ok ||
    result.ok !== true
  ) {
    throw new Error(
      result.description ||
      "Telegram API error"
    );
  }

  return result.result;
}

async function joined(
  env,
  chatId,
  userId
) {
  try {
    const member =
      await telegramApi(
        env,
        "getChatMember",
        {
          chat_id: chatId,
          user_id: userId
        }
      );

    if (
      member.status === "left" ||
      member.status === "kicked"
    ) {
      return false;
    }

    if (
      member.status ===
      "restricted"
    ) {
      return (
        member.is_member === true
      );
    }

    return [
      "member",
      "administrator",
      "creator"
    ].includes(
      member.status
    );

  } catch (error) {
    console.log(
      "Membership error:",
      chatId,
      userId,
      error.message
    );

    return false;
  }
}

async function membership(
  env,
  userId
) {
  const [
    groupJoined,
    channelJoined
  ] = await Promise.all([
    joined(
      env,
      GROUP_ID,
      userId
    ),

    joined(
      env,
      CHANNEL_ID,
      userId
    )
  ]);

  return {
    access:
      groupJoined &&
      channelJoined,

    groupJoined,
    channelJoined
  };
}

async function ensureSchema(env) {
  if (!env.DB) {
    throw new Error(
      "D1 DB binding পাওয়া যায়নি।"
    );
  }

  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        first_name TEXT,
        last_name TEXT,
        username TEXT,
        balance REAL NOT NULL DEFAULT 0,
        referral_count INTEGER NOT NULL DEFAULT 0,
        referred_by INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL,
        referred_id INTEGER NOT NULL UNIQUE,
        reward REAL NOT NULL DEFAULT 5,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK(referrer_id != referred_id)
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,

        method TEXT NOT NULL
          CHECK(
            method IN (
              'bKash',
              'Nagad'
            )
          ),

        account_number TEXT NOT NULL,

        amount REAL NOT NULL
          CHECK(amount >= 500),

        status TEXT NOT NULL
          DEFAULT 'pending'
          CHECK(
            status IN (
              'pending',
              'paid',
              'rejected'
            )
          ),

        created_at TEXT NOT NULL
          DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_referrals_referrer
      ON referrals(referrer_id)
    `),

    env.DB.prepare(`
      CREATE UNIQUE INDEX
      IF NOT EXISTS
      idx_referrals_referred_unique
      ON referrals(referred_id)
    `),

    env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_withdrawals_user_status
      ON withdrawals(
        user_id,
        status
      )
    `)
  ]);
}

async function saveUser(
  env,
  user
) {
  await env.DB.prepare(`
    INSERT INTO users (
      id,
      first_name,
      last_name,
      username,
      balance,
      referral_count,
      created_at
    )

    VALUES (
      ?,
      ?,
      ?,
      ?,
      0,
      0,
      CURRENT_TIMESTAMP
    )

    ON CONFLICT(id)
    DO UPDATE SET
      first_name =
        excluded.first_name,

      last_name =
        excluded.last_name,

      username =
        excluded.username
  `)
    .bind(
      user.id,
      user.firstName || "",
      user.lastName || "",
      user.username || ""
    )
    .run();
}

async function botRegister(
  request,
  env
) {
  if (
    !botAllowed(
      request,
      env
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Bot access denied."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const userId =
    Number(body.userId);

  if (!validId(userId)) {
    return json(
      {
        success: false,
        error:
          "Invalid Telegram user ID"
      },
      400
    );
  }

  await saveUser(env, {
    id: userId,

    firstName:
      safeText(
        body.firstName,
        100
      ),

    lastName:
      safeText(
        body.lastName,
        100
      ),

    username:
      safeText(
        body.username,
        100
      )
  });

  return json({
    success: true,
    userId
  });
}

async function referralCredit(
  request,
  env
) {
  if (
    !botAllowed(
      request,
      env
    )
  ) {
    return json(
      {
        success: false,
        credited: false,
        error:
          "Bot access denied."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const referredId =
    Number(body.userId);

  const referrerId =
    Number(body.referrerId);

  if (
    !validId(referredId) ||
    !validId(referrerId)
  ) {
    return json(
      {
        success: false,
        credited: false,
        error:
          "Invalid Telegram user ID"
      },
      400
    );
  }

  if (
    referredId === referrerId
  ) {
    return json(
      {
        success: false,
        credited: false,
        error:
          "নিজেকে Referral করা যাবে না।"
      },
      400
    );
  }

  const memberStatus =
    await membership(
      env,
      referredId
    );

  if (!memberStatus.access) {
    return json(
      {
        success: false,
        credited: false,
        ...memberStatus,

        error:
          "নতুন সদস্য Group ও Channel Verify করেনি।"
      },
      403
    );
  }

  await saveUser(env, {
    id: referredId,

    firstName:
      safeText(
        body.firstName,
        100
      ),

    lastName:
      safeText(
        body.lastName,
        100
      ),

    username:
      safeText(
        body.username,
        100
      )
  });

  const referrer =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE id = ?
    `)
      .bind(referrerId)
      .first();

  if (!referrer) {
    return json(
      {
        success: false,
        credited: false,
        error:
          "Referrer account পাওয়া যায়নি।"
      },
      404
    );
  }

  const previous =
    await env.DB.prepare(`
      SELECT id
      FROM referrals
      WHERE referred_id = ?
      LIMIT 1
    `)
      .bind(referredId)
      .first();

  if (previous) {
    return json({
      success: true,
      credited: false,
      alreadyCredited: true,

      message:
        "এই সদস্যের Referral Reward আগেই দেওয়া হয়েছে।"
    });
  }

  try {
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO referrals (
          referrer_id,
          referred_id,
          reward,
          created_at
        )

        VALUES (
          ?,
          ?,
          ?,
          CURRENT_TIMESTAMP
        )
      `)
        .bind(
          referrerId,
          referredId,
          REFERRAL_REWARD
        ),

      env.DB.prepare(`
        UPDATE users

        SET
          balance =
            balance + ?,

          referral_count =
            referral_count + 1

        WHERE id = ?
      `)
        .bind(
          REFERRAL_REWARD,
          referrerId
        ),

      env.DB.prepare(`
        UPDATE users

        SET referred_by = ?

        WHERE id = ?
        AND referred_by IS NULL
      `)
        .bind(
          referrerId,
          referredId
        )
    ]);

  } catch (error) {
    const duplicate =
      await env.DB.prepare(`
        SELECT id
        FROM referrals
        WHERE referred_id = ?
      `)
        .bind(referredId)
        .first();

    if (duplicate) {
      return json({
        success: true,
        credited: false,
        alreadyCredited: true,

        message:
          "Referral Reward আগেই দেওয়া হয়েছে।"
      });
    }

    throw error;
  }

  return json({
    success: true,
    credited: true,
    reward:
      REFERRAL_REWARD,

    message:
      "Referral সফল হয়েছে। ৳5 Balance-এ যোগ হয়েছে।"
  });
}

async function session(
  request,
  env
) {
  let user;

  try {
    user =
      await telegramUser(
        request,
        env
      );

  } catch (error) {
    return json(
      {
        success: false,
        error:
          error.message
      },
      401
    );
  }

  await saveUser(
    env,
    user
  );

  const memberStatus =
    await membership(
      env,
      user.id
    );

  const account =
    await env.DB.prepare(`
      SELECT
        id,
        first_name,
        last_name,
        username,
        balance,
        referral_count,
        referred_by

      FROM users

      WHERE id = ?
    `)
      .bind(user.id)
      .first();

  return json({
    success: true,

    membership:
      memberStatus,

    user: {
      id:
        account.id,

      firstName:
        account.first_name || "",

      lastName:
        account.last_name || "",

      username:
        account.username || "",

      balance:
        money(account.balance),

      referralCount:
        Number(
          account.referral_count || 0
        ),

      referralEarnings:
        money(
          Number(
            account.referral_count || 0
          ) *
          REFERRAL_REWARD
        ),

      referredBy:
        account.referred_by || null
    },

    referralReward:
      REFERRAL_REWARD,

    minimumWithdraw:
      MIN_WITHDRAW
  });
}

async function withdraw(
  request,
  env
) {
  let user;

  try {
    user =
      await telegramUser(
        request,
        env
      );

  } catch (error) {
    return json(
      {
        success: false,
        error:
          error.message
      },
      401
    );
  }

  const body =
    await readJson(request);

  const method =
    safeText(
      body.method,
      20
    );

  const accountNumber =
    safeText(
      body.accountNumber,
      20
    );

  const amount =
    money(body.amount);

  if (
    method !== "bKash" &&
    method !== "Nagad"
  ) {
    return json(
      {
        success: false,
        error:
          "bKash অথবা Nagad নির্বাচন করুন।"
      },
      400
    );
  }

  if (
    !validPhone(
      accountNumber
    )
  ) {
    return json(
      {
        success: false,
        error:
          "সঠিক ১১ সংখ্যার মোবাইল নম্বর দিন।"
      },
      400
    );
  }

  if (
    !Number.isFinite(amount) ||
    amount < MIN_WITHDRAW
  ) {
    return json(
      {
        success: false,
        error:
          "সর্বনিম্ন ৳500 Withdraw করতে হবে।"
      },
      400
    );
  }

  await saveUser(
    env,
    user
  );

  const memberStatus =
    await membership(
      env,
      user.id
    );

  if (!memberStatus.access) {
    return json(
      {
        success: false,
        error:
          "Withdraw করার আগে Group ও Channel membership প্রয়োজন।"
      },
      403
    );
  }

  const account =
    await env.DB.prepare(`
      SELECT balance
      FROM users
      WHERE id = ?
    `)
      .bind(user.id)
      .first();

  if (
    !account ||
    money(account.balance) <
      amount
  ) {
    return json(
      {
        success: false,
        error:
          "পর্যাপ্ত Balance নেই।"
      },
      400
    );
  }

  const pending =
    await env.DB.prepare(`
      SELECT id
      FROM withdrawals

      WHERE user_id = ?
      AND status = 'pending'

      LIMIT 1
    `)
      .bind(user.id)
      .first();

  if (pending) {
    return json(
      {
        success: false,
        error:
          "আপনার একটি Pending Withdraw Request আছে।"
      },
      409
    );
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO withdrawals (
        user_id,
        method,
        account_number,
        amount,
        status,
        created_at
      )

      VALUES (
        ?,
        ?,
        ?,
        ?,
        'pending',
        CURRENT_TIMESTAMP
      )
    `)
      .bind(
        user.id,
        method,
        accountNumber,
        amount
      )
      .run();

  return json({
    success: true,

    withdrawalId:
      result.meta.last_row_id,

    status:
      "pending",

    message:
      "Withdraw Request সফলভাবে জমা হয়েছে।"
  });
}

async function adminList(
  request,
  env
) {
  if (
    !adminAllowed(
      request,
      env
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Admin access denied."
      },
      401
    );
  }

  const url =
    new URL(request.url);

  const status =
    safeText(
      url.searchParams.get(
        "status"
      ) || "pending",
      20
    );

  const allowed = [
    "pending",
    "paid",
    "rejected",
    "all"
  ];

  if (
    !allowed.includes(status)
  ) {
    return json(
      {
        success: false,
        error:
          "Invalid withdrawal status"
      },
      400
    );
  }

  let statement;

  if (status === "all") {
    statement =
      env.DB.prepare(`
        SELECT
          w.id,
          w.user_id,
          w.method,
          w.account_number,
          w.amount,
          w.status,
          w.created_at,
          u.first_name,
          u.last_name,
          u.username,
          u.balance

        FROM withdrawals w

        LEFT JOIN users u
          ON u.id = w.user_id

        ORDER BY w.id DESC

        LIMIT 200
      `);

  } else {
    statement =
      env.DB.prepare(`
        SELECT
          w.id,
          w.user_id,
          w.method,
          w.account_number,
          w.amount,
          w.status,
          w.created_at,
          u.first_name,
          u.last_name,
          u.username,
          u.balance

        FROM withdrawals w

        LEFT JOIN users u
          ON u.id = w.user_id

        WHERE w.status = ?

        ORDER BY w.id DESC

        LIMIT 200
      `)
        .bind(status);
  }

  const result =
    await statement.all();

  return json({
    success: true,

    withdrawals:
      result.results || []
  });
}

async function adminPaid(
  request,
  env
) {
  if (
    !adminAllowed(
      request,
      env
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Admin access denied."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const id =
    Number(
      body.withdrawalId
    );

  if (
    !Number.isSafeInteger(id) ||
    id < 1
  ) {
    return json(
      {
        success: false,
        error:
          "Invalid Withdrawal ID"
      },
      400
    );
  }

  const item =
    await env.DB.prepare(`
      SELECT
        id,
        user_id,
        amount,
        status

      FROM withdrawals

      WHERE id = ?
    `)
      .bind(id)
      .first();

  if (!item) {
    return json(
      {
        success: false,
        error:
          "Withdraw Request পাওয়া যায়নি।"
      },
      404
    );
  }

  if (
    item.status !== "pending"
  ) {
    return json(
      {
        success: false,
        error:
          "এই Request আগেই Process করা হয়েছে।"
      },
      409
    );
  }

  const account =
    await env.DB.prepare(`
      SELECT balance
      FROM users
      WHERE id = ?
    `)
      .bind(item.user_id)
      .first();

  if (
    !account ||
    money(account.balance) <
      money(item.amount)
  ) {
    return json(
      {
        success: false,
        error:
          "Member-এর পর্যাপ্ত Balance নেই।"
      },
      409
    );
  }

  await env.DB.batch([
    env.DB.prepare(`
      UPDATE users

      SET balance =
        balance - ?

      WHERE id = ?
      AND balance >= ?

      AND EXISTS (
        SELECT 1
        FROM withdrawals

        WHERE id = ?
        AND status = 'pending'
      )
    `)
      .bind(
        item.amount,
        item.user_id,
        item.amount,
        id
      ),

    env.DB.prepare(`
      UPDATE withdrawals

      SET status = 'paid'

      WHERE id = ?
      AND status = 'pending'
    `)
      .bind(id)
  ]);

  return json({
    success: true,
    status: "paid",
    deducted:
      money(item.amount),

    message:
      "Withdraw Request PAID করা হয়েছে।"
  });
}

async function adminReject(
  request,
  env
) {
  if (
    !adminAllowed(
      request,
      env
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Admin access denied."
      },
      401
    );
  }

  const body =
    await readJson(request);

  const id =
    Number(
      body.withdrawalId
    );

  if (
    !Number.isSafeInteger(id) ||
    id < 1
  ) {
    return json(
      {
        success: false,
        error:
          "Invalid Withdrawal ID"
      },
      400
    );
  }

  const result =
    await env.DB.prepare(`
      UPDATE withdrawals

      SET status = 'rejected'

      WHERE id = ?
      AND status = 'pending'
    `)
      .bind(id)
      .run();

  if (!result.meta.changes) {
    return json(
      {
        success: false,
        error:
          "Pending Withdraw Request পাওয়া যায়নি।"
      },
      404
    );
  }

  return json({
    success: true,
    status: "rejected",

    message:
      "Withdraw Request Reject করা হয়েছে।"
  });
}

function adminPage() {
  return `<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1">

<title>SM Earn Admin</title>

<style>
*{
box-sizing:border-box
}

body{
margin:0;
background:#f3f8f5;
color:#173c2b;
font-family:system-ui,sans-serif
}

main{
max-width:900px;
margin:auto;
padding:18px
}

.card{
background:white;
border-radius:16px;
padding:16px;
margin-bottom:14px;
box-shadow:0 4px 14px #00000012
}

h1{
color:#087a43
}

input,
select,
button{
font:inherit;
padding:11px;
border-radius:10px
}

input,
select{
width:100%;
border:1px solid #ccd9d1;
margin:6px 0 12px
}

button{
border:0;
font-weight:700;
cursor:pointer
}

.green{
background:#078b49;
color:white
}

.red{
background:#c33030;
color:white
}

.item{
border:1px solid #dce7e0;
border-radius:13px;
padding:14px;
margin-top:10px
}

.actions{
display:flex;
gap:8px;
flex-wrap:wrap
}

.error{
color:#c33030;
font-weight:700
}

.success{
color:#078b49;
font-weight:700
}
</style>
</head>

<body>

<main>

<h1>💰 SM Earn Admin</h1>

<div class="card">

<label>
Admin Secret
</label>

<input
id="secret"
type="password"
placeholder="ADMIN_SECRET লিখুন">

<label>
Status
</label>

<select id="status">
<option value="pending">
Pending
</option>

<option value="paid">
Paid
</option>

<option value="rejected">
Rejected
</option>

<option value="all">
All
</option>
</select>

<button
class="green"
onclick="loadItems()">
Request দেখুন
</button>

<p id="message"></p>

</div>

<div class="card">

<h2>
Withdraw Requests
</h2>

<div id="items">
Secret লিখে Request দেখুন।
</div>

</div>

</main>

<script>
const secretInput =
document.getElementById(
"secret"
);

const statusInput =
document.getElementById(
"status"
);

const message =
document.getElementById(
"message"
);

const items =
document.getElementById(
"items"
);

function esc(value){
return String(
value == null ? "" : value
)
.replaceAll("&","&amp;")
.replaceAll("<","&lt;")
.replaceAll(">","&gt;")
.replaceAll('"',"&quot;");
}

function itemHtml(item){

let actions = "";

if(item.status === "pending"){

actions =
'<div class="actions">' +

'<button class="green" onclick="processItem(' +
Number(item.id) +
',\\'paid\\')">' +
'✅ PAID</button>' +

'<button class="red" onclick="processItem(' +
Number(item.id) +
',\\'reject\\')">' +
'❌ REJECT</button>' +

'</div>';

}

return (
'<div class="item">' +

'<b>Request #' +
esc(item.id) +
'</b>' +

'<p>Member: ' +
esc(item.first_name) +
' ' +
esc(item.last_name) +
'</p>' +

'<p>Telegram ID: ' +
esc(item.user_id) +
'</p>' +

'<p>Username: @' +
esc(item.username || " নেই") +
'</p>' +

'<p>Method: <b>' +
esc(item.method) +
'</b></p>' +

'<p>Number: <b>' +
esc(item.account_number) +
'</b></p>' +

'<p>Amount: <b>৳' +
esc(item.amount) +
'</b></p>' +

'<p>Status: <b>' +
esc(item.status) +
'</b></p>' +

actions +

'</div>'
);

}

async function loadItems(){

message.className = "";
message.textContent =
"Loading...";

const secret =
secretInput.value.trim();

const status =
statusInput.value;

if(!secret){

message.className =
"error";

message.textContent =
"Admin Secret লিখুন।";

return;
}

try{

const response =
await fetch(
"/admin/withdrawals?status=" +
encodeURIComponent(status),
{
headers:{
"X-Admin-Secret":secret
}
}
);

const data =
await response.json();

if(!response.ok){

throw new Error(
data.error ||
"Request failed"
);

}

message.className =
"success";

message.textContent =
"মোট " +
data.withdrawals.length +
"টি Request পাওয়া গেছে।";

items.innerHTML =
data.withdrawals.length

? data.withdrawals
.map(itemHtml)
.join("")

: "<p>কোনো Request নেই।</p>";

}catch(error){

message.className =
"error";

message.textContent =
error.message;

}

}

async function processItem(
id,
action
){

const secret =
secretInput.value.trim();

if(!secret){

message.className =
"error";

message.textContent =
"Admin Secret লিখুন।";

return;
}

const text =
action === "paid"

? "টাকা পাঠানোর পরে PAID করবেন?"

: "Request Reject করবেন?";

if(!confirm(text)){
return;
}

try{

const response =
await fetch(
"/admin/withdrawals/" +
action,
{
method:"POST",

headers:{
"Content-Type":
"application/json",

"X-Admin-Secret":
secret
},

body:JSON.stringify({
withdrawalId:id
})
}
);

const data =
await response.json();

if(!response.ok){

throw new Error(
data.error ||
"Action failed"
);

}

alert(
data.message ||
"সফল হয়েছে"
);

await loadItems();

}catch(error){

alert(error.message);

}

}
</script>

</body>
</html>`;
}

export default {

  async fetch(request, env) {

    if (
      request.method ===
      "OPTIONS"
    ) {
      return new Response(
        null,
        {
          status: 204,
          headers: CORS
        }
      );
    }

    try {
      await ensureSchema(env);

      const url =
        new URL(request.url);

      const path =
        url.pathname;

      /*
        API STATUS
      */

      if (
        request.method === "GET" &&
        path === "/"
      ) {
        return json({
          ok: true,

          app:
            APP_NAME,

          version:
            VERSION,

          referralReward:
            REFERRAL_REWARD,

          minimumWithdraw:
            MIN_WITHDRAW,

          telegramAuth:
            true,

          referralSecurity:
            true,

          adminPanel:
            "/admin"
        });
      }

      /*
        HEALTH CHECK
      */

      if (
        request.method === "GET" &&
        path === "/health"
      ) {
        return json({
          ok: true,

          database:
            Boolean(env.DB),

          botToken:
            Boolean(
              env.BOT_TOKEN
            ),

          botApiSecret:
            Boolean(
              env.BOT_API_SECRET
            ),

          adminSecret:
            Boolean(
              env.ADMIN_SECRET
            )
        });
      }

      /*
        ADMIN PANEL
      */

      if (
        request.method === "GET" &&
        path === "/admin"
      ) {
        return html(
          adminPage()
        );
      }

      /*
        CHECK MEMBERSHIP
      */

      if (
        request.method === "POST" &&
        path ===
          "/check-membership"
      ) {
        let user;

        try {
          user =
            await telegramUser(
              request,
              env
            );

        } catch (error) {
          return json(
            {
              success: false,
              error:
                error.message
            },
            401
          );
        }

        const result =
          await membership(
            env,
            user.id
          );

        return json({
          success: true,
          ...result
        });
      }

      /*
        BOT REGISTER USER
      */

      if (
        request.method === "POST" &&
        path ===
          "/bot/register-user"
      ) {
        return botRegister(
          request,
          env
        );
      }

      /*
        BOT REFERRAL CREDIT
      */

      if (
        request.method === "POST" &&
        path ===
          "/bot/referral-credit"
      ) {
        return referralCredit(
          request,
          env
        );
      }

      /*
        MINI APP SESSION
      */

      if (
        request.method === "POST" &&
        path === "/session"
      ) {
        return session(
          request,
          env
        );
      }

      /*
        WITHDRAW REQUEST
      */

      if (
        request.method === "POST" &&
        path === "/withdraw"
      ) {
        return withdraw(
          request,
          env
        );
      }

      /*
        ADMIN LIST
      */

      if (
        request.method === "GET" &&
        path ===
          "/admin/withdrawals"
      ) {
        return adminList(
          request,
          env
        );
      }

      /*
        ADMIN PAID
      */

      if (
        request.method === "POST" &&
        path ===
          "/admin/withdrawals/paid"
      ) {
        return adminPaid(
          request,
          env
        );
      }

      /*
        ADMIN REJECT
      */

      if (
        request.method === "POST" &&
        path ===
          "/admin/withdrawals/reject"
      ) {
        return adminReject(
          request,
          env
        );
      }

      return json(
        {
          success: false,
          error:
            "API route পাওয়া যায়নি।"
        },
        404
      );

    } catch (error) {

      console.log(error);

      return json(
        {
          success: false,

          error:
            error?.message ||
            "Server error"
        },
        500
      );
    }
  }
};
