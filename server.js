require('dotenv').config();
const os = require('os');
const child_process = require('child_process');
const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const cron = require('node-cron');
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const nodemailer = require('nodemailer');
const http = require('http');
const rateLimit = require('express-rate-limit');
const MongoRateLimitStore = require('rate-limit-mongo');
const { OAuth2Client } = require('google-auth-library');

// Helper for Anti-Greylisting delays
const delay = (ms) => new Promise(res => setTimeout(res, ms));

const app = express();

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;
const SCANS_DIR = path.join(__dirname, 'storage', 'scans');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const VPS_SAFETY_LIMIT = 10000000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;
const WEBHOOK_SECRET = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;

const sendToLoops = async (email, eventName, properties) => {
    if (!process.env.LOOPS_API_KEY) return;
    try {
        // Corrected Endpoint: /api/v1/contacts/update using PUT
        await axios.put('https://app.loops.so/api/v1/contacts/update', {
            email: email,
            ...properties
        }, {
            headers: { 'Authorization': `Bearer ${process.env.LOOPS_API_KEY}` }
        });

        if (eventName) {
            await axios.post('https://app.loops.so/api/v1/events/send', {
                email: email,
                eventName: eventName
            }, {
                headers: { 'Authorization': `Bearer ${process.env.LOOPS_API_KEY}` }
            });
        }
    } catch (err) {
        console.error("Loops API Error:", err.response?.data || err.message);
    }
};

if (!fs.existsSync(SCANS_DIR)) fs.mkdirSync(SCANS_DIR, { recursive: true });

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 16) {
    console.error('⚠️  WARNING: ADMIN_PASSWORD is missing or too short. Set a 32+ char password in .env');
}

// ─── CHATBOT CONFIGURATION ────────────────────────────────────────────────────
const CHATBOT_SYSTEM_PROMPT = `You are the Sealch Pro support assistant. Answer questions about Sealch Pro — an email verification platform at sealch.com.

RESPONSE RULES (follow strictly):
- Keep answers SHORT. 1–2 sentences for simple questions. Never write paragraphs.
- Use a bullet list ONLY when listing 3+ distinct items (plans, steps, features).
- Format bullets as plain dashes: "- item". Never use markdown headers or bold.
- Start your answer directly — no "Great question!", "Sure!", "Of course!", "Absolutely!" or any filler opener.
- For "how do I" questions, give a maximum of 3 steps.
- For pricing, answer directly: "$35/mo for Growth — 5,000/day, 150k/month."
- If asked something outside Sealch, reply: "I can only help with Sealch questions — is there something else I can help you with?"
- Never repeat the question back. Never use ellipsis (...). Never say "feel free to".

PRODUCT:
- Real-time SMTP email verification — checks if mailboxes actually exist.
- Accuracy: 99.2%. Handles Gmail, Yahoo, Outlook, catch-all domains.
- Results: Deliverable (safe), Risky (catch-all), Invalid, Disposable.
- Disposable/unknown results: no credit charged. You only pay for actionable results.
- Role account detection: flags info@, support@, admin@ in metadata.

HOW TO USE:
- Dashboard → paste emails or drag & drop a CSV (up to 50MB) → Start Scan.
- Bulk scan runs in real-time with pause/resume. Export by segment (clean, risky, invalid, all).
- Quick-check: single email bar at the top of the dashboard — no scan needed.
- API: paid plans only. Endpoint POST /api/verify/bulk, max 50 emails per call. Headers: x-api-key, Content-Type: application/json.
- API key: Dashboard → API Keys page.

PLANS & PRICING:
- Free trial: 100/day for 7 days, no card required.
- Starter: $12/mo or $10/mo (yearly) — 1,000/day, 30k/month.
- Growth: $35/mo or $29/mo (yearly) — 5,000/day, 150k/month. Most popular.
- Power: $59/mo or $49/mo (yearly) — 9,000/day, 270k/month.
- Enterprise: custom — email tool@sealch.com.
- Pay-as-you-go (credits never expire, stack on top of daily quota):
  - 10,000 = $15 ($1.50/1k)
  - 100,000 = $49 ($0.49/1k)
  - 500,000 = $199 ($0.40/1k)
  - 1,000,000 = $349 ($0.35/1k)
- Yearly saves 20%. Daily quotas reset at midnight UTC and do NOT roll over.

BILLING & SUPPORT:
- Billing portal: billing.sealch.com/billing (manage subscription, invoices, cancel).
- To change or cancel: go to billing.sealch.com/billing — no need to contact support.
- Support tickets: Dashboard → Help Center.
- Contact: tool@sealch.com for enterprise or account issues.

REFERRAL:
- Earn 20% recurring commission. Dashboard → Referrals for your unique link.`;

const CHATBOT_MODEL = 'claude-haiku-4-5-20251001';
const CHATBOT_MAX_TOKENS = 400;
const CHATBOT_MAX_MESSAGES = 20;
const CHATBOT_MAX_MESSAGE_LENGTH = 2000;

// ─── DISPOSABLE EMAIL DETECTION ───────────────────────────────────────────────
const DISPOSABLE_DOMAINS = new Set([
    'mailinator.com','guerrillamail.com','guerrillamail.de','guerrillamail.net',
    'guerrillamail.org','guerrillamailblock.com','grr.la','guerrillamail.biz',
    'tempmail.com','temp-mail.org','temp-mail.io','temp-mail.de',
    'throwaway.email','throwaway.com','throwamail.com',
    'yopmail.com','yopmail.fr','yopmail.net','yopmail.gq',
    'sharklasers.com','pokemail.net',
    'spam4.me','spamgourmet.com','trashmail.com','trashmail.me','trashmail.net',
    'trashmail.org','trashmail.io','trashymail.com',
    'dispostable.com','mailnesia.com','maildrop.cc',
    'fakeinbox.com','fakemail.net','tempail.com','tempr.email',
    'discard.email','discardmail.com','discardmail.de',
    'mailcatch.com','mailexpire.com','mailforspam.com',
    'mailnull.com','mailscrap.com','mailseal.de',
    'mailtemp.info','mailzilla.com','mailzilla.org',
    'mintemail.com','mohmal.com','meltmail.com',
    'mt2015.com','mytemp.email','mytrashmail.com',
    'nobulk.com','nogmailspam.info','nomail.xl.cx',
    'nospam.ze.tc','objectmail.com','odnorazovoe.ru',
    'one-time.email','oneoffemail.com','onewaymail.com',
    'otherinbox.com','owlpic.com','pjjkp.com',
    'plexolan.de','proxymail.eu','putthisinyouremail.com',
    'quickinbox.com','rcpt.at',
    'reallymymail.com','receiveee.com','regbypass.com',
    'rhyta.com','rklips.com','rmqkr.net',
    'royal.net','rppkn.com','rtrtr.com',
    'safetymail.info','saynotospams.com','scbox.one.pl',
    'shieldedmail.com','shiftmail.com',
    'skeefmail.com','slaskpost.se','slipry.net',
    'smashmail.de','soodonims.com','spam.la','spam.su',
    'spamavert.com','spambob.com','spambob.net','spambog.com',
    'spambox.us','spamcero.com','spamcorptastic.com',
    'spamex.com','spamfree24.com','spamfree24.de',
    'spamfree24.eu','spamfree24.info','spamfree24.net',
    'spamfree24.org','spamgoes.in','spamherelots.com',
    'spamhereplease.com','spamhole.com','spamify.com',
    'spaminator.de','spamkill.info','spaml.com','spaml.de',
    'spamoff.de','spamslicer.com','spamspot.com',
    'spamthis.co.uk','spamtrail.com','spamtrap.ro',
    'superrito.com','suremail.info','teleworm.us',
    'temp.emeraldcraft.com','tempalias.com',
    'tempe4mail.com','tempemail.biz','tempemail.co.za',
    'tempemail.com','tempemail.net','tempinbox.com',
    'tempinbox.co.uk','tempmail.eu','tempmaildemo.com',
    'tempmailer.com','tempmailer.de','tempomail.fr',
    'temporarioemail.com.br','temporaryemail.net','temporaryemail.us',
    'temporaryforwarding.com','temporaryinbox.com','temporarymailaddress.com',
    'thanksnospam.info','thankyou2010.com','thisisnotmyrealemail.com',
    'throwawayemailaddress.com','tittbit.in','tmail.ws',
    'tmailinator.com','toiea.com','tradermail.info',
    'trash-amil.com','trash-mail.at','trash-mail.com',
    'trash-mail.de','trash2009.com','trashemail.de',
    'trashymail.net','trbvm.com','trbvn.com',
    'trickmail.net','trillianpro.com','turual.com',
    'twinmail.de','tyldd.com','uggsrock.com',
    'upliftnow.com','uplipht.com','venompen.com',
    'veryreallyme.com','vidchart.com','viditag.com',
    'viewcastmedia.com','viewcastmedia.net','viewcastmedia.org',
    'vubby.com','wasteland.rfc822.org','webemail.me',
    'weg-werf-email.de','wegwerf-emails.de','wegwerfadresse.de',
    'wegwerfemail.com','wegwerfemail.de','wegwerfmail.de',
    'wegwerfmail.info','wegwerfmail.net','wegwerfmail.org',
    'wh4f.org','whatiaas.com','whatpaas.com',
    'whyspam.me','wikidocuslice.com','willselfdestruct.com',
    'winemaven.info','wronghead.com','wuzup.net',
    'wuzupmail.net','wwwnew.eu','xagloo.com',
    'xemaps.com','xents.com','xjoi.com',
    'xoxy.net','xyzfree.net','yapped.net',
    'yep.it','yogamaven.com',
    'yomail.info','yuurok.com','zehnminutenmail.de',
    'zippymail.info','zoaxe.com','zoemail.org',
    '10minutemail.com','10minutemail.co.za','10minutemail.net',
    '10minutemail.be','10minutemail.de','10minutemail.info',
    '10minutemail.nl','10minutemail.org','10minutemail.pl',
    '10minutemail.pro','10minutemail.us','10mail.org',
    '20minutemail.com','20minutemail.it','20mail.it',
    '20email.eu','20email.it',
    'guerrillamail.info',
    'mailinator2.com','mailinator.net','mailinator.org',
    'mailinator.us','mailinater.com','mailinator.co.uk',
    'getairmail.com','filzmail.com','emailondeck.com',
    'emailfake.com','emkei.cz','emlpro.com','emlhub.com',
    'crazymailing.com','cool.fr.nf','courriel.fr.nf',
    'courrieltemporaire.com','cuvox.de','dacoolest.com',
    'dandikmail.com','dayrep.com','dcemail.com',
    'deadaddress.com','despammed.com','devnullmail.com',
    'dfgh.net','digitalsanctuary.com','dingbone.com',
    'disposableaddress.com','disposableemailaddresses.emailmiser.com',
    'disposableinbox.com','dispose.it','disposeamail.com',
    'dm.w3internet.co.uk','dodgeit.com','dodgit.com',
    'dontreg.com','dontsendmespam.de','drdrb.com',
    'dump-email.info','dumpanyjunk.com','dumpmail.de',
    'dumpyemail.com','e-mail.com','e-mail.org',
    'e4ward.com','easytrashmail.com','einrot.com',
    'emailigo.de','emailisvalid.com','emailmiser.com',
    'emailsensei.com','emailtemporario.com.br','emailwarden.com',
    'emailx.at.hm','emailxfer.com','emz.net',
    'enterto.com','ephemail.net','etranquil.com',
    'etranquil.net','etranquil.org','evopo.com',
    'explodemail.com','express.net.ua','eyepaste.com',
    'fastacura.com','fastchevy.com','fastchrysler.com',
    'fastkawasaki.com','fastmazda.com','fastmitsubishi.com',
    'fastnissan.com','fastsubaru.com','fastsuzuki.com',
    'fasttoyota.com','fastyamaha.com',
    'garliclife.com','get1mail.com','get2mail.fr',
    'getonemail.com','getonemail.net','ghosttexter.de',
    'girlsundertheinfluence.com','gishpuppy.com',
    'grandmamail.com','grandmasmail.com','great-host.in',
    'greensloth.com','haltospam.com','harakirimail.com',
    'hartbot.de','hatespam.org','hellodream.mobi',
    'hidemail.de','hidzz.com','hmamail.com',
    'hopemail.biz','hotpop.com','hulapla.de',
    'ieatspam.eu','ieatspam.info','ieh-mail.de',
    'ihateyoualot.info','iheartspam.org','imails.info',
    'inbax.tk','inbox.si','inboxalias.com',
    'incognitomail.com','incognitomail.net','incognitomail.org',
    'insorg-mail.info','ipoo.org','irish2me.com',
    'iwi.net','jetable.com','jetable.fr.nf',
    'jetable.net','jetable.org','jnxjn.com',
    'jourrapide.com','junk1.com','junkmail.com',
    'junkmail.ga','junkmail.gq','kasmail.com',
    'kaspop.com','keepmymail.com','killmail.com',
    'killmail.net','kir.ch.tc','klassmaster.com',
    'klassmaster.net','klzlk.com','koszmail.pl',
    'kurzepost.de','lawlita.com','letthemeatspam.com',
    'lhsdv.com','lifebyfood.com','link2mail.net',
    'litedrop.com','lol.ovpn.to','lolfreak.net',
    'lookugly.com','lopl.co.cc','lortemail.dk',
    'lovemeleaveme.com','lr78.com','lroid.com',
    'lukop.dk','m21.cc','mail-hierarchie.de',
    'mail-temporaire.fr','mail.by','mail.mezimages.net',
    'mail.zp.ua','mail1a.de','mail21.cc',
    'mail2rss.org','mail333.com','mail4trash.com',
    'mailbidon.com','mailblocks.com','mailbucket.org',
    'mailcat.biz','maildu.de','maileater.com',
    'mailfa.tk','mailfreeonline.com',
    'mailfs.com','mailguard.me','mailhazard.com',
    'mailhazard.us','mailhz.me','mailimate.com',
    'mailin8r.com','mailincubator.com',
    'mailme.ir','mailme.lv','mailme24.com',
    'mailmetrash.com','mailmoat.com','mailms.com',
    'mailna.co','mailna.in','mailna.me',
    'mailnator.com','mailorg.org',
    'mailpick.biz','mailproxsy.com','mailquack.com',
    'mailrock.biz','mailsac.com','mailsiphon.com',
    'mailslapping.com','mailslite.com','mailstome.de',
    'mailtothis.com','mailtrash.net','mailtv.net',
    'mailtv.tv',
    'makemetheking.com','manifestgenerator.com','manybrain.com',
    'mbx.cc','mega.zik.dj','meinspamschutz.de',
    'messagebeamer.de','mezimages.net',
    'ministry-of-silly-walks.de',
    'misterpinball.de','mmmmail.com','moakt.com',
    'mobi.web.id','mobileninja.co.uk','moncourrier.fr.nf',
    'monemail.fr.nf','monmail.fr.nf','monumentmail.com',
    'msa.minsmail.com','mt2009.com','mx0.wwwnew.eu',
    'my10minutemail.com','mycard.net.ua','mycleaninbox.net',
    'myemailboxy.com','mymail-in.net','mymailoasis.com',
    'myspaceinc.com','myspaceinc.net','myspaceinc.org',
    'myspacepimpedup.com','mytempemail.com','mytempmail.com',
    'neomailbox.com','nepwk.com',
    'nervmich.net','nervtansen.de','netmails.com',
    'netmails.net','neverbox.com','nice-4u.com',
    'nincsmail.hu','nnh.com','no-spam.ws',
    'noblepioneer.com','nomail.pw',
    'nomail2me.com','nomorespamemails.com','nonspam.eu',
    'nonspammer.de','noref.in','nospam.wins.com.br',
    'nospam4.us','nospamfor.us',
    'nospammail.net','nospamthanks.info','nothingtoseehere.ca',
    'nowmymail.com','nurfuerspam.de',
    'nwldx.com','obobbo.com',
    'oopi.org','opayq.com','ordinaryamerican.net',
    'ourklips.com','outlawspam.com',
    'ovpn.to','pancakemail.com',
    'pimpedupmyspace.com',
    'pookmail.com','privacy.net','privatdemail.net',
    'prtnx.com','punkass.com',
    'pwrby.com'
]);

function isDisposableEmail(email) {
    const domain = email.split('@')[1];
    if (!domain) return false;
    return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

// ─── HTTP AGENT + PER-REQUEST TIMEOUTS ────────────────────────────────────────
const WORKER_TIMEOUT  = 20000;
const FALLBACK_TIMEOUT = 8000;
const RETRY_TIMEOUT   = 25000;
const fastAgent = new http.Agent({
    keepAlive: false,  // keep-alive with proxy25 IP rotation accumulates stale socket listeners
    maxSockets: 10,
});

const apiClient = axios.create({ httpAgent: fastAgent });

// ─── DB & SESSION ─────────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000
}).then(() => {
    console.log('✅ DATABASE HANDSHAKE COMPLETE');
    // Safety reset: if a previous process was SIGKILL'd (OOM, power loss), the counter
    // may be stuck > 0. Only instance 0 resets, after a 4s delay to let any final
    // releaseProxySlot() calls from the dying old process complete first.
    if (process.env.NODE_APP_INSTANCE === '0') {
        setTimeout(() => {
            mongoose.connection.db.collection('proxylocks')
                .updateOne({ _id: 'global' }, { $set: { active: 0 } }, { upsert: true })
                .then(() => console.log('✅ Proxy lock reset'))
                .catch(() => {});
        }, 4000);
    }
});

const store = new MongoDBStore({
    uri: MONGO_URI,
    collection: 'sessions',
    connectionOptions: { serverSelectionTimeoutMS: 10000 }
});
store.on('error', (err) => console.log("Session Syncing..."));

const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationCode: String,
    verificationCodeExpiry: Date,
    apiKey: { type: String, unique: true, sparse: true, index: true },
    daily_limit: { type: Number, default: 100 },
    used_today: { type: Number, default: 0 },
    lifetime_credits: { type: Number, default: 0 },
    usage_history: [{ date: String, count: Number }],
    referralCode: { type: String, unique: true, sparse: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    referralEarnings: { type: Number, default: 0 },
    referralCount: { type: Number, default: 0 },
    last_active: Date,
    createdAt: { type: Date, default: Date.now }
}));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    subject: String,
    status: { type: String, default: 'open' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    replies: [{
        sender: { type: String, enum: ['user', 'admin'] },
        message: String,
        createdAt: { type: Date, default: Date.now }
    }]
}));

const Scan = mongoose.model('Scan', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    name: String,
    date: { type: Date, default: Date.now },
    stats: { safe: Number, risky: Number, invalid: Number, total: Number },
    fileName: String
}));

const NodeWorker = mongoose.model('NodeWorker', new mongoose.Schema({
    id: { type: String, unique: true },
    url: String,
    active: { type: Boolean, default: true },
    used_today: { type: Number, default: 0 },
    error_count: { type: Number, default: 0 },
    last_error: String,
    last_error_time: Date
}));


// ─── PROXY USAGE TRACKING (Proxy25 · 300K/mo · resets 7th) ──────────────────
const ProxyUsage = mongoose.model('ProxyUsage', new mongoose.Schema({
    period: { type: String, unique: true },
    count: { type: Number, default: 0 },
    limit: { type: Number, default: 600000 },
    updatedAt: { type: Date, default: Date.now }
}));

// Shared across all PM2 instances — single atomic counter in MongoDB
const ProxyLock = mongoose.model('ProxyLock', new mongoose.Schema({
    _id: { type: String },
    active: { type: Number, default: 0 }
}));

function getProxyPeriod() {
    const now = new Date();
    let y = now.getUTCFullYear(), m = now.getUTCMonth() + 1;
    if (now.getUTCDate() < 7) { m--; if (m === 0) { m = 12; y--; } }
    return y + '-' + String(m).padStart(2, '0');
}

// --- IN-MEMORY BATCH WRITING ---
let proxyUsageCache = 0;
const workerUsageCache = {};

setInterval(() => {
    // 1. Flush Proxy Usage
    if (proxyUsageCache > 0) {
        const countToFlush = proxyUsageCache;
        proxyUsageCache = 0;
        const period = getProxyPeriod();
        ProxyUsage.findOneAndUpdate(
            { period },
            { $inc: { count: countToFlush }, $set: { updatedAt: new Date() } },
            { upsert: true }
        ).catch(() => {});
    }
    // 2. Flush NodeWorker Usage
    for (const [workerId, count] of Object.entries(workerUsageCache)) {
        if (count > 0) {
            const countToFlush = count;
            workerUsageCache[workerId] = 0;
            NodeWorker.updateOne({ id: workerId }, { $inc: { used_today: countToFlush } }).catch(() => {});
        }
    }
}, 5000); // Writes to DB only once every 5 seconds!

async function trackProxyUsage() {
    proxyUsageCache++;
}

app.set('trust proxy', 1);
app.use(express.json({ limit: '50mb', verify: (req, res, buf) => { req.rawBody = buf; } }));

// Serve chatbot widget script
app.get('/sealch-chatbot.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.sendFile(path.join(__dirname, 'sealch-chatbot.js'));
});
app.use(cors({
    origin: ['https://sealch.com', 'https://www.sealch.com', 'https://app.sealch.com'],
    credentials: true
}));

// ─── RATE LIMITERS ────────────────────────────────────────────────────────────
// MongoDB store ensures the limits are shared across all 4 PM2 instances.
// Without a shared store each instance has its own counter → 4× bypass.
const mongoLimitStore = (collectionName, expireMs) => new MongoRateLimitStore({
    uri: MONGO_URI,
    collectionName,
    expireTimeMs: expireMs
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 6000,
    store: mongoLimitStore('ratelimit_api', 60 * 1000),
    requestPropertyName: 'apiRateLimit',
    message: { error: "Rate limit exceeded. Try again in 60 seconds." }
});
app.use('/api/', apiLimiter);

const chatLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    store: mongoLimitStore('ratelimit_chat', 60 * 60 * 1000),
    requestPropertyName: 'chatRateLimit',
    message: { error: "Too many chat messages. Please wait an hour or email tool@sealch.com." }
});

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    store: mongoLimitStore('ratelimit_admin', 15 * 60 * 1000),
    skipSuccessfulRequests: true,
    requestPropertyName: 'adminRateLimit',
    message: { error: "Too many failed login attempts. Try again in 15 minutes." }
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: store,
    proxy: true,
    cookie: { secure: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7, domain: '.sealch.com' }
}));

// ─── SMTP ────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
    host: 'smtp.zoho.com', port: 465, secure: true,
    auth: { user: process.env.ZOHO_USER, pass: process.env.ZOHO_PASS }
});

const getEmailHtml = (code, type = "verification") => {
    const isVerify = type === "verification";
    const label = isVerify ? "Email Verification" : "Password Reset";
    const title = isVerify ? "Confirm your email" : "Reset your password";
    const sub = isVerify
        ? "Enter this code in the Sealch app to activate your account."
        : "Enter this code in the Sealch app to set a new password.";
    return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f1f5f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:48px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:540px;margin:0 auto;">
    <tr><td style="padding-bottom:24px;"><img src="https://sealch.com/sealch--logo.png" alt="Sealch" height="28" style="display:block;"></td></tr>
    <tr><td style="background:#ffffff;border-radius:12px;border:1px solid #e2e8f0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="height:4px;background:#059669;border-radius:12px 12px 0 0;font-size:0;">&nbsp;</td></tr>
        <tr><td style="padding:36px 40px 32px;">
          <p style="margin:0 0 6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:#059669;">${label}</p>
          <h1 style="margin:0 0 12px;font-size:22px;font-weight:800;color:#0f172a;letter-spacing:-0.01em;">${title}</h1>
          <p style="margin:0 0 28px;font-size:14px;color:#64748b;line-height:1.65;">${sub}</p>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr><td style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:24px;text-align:center;">
              <span style="font-size:42px;font-weight:900;color:#0f172a;letter-spacing:0.2em;font-family:'Courier New',Consolas,monospace;">${code}</span>
            </td></tr>
          </table>
          <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.65;">Valid for <strong style="color:#64748b;">10 minutes</strong>. If you didn't request this, you can safely ignore this email — your account is secure.</p>
        </td></tr>
        <tr><td style="padding:16px 40px;background:#f8fafc;border-top:1px solid #f1f5f9;border-radius:0 0 12px 12px;">
          <p style="margin:0;font-size:11.5px;color:#94a3b8;">© 2026 Sealch Pro &nbsp;·&nbsp; <a href="https://sealch.com" style="color:#94a3b8;text-decoration:none;">sealch.com</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
};

const getTicketEmailHtml = (title, message) => {
    return `<div style="background-color:#050505;padding:50px 20px;font-family:sans-serif;color:#ffffff;text-align:center;">
        <div style="max-width:500px;margin:0 auto;background:#0a0a0a;border:1px solid #10b98133;border-radius:32px;padding:40px;border-bottom:4px solid #10b981;">
            <img src="https://sealch.com/sealch--logo.png" style="height:40px;margin-bottom:30px;">
            <h2 style="font-size:20px;font-weight:800;margin-bottom:15px;">${title}</h2>
            <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin-bottom:30px;text-align:left;">${message}</p>
            <a href="https://app.sealch.com/?mode=login" style="display:inline-block;background:#10b981;color:#000;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:700;font-size:13px;">View Ticket</a>
            <div style="margin-top:40px;padding-top:20px;border-top:1px solid #ffffff0a;">
                <p style="color:#64748b;font-size:10px;">© 2026 Sealch Pro</p>
            </div>
        </div>
    </div>`;
};

// ─── INFRASTRUCTURE ───────────────────────────────────────────────────────────
let activeWorkers = [];
let workerRotationIndex = 0;

const syncNodes = async () => {
    try {
        const nodes = await NodeWorker.find({});
        activeWorkers = nodes.filter(w => w.active && w.used_today < VPS_SAFETY_LIMIT);
    } catch (e) { console.error("Node Sync Error"); }
};
setInterval(syncNodes, 10000);
setTimeout(syncNodes, 1000);

// SMTP identity presented during handshake — must match our domain so it looks like us, not Reacher
const SMTP_FROM  = process.env.SMTP_FROM_EMAIL  || 'verify@sealch.com';
const SMTP_HELLO = process.env.SMTP_HELLO_NAME  || 'sealch.com';

async function callWorker(email, workerIndex, timeout) {
    const worker = activeWorkers[workerIndex];
    if (!worker) throw new Error('No worker at index');
    try {
        const res = await apiClient.post(worker.url, {
            to_email: email,
            from_email: SMTP_FROM,
            hello_name: SMTP_HELLO,
        }, { timeout });
        // Track success in RAM instead of hitting the DB every time
        workerUsageCache[worker.id] = (workerUsageCache[worker.id] || 0) + 1;
        trackProxyUsage().catch(() => {});
        return res.data;
    } catch (e) {
        const errorMsg = e.code || e.message;

        // Timeout handling: It's greylisting, do not penalize node
        if (errorMsg.includes('ECONNABORTED') || errorMsg.includes('ETIMEDOUT') || errorMsg.includes('timeout')) {
            return { is_reachable: "unknown", reason: "Anti-spam greylisting" };
        }

        // Real Error: Log to dashboard
        NodeWorker.updateOne({ id: worker.id }, {
            $inc: { error_count: 1 },
            $set: { last_error: errorMsg, last_error_time: new Date() }
        }).catch(() => {});

        throw new Error(`Worker ${worker.id} failed: ${errorMsg}`);
    }
}

async function callFallback(email, timeout) {
    const res = await apiClient.post(
        'http://127.0.0.1:8080/v1/check_email',
        { to_email: email, from_email: SMTP_FROM, hello_name: SMTP_HELLO },
        { timeout }
    );
    return res.data;
}

// ─── DOMAIN CONCURRENCY LIMITER ──────────────────────────────────────────────
const domainConcurrency = new Map();
const MAX_PER_DOMAIN = 3;

function acquireDomainSlot(domain) {
    return new Promise(resolve => {
        const d = domain.toLowerCase();
        if (!domainConcurrency.has(d)) domainConcurrency.set(d, { active: 0, queue: [] });
        const slot = domainConcurrency.get(d);
        if (slot.active < MAX_PER_DOMAIN) {
            slot.active++;
            resolve();
        } else {
            slot.queue.push(resolve);
        }
    });
}

function releaseDomainSlot(domain) {
    const d = domain.toLowerCase();
    const slot = domainConcurrency.get(d);
    if (!slot) return;
    if (slot.queue.length > 0) {
        // Transfer the slot to the next waiter — active count stays the same
        const next = slot.queue.shift();
        next();
    } else {
        slot.active--;
        if (slot.active <= 0) domainConcurrency.delete(d);
    }
}

// ─── GLOBAL PROXY CONCURRENCY LIMITER (shared across all PM2 instances) ────
// Uses MongoDB as the shared atomic counter so 4 instances × N each ≠ 4N concurrent.
// With in-memory counters, 4 PM2 instances × 4 slots each = up to 16 concurrent
// requests hitting proxy25 against a limit of 5, causing rejections.
const MAX_PROXY_CONCURRENT = 4;

async function acquireProxySlot() {
    while (true) {
        const result = await ProxyLock.findOneAndUpdate(
            { _id: 'global', active: { $lt: MAX_PROXY_CONCURRENT } },
            { $inc: { active: 1 } },
            { upsert: true, new: true }
        ).catch((err) => {
            if (err.code === 11000) return null; // concurrent upsert race, retry
            return null;
        });
        if (result) return;
        await delay(500 + Math.random() * 500); // longer jitter — reduces MongoDB polling ops/sec by 5×
    }
}

async function releaseProxySlot() {
    await ProxyLock.updateOne(
        { _id: 'global', active: { $gt: 0 } },
        { $inc: { active: -1 } }
    ).catch(() => {});
}

async function verifyEmailEngine(email) {
    const domain = email.split('@')[1] || 'unknown';
    await acquireDomainSlot(domain);
    await acquireProxySlot();

    try {
        let result = null;

        if (activeWorkers.length > 0) {
            workerRotationIndex = (workerRotationIndex + 1) % activeWorkers.length;
            const idx1 = workerRotationIndex;
            try {
                result = await callWorker(email, idx1, WORKER_TIMEOUT);
            } catch (e) {
                const msg = e.message || "";
                if (!msg.includes("timeout") && !msg.includes("ECONNABORTED")) {
                    console.error(`[Attempt 1] ${msg}`);
                }
                result = null;
            }
        }

        if (!result) {
            try {
                result = await callFallback(email, FALLBACK_TIMEOUT);
            } catch (e) {
                result = { is_reachable: "unknown", reason: "Mail server unreachable" };
            }
        }

        return result;
    } finally {
        releaseProxySlot();
        releaseDomainSlot(domain);
    }
}

// ─── PROVIDER DETECTION ───────────────────────────────────────────────────────
function detectProvider(result, email) {
    const domain = email.split('@')[1].toLowerCase();

    if (/gmail\.com|googlemail\.com/.test(domain)) return "Gmail";
    if (/outlook\.|hotmail\.|live\.|msn\./.test(domain)) return "Outlook";
    if (/yahoo\.|ymail\./.test(domain)) return "Yahoo";
    if (/icloud\.com|me\.com|mac\.com/.test(domain)) return "iCloud";
    if (/protonmail\.|proton\.me/.test(domain)) return "ProtonMail";
    if (/zoho\./.test(domain)) return "Zoho";
    if (/aol\./.test(domain)) return "AOL";
    if (/gmx\.|web\.de/.test(domain)) return "GMX";

    let mxData = "";
    if (result.mx_domain) mxData = result.mx_domain;
    else if (result.mx_records) mxData = Array.isArray(result.mx_records) ? result.mx_records.join(' ') : result.mx_records;
    else if (result.mx && result.mx.records) mxData = result.mx.records.join(' ');
    else if (result.mx && typeof result.mx === 'string') mxData = result.mx;

    if (!mxData) return "Unknown";

    const m = mxData.toLowerCase();
    if (m.includes('google.com') || m.includes('gmail-smtp') || m.includes('googlemail.com')) return "Google Workspace";
    if (m.includes('outlook.com') || m.includes('protection.outlook.com')) return "Microsoft 365";
    if (m.includes('zoho.com')) return "Zoho Mail";
    if (m.includes('amazonses.com') || m.includes('amazonaws.com')) return "Amazon SES";
    if (m.includes('mailgun.org')) return "Mailgun";
    if (m.includes('sendgrid.net')) return "SendGrid";
    if (m.includes('mimecast.com')) return "Mimecast";
    if (m.includes('protonmail.ch')) return "ProtonMail";
    if (m.includes('pphosted.com')) return "Proofpoint";
    if (m.includes('barracudanetworks.com')) return "Barracuda";

    return "Custom Domain";
}

// ─── ROLE ACCOUNT DETECTION ──────────────────────────────────────────────────
function applyRoleAccountFlag(result, email) {
    const targetEmail = result.input || email || "";
    const isRoleAccount = (result.misc && result.misc.is_role_account === true) ||
        /^(info|contact|hello|hi|welcome|inquiries|enquiries|sales|partners|partnerships|affiliates|business|growth|support|help|care|cs|customerservice|billing|admin|office|team|management|hq|ops|operations|marketing|pr|press|media|comms|social|hr|careers|jobs|talent|recruiting|people|booking|bookings|reservations|events)@/i.test(targetEmail);

    if (isRoleAccount) {
        result.is_role_account = true;
        if ((result.is_reachable || '').toLowerCase() === 'safe') {
            result.sealch_note = 'role_catchall_upgraded';
        }
    }
    return result;
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/google', async (req, res) => {
    const { token, refCode } = req.body;
    try {
        const ticket = await googleClient.verifyIdToken({ idToken: token, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        const email = payload.email.toLowerCase().trim();
        const name = payload.given_name || payload.name.split(' ')[0] || "there";
        let user = await User.findOne({ email });

        if (!user) {
            let referredById = null;
            if (refCode) {
                const referrer = await User.findOne({ referralCode: refCode });
                if (referrer) {
                    referredById = referrer._id;
                    await User.findByIdAndUpdate(referrer._id, { $inc: { referralCount: 1 } });
                }
            }
            const randomPass = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
            const rCode = crypto.randomBytes(5).toString('hex');
            user = new User({ username: name, email, password: randomPass, isVerified: true, daily_limit: 100, referralCode: rCode, referredBy: referredById });
            await user.save();
           // Send to Loops
            sendToLoops(email, 'trial_started', { firstName: name, userStatus: 'trial' });
        }

        req.session.userId = user._id;
        res.json({ success: true });
    } catch (e) {
        console.error("Google Auth Error:", e);
        res.status(401).json({ error: "Google authentication failed." });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password, cfToken, refCode } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const cleanEmail = email.toLowerCase().trim();
    try {
        const verifyRes = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            secret: TURNSTILE_SECRET,
            response: cfToken
        }, {
            family: 4 // Force IPv4 to prevent IPv6 routing timeouts
        });

        if (!verifyRes.data.success) return res.status(400).json({ error: "Security check failed." });
    } catch (err) {
        return res.status(500).json({ error: "Captcha service unreachable." });
    }

    const vCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);
    try {
        const existing = await User.findOne({ email: cleanEmail });
        if (existing) return res.status(400).json({ error: "Email registered" });
        const hashedPassword = await bcrypt.hash(password, 12);

        await transporter.sendMail({
            from: '"Sealch Pro" <tool@sealch.com>', to: cleanEmail,
            subject: `${vCode} is your access code`, html: getEmailHtml(vCode, "verification")
        });

        let referredById = null;
        if (refCode) {
            const referrer = await User.findOne({ referralCode: refCode });
            if (referrer) {
                referredById = referrer._id;
                await User.findByIdAndUpdate(referrer._id, { $inc: { referralCount: 1 } });
            }
        }
        const rCode = crypto.randomBytes(5).toString('hex');
        const newUser = new User({
            username, email: cleanEmail, password: hashedPassword,
            verificationCode: vCode, verificationCodeExpiry: expiry,
            daily_limit: 100, referralCode: rCode, referredBy: referredById
        });
        await newUser.save();

        // Send to Loops
        sendToLoops(cleanEmail, 'trial_started', { firstName: username, userStatus: 'trial' });

        res.json({ success: true });
    } catch (e) {
        console.error("Registration Error:", e);
        res.status(400).json({ error: "SMTP/DB Error" });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const cleanEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: cleanEmail });
    if (!user) return res.status(404).json({ error: "Email not found" });
    const vCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);
    user.verificationCode = vCode;
    user.verificationCodeExpiry = expiry;
    await user.save();
    try {
        await transporter.sendMail({
            from: '"Sealch Pro" <tool@sealch.com>', to: cleanEmail,
            subject: `${vCode} is your reset code`, html: getEmailHtml(vCode, "reset")
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: "SMTP Error" }); }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const cleanEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: cleanEmail, verificationCode: code });
    if (!user) return res.status(400).json({ error: "Invalid Code" });
    if (user.verificationCodeExpiry && new Date() > user.verificationCodeExpiry) {
        return res.status(400).json({ error: "Code expired. Request a new one." });
    }
    user.password = await bcrypt.hash(newPassword, 12);
    user.verificationCode = null;
    user.verificationCodeExpiry = null;
    await user.save();
    res.json({ success: true });
});

app.post('/api/verify-email', async (req, res) => {
    const { email, code } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const user = await User.findOne({ email: email.toLowerCase().trim(), verificationCode: code });
    if (!user) return res.status(400).json({ error: "Invalid Code" });
    if (user.verificationCodeExpiry && new Date() > user.verificationCodeExpiry) {
        return res.status(400).json({ error: "Code expired. Register again or contact support." });
    }
    user.isVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpiry = null;
    await user.save();
    req.session.userId = user._id;
    res.json({ success: true });
});

app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const cleanEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: cleanEmail, isVerified: false });
    if (!user) return res.status(404).json({ error: "Account not found or already verified" });
    const vCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationCode = vCode;
    user.verificationCodeExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();
    try {
        await transporter.sendMail({
            from: '"Sealch Pro" <tool@sealch.com>', to: cleanEmail,
            subject: `${vCode} is your access code`, html: getEmailHtml(vCode, "verification")
        });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Failed to send email" }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid credentials" });
    if (user.isVerified !== true) return res.status(403).json({ error: "Verify email" });
    req.session.userId = user._id;
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).end();
    let user = await User.findById(req.session.userId).select('-password');

    // Auto-generate referral code for old users if they don't have one
    if (!user.referralCode) {
        user.referralCode = crypto.randomBytes(5).toString('hex');
        await user.save();
    }

    let userObj = user.toObject();

    let forecastDays = null;
    if (userObj.usage_history && userObj.usage_history.length > 2) {
        const total = userObj.usage_history.reduce((acc, curr) => acc + curr.count, 0);
        const avg = total / userObj.usage_history.length;
        if (avg > 0) forecastDays = Math.round((userObj.daily_limit - userObj.used_today) / avg);
    }
    res.json({ ...userObj, forecastDays });
});

app.post('/api/keys/generate', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const user = await User.findById(req.session.userId);
    if (user.daily_limit <= 100 && user.lifetime_credits <= 0) {
        return res.status(403).json({ error: "API access requires an active Pro plan or Credit Pack." });
    }
    const key = `SEALCH_LIVE_${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    await User.findByIdAndUpdate(req.session.userId, { apiKey: key });
    res.json({ apiKey: key });
});

app.get('/api/docs/snippets', (req, res) => {
    res.json({
        curl: `curl -X POST https://sealch.com/api/verify/bulk \\\n  -H "x-api-key: YOUR_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"emails": ["founder@apple.com", "sales@microsoft.com"]}'`,
        nodejs: `const axios = require('axios');\n\nawait axios.post('https://sealch.com/api/verify/bulk',\n  { emails: ['founder@apple.com', 'sales@microsoft.com'] },\n  { headers: { 'x-api-key': 'YOUR_KEY' } }\n);`,
        python: `import requests\n\nres = requests.post(\n    "https://sealch.com/api/verify/bulk",\n    json={"emails": ["founder@apple.com", "sales@microsoft.com"]},\n    headers={"x-api-key": "YOUR_KEY"}\n)`
    });
});

// ─── HISTORY ENGINE ───────────────────────────────────────────────────────────
app.post('/api/history/save', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { name, stats, results, headers } = req.body;
    const fileName = `${req.session.userId}_${Date.now()}.json`;
    await fs.promises.writeFile(path.join(SCANS_DIR, fileName), JSON.stringify({ results, headers }));
    const newScan = new Scan({ userId: req.session.userId, name, stats, fileName });
    await newScan.save();
    res.json({ success: true });
});

app.get('/api/history/list', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const scans = await Scan.find({ userId: req.session.userId }).sort({ date: -1 }).limit(50).lean();
    res.json(scans);
});

app.get('/api/history/view/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const scan = await Scan.findOne({ _id: req.params.id, userId: req.session.userId }).lean();
    if (!scan) return res.status(404).end();
    try {
        const parsed = JSON.parse(fs.readFileSync(path.join(SCANS_DIR, scan.fileName)));
        let results = parsed.results || parsed;
        let headers = parsed.headers || ["Email"];
        res.json({ ...scan, results, headers });
    } catch (e) { res.status(500).json({ error: "File missing" }); }
});

app.post('/api/history/delete-all', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const scans = await Scan.find({ userId: req.session.userId });
    await Promise.all(scans.map(s => fs.promises.unlink(path.join(SCANS_DIR, s.fileName)).catch(() => {})));
    await Scan.deleteMany({ userId: req.session.userId });
    res.json({ success: true });
});

// ─── SINGLE VERIFY ENDPOINT ───────────────────────────────────────────────────
app.post('/api/verify', async (req, res) => {
    let user;
    const apiKey = req.headers['x-api-key'];
    const query = apiKey ? { apiKey } : { _id: req.session.userId };
    if (!query.apiKey && !query._id) return res.status(403).json({ error: "Auth required" });

    const { email } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });

    if (isDisposableEmail(email)) {
        const authUser = await User.findOne(query);
        if (!authUser) return res.status(403).json({ error: "Auth required" });
        return res.json({
            is_reachable: "invalid",
            input: email,
            provider: "Disposable",
            reason: "Disposable/temporary email address",
            is_disposable: true,
            sealch_note: "disposable_detected",
            credits: {
                used: authUser.used_today,
                limit: authUser.daily_limit,
                lifetime: authUser.lifetime_credits
            }
        });
    }

    // Attempt to parse out user ID to pass via webhook header
    let currentUserId = req.session.userId ? req.session.userId.toString() : "API_USER";

    let usedFromLifetime = false;
    user = await User.findOneAndUpdate(
        { ...query, daily_limit: { $gt: 0 }, $expr: { $lt: ["$used_today", "$daily_limit"] } },
        { $inc: { used_today: 1 }, $set: { last_active: new Date() } },
        { new: true }
    );
    if (!user) {
        user = await User.findOneAndUpdate(
            { ...query, lifetime_credits: { $gt: 0 } },
            { $inc: { lifetime_credits: -1, used_today: 1 }, $set: { last_active: new Date() } },
            { new: true }
        );
        usedFromLifetime = true;
    }
    if (!user) return res.status(403).json({ error: "Limit reached. Upgrade or buy credits." });

    let result;
    try {
        result = await verifyEmailEngine(email);
    } catch (e) {
        console.error('Verify engine error:', e.message);
        return res.status(503).json({ error: "Verification temporarily unavailable." });
    }

    const finalStatus = (result.is_reachable || "").toLowerCase();
    if (finalStatus === "unknown") {
        if (usedFromLifetime) {
            await User.findOneAndUpdate({ _id: user._id }, { $inc: { lifetime_credits: 1, used_today: -1 } });
            user.lifetime_credits = (user.lifetime_credits || 0) + 1;
            user.used_today = Math.max(0, user.used_today - 1);
        } else {
            await User.findOneAndUpdate({ _id: user._id }, { $inc: { used_today: -1 } });
            user.used_today = Math.max(0, user.used_today - 1);
        }
        result.is_reachable = "risky";
        result.reason = "Server Firewall (Protected)";
        result.sealch_note = "unknown_not_charged";
    }

    result = applyRoleAccountFlag(result, email);
    const provider = detectProvider(result, email);

    // Whitelist — never spread raw engine fields to the client
    res.json({
        is_reachable: result.is_reachable,
        reason: result.reason || null,
        provider,
        is_disposable: result.is_disposable || false,
        is_role_account: result.is_role_account || false,
        sealch_note: result.sealch_note || null,
        credits: {
            used: user.used_today,
            limit: user.daily_limit,
            lifetime: user.lifetime_credits
        }
    });
});

// ─── BULK VERIFY ENDPOINT ─────────────────────────────────────────────────────
app.post('/api/verify/bulk', async (req, res) => {
    let user;
    const apiKey = req.headers['x-api-key'];
    if (apiKey) user = await User.findOne({ apiKey });
    else if (req.session.userId) user = await User.findOne({ _id: req.session.userId });
    if (!user) return res.status(403).json({ error: "Auth required" });

    const { emails } = req.body;
    if (!Array.isArray(emails) || emails.length === 0) {
        return res.status(400).json({ error: "Invalid payload. Expected an array of emails." });
    }
    if (emails.some(e => typeof e !== 'string' || !e.includes('@'))) {
        return res.status(400).json({ error: "Invalid email format in array." });
    }
    if (emails.length > 50) {
        return res.status(400).json({
            error: "Max 50 emails per bulk request. For larger batches, split into multiple requests."
        });
    }

    const disposableEmails = [];
    const realEmails = [];
    for (const email of emails) {
        if (isDisposableEmail(email)) {
            disposableEmails.push(email);
        } else {
            realEmails.push(email);
        }
    }

    const needed = realEmails.length;
    let chargedToDaily = 0;
    let chargedToLifetime = 0;
    if (needed > 0) {
        // Calculate split upfront from the snapshot, then commit atomically to prevent
        // two concurrent bulk requests double-spending the same credits
        const dailyAvailable = user.daily_limit > 0 ? Math.max(0, user.daily_limit - user.used_today) : 0;
        if (dailyAvailable >= needed) {
            chargedToDaily = needed;
        } else {
            const remainingNeeded = needed - dailyAvailable;
            if (user.lifetime_credits >= remainingNeeded) {
                chargedToDaily = dailyAvailable;
                chargedToLifetime = remainingNeeded;
            } else {
                return res.status(403).json({ error: "Not enough combined credits for this batch." });
            }
        }

        const creditUpdate = { $set: { last_active: new Date() }, $inc: { used_today: needed } };
        if (chargedToLifetime > 0) creditUpdate.$inc.lifetime_credits = -chargedToLifetime;

        // Only enforce the daily cap atomically when we're actually spending daily credits.
        // Pay-as-you-go users have daily_limit=0 so the $expr would always fail once used_today>0.
        const matchCondition = {
            _id: user._id,
            ...(chargedToLifetime > 0 ? { lifetime_credits: { $gte: chargedToLifetime } } : {})
        };
        if (chargedToDaily > 0) {
            matchCondition.$expr = { $lte: [{ $add: ['$used_today', chargedToDaily] }, '$daily_limit'] };
        }

        const charged = await User.findOneAndUpdate(matchCondition, creditUpdate, { new: true });
        if (!charged) return res.status(403).json({ error: "Not enough combined credits for this batch." });
        user = charged;
    }

    const rawResults = [];

    for (const email of disposableEmails) {
        rawResults.push({
            email,
            is_reachable: "invalid",
            provider: "Disposable",
            reason: "Disposable/temporary email address",
            is_disposable: true,
            sealch_note: "disposable_detected"
        });
    }

    let unknownCount = 0;
    const CHUNK_SIZE = 25;
    for (let i = 0; i < realEmails.length; i += CHUNK_SIZE) {
        const chunk = realEmails.slice(i, i + CHUNK_SIZE);
        const chunkPromises = chunk.map(async (email) => {
            let result;
            try {
                result = await verifyEmailEngine(email);
            } catch (e) {
                console.error('Bulk engine error:', e.message);
                result = { is_reachable: "risky", reason: "Verification unavailable" };
            }
            const status = (result.is_reachable || "").toLowerCase();

            if (status === "unknown") {
                unknownCount++;
                result.is_reachable = "risky";
                result.reason = "Server Firewall (Protected)";
                result.sealch_note = "unknown_not_charged";
            }

            result = applyRoleAccountFlag(result, email);
            const provider = detectProvider(result, email);
            // Whitelist — never expose raw engine fields
            return {
                email,
                is_reachable: result.is_reachable,
                reason: result.reason || null,
                provider,
                is_disposable: result.is_disposable || false,
                is_role_account: result.is_role_account || false,
                sealch_note: result.sealch_note || null,
            };
        });
        const resolvedChunk = await Promise.all(chunkPromises);
        rawResults.push(...resolvedChunk);
    }

    if (unknownCount > 0) {
        const refund = Math.min(unknownCount, needed);
        const lifetimeRefund = Math.min(refund, chargedToLifetime);
        const dailyRefund = Math.min(refund - lifetimeRefund, chargedToDaily);
        const update = { $inc: {} };
        if (refund > 0) update.$inc.used_today = -refund;
        if (lifetimeRefund > 0) update.$inc.lifetime_credits = lifetimeRefund;

        if (Object.keys(update.$inc).length > 0) {
            await User.findOneAndUpdate({ _id: user._id }, update);
            user.used_today = Math.max(0, user.used_today - refund);
            user.lifetime_credits = (user.lifetime_credits || 0) + lifetimeRefund;
        }
    }

    res.json({
        results: rawResults,
        credits: {
            used: user.used_today,
            limit: user.daily_limit,
            lifetime: user.lifetime_credits
        }
    });
});

app.post('/api/logout', (req, res) => {
    if (req.session) { req.session.destroy(); res.clearCookie('connect.sid'); }
    res.json({ success: true });
});

app.post('/api/tickets', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: "Missing fields" });
    const ticket = new Ticket({ userId: req.session.userId, subject, replies: [{ sender: 'user', message }] });
    await ticket.save();

    // Send emails in background
    User.findById(req.session.userId).then(user => {
        if (user && user.email) {
            // 1. Alert to User
            const userMsg = `We have received your support ticket regarding "<b>${subject}</b>". Our team will review it and get back to you shortly.`;
            transporter.sendMail({
                from: '"Sealch Support" <tool@sealch.com>',
                to: user.email,
                subject: `Ticket Received: ${subject}`,
                html: getTicketEmailHtml("Support Request Received", userMsg)
            }).catch(e => console.log("Mail Error:", e.message));

            // 2. Alert to Admin
            transporter.sendMail({
                from: '"Sealch System" <tool@sealch.com>',
                to: 'tool@sealch.com',
                subject: `🚨 New Ticket: ${subject}`,
                html: `New support ticket from <b>${user.email}</b>.<br><br>Message: ${message}`
            }).catch(e => {});
        }
    });

    res.json({ success: true, ticket });
});

app.get('/api/tickets', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    res.json(await Ticket.find({ userId: req.session.userId }).sort({ updatedAt: -1 }).lean());
});

app.get('/api/tickets/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const ticket = await Ticket.findOne({ _id: req.params.id, userId: req.session.userId }).lean();
    if (!ticket) return res.status(404).json({ error: "Not found" });
    res.json(ticket);
});

app.post('/api/tickets/:id/reply', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message required" });
    const ticket = await Ticket.findOne({ _id: req.params.id, userId: req.session.userId });
    if (!ticket || ticket.status === 'closed') return res.status(400).json({ error: "Not found or closed" });
    ticket.replies.push({ sender: 'user', message });
    ticket.status = 'open'; ticket.updatedAt = new Date();
    await ticket.save(); res.json({ success: true });
});

// ─── ACCOUNT MANAGEMENT ───────────────────────────────────────────────────────
app.post('/api/account/update-profile', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { username } = req.body;
    if (!username || typeof username !== 'string' || username.trim().length < 2)
        return res.status(400).json({ error: 'Name must be at least 2 characters' });
    await User.findByIdAndUpdate(req.session.userId, { username: username.trim() });
    res.json({ success: true });
});

app.post('/api/account/change-password', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).end();
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect' });
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true });
});

app.post('/api/account/delete', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const { confirmation } = req.body;
    if (confirmation !== 'DELETE') return res.status(400).json({ error: 'Type DELETE to confirm' });
    const userId = req.session.userId;
    await User.findByIdAndDelete(userId);
    await Scan.deleteMany({ userId });
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.json({ success: true });
});

// ─── CHECKOUT URL ─────────────────────────────────────────────────────────────
const CHECKOUT_PLANS = {
    starter: { m: 1529909, y: 1529927 },
    growth:  { m: 1529925, y: 1529932 },
    power:   { m: 1529926, y: 1529934 }
};
const PAYG_PRODUCTS = {
    payg_10k:  '4ac59c1a-ea5f-4f74-af38-cd0e3c2ab678',
    payg_100k: '2c648aea-718b-44e4-9c81-bdda6fc7c4fd',
    payg_500k: 'ca0ed186-bb2e-43b8-a133-424c6ef55c38',
    payg_1m:   '02daa5e4-5312-4b63-a013-4bf1817ee84e'
};
const CHECKOUT_PRODUCT = '9213674b-baca-480c-a386-26c11cdbf322';

let lsStoreId = null;
async function getLsStoreId() {
    if (lsStoreId) return lsStoreId;
    const r = await axios.get('https://api.lemonsqueezy.com/v1/stores', {
        headers: { 'Authorization': `Bearer ${process.env.LEMONSQUEEZY_API_KEY}`, 'Accept': 'application/vnd.api+json' }
    });
    lsStoreId = r.data.data[0].id;
    return lsStoreId;
}

app.post('/api/checkout-url', async (req, res) => {
    if (!req.session.userId) return res.status(401).end();
    const user = await User.findById(req.session.userId).select('email');
    if (!user) return res.status(404).end();

    const { plan, yearly } = req.body;
    const validPlans = ['starter', 'growth', 'power', 'payg_10k', 'payg_100k', 'payg_500k', 'payg_1m'];
    if (!plan || !validPlans.includes(plan)) return res.status(400).json({ error: 'Invalid plan' });

    const email = user.email;
    const emailEnc = encodeURIComponent(email);

    // PAYG: separate products, no variant selector issue
    if (plan.startsWith('payg_')) {
        const url = `https://sealch.lemonsqueezy.com/checkout/buy/${PAYG_PRODUCTS[plan]}?embed=1&checkout[email]=${emailEnc}&checkout[custom][app_email]=${emailEnc}`;
        return res.json({ url });
    }

    // Subscriptions: use LemonSqueezy API to create a variant-locked checkout (no variant selector shown)
    const variantId = yearly ? CHECKOUT_PLANS[plan].y : CHECKOUT_PLANS[plan].m;

    try {
        const storeId = await getLsStoreId();
        const lsRes = await axios.post('https://api.lemonsqueezy.com/v1/checkouts', {
            data: {
                type: 'checkouts',
                attributes: {
                    checkout_data: {
                        email,
                        custom: { app_email: email }
                    },
                    product_options: {
                        enabled_variants: [variantId]
                    }
                },
                relationships: {
                    store: { data: { type: 'stores', id: String(storeId) } },
                    variant: { data: { type: 'variants', id: String(variantId) } }
                }
            }
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.LEMONSQUEEZY_API_KEY}`,
                'Content-Type': 'application/vnd.api+json',
                'Accept': 'application/vnd.api+json'
            }
        });

        const checkoutUrl = lsRes.data.data.attributes.url;
        const sep = checkoutUrl.includes('?') ? '&' : '?';
        return res.json({ url: checkoutUrl + sep + 'embed=1' });
    } catch (e) {
        console.error('LemonSqueezy API error:', e.response?.data || e.message);
        // Fallback: direct URL with variant pre-selected (still shows all options but correct one is active)
        const url = `https://sealch.lemonsqueezy.com/checkout/buy/${CHECKOUT_PRODUCT}?embed=1&checkout[variant_id]=${variantId}&checkout[email]=${emailEnc}&checkout[custom][app_email]=${emailEnc}`;
        return res.json({ url });
    }
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────
const requireAdmin = (req, res, next) => {
    if (!req.session || !req.session.isAdmin) return res.status(403).end();
    next();
};

app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
    const { password } = req.body;
    if (!password || typeof password !== 'string') {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    if (!ADMIN_PASSWORD) {
        console.error('⚠️  Admin login attempted but ADMIN_PASSWORD is not set');
        return res.status(500).json({ error: "Server misconfigured" });
    }
    const expected = Buffer.from(ADMIN_PASSWORD, 'utf8');
    const provided = Buffer.from(password, 'utf8');
    let match = false;
    if (expected.length === provided.length) {
        match = crypto.timingSafeEqual(expected, provided);
    }
    if (!match) {
        await new Promise(r => setTimeout(r, 50));
        return res.status(401).json({ error: "Invalid credentials" });
    }
    req.session.isAdmin = true;
    res.json({ success: true });
});

app.get('/api/admin/system', requireAdmin, (req, res) => {
    const totalRam = os.totalmem();
    const freeRam = os.freemem();
    const usedRam = totalRam - freeRam;
    const ramPct = ((usedRam / totalRam) * 100).toFixed(1);
    const cores = os.cpus().length;
    const loadAvg = os.loadavg()[0];
    const cpuPct = ((loadAvg / cores) * 100).toFixed(1);
    child_process.exec('df -k /', (err, stdout) => {
        let diskPct = 0, diskTotal = 0, diskUsed = 0;
        if (!err) {
            const lines = stdout.trim().split('\n');
            if (lines.length > 1) {
                const parts = lines[1].replace(/\s+/g, ' ').split(' ');
                diskTotal = Math.round(parseInt(parts[1]) / 1024 / 1024);
                diskUsed = Math.round(parseInt(parts[2]) / 1024 / 1024);
                diskPct = parseInt(parts[4].replace('%', ''));
            }
        }
        res.json({
            ram: { used: Math.round(usedRam/1024/1024/1024), total: Math.round(totalRam/1024/1024/1024), pct: ramPct },
            cpu: { pct: Math.min(cpuPct, 100).toFixed(1), cores },
            disk: { used: diskUsed, total: diskTotal, pct: diskPct }
        });
    });
});

app.get('/api/admin/nodes', requireAdmin, async (req, res) => {
    res.json(await NodeWorker.find({}).lean());
});

app.post('/api/admin/nodes/add', requireAdmin, async (req, res) => {
    const { id, ip } = req.body;
    if (!id || !ip) return res.status(400).json({ error: "Missing id or ip" });
    const url = ip.includes(':') ? `http://${ip}/v1/check_email` : `http://${ip}:8080/v1/check_email`;
    await NodeWorker.findOneAndUpdate({ id }, { url, active: true, used_today: 0 }, { upsert: true });
    await syncNodes();
    res.json({ success: true });
});

app.post('/api/admin/nodes/delete', requireAdmin, async (req, res) => {
    await NodeWorker.deleteOne({ id: req.body.id });
    await syncNodes();
    res.json({ success: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    res.json(await User.find().select('-password').lean());
});

app.post('/api/admin/users/update', requireAdmin, async (req, res) => {
    const { email, limit, lifetime, apiKey } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: "Invalid email" });
    const update = {};
    if (limit !== undefined && limit !== "") update.daily_limit = parseInt(limit);
    if (lifetime !== undefined && lifetime !== "") update.lifetime_credits = parseInt(lifetime);
    if (apiKey) update.apiKey = apiKey;
    await User.findOneAndUpdate({ email: email.toLowerCase().trim() }, update);
    res.json({ success: true });
});

app.post('/api/admin/reset-user', requireAdmin, async (req, res) => {
    if (!req.body.email || typeof req.body.email !== 'string') return res.status(400).json({ error: "Invalid email" });
    await User.findOneAndUpdate({ email: req.body.email.toLowerCase().trim() }, { used_today: 0 });
    res.json({ success: true });
});

app.post('/api/admin/delete', requireAdmin, async (req, res) => {
    if (!req.body.email || typeof req.body.email !== 'string') return res.status(400).json({ error: "Invalid email" });
    await User.findOneAndDelete({ email: req.body.email.toLowerCase().trim() });
    res.json({ success: true });
});

app.post('/api/admin/create-trial', requireAdmin, async (req, res) => {
    if (!req.body.email || typeof req.body.email !== 'string') return res.status(400).json({ error: "Invalid email" });
    await User.findOneAndUpdate({ email: req.body.email.toLowerCase().trim() }, { $inc: { daily_limit: 100 } });
    res.json({ success: true });
});

app.get('/api/admin/recent-scans', requireAdmin, async (req, res) => {
    try {
        const scans = await Scan.find().sort({ date: -1 }).limit(20).populate('userId', 'email').lean();
        res.json(scans);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch scans" });
    }
});

// ─── TICKETS (ADMIN) ────────────────────────────────────────────────────────
app.get('/api/admin/tickets', requireAdmin, async (req, res) => {
    res.json(await Ticket.find().populate('userId', 'email').sort({ updatedAt: -1 }).lean());
});

app.post('/api/admin/tickets/:id/reply', requireAdmin, async (req, res) => {
    const { message } = req.body;
    // Populate the userId so we have access to the user's email address
    const ticket = await Ticket.findById(req.params.id).populate('userId');
    if (!ticket) return res.status(404).json({ error: "Not found" });

    ticket.replies.push({ sender: 'admin', message });
    ticket.status = 'answered';
    ticket.updatedAt = new Date();
    await ticket.save();

    // Send email to user notifying them of the reply
    if (ticket.userId && ticket.userId.email) {
        const formattedMessage = message.replace(/\n/g, '<br>');
        const userMsg = `Our support team has replied to your ticket "<b>${ticket.subject}</b>".<br><br><div style="background:#111;padding:15px;border-radius:8px;border:1px solid #333;">${formattedMessage}</div>`;
        transporter.sendMail({
            from: '"Sealch Support" <tool@sealch.com>',
            to: ticket.userId.email,
            subject: `Re: ${ticket.subject}`,
            html: getTicketEmailHtml("Update on your Ticket", userMsg)
        }).catch(e => console.log("Mail Error:", e.message));
    }

    res.json({ success: true });
});

app.post('/api/admin/tickets/:id/close', requireAdmin, async (req, res) => {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ error: "Not found" });
    ticket.status = 'closed'; ticket.updatedAt = new Date();
    await ticket.save(); res.json({ success: true });
});

// ─── PROXY USAGE ADMIN ENDPOINT ────────────────────────────────────────────
app.get('/api/admin/proxy-usage', requireAdmin, async (req, res) => {
    const period = getProxyPeriod();
    const usage = await ProxyUsage.findOne({ period });
    const count = usage ? usage.count : 0;
    const limit = usage ? usage.limit : 600000;
    const now = new Date();
    let resetMonth = now.getUTCMonth(), resetYear = now.getUTCFullYear();
    if (now.getUTCDate() >= 7) { resetMonth++; if (resetMonth > 11) { resetMonth = 0; resetYear++; } }
    const resetDate = new Date(Date.UTC(resetYear, resetMonth, 7));
    const daysLeft = Math.ceil((resetDate - now) / 86400000);
    const [history, lock] = await Promise.all([
        ProxyUsage.find().sort({ period: -1 }).limit(3).lean(),
        ProxyLock.findOne({ _id: 'global' }).lean()
    ]);
    const liveActive = lock ? Math.max(0, lock.active) : 0;
    res.json({ period, count, limit, remaining: limit - count, pct: ((count / limit) * 100).toFixed(1), daysLeft, resetDate: resetDate.toISOString().split('T')[0], history, liveActive, liveMax: MAX_PROXY_CONCURRENT });
});

app.post('/api/admin/proxy-usage/override', requireAdmin, async (req, res) => {
    const { newCount } = req.body;
    if (newCount === undefined || typeof newCount !== 'number') {
        return res.status(400).json({ error: "Invalid count provided" });
    }

    const period = getProxyPeriod();
    await ProxyUsage.findOneAndUpdate(
        { period },
        { $set: { count: newCount, updatedAt: new Date() } },
        { upsert: true }
    );

    res.json({ success: true, message: `Proxy usage forced to ${newCount}` });
});

// ─── WEBHOOK ──────────────────────────────────────────────────────────────────
app.post('/api/webhook', async (req, res) => {
    if (!WEBHOOK_SECRET || !req.rawBody) {
        console.error('⛔ Webhook rejected: WEBHOOK_SECRET not configured or raw body missing');
        return res.status(500).send('Webhook not configured');
    }
    const sig = req.headers['x-signature'];
    if (!sig) return res.status(401).send('Missing signature');
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const digest = hmac.update(req.rawBody).digest('hex');
    if (sig !== digest) {
        console.error('⛔ Webhook signature mismatch — possible forgery attempt');
        return res.status(401).send('Invalid signature');
    }

    try {
        const event = req.body;
        const eventName = event.meta.event_name;

        // Extract the true account email from custom_data, fallback to billing email
        const rawEmail = (event.meta.custom_data && event.meta.custom_data.app_email)
            ? event.meta.custom_data.app_email
            : event.data.attributes.user_email;

        if (!rawEmail) {
            console.error('⛔ Webhook received without an email address');
            return res.status(200).send('OK');
        }

        const userEmail = rawEmail.toLowerCase().trim();

        if (eventName === 'order_created') {
            const amountPaidCents = event.data.attributes.total || 0;
            if (amountPaidCents > 0) {
                const commissionUsd = (amountPaidCents * 0.20) / 100;
                const purchasingUser = await User.findOne({ email: userEmail });
                if (purchasingUser && purchasingUser.referredBy) {
                    await User.findByIdAndUpdate(purchasingUser.referredBy, { $inc: { referralEarnings: commissionUsd } });
                    console.log(`💸 Affiliate: Added $${commissionUsd.toFixed(2)} to referrer`);
                }
            }

            const firstItem = event.data.attributes.first_order_item;
            if (firstItem) {
                const purchasedVariant = firstItem.variant_id.toString();
                let addedCredits = 0;
                if (purchasedVariant === "1506732") addedCredits = 10000;
                else if (purchasedVariant === "1506743") addedCredits = 100000;
                else if (purchasedVariant === "1506746") addedCredits = 500000;
                else if (purchasedVariant === "1506749") addedCredits = 1000000;

                if (addedCredits > 0) {
                    const updatedUser = await User.findOneAndUpdate(
                        { email: userEmail },
                        { $inc: { lifetime_credits: addedCredits } },
                        { new: true }
                    );
                    if (updatedUser) {
                        console.log(`💰 PAYG Purchase: Added ${addedCredits} credits to ${userEmail}`);
                    } else {
                        console.error(`❌ PAYG Purchase Failed: User ${userEmail} not found in DB! Variant: ${purchasedVariant}`);
                    }
                } else {
                    console.error(`⚠️ PAYG Purchase Ignored: Variant ID ${purchasedVariant} not recognized for ${userEmail}`);
                }
            } else {
                console.error(`⚠️ Webhook error: No first_order_item found for ${userEmail}`);
            }
            return res.status(200).send('OK');
        }

        // Subscription events
        const attributes = event.data.attributes;
        const variantId = attributes.variant_id ? attributes.variant_id.toString() : null;
        const subStatus = attributes.status;

        if (subStatus === 'expired' || subStatus === 'unpaid') {
            // Only reset daily_limit if the user was a subscriber (daily_limit > 0).
            // PAYG users have daily_limit = 0 and must never be touched here.
            const resetResult = await User.findOneAndUpdate(
                { email: userEmail, daily_limit: { $gt: 0 } },
                { daily_limit: 100 }
            );
            if (resetResult) {
                console.log(`❌ Subscription Expired: ${userEmail} → 100`);
            } else {
                console.log(`⚠️ Expiry webhook for ${userEmail} skipped — user not found or is PAYG`);
            }
            return res.status(200).send('OK');
        }

        if (subStatus === 'active' || subStatus === 'on_trial' || subStatus === 'cancelled') {
            // Legacy custom rule
            if (userEmail === 'amr@amrico.net') {
                if (eventName === 'subscription_created' || eventName === 'subscription_payment_success') {
                    await User.findOneAndUpdate({ email: userEmail }, { daily_limit: 0, $inc: { lifetime_credits: 150000 } });
                } else {
                    await User.findOneAndUpdate({ email: userEmail }, { daily_limit: 0 });
                }
                return res.status(200).send('OK');
            }

            let newLimit = 100;
            // Old & New Starter (1k)
            if (["1354731","1361604","1529909","1529927"].includes(variantId)) newLimit = 1000;
            // Old & New Growth (5k)
            else if (["1354737","1361607","1529925","1529932"].includes(variantId)) newLimit = 5000;
            // Old & New Power (9k)
            else if (["1354739","1361609","1529926","1529934"].includes(variantId)) newLimit = 9000;
            // Custom Enterprise Tier (20k)
            else if (["1716289"].includes(variantId)) newLimit = 20000;

            await User.findOneAndUpdate({ email: userEmail }, { daily_limit: newLimit });
            console.log(`✅ Credit Update: ${userEmail} → ${newLimit} (Variant: ${variantId})`);
            // Tag as paid in Loops to stop trial emails
            sendToLoops(userEmail, null, { userStatus: 'paid' });
            return res.status(200).send('OK');
        }

        res.status(200).send('Ignored Event');
    } catch (err) {
        console.error('Webhook Internal Error:', err);
        res.status(500).send('Internal Error');
    }
});

// ─── DATA RETENTION WARNING CRON ──────────────────────────────────────────────
const getRetentionEmailHtml = (daysLeft) => {
    return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f1f5f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:48px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:540px;margin:0 auto;">
    <tr><td style="padding-bottom:24px;"><img src="https://sealch.com/sealch--logo.png" alt="Sealch" height="28" style="display:block;"></td></tr>
    <tr><td style="background:#ffffff;border-radius:12px;border:1px solid #e2e8f0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="height:4px;background:#f59e0b;border-radius:12px 12px 0 0;font-size:0;">&nbsp;</td></tr>
        <tr><td style="padding:36px 40px 32px;">
          <p style="margin:0 0 6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:#d97706;">Data Retention</p>
          <h1 style="margin:0 0 12px;font-size:22px;font-weight:800;color:#0f172a;letter-spacing:-0.01em;">Your scan history is expiring</h1>
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
            <tr><td style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 20px;">
              <span style="font-size:14px;font-weight:700;color:#92400e;">&#9200; Deleting in ${daysLeft}</span>
            </td></tr>
          </table>
          <p style="margin:0 0 14px;font-size:14px;color:#374151;line-height:1.7;">Your scan history is automatically deleted after 30 days to protect your privacy. Files scheduled for deletion will be permanently removed in <strong>${daysLeft}</strong>.</p>
          <p style="margin:0 0 28px;font-size:14px;color:#374151;line-height:1.7;">Log in now and download your CSV files before they're gone.</p>
          <table role="presentation" cellpadding="0" cellspacing="0">
            <tr><td style="background:#059669;border-radius:8px;">
              <a href="https://app.sealch.com/?mode=login" style="display:inline-block;padding:12px 24px;font-size:14px;font-weight:700;color:#ffffff;text-decoration:none;">Download CSVs &rarr;</a>
            </td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:16px 40px;background:#f8fafc;border-top:1px solid #f1f5f9;border-radius:0 0 12px 12px;">
          <p style="margin:0;font-size:11.5px;color:#94a3b8;">© 2026 Sealch Pro &nbsp;·&nbsp; <a href="https://sealch.com" style="color:#94a3b8;text-decoration:none;">sealch.com</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
};

cron.schedule('0 12 * * *', async () => {
    if (process.env.NODE_APP_INSTANCE !== '0') return;
    const now = Date.now();
    const dayInMs = 24 * 60 * 60 * 1000;

    // Find scans exactly 23 days old (7 days warning)
    const start23 = new Date(now - (24 * dayInMs));
    const end23 = new Date(now - (23 * dayInMs));

    // Find scans exactly 29 days old (24h warning)
    const start29 = new Date(now - (30 * dayInMs));
    const end29 = new Date(now - (29 * dayInMs));

    const warnUsers = async (start, end, messageStr) => {
        const expiringScans = await Scan.find({ date: { $gte: start, $lt: end } }).populate('userId');
        const notifiedUsers = new Set();
        for (const scan of expiringScans) {
            if (scan.userId && scan.userId.email && !notifiedUsers.has(scan.userId.email)) {
                notifiedUsers.add(scan.userId.email);
                transporter.sendMail({
                    from: '"Sealch Pro" <tool@sealch.com>',
                    to: scan.userId.email,
                    subject: `Action Required: Scan history deleting in ${messageStr}`,
                    html: getRetentionEmailHtml(messageStr)
                }).catch(()=>{});
            }
        }
    };

    await warnUsers(start23, end23, "7 days");
    await warnUsers(start29, end29, "24 hours");
});

// ─── CRON — MIDNIGHT RESET ────────────────────────────────────────────────────
cron.schedule('0 0 * * *', async () => {
    if (process.env.NODE_APP_INSTANCE !== '0') return;
    const todayStr = new Date().toISOString().split('T')[0];
    const sevenDaysInMs = 7 * 24 * 60 * 60 * 1000;
    const now = Date.now();

    await User.updateMany({}, [
        {
            $set: {
                usage_history: {
                    $slice: [
                        { $concatArrays: ["$usage_history", [{ date: todayStr, count: "$used_today" }]] },
                        -7
                    ]
                },
                used_today: 0
            }
        }
    ]).catch(() => {
        User.find({}).then(users => {
            for (let u of users) {
                u.usage_history.push({ date: todayStr, count: u.used_today });
                if (u.usage_history.length > 7) u.usage_history.shift();
                u.used_today = 0;
                if (u.daily_limit === 100 && (now - new Date(u.createdAt).getTime()) > sevenDaysInMs) {
                    u.daily_limit = 0;
                }
                u.save();
            }
        });
    });

    await User.updateMany(
        {
            daily_limit: 100,
            createdAt: { $lt: new Date(now - sevenDaysInMs) }
        },
        { $set: { daily_limit: 0 } }
    );

    // Reset daily worker usage AND error counts
    await NodeWorker.updateMany({}, { used_today: 0, error_count: 0 });

    // CLEANUP: Delete scan files older than 30 days
    const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);
    const oldScans = await Scan.find({ date: { $lt: new Date(thirtyDaysAgo) } });
    for (const scan of oldScans) {
        const filePath = path.join(SCANS_DIR, scan.fileName);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    await Scan.deleteMany({ date: { $lt: new Date(thirtyDaysAgo) } });

    console.log('✅ Daily reset complete');
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    try {
        const dbState = mongoose.connection.readyState;
        const workerCount = activeWorkers.length;
        res.json({
            status: dbState === 1 ? 'healthy' : 'degraded',
            db: dbState === 1 ? 'connected' : 'disconnected',
            workers: workerCount,
            uptime: Math.round(process.uptime()),
            memory: Math.round(process.memoryUsage().rss / 1024 / 1024) + 'MB'
        });
    } catch (e) {
        res.status(500).json({ status: 'unhealthy', error: e.message });
    }
});

// ─── AI CHATBOT PROXY ─────────────────────────────────────────────────────────
app.post('/api/chat', chatLimiter, async (req, res) => {
    const { messages } = req.body;

    if (!Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Invalid payload' });
    }
    if (messages.length > CHATBOT_MAX_MESSAGES) {
        return res.status(400).json({ error: 'Conversation too long. Refresh to start over.' });
    }
    for (const msg of messages) {
        if (!msg || typeof msg !== 'object') return res.status(400).json({ error: 'Invalid message' });
        if (msg.role !== 'user' && msg.role !== 'assistant') return res.status(400).json({ error: 'Invalid role' });
        if (typeof msg.content !== 'string') return res.status(400).json({ error: 'Invalid content' });
        if (msg.content.length > CHATBOT_MAX_MESSAGE_LENGTH) {
            return res.status(400).json({ error: 'Message too long' });
        }
    }

    try {
        const response = await axios.post('https://api.anthropic.com/v1/messages', {
            model: CHATBOT_MODEL,
            max_tokens: CHATBOT_MAX_TOKENS,
            system: CHATBOT_SYSTEM_PROMPT,
            messages: messages
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': process.env.ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
            },
            timeout: 30000
        });
        res.json(response.data);
    } catch (err) {
        console.error('Chat error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Chat service unavailable' });
    }
});

// ─── START SERVER & GRACEFUL SHUTDOWN ─────────────────────────────────────────
const server = app.listen(3000, '0.0.0.0', () => {
    console.log('🚀 GATEKEEPER PRO ONLINE ON 3000');
    // Tell PM2 we are ready to receive traffic (useful for reload)
    if (process.send) process.send('ready');
});

function gracefulShutdown(signal) {
    console.log(`🛑 ${signal} received. Shutting down gracefully...`);

    server.close(() => {
        console.log('✅ All active HTTP requests finished.');
        mongoose.connection.close(false).then(() => {
            console.log('✅ MongoDB connection closed.');
            process.exit(0);
        });
    });

    setTimeout(() => {
        console.error('⚠️ Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 15000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
// PM2 sends SIGTERM for graceful reload — without this handler the process gets SIGKILL'd immediately
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
