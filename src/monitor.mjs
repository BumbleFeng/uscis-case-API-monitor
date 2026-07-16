import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { chromium } from "playwright";

const cwd = process.cwd();
const stateDir = path.join(cwd, "state");
const snapshotsDir = path.join(cwd, "snapshots");
const authFile = path.join(stateDir, "auth.json");
const lastFile = path.join(stateDir, "last.json");
const configFile = path.join(cwd, "config.local.json");
const exampleConfigFile = path.join(cwd, "config.example.json");

const LOGIN_EMAIL_SELECTORS = [
  'input[type="email"]',
  'input[name*="email" i]',
  'input[name*="username" i]',
  'input[id*="username" i]',
  'input[id*="email" i]',
  'input[placeholder*="email" i]',
  'input[placeholder*="username" i]',
  'input[autocomplete="username"]',
  'input[type="text"]',
];

const LOGIN_PASSWORD_SELECTORS = [
  'input[type="password"]',
  'input[name*="password" i]',
  'input[autocomplete="current-password"]',
];

const OTP_INPUT_SELECTORS = [
  '#secure-verification-code',
  '[data-testid="test-secure-verification-code"]',
  'input[autocomplete="one-time-code"]',
  'input[name*="code" i]',
  'input[id*="code" i]',
  'input[inputmode="numeric"]',
  'input[type="tel"]',
];

const BUTTON_TEXTS = [/sign in/i, /log in/i, /submit/i, /continue/i, /verify/i];

function ensureDirs() {
  fs.mkdirSync(stateDir, { recursive: true });
  fs.mkdirSync(snapshotsDir, { recursive: true });
}

function loadConfig() {
  const source = fs.existsSync(configFile) ? configFile : exampleConfigFile;
  return JSON.parse(fs.readFileSync(source, "utf8"));
}

function loginIdentifier(config) {
  return config.uscisUsername || config.uscisEmail;
}

function getApiUrls(config) {
  if (Array.isArray(config.apiUrls)) return config.apiUrls;
  if (config.apiUrl) {
    return [{ key: "caseStatus", label: "Case Status", url: `${config.apiUrl}/{receiptNumber}` }];
  }
  return [];
}

function resolveUrl(template, receiptNumber) {
  return template.replace(/{receiptNumber}/g, receiptNumber);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function isVerificationPageUrl(url) {
  const lower = url.toLowerCase();
  return lower.includes("verification") || lower.includes("two-factor") || lower.includes("2fa");
}

async function firstVisible(page, selectors, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const selector of selectors) {
      const locator = page.locator(selector).first();
      if (await locator.count()) {
        const visible = await locator.isVisible().catch(() => false);
        if (visible) {
          return locator;
        }
      }
    }
    await page.waitForTimeout(250);
  }
  return null;
}

async function firstVisibleInPageOrFrames(page, selectors, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const fromPage = await firstVisible(page, selectors, 500);
    if (fromPage) {
      return fromPage;
    }
    for (const frame of page.frames()) {
      for (const selector of selectors) {
        const locator = frame.locator(selector).first();
        if (await locator.count()) {
          const visible = await locator.isVisible().catch(() => false);
          if (visible) {
            return locator;
          }
        }
      }
    }
    await page.waitForTimeout(250);
  }
  return null;
}

async function clickButton(page, regexes) {
  const preferredSelectors = [
    '[data-testid="sign-in-btn"]',
    '#sign-in-btn',
    'button[id="sign-in-btn"]',
  ];
  
  // Try preferred selectors first
  for (const selector of preferredSelectors) {
    const button = page.locator(selector).first();
    if (await button.count() && await button.isVisible().catch(() => false)) {
      console.log(`    Found button: ${selector}`);
      await button.click({ timeout: 5000 }).catch(() => {});
      return true;
    }
  }
  
  // Try by text/role
  for (const regex of regexes) {
    const button = page.getByRole("button", { name: regex }).first();
    if (await button.count()) {
      console.log(`    Found button by role: ${regex}`);
      await button.click({ timeout: 5000 }).catch(() => {});
      return true;
    }
    
    const input = page.locator('input[type="submit"], button').filter({ hasText: regex }).first();
    if (await input.count()) {
      console.log(`    Found submit by text: ${regex}`);
      await input.click({ timeout: 5000 }).catch(() => {});
      return true;
    }
  }
  
  return false;
}

async function waitForPostSubmitChange(page, timeout = 5000) {
  const startUrl = page.url();
  const startHtml = await page.content().catch(() => "");
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    await page.waitForTimeout(250);
    const currentUrl = page.url();
    if (currentUrl !== startUrl) {
      return true;
    }
    const currentHtml = await page.content().catch(() => "");
    if (currentHtml !== startHtml) {
      return true;
    }
  }
  return false;
}

function readOtp(otpConfig) {
  const mode = otpConfig?.mode || "imap";
  
  if (mode === "imap") {
    // Use IMAP email mode
    if (!otpConfig) {
      throw new Error("OTP config required for IMAP mode");
    }
    return new Promise((resolve, reject) => {
      const child = spawn(
        "python3",
        [path.join("src", "email_otp.py"), "--config-json", JSON.stringify(otpConfig)],
        {
          cwd,
          stdio: ["ignore", "pipe", "inherit"],
        },
      );

      let stdout = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", (error) => {
        reject(error);
      });

      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error("Failed to read OTP from email"));
          return;
        }
        resolve(stdout.trim());
      });
    });
  } else if (mode === "sms-imessage") {
    // Use macOS Messages (iMessage) mode
    if (!otpConfig) {
      throw new Error("OTP config required for SMS/iMessage mode");
    }
    return new Promise((resolve, reject) => {
      const child = spawn(
        "python3",
        [path.join("src", "sms_imessage.py"), "--config-json", JSON.stringify(otpConfig)],
        {
          cwd,
          stdio: ["ignore", "pipe", "inherit"],
        },
      );

      let stdout = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.on("error", (error) => {
        reject(error);
      });

      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error("Failed to read OTP from SMS/iMessage"));
          return;
        }
        resolve(stdout.trim());
      });
    });
  } else {
    throw new Error(`Unsupported OTP mode: ${mode}`);
  }
}

// Legacy function for backward compatibility
function readOtpFromEmail(otpConfig) {
  return readOtp(otpConfig);
}

function normalizeOtp(rawCode) {
  const digitsOnly = String(rawCode || "").replace(/\D+/g, "");
  if (digitsOnly.length >= 6) {
    return digitsOnly.slice(0, 6);
  }
  return String(rawCode || "").trim();
}

async function typeLikeHuman(locator, value) {
  await locator.focus().catch(() => {});
  await locator.click({ clickCount: 3 }).catch(() => {});
  await locator.press("Backspace").catch(() => {});
  for (const char of String(value)) {
    await locator.type(char, { delay: 90 + Math.floor(Math.random() * 80) }).catch(async () => {
      await locator.fill(String(value)).catch(() => {});
    });
  }

  // Some React forms only validate after input/change/blur events.
  await locator.evaluate((node) => {
    node.dispatchEvent(new Event("input", { bubbles: true }));
    node.dispatchEvent(new Event("change", { bubbles: true }));
    node.dispatchEvent(new Event("blur", { bubbles: true }));
  }).catch(() => {});
}

async function waitForOtpPostSubmit(page, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    await page.waitForTimeout(300);
    const stillOnOtp = await firstVisibleInPageOrFrames(page, OTP_INPUT_SELECTORS, 300);
    if (!stillOnOtp) {
      return true;
    }
  }
  return false;
}

async function looksLoggedOut(page) {
  const url = page.url().toLowerCase();
  if (isVerificationPageUrl(url)) {
    return false;
  }
  if (url.includes("/oidc/login") || url.includes("/oauth/authorize")) {
    return true;
  }
  for (const selector of [...LOGIN_EMAIL_SELECTORS, ...LOGIN_PASSWORD_SELECTORS]) {
    const locator = page.locator(selector).first();
    if (await locator.count()) {
      const visible = await locator.isVisible().catch(() => false);
      if (visible) {
        return true;
      }
    }
  }
  return false;
}

async function fillFirst(page, selectors, value) {
  const input = await firstVisibleInPageOrFrames(page, selectors);
  if (!input) {
    const summary = await pageSummary(page);
    await writeDebugSnapshot(page, "missing-input");
    throw new Error(
      `Could not find input for selectors: ${selectors.join(", ")}\nURL: ${summary.url}\nTitle: ${summary.title}\nHeading: ${summary.heading}\nAlert: ${summary.alert}\nText: ${summary.text.slice(0, 300)}`,
    );
  }
  await input.fill(value);
}

async function pageSummary(page) {
  const summary = await page.evaluate(() => {
    const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 1000);
    const heading = document.querySelector("h1,h2,h3")?.textContent?.trim() || "";
    const alert =
      document.querySelector('[role="alert"], .usa-alert, .alert, .error, [data-testid*="error" i]')?.textContent?.trim() || "";
    return {
      title: document.title,
      heading,
      alert,
      text,
    };
  });
  return {
    url: page.url(),
    ...summary,
  };
}

async function writeDebugSnapshot(page, label) {
  const stamp = new Date().toISOString().replaceAll(":", "-");
  const base = path.join(snapshotsDir, `${stamp}-${label}`);
  await page.screenshot({ path: `${base}.png`, fullPage: true }).catch(() => {});
  const html = await page.content().catch(() => "");
  if (html) {
    fs.writeFileSync(`${base}.html`, html, "utf8");
  }
  return base;
}

async function maybeHandleOtp(page, config) {
  console.log("  Finding OTP input field...");
  const otpInput = page.locator(OTP_INPUT_SELECTORS.join(", ")).first();
  const visible = await otpInput.isVisible().catch(() => false);
  if (!visible) {
    console.log("  No OTP input field found");
    return false;
  }

  try {
    const mode = config.otp?.mode || "imap";
    const modeLabel = mode === "sms-imessage" ? "SMS/iMessage" : "email";
    console.log(`  Mode: ${modeLabel}`);
    
    // Validate OTP config exists
    if (!config.otp) {
      throw new Error("OTP configuration not found");
    }
    
    console.log(`  Reading OTP code from ${modeLabel}...`);
    const rawCode = await readOtp(config.otp);
    const code = normalizeOtp(rawCode);
    console.log(`  ✓ Code retrieved: ${code.substring(0, 2)}***`);

    console.log(`  Filling code into input...`);
    await otpInput.fill(code).catch(() => {});
    await otpInput.evaluate((node) => {
      node.dispatchEvent(new Event("input", { bubbles: true }));
      node.dispatchEvent(new Event("change", { bubbles: true }));
    }).catch(() => {});
    
    await page.waitForTimeout(500);
    await writeDebugSnapshot(page, "otp-filled");

    // Try multiple submit methods
    console.log(`  Submitting code...`);
    
    // Method 1: Look for explicit submit button
    const submitBtn = page.locator('button, input[type="submit"]').filter({ hasText: /submit|verify|continue/i }).first();
    if (await submitBtn.count()) {
      console.log("    Clicking submit button...");
      await submitBtn.click().catch(() => {});
      await page.waitForTimeout(1000);
      
      if (await waitForOtpPostSubmit(page, 8000)) {
        console.log("  ✓ OTP accepted");
        return true;
      }
    }

    // Method 2: Press Enter
    console.log("    Trying Enter key...");
    await otpInput.press("Enter").catch(() => {});
    await page.waitForTimeout(1000);
    
    if (await waitForOtpPostSubmit(page, 8000)) {
      console.log("  ✓ OTP accepted");
      return true;
    }

    console.log("  ✓ OTP submitted (may still be processing)");
    return true;
  } catch (error) {
    console.error(`  ✗ OTP error: ${error.message}`);
    throw error;
  }
}

async function submitLogin(page) {
  console.log("Attempting to submit login form...");
  const startUrl = page.url();

  // Try clicking login button (single click only)
  console.log("  Trying to click login button...");
  const clicked = await clickButton(page, [/(sign|log)\s*in/i, /continue/i, /next/i]);
  
  if (!clicked) {
    // Fallback: press Enter on password field
    console.log("  No button found, pressing Enter...");
    const passwordInput = await firstVisibleInPageOrFrames(page, LOGIN_PASSWORD_SELECTORS, 3000);
    if (passwordInput) {
      await passwordInput.press("Enter").catch(() => {});
    } else {
      throw new Error("Cannot find login button or password field to submit");
    }
  }

  // Wait for page navigation or OTP page (up to 15s)
  console.log("  Waiting for page response...");
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    await page.waitForTimeout(500);
    
    // Check URL changed
    if (page.url() !== startUrl) {
      console.log("  ✓ Page navigated");
      return;
    }
    
    // Check if OTP input appeared (same URL but different content)
    const otpVisible = await page.locator(OTP_INPUT_SELECTORS.join(", ")).first().isVisible().catch(() => false);
    if (otpVisible) {
      console.log("  ✓ OTP page detected");
      return;
    }
  }

  // First attempt timed out — try Enter key fallback and wait another 15s
  console.log("  ⚠️ No navigation after 15s, trying Enter key fallback...");
  const passwordInput = await firstVisibleInPageOrFrames(page, LOGIN_PASSWORD_SELECTORS, 2000);
  if (passwordInput) {
    await passwordInput.press("Enter").catch(() => {});
  }

  const deadline2 = Date.now() + 15000;
  while (Date.now() < deadline2) {
    await page.waitForTimeout(500);
    if (page.url() !== startUrl) {
      console.log("  ✓ Page navigated after Enter fallback");
      return;
    }
    const otpVisible = await page.locator(OTP_INPUT_SELECTORS.join(", ")).first().isVisible().catch(() => false);
    if (otpVisible) {
      console.log("  ✓ OTP page detected after Enter fallback");
      return;
    }
  }

  console.log("  ⚠️ No navigation detected after extended wait — login form submit may have failed");
}

async function browserWithState(useSavedState) {
  const storageState = useSavedState && fs.existsSync(authFile) ? authFile : undefined;
  const browser = await chromium.launch({
    channel: "chrome",
    headless: false,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--disable-dev-shm-usage',
      // Disable detection of being automated
      '--disable-features=IsolateOrigins,site-per-process',
    ],
  });
  const context = await browser.newContext({
    storageState,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    locale: 'en-US',
    timezoneId: 'America/New_York',
    colorScheme: 'light',
  });
  
  // Stealth mode: hide webdriver property
  const page = await context.newPage();
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'webdriver', {
      get: () => false,
    });
    // Hide chrome detection
    if (window.chrome === undefined) {
      window.chrome = {};
    }
    Object.defineProperty(window, 'chrome', {
      get: () => ({
        runtime: {}
      }),
    });
  });
  
  return { browser, context, page };
}

async function login(config) {
  const { browser, context, page } = await browserWithState(false);
  try {
    console.log("Starting login process...");
    console.log(`Navigating to ${config.loginUrl}`);
    await page.goto(config.loginUrl, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2000); // Allow time for JavaScript to load
    
    console.log("Filling email/username...");
    await fillFirst(page, LOGIN_EMAIL_SELECTORS, loginIdentifier(config));
    await page.waitForTimeout(500);
    
    console.log("Filling password...");
    await fillFirst(page, LOGIN_PASSWORD_SELECTORS, config.uscisPassword);
    await page.waitForTimeout(500);
    
    await writeDebugSnapshot(page, "login-form-filled");
    console.log("✓ Login form filled");

    console.log("Submitting login form...");
    await submitLogin(page);
    
    console.log("Waiting for page to load after login...");
    await page.waitForLoadState("domcontentloaded").catch(() => {});
    await page.waitForTimeout(3000);
    await writeDebugSnapshot(page, "after-primary-submit");

    console.log("Checking for OTP requirement...");
    try {
      console.log("Looking for OTP input (checking for 12 seconds)...");
      const otpInput = await firstVisibleInPageOrFrames(page, OTP_INPUT_SELECTORS, 12000).catch(() => null);
      
      if (otpInput) {
        console.log("✓ OTP input found, proceeding with OTP handling...");
        const handledOtp = await maybeHandleOtp(page, config);
        if (handledOtp) {
          console.log("✓ OTP submitted");
          await page.waitForLoadState("domcontentloaded").catch(() => {});
          await page.waitForTimeout(3000);
          await writeDebugSnapshot(page, "after-otp-submit");
        }
      } else {
        console.log("No OTP input found - proceeding without OTP");
      }
    } catch (otpError) {
      console.error(`⚠️  OTP handling error (continuing): ${otpError.message}`);
      await writeDebugSnapshot(page, "otp-error");
    }

    console.log(`Waiting ${config.postLoginWaitMs ?? 5000}ms before navigating to monitor URL...`);
    await page.waitForTimeout(config.postLoginWaitMs ?? 5000);
    
    console.log(`Navigating to ${config.monitorUrl}`);
    await page.goto(config.monitorUrl, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(3000);
    
    console.log("Checking if logged in successfully...");
    if (await looksLoggedOut(page)) {
      const summary = await pageSummary(page);
      await writeDebugSnapshot(page, "login-failed");
      throw new Error(
        `Login did not stick. URL: ${summary.url}\nTitle: ${summary.title}\nHeading: ${summary.heading}\nAlert: ${summary.alert}\nText: ${summary.text.slice(0, 300)}`,
      );
    }
    
    console.log("✓ Successfully logged in!");

    // Validate the session actually works via a real API call before saving
    const apiUrls = getApiUrls(config);
    if (apiUrls.length > 0 && config.receiptNumbers?.length > 0) {
      console.log("Validating session via API...");
      const cookies = await context.cookies();
      const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join("; ");
      const testReceipt = config.receiptNumbers[0];
      const testUrl = resolveUrl(apiUrls[0].url, testReceipt);
      try {
        const testRes = await fetch(testUrl, {
          headers: {
            "Cookie": cookieHeader,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json",
            "Referer": config.monitorUrl,
          },
        });
        if (testRes.status === 401) {
          throw new Error("API validation failed: 401 Unauthorized — session not actually established");
        }
        if (testRes.ok) {
          const data = await testRes.json().catch(() => null);
          if (data && data.data === null && data.error) {
            throw new Error("API validation failed: session token rejected by USCIS API");
          }
        }
        console.log("✓ API session validated");
      } catch (err) {
        if (err.message.startsWith("API validation failed")) {
          throw new Error(`Login appeared to succeed but auth is invalid: ${err.message}`);
        }
        console.warn(`⚠️ Could not validate API session: ${err.message} (saving anyway)`);
      }
    }

    await context.storageState({ path: authFile });
    console.log(`✓ Saved authenticated session to ${authFile}`);
  } finally {
    await browser.close();
  }
}

async function extractMonitoredText(page, config) {
  await page.goto(config.monitorUrl, { waitUntil: "domcontentloaded" });
  if (await looksLoggedOut(page)) {
    await writeDebugSnapshot(page, "poll-session-expired");
    throw new Error("Session expired. Run `npm run reauth`.");
  }
  if (config.monitorReadySelector) {
    await page.locator(config.monitorReadySelector).first().waitFor({ timeout: 30000 });
  }
  const contentLocator = page.locator(config.contentSelector || "body").first();
  await contentLocator.waitFor({ timeout: 30000 });
  const text = (await contentLocator.innerText()).replace(/\s+/g, " ").trim();
  const html = await contentLocator.innerHTML();
  return { text, html };
}

function requireAuthState() {
  if (!fs.existsSync(authFile)) {
    throw new Error("Missing state/auth.json. Run `npm run login` first.");
  }
}

function saveSnapshot(prefix, text, html) {
  const stamp = new Date().toISOString().replaceAll(":", "-");
  const textFile = path.join(snapshotsDir, `${stamp}-${prefix}.txt`);
  const htmlFile = path.join(snapshotsDir, `${stamp}-${prefix}.html`);
  fs.writeFileSync(textFile, `${text}\n`, "utf8");
  fs.writeFileSync(htmlFile, html, "utf8");
  return { textFile, htmlFile };
}

const caseHistoryFile = path.join(stateDir, "case-history.json");

function loadCaseHistory() {
  if (!fs.existsSync(caseHistoryFile)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(caseHistoryFile, "utf8"));
  } catch (e) {
    console.warn("Could not parse case history, starting fresh");
    return {};
  }
}

function saveCaseHistory(history) {
  fs.writeFileSync(caseHistoryFile, JSON.stringify(history, null, 2) + "\n", "utf8");
}

function deepHash(obj) {
  // Create a hash of the object for change detection
  return sha256(JSON.stringify(obj || {}));
}

function migrateHistoryRecord(record) {
  if (!record?.current) return record;
  if (record.current.data !== undefined && !record.current.caseStatus) {
    return {
      ...record,
      current: { caseStatus: record.current },
      previous: record.previous?.data !== undefined ? { caseStatus: record.previous } : record.previous,
    };
  }
  return record;
}

function detectChanges(previousData, currentData) {
  const changes = {};

  if (!previousData) {
    return { isChanged: true, changes: {}, summary: "New case" };
  }

  // Case Status endpoint — detailed field comparison
  const prevCase = previousData.caseStatus;
  const currCase = currentData.caseStatus;
  if (currCase?.data) {
    const prevD = prevCase?.data || {};
    const currD = currCase.data;

    if (prevD.updatedAt !== currD.updatedAt) {
      changes.updatedAt = { from: prevD.updatedAt, to: currD.updatedAt };
    }

    const prevEventCount = (prevD.events || []).length;
    const currEventCount = (currD.events || []).length;
    if (prevEventCount !== currEventCount) {
      changes.events = {
        from: prevEventCount,
        to: currEventCount,
        newEvents: (currD.events || []).slice(prevEventCount),
      };
    }

    if (prevD.closed !== currD.closed) {
      changes.closed = { from: prevD.closed, to: currD.closed };
    }

    if (prevD.actionRequired !== currD.actionRequired) {
      changes.actionRequired = { from: prevD.actionRequired, to: currD.actionRequired };
    }
  }

  // Other endpoints — hash comparison
  for (const key of Object.keys(currentData)) {
    if (key === "caseStatus") continue;
    const curr = currentData[key];
    if (!curr) continue;
    const prev = previousData[key];
    if (!prev || deepHash(prev) !== deepHash(curr)) {
      changes[key] = { changed: true };
    }
  }

  const isChanged = Object.keys(changes).length > 0;

  let summary = "No changes";
  if (isChanged) {
    const parts = [];
    if (changes.events?.newEvents?.length) {
      const latest = changes.events.newEvents[changes.events.newEvents.length - 1];
      parts.push(`${changes.events.newEvents.length} new event(s): ${latest.actionCodeText || "Unknown"}`);
    }
    if (changes.updatedAt) {
      parts.push(`updated ${changes.updatedAt.from || "N/A"} → ${changes.updatedAt.to || "N/A"}`);
    }
    if (changes.closed) {
      parts.push(changes.closed.to ? "case CLOSED" : "case RE-OPENED");
    }
    if (changes.actionRequired) {
      parts.push(changes.actionRequired.to ? "ACTION REQUIRED" : "action no longer required");
    }
    for (const key of Object.keys(changes)) {
      if (["events", "updatedAt", "closed", "actionRequired"].includes(key)) continue;
      parts.push(`${key} data changed`);
    }
    summary = parts.join("; ");
  }

  return { isChanged, changes, summary };
}

async function getCookies(config) {
  // Read cookies from saved auth state
  let cookies = [];
  try {
    const authState = JSON.parse(fs.readFileSync(authFile, "utf8"));
    if (authState.cookies) {
      cookies = authState.cookies;
    }
  } catch (e) {
    console.warn("⚠️  Could not read cookies from auth state, trying without cookies...");
  }
  
  // Build Cookie header
  return cookies.map(c => `${c.name}=${c.value}`).join("; ");
}

async function fetchEndpoint(url, config) {
  const cookieHeader = await getCookies(config);

  let response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: {
        "Cookie": cookieHeader,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Referer": config.monitorUrl,
      },
    });
  } catch (networkErr) {
    const err = new Error(`Network error: ${networkErr.message}`);
    err.code = "NETWORK_ERROR";
    throw err;
  }

  if (response.status === 401) {
    const error = new Error("SESSION_EXPIRED");
    error.code = "SESSION_EXPIRED";
    error.statusCode = 401;
    throw error;
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();

  if (data.data === null && data.error) {
    const error = new Error("SESSION_EXPIRED");
    error.code = "SESSION_EXPIRED";
    error.apiError = data.error;
    throw error;
  }

  return data;
}

async function fetchAllEndpoints(receiptNumber, config) {
  const apiUrls = getApiUrls(config);
  const results = {};

  for (const endpoint of apiUrls) {
    const url = resolveUrl(endpoint.url, receiptNumber);
    console.log(`  📡 ${endpoint.label}: ${url}`);
    try {
      results[endpoint.key] = await fetchEndpoint(url, config);
    } catch (error) {
      if (error.code === "SESSION_EXPIRED") throw error;
      console.log(`  ⚠️  ${endpoint.label}: ${error.message}`);
      results[endpoint.key] = null;
    }
  }

  return results;
}

async function fetchSingleCase(receiptNumber, config) {
  const apiUrls = getApiUrls(config);
  if (apiUrls.length === 0) throw new Error("No API URLs configured");
  const url = resolveUrl(apiUrls[0].url, receiptNumber);
  return fetchEndpoint(url, config);
}

async function sendDiscordWebhook(webhookUrl, payload, { retries = 2, delayMs = 3000 } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        throw new Error(`Discord webhook failed: ${res.status} ${res.statusText}`);
      }
      return; // success
    } catch (err) {
      lastError = err;
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, delayMs));
      }
    }
  }
  throw lastError;
}

function buildDiscordEmbed(receiptNumber, endpointData, changes, summary) {
  const caseData = endpointData.caseStatus?.data || {};
  const changedFields = Object.entries(changes || {});

  const fields = [
    { name: "Receipt Number", value: receiptNumber, inline: true },
    { name: "Applicant", value: caseData.applicantName || "N/A", inline: true },
    { name: "Updated At", value: caseData.updatedAt || "N/A", inline: true },
  ];

  // Supplementary endpoint data
  const apiUrls = [
    { key: "location", label: "Location" },
    { key: "receiptNotice", label: "Receipt Notice" },
    { key: "documents", label: "Documents" },
  ];
  for (const { key, label } of apiUrls) {
    const raw = endpointData[key];
    if (!raw) continue;
    const payload = raw.data ?? raw;
    if (key === "documents" && Array.isArray(payload)) {
      fields.push({ name: label, value: `${payload.length} document(s)`, inline: true });
    } else if (payload && typeof payload === "object") {
      const preview = JSON.stringify(payload).slice(0, 200);
      fields.push({ name: label, value: preview || "Available", inline: false });
    }
  }

  for (const [key, detail] of changedFields) {
    if (key === "events" && detail.newEvents?.length) {
      for (const evt of detail.newEvents) {
        fields.push({
          name: "New Event",
          value: `**${evt.actionCodeText || "Unknown"}**\n${evt.dispositionCodeText || ""}\n${evt.eventDate || ""}`,
        });
      }
    } else if (detail.changed) {
      // Supplementary endpoint changed
    } else if (detail.from !== undefined || detail.to !== undefined) {
      fields.push({
        name: key,
        value: `${detail.from ?? "—"} → ${detail.to ?? "—"}`,
        inline: true,
      });
    }
  }

  return {
    embeds: [{
      title: `🔄 Case Update: ${caseData.formName || receiptNumber}`,
      description: summary || undefined,
      color: 0xff9900,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: "USCIS Case Monitor" },
    }],
  };
}

async function triggerNotification(receiptNumber, caseData, changes, summary, config) {
  try {
    console.log(`\n🔔 [NOTIFICATION] Case ${receiptNumber} updated:`);
    console.log(`  Summary: ${summary}`);

    const webhookUrl = config?.discordWebhookUrl || process.env.PHONEMONITOR_DISCORD_WEBHOOK_URL;
    if (!webhookUrl) {
      console.log("  ⚠️ No Discord webhook URL configured (set discordWebhookUrl in config or PHONEMONITOR_DISCORD_WEBHOOK_URL env var)");
      return;
    }

    const payload = buildDiscordEmbed(receiptNumber, caseData, changes, summary);
    await sendDiscordWebhook(webhookUrl, payload);
    console.log("  ✓ Discord notification sent");
  } catch (error) {
    console.error(`  ✗ Discord notification failed: ${error.message}`);
  }
}

async function checkAllCases(config) {
  requireAuthState();
  
  const receiptNumbers = config.receiptNumbers || (config.receiptNumber ? [config.receiptNumber] : []);
  if (receiptNumbers.length === 0) {
    throw new Error("No receiptNumbers found in config. Please add receiptNumbers array to config.local.json");
  }
  
  let sessionExpired = false;
  let retryCount = 0;
  const maxRetries = 1;
  
  while (retryCount <= maxRetries) {
    try {
      console.log(`\n📋 Checking ${receiptNumbers.length} case(s)...\n`);
      
      const history = loadCaseHistory();
      const results = [];
      
      for (const receiptNumber of receiptNumbers) {
        try {
          console.log(`⏳ Fetching ${receiptNumber}...`);
          const endpointData = await fetchAllEndpoints(receiptNumber, config);

          const caseData = endpointData.caseStatus;
          if (!caseData || !caseData.data) {
            console.log(`⚠️  Could not fetch ${receiptNumber} (invalid response), skipping...\n`);
            results.push({
              receiptNumber,
              isChanged: false,
              formName: null,
              updatedAt: null,
              error: "Invalid API response",
            });
            continue;
          }

          // Detect changes (migrate old history format if needed)
          const previousRecord = migrateHistoryRecord(history[receiptNumber]);
          const { isChanged, changes, summary } = detectChanges(previousRecord?.current, endpointData);

          // Update history
          history[receiptNumber] = {
            lastFetchAt: new Date().toISOString(),
            lastHash: deepHash(endpointData),
            current: endpointData,
            previous: previousRecord?.current || null,
            changes: isChanged ? changes : null,
          };

          // Print summary
          const data = caseData.data || {};
          console.log(`✓ ${data.formName || "N/A"}`);
          console.log(`  Receipt: ${receiptNumber}`);
          console.log(`  Name: ${data.applicantName || "N/A"}`);
          console.log(`  Updated: ${data.updatedAt || "N/A"}`);
          console.log(`  Events: ${(data.events || []).length}`);

          for (const key of Object.keys(endpointData)) {
            if (key === "caseStatus") continue;
            const val = endpointData[key];
            console.log(`  ${key}: ${val ? "✓" : "✗ null"}`);
          }

          console.log(`  Status: ${isChanged ? `🔄 ${summary}` : "✓ No changes"}`);

          if (isChanged) {
            await triggerNotification(receiptNumber, endpointData, changes, summary, config);
          }

          console.log();

          results.push({
            receiptNumber,
            isChanged,
            formName: data.formName || null,
            updatedAt: data.updatedAt || null,
          });
        } catch (error) {
          if (error.code === "SESSION_EXPIRED") {
            console.error(`⚠️  Session expired while fetching ${receiptNumber}`);
            sessionExpired = true;
            throw error;
          }

          if (error.code === "NETWORK_ERROR") {
            console.error(`❌ Network error fetching ${receiptNumber}: ${error.message}\n`);
          } else {
            console.error(`❌ Error processing ${receiptNumber}: ${error.message}\n`);
          }
          results.push({
            receiptNumber,
            isChanged: false,
            formName: null,
            updatedAt: null,
            error: error.message,
          });
        }
      }
      
      // Save updated history
      saveCaseHistory(history);
      console.log(`✓ History saved to ${caseHistoryFile}\n`);
      
      // Return summary
      const summary = {
        checkedAt: new Date().toISOString(),
        totalCases: receiptNumbers.length,
        changedCases: results.filter(r => r.isChanged && !r.error).length,
        results,
      };
      
      console.log("📊 Summary:");
      console.log(JSON.stringify(summary, null, 2));
      
      // Send Discord summary
      const webhookUrl = config?.discordWebhookUrl || process.env.PHONEMONITOR_DISCORD_WEBHOOK_URL;
      if (webhookUrl) {
        const ts = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
        const errorResults = summary.results.filter(r => r.error);
        const successResults = summary.results.filter(r => !r.error);

        if (errorResults.length === summary.totalCases) {
          // All cases failed — send error alert
          const firstError = errorResults[0]?.error || "Unknown error";
          await sendDiscordWebhook(webhookUrl, {
            content: `⚠️ \`${ts}\` All ${summary.totalCases} case checks failed — \`${firstError}\`. Will retry next cycle.`,
          }).catch((e) => console.error(`Discord notify failed: ${e.message}`));
        } else if (errorResults.length > 0) {
          // Partial failure
          const failed = errorResults.map(r => r.receiptNumber).join(", ");
          await sendDiscordWebhook(webhookUrl, {
            content: `⚠️ \`${ts}\` Checked ${summary.totalCases} cases — ${successResults.length} OK, ${errorResults.length} failed (${failed}). Will retry next cycle.`,
          }).catch((e) => console.error(`Discord notify failed: ${e.message}`));
        } else if (summary.changedCases === 0) {
          // All success, no changes
          await sendDiscordWebhook(webhookUrl, {
            content: `\`${ts}\` ✓ Checked ${summary.totalCases} cases — no changes found.`,
          }).catch((e) => console.error(`Discord notify failed: ${e.message}`));
        }
        // If changedCases > 0, individual notifications already sent via triggerNotification()
      }
      
      return summary; // Success, exit loop
      
    } catch (error) {
      if (error.code === "SESSION_EXPIRED" && retryCount < maxRetries) {
        retryCount++;
        sessionExpired = true;
        // Immediately re-authenticate before next retry
        console.log("\n🔄 Session expired, re-authenticating...\n");
        await login(config);
        console.log("\n✓ Re-authentication successful, retrying case checks...\n");
        sessionExpired = false;
        // Loop will continue and try again
        continue;
      }
      
      // If we've exhausted retries or it's a different error, throw
      throw error;
    }
  }
}

async function fetchCaseJson(config) {
  requireAuthState();

  const receiptNumbers = config.receiptNumbers || (config.receiptNumber ? [config.receiptNumber] : []);
  if (receiptNumbers.length === 0) {
    throw new Error("receiptNumbers not found in config. Please add it to config.local.json");
  }

  const receiptNumber = receiptNumbers[0];
  const endpointData = await fetchAllEndpoints(receiptNumber, config);
  const caseData = endpointData.caseStatus;

  if (!caseData) {
    throw new Error(`Failed to fetch case ${receiptNumber}`);
  }

  const caseFile = path.join(stateDir, "case.json");
  fs.writeFileSync(caseFile, JSON.stringify(endpointData, null, 2) + "\n", "utf8");
  console.log(`\n✓ Case data saved to ${caseFile}`);
  console.log(`\n📋 Case Summary:`);
  console.log(`   Receipt #: ${caseData.data?.receiptNumber}`);
  console.log(`   Status: ${caseData.data?.formName}`);
  console.log(`   Submitted: ${caseData.data?.submissionDate}`);
  console.log(`   Updated: ${caseData.data?.updatedAt}`);
  console.log(`   Events: ${caseData.data?.events?.length || 0}`);

  for (const key of Object.keys(endpointData)) {
    if (key === "caseStatus") continue;
    console.log(`   ${key}: ${endpointData[key] ? "✓ data received" : "✗ null"}`);
  }

  console.log(`\n📄 Full JSON:`);
  console.log(JSON.stringify(endpointData, null, 2));
}

async function poll(config) {
  requireAuthState();
  const { browser, page } = await browserWithState(true);
  try {
    const { text, html } = await extractMonitoredText(page, config);
    const hash = sha256(text);
    const now = new Date().toISOString();
    const previous = fs.existsSync(lastFile) ? JSON.parse(fs.readFileSync(lastFile, "utf8")) : null;
    const changed = !previous || previous.hash !== hash;
    const snapshot = saveSnapshot("monitor", text, html);
    const state = {
      checkedAt: now,
      hash,
      changed,
      textPreview: text.slice(0, 400),
      snapshot,
    };
    if (previous && previous.hash) {
      state.previousHash = previous.hash;
    }
    fs.writeFileSync(lastFile, JSON.stringify(state, null, 2) + "\n", "utf8");
    console.log(JSON.stringify(state, null, 2));
    if (changed) {
      process.exitCode = 2;
    }
  } finally {
    await browser.close();
  }
}

// --- Scheduler ---

function isWithinSchedule() {
  // Check if current time is within ET weekday 9am-8pm
  const now = new Date();
  const etStr = now.toLocaleString("en-US", { timeZone: "America/New_York" });
  const et = new Date(etStr);
  const day = et.getDay(); // 0=Sun, 6=Sat
  const hour = et.getHours();
  if (day === 0 || day === 6) return false;
  return hour >= 9 && hour < 20;
}

function getSchedulerIntervalMs(config) {
  // Supports either config.scheduler.intervalHours or config.schedulerIntervalHours.
  const raw = config?.scheduler?.intervalHours ?? config?.schedulerIntervalHours ?? 3;
  const hours = Number(raw);
  if (!Number.isFinite(hours) || hours <= 0) {
    return 3 * 60 * 60 * 1000;
  }
  return Math.max(Math.round(hours * 60 * 60 * 1000), 60000);
}

function nextScheduledRun(intervalMs) {
  // Returns ms until the next valid clock-aligned slot in the ET weekday window.
  const now = new Date();
  const etStr = now.toLocaleString("en-US", { timeZone: "America/New_York" });
  const et = new Date(etStr);
  const day = et.getDay();
  const hour = et.getHours();
  const minute = et.getMinutes();
  const second = et.getSeconds();
  const millisecond = et.getMilliseconds();
  const isWeekday = day >= 1 && day <= 5;
  const isWithinWindow = isWeekday && hour >= 9 && hour < 20;
  
  // If within schedule, wait until the next aligned slot.
  if (isWithinWindow) {
    const intervalMinutes = Math.max(Math.round(intervalMs / 60000), 1);
    const minutesSinceWindowStart = (hour - 9) * 60 + minute;
    const remainder = minutesSinceWindowStart % intervalMinutes;
    const minutesToNextSlot = remainder === 0 ? intervalMinutes : intervalMinutes - remainder;
    const nextSlotMinutesSinceWindowStart = minutesSinceWindowStart + minutesToNextSlot;

    // Keep checks inside the 9am-8pm ET window. Anything landing at or after 8pm rolls to next weekday 9am.
    if (nextSlotMinutesSinceWindowStart < 11 * 60) {
      const waitMs = minutesToNextSlot * 60000 - second * 1000 - millisecond;
      return Math.max(waitMs, 5000);
    }
  }
  
  // Calculate time until next weekday 9am ET
  let daysUntil;
  if (day === 6) daysUntil = 2; // Sat -> Mon
  else if (day === 0) daysUntil = 1; // Sun -> Mon
  else if (isWithinWindow) daysUntil = (day === 5) ? 3 : 1; // No remaining slot today
  else if (hour >= 20) daysUntil = (day === 5) ? 3 : 1; // After 8pm, next weekday
  else daysUntil = 0; // Before 9am today
  
  const next = new Date(et);
  next.setDate(next.getDate() + daysUntil);
  next.setHours(9, 0, 0, 0);
  return Math.max(next.getTime() - et.getTime(), 60000);
}

async function scheduledCheck(config) {
  // Smart check: try API first, login only if needed
  const etStr = new Date().toLocaleString("en-US", { timeZone: "America/New_York" });
  console.log(`\n⏰ Scheduled check at ${etStr} ET\n`);
  
  const hasAuth = fs.existsSync(authFile);
  if (!hasAuth) {
    console.log("No auth state found, performing login...");
    await login(config);
  }
  
  try {
    // Try fetching with existing token
    await checkAllCases(config);
  } catch (error) {
    if (error.code === "SESSION_EXPIRED" || error.message?.includes("SESSION_EXPIRED")) {
      // checkAllCases already retries once with auto-reauth
      // If we're here, the retry also failed
      console.error("❌ Failed even after re-authentication");
      const webhookUrl = config?.discordWebhookUrl || process.env.PHONEMONITOR_DISCORD_WEBHOOK_URL;
      if (webhookUrl) {
        await sendDiscordWebhook(webhookUrl, {
          content: `❌ \`${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC\` Scheduled check failed: ${error.message}`,
        }).catch(() => {});
      }
    } else {
      throw error;
    }
  }
}

async function runScheduler(config) {
  const intervalMs = getSchedulerIntervalMs(config);
  const intervalHours = Number((intervalMs / (60 * 60 * 1000)).toFixed(2));
  const intervalLabel = Number.isInteger(intervalHours)
    ? `${intervalHours} hour${intervalHours === 1 ? "" : "s"}`
    : `${intervalHours} hours`;

  console.log("🕐 USCIS Case Monitor Scheduler started");
  console.log(`   Schedule: Weekdays 9am–8pm ET, every ${intervalLabel}`);
  console.log("   Press Ctrl+C to stop\n");
  
  const run = async () => {
    if (isWithinSchedule()) {
      try {
        await scheduledCheck(config);
      } catch (error) {
        console.error(`❌ Scheduled check error: ${error.message}`);
      }
    } else {
      const etStr = new Date().toLocaleString("en-US", { timeZone: "America/New_York" });
      console.log(`⏸️  Outside schedule (${etStr} ET). Skipping.`);
    }
    
    const waitMs = nextScheduledRun(intervalMs);
    const waitMin = Math.round(waitMs / 60000);
    console.log(`⏳ Next check in ${waitMin} minutes\n`);
    setTimeout(run, waitMs);
  };
  
  // Run immediately on start
  await run();
}

async function main() {
  ensureDirs();
  const config = loadConfig();
  const command = process.argv[2] || "poll";
  if (command === "login" || command === "reauth") {
    await login(config);
    return;
  }
  if (command === "check-all-cases") {
    await checkAllCases(config);
    return;
  }
  if (command === "scheduled-check") {
    await scheduledCheck(config);
    return;
  }
  if (command === "scheduler") {
    await runScheduler(config);
    return;
  }
  if (command === "fetch-case-json") {
    await fetchCaseJson(config);
    return;
  }
  if (command === "otp-test") {
    const code = await readOtpFromEmail(config.otp);
    console.log(code);
    return;
  }
  if (command === "poll") {
    await poll(config);
    return;
  }
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
