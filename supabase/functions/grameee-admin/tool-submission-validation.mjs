const MAX_IMAGE_BYTES = 650 * 1024;
const FIELD_LIMITS = Object.freeze({
  name: 160,
  url: 2048,
  category: 120,
  description: 4000,
  submittedByName: 160,
  submittedByEmail: 320,
});

const FORBIDDEN_INLINE = /[\u0000-\u001f\u007f<>]/u;
const FORBIDDEN_MULTILINE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f<>]/u;
const FORBIDDEN_URL = /[\u0000-\u0020\u007f<>"'`\\]/u;
const EMAIL_PATTERN = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/iu;
const IMAGE_PATTERN = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]+={0,2})$/u;

export class ToolSubmissionValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolSubmissionValidationError";
  }
}

function codePointLength(value) {
  return Array.from(value).length;
}

function readText(value, fieldName, maxLength, { required = false, multiline = false } = {}) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new ToolSubmissionValidationError(`${fieldName} must be text.`);
  }

  const text = String(value ?? "").replace(/\r\n?/gu, "\n").trim();
  if (required && !text) {
    throw new ToolSubmissionValidationError(`${fieldName} is required.`);
  }
  if (!text) return "";
  if (codePointLength(text) > maxLength) {
    throw new ToolSubmissionValidationError(`${fieldName} is too long.`);
  }
  if ((multiline ? FORBIDDEN_MULTILINE : FORBIDDEN_INLINE).test(text)) {
    throw new ToolSubmissionValidationError(`${fieldName} contains unsupported characters.`);
  }
  return text;
}

function canonicalHttpsUrl(value) {
  const raw = readText(value, "Tool URL", FIELD_LIMITS.url, { required: true });
  if (FORBIDDEN_URL.test(raw)) {
    throw new ToolSubmissionValidationError("Tool URL contains unsupported characters.");
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ToolSubmissionValidationError("Tool URL must be a valid HTTPS URL.");
  }

  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
    throw new ToolSubmissionValidationError("Tool URL must be a public HTTPS URL without embedded credentials.");
  }

  const canonical = parsed.href;
  if (codePointLength(canonical) > FIELD_LIMITS.url || FORBIDDEN_URL.test(canonical)) {
    throw new ToolSubmissionValidationError("Tool URL is not supported.");
  }
  return canonical;
}

function validEmail(value) {
  const email = readText(value, "Submitter email", FIELD_LIMITS.submittedByEmail).toLowerCase();
  if (email && !EMAIL_PATTERN.test(email)) {
    throw new ToolSubmissionValidationError("Submitter email must be a valid email address.");
  }
  return email;
}

function decodeBase64(value) {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (btoa(binary) !== value) throw new Error("Non-canonical base64");
    return bytes;
  } catch {
    throw new ToolSubmissionValidationError("Background image data is invalid.");
  }
}

function hasExpectedSignature(mimeType, bytes) {
  if (mimeType === "image/png") {
    return bytes.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((byte, index) => bytes[index] === byte);
  }
  if (mimeType === "image/jpeg") {
    return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  }
  return bytes.length >= 12
    && String.fromCharCode(...bytes.slice(0, 4)) === "RIFF"
    && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP";
}

function validImageDataUrl(value) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new ToolSubmissionValidationError("Background image must be a data URL.");
  }
  const dataUrl = String(value ?? "");
  if (!dataUrl) return "";
  if (dataUrl.length > Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 64) {
    throw new ToolSubmissionValidationError("Background image must be 650 KB or smaller.");
  }

  const match = dataUrl.match(IMAGE_PATTERN);
  if (!match) {
    throw new ToolSubmissionValidationError("Background image must be a base64 PNG, JPEG, or WEBP image.");
  }
  const [, mimeType, payload] = match;
  const bytes = decodeBase64(payload);
  if (bytes.byteLength > MAX_IMAGE_BYTES) {
    throw new ToolSubmissionValidationError("Background image must be 650 KB or smaller.");
  }
  if (!hasExpectedSignature(mimeType, bytes)) {
    throw new ToolSubmissionValidationError("Background image content does not match its declared format.");
  }
  return dataUrl;
}

function validColor(value) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new ToolSubmissionValidationError("Background color must be text.");
  }
  const color = String(value ?? "").trim().toLowerCase();
  if (color && !/^#[0-9a-f]{6}$/u.test(color)) {
    throw new ToolSubmissionValidationError("Background color must be a six-digit hex color.");
  }
  return color;
}

function descriptionForStorage(description, backgroundColor, backgroundImage) {
  const style = {};
  if (backgroundColor) style.color = backgroundColor;
  if (backgroundImage) style.image = backgroundImage;
  const marker = Object.keys(style).length
    ? `[[tool-card-style:${btoa(JSON.stringify(style))}]]\n`
    : "";
  return `${marker}${description}`.trim();
}

export function validateToolSubmission(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ToolSubmissionValidationError("Submission body must be an object.");
  }

  const name = readText(body.name, "Tool name", FIELD_LIMITS.name, { required: true });
  const url = canonicalHttpsUrl(body.url);
  const category = readText(body.category, "Category", FIELD_LIMITS.category);
  const description = readText(body.description, "Description", FIELD_LIMITS.description, { multiline: true });
  const submittedByName = readText(body.submittedByName, "Submitter name", FIELD_LIMITS.submittedByName);
  const submittedByEmail = validEmail(body.submittedByEmail);
  const backgroundColor = validColor(body.backgroundColor);
  const backgroundImage = validImageDataUrl(body.backgroundImage);

  return {
    name,
    url,
    category: category || null,
    description: descriptionForStorage(description, backgroundColor, backgroundImage) || null,
    submitted_by_name: submittedByName || null,
    submitted_by_email: submittedByEmail || null,
    status: "pending",
  };
}

export const TOOL_SUBMISSION_LIMITS = Object.freeze({ ...FIELD_LIMITS, imageBytes: MAX_IMAGE_BYTES });
