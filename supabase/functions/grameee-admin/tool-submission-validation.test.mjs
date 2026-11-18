import assert from "node:assert/strict";
import test from "node:test";
import {
  TOOL_SUBMISSION_LIMITS,
  ToolSubmissionValidationError,
  validateToolSubmission,
} from "./tool-submission-validation.mjs";

const pngDataUrl = "data:image/png;base64,iVBORw0KGgo=";
const valid = () => ({
  name: "Community planning tool",
  url: "https://Example.com:443/path/../tool?q=one",
  category: "Planning",
  description: "A practical tool.\nFor field teams.",
  submittedByName: "Asha",
  submittedByEmail: "ASHA@example.org",
  backgroundColor: "#EFF7EF",
  backgroundImage: pngDataUrl,
});

test("normalizes a valid submission and creates only a pending row", () => {
  const result = validateToolSubmission(valid());
  assert.equal(result.url, "https://example.com/tool?q=one");
  assert.equal(result.submitted_by_email, "asha@example.org");
  assert.equal(result.status, "pending");
  assert.match(result.description, /^\[\[tool-card-style:/u);
  assert.equal(Object.hasOwn(result, "approved_at"), false);
});

test("rejects non-HTTPS, credentialed, malformed, and quote-breaking URLs", () => {
  for (const url of [
    "http://example.org",
    "javascript:alert(1)",
    "https://user:pass@example.org/",
    "https://example.org/\" onmouseover=\"x",
    "https://example.org/\u0007",
  ]) {
    assert.throws(() => validateToolSubmission({ ...valid(), url }), ToolSubmissionValidationError);
  }
});

test("rejects markup, forbidden controls, oversized fields, and invalid email", () => {
  const fixtures = [
    { name: '\"><img src=x onerror=alert(1)>' },
    { category: "Planning\u0000hidden" },
    { description: "safe\u0007unsafe" },
    { name: "x".repeat(TOOL_SUBMISSION_LIMITS.name + 1) },
    { submittedByEmail: "not-an-email" },
  ];
  for (const fixture of fixtures) {
    assert.throws(() => validateToolSubmission({ ...valid(), ...fixture }), ToolSubmissionValidationError);
  }
});

test("allows ordinary punctuation and description line breaks", () => {
  const result = validateToolSubmission({
    ...valid(),
    name: "Farmer's planning tool",
    description: "First line\nSecond line — field-tested.",
  });
  assert.match(result.name, /Farmer's/u);
  assert.match(result.description, /First line\nSecond line/u);
});

test("accepts PNG, JPEG and WEBP signatures and rejects SVG, spoofed, malformed, and oversized images", () => {
  const images = [
    "data:image/png;base64,iVBORw0KGgo=",
    "data:image/jpeg;base64,/9j/",
    "data:image/webp;base64,UklGRgAAAABXRUJQ",
  ];
  for (const backgroundImage of images) {
    assert.doesNotThrow(() => validateToolSubmission({ ...valid(), backgroundImage }));
  }
  for (const backgroundImage of [
    "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
    "data:image/png;base64,PHN2Zz4=",
    "data:image/png;base64,not_base64",
    `data:image/png;base64,${"A".repeat(Math.ceil((TOOL_SUBMISSION_LIMITS.imageBytes + 1) / 3) * 4)}`,
  ]) {
    assert.throws(() => validateToolSubmission({ ...valid(), backgroundImage }), ToolSubmissionValidationError);
  }
});
