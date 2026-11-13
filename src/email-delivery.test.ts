import assert from "node:assert/strict";
import test from "node:test";
import { ResendEmailDelivery } from "./email-delivery.js";

test("Resend sends a minimal transactional email and returns provider ID", async () => {
  let captured: { url: string; init?: RequestInit } | undefined;
  const delivery = new ResendEmailDelivery("re_test_key_123456789012345", "OniShield <security@example.test>", async (input, init) => {
    captured = { url: String(input), init };
    return new Response(JSON.stringify({ id: "email_test_123" }), { status: 200 });
  });
  const result = await delivery.send({
    to: "operator@example.test",
    subject: "Verify your OniShield email",
    html: "<p>Verify</p>",
    text: "Verify"
  });
  assert.equal(result.id, "email_test_123");
  assert.equal(captured?.url, "https://api.resend.com/emails");
  assert.equal(captured?.init?.method, "POST");
  const headers = captured?.init?.headers as Record<string, string>;
  assert.equal(headers.authorization, "Bearer re_test_key_123456789012345");
  const body = JSON.parse(String(captured?.init?.body));
  assert.deepEqual(body.to, ["operator@example.test"]);
  assert.equal(body.from, "OniShield <security@example.test>");
});

test("Resend rejects malformed recipients and unsafe subjects before network access", async () => {
  let called = false;
  const delivery = new ResendEmailDelivery("re_test_key_123456789012345", "security@example.test", async () => {
    called = true;
    return new Response(JSON.stringify({ id: "unused" }));
  });
  await assert.rejects(() => delivery.send({
    to: "bad-address",
    subject: "Hello",
    html: "<p>Hello</p>",
    text: "Hello"
  }), /recipient/);
  await assert.rejects(() => delivery.send({
    to: "operator@example.test",
    subject: "Hello\r\nBcc: attacker@example.test",
    html: "<p>Hello</p>",
    text: "Hello"
  }), /subject/);
  assert.equal(called, false);
});

test("Resend provider errors are sanitized", async () => {
  const delivery = new ResendEmailDelivery("re_test_key_123456789012345", "security@example.test", async () =>
    new Response("private provider detail", { status: 401 }));
  await assert.rejects(() => delivery.send({
    to: "operator@example.test",
    subject: "Hello",
    html: "<p>Hello</p>",
    text: "Hello"
  }), /HTTP 401/);
});
