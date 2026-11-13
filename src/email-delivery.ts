export interface TransactionalEmail {
  to: string;
  subject: string;
  html: string;
  text: string;
  idempotencyKey: string;
}

export interface EmailDelivery {
  send(message: TransactionalEmail): Promise<{ id: string }>;
}

interface ResendResponse {
  id?: string;
  message?: string;
}

export class ResendEmailDelivery implements EmailDelivery {
  constructor(
    private readonly apiKey: string,
    private readonly from: string,
    private readonly request: typeof fetch = fetch
  ) {
    if (apiKey.trim().length < 20) throw new Error("RESEND_API_KEY is invalid");
    if (!from.trim() || /[\r\n]/.test(from)) throw new Error("EMAIL_FROM is invalid");
  }

  async send(message: TransactionalEmail): Promise<{ id: string }> {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(message.to) || /[\r\n]/.test(message.to)) {
      throw new Error("Invalid transactional email recipient");
    }
    if (!message.subject.trim() || message.subject.length > 180 || /[\r\n]/.test(message.subject)) {
      throw new Error("Invalid transactional email subject");
    }
    if (!message.html.trim() || !message.text.trim() || message.html.length > 100_000 || message.text.length > 100_000) {
      throw new Error("Transactional email must include HTML and plain text");
    }

    if (!/^[A-Za-z0-9._:/-]{1,256}$/.test(message.idempotencyKey)) {
      throw new Error("Invalid transactional email idempotency key");
    }

    let response: Response;
    try {
      response = await this.request("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          "idempotency-key": message.idempotencyKey
        },
        body: JSON.stringify({
          from: this.from,
          to: [message.to],
          subject: message.subject,
          html: message.html,
          text: message.text
        }),
        signal: AbortSignal.timeout(10_000)
      });
    } catch {
      throw new Error("Transactional email provider unavailable");
    }

    if (!response.ok) {
      // Provider response bodies may contain recipient metadata; do not propagate or log them.
      throw new Error(`Transactional email rejected (HTTP ${response.status})`);
    }

    let payload: ResendResponse;
    try {
      payload = await response.json() as ResendResponse;
    } catch {
      throw new Error("Transactional email provider returned an invalid response");
    }
    if (!payload.id || typeof payload.id !== "string") {
      throw new Error("Transactional email provider omitted message ID");
    }
    return { id: payload.id };
  }
}
