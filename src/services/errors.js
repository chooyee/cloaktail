// A refusal the developer can act on, shared by the HTML pages and the REST API (routes/api.js):
// `status` is the HTTP status, `code` a stable machine-readable reason (listed in the API's agent
// guide), `message` a sentence for a person. Anything else thrown is an unexpected 500.
export class ServiceError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const notFound = (what) => new ServiceError(404, 'not_found', `${what} not found.`);
export const invalid = (message, extra) => new ServiceError(422, 'validation_failed', message, extra);
