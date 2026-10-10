// Provider credentials. Real-looking values are assembled at generation time from
// browser_export.PLACEHOLDERS, so no provider-format literal is ever committed.
const awsKeyId = "__FAKE_AWS_KEY_ID__";
const aws_secret_access_key = "__FAKE_AWS_SECRET__";
const ghToken = "__FAKE_GITHUB_TOKEN__";
const ghPat = "__FAKE_GITHUB_PAT__";
const stripe = "__FAKE_STRIPE_KEY__";
const stripeRestricted = "__FAKE_STRIPE_RESTRICTED__";
const google = "__FAKE_GOOGLE_KEY__";
const slack = "__FAKE_SLACK_TOKEN__";
const hook = "__FAKE_SLACK_WEBHOOK__";
const openai = "__FAKE_OPENAI_KEY__";
const anthropic = "__FAKE_ANTHROPIC_KEY__";
const groq = "__FAKE_GROQ_KEY__";
const pem = "__FAKE_PRIVATE_KEY_HEADER__";
const session = "__FAKE_JWT__";
const db = "__FAKE_DB_URL__";
// Near misses that must stay quiet.
const shortKey = "AKIA1234";
const notGithub = "ghp_short";
const tooShort = "sk_test_tooShort";
const placeholderDb = "__FAKE_DB_URL_PLACEHOLDER__";
const envDb = "__FAKE_DB_URL_ENV__";
