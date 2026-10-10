// Inline suppressions. Each line is a parser case; the golden records what Python decides.
el.innerHTML = a;  // codeguard-ignore -- sanitized upstream
// codeguard-ignore-next-line: cg-eval
eval(b);
eval(c);
el.innerHTML = q; eval(q);  // codeguard-ignore: CG-EVAL
// codeguard-ignore-next-line: CG-SQLI-CONCAT
el.innerHTML = q2; eval(q2);
eval(x1); // codeguard-ignore CG-EVAL
eval(x2); // codeguard-ignore(CG-EVAL)
eval(x3); // codeguard-ignore=CG-EVAL
eval(x4); // codeguard-ignore: false positive, reviewed
eval(x5); // nocodeguard-ignore
eval(x6); // see codeguard-ignore docs
eval(x7); // codeguard-ignore-file
eval(x8); // codeguard-ignored
const s1 = "codeguard-ignore"; eval(x9);
const s2 = '// codeguard-ignore'; eval(x10);
fetch('https://x.test/#codeguard-ignore'); eval(x11);
eval(x12); /* codeguard-ignore: CG-EVAL, CG-XSS-INNERHTML */
eval(x13);  // CODEGUARD-IGNORE
eval(x14);  // codeguard-ignore: Cg-Eval -- mixed-case rule id
const tpl = `
  eval(x15) // codeguard-ignore
`;
eval(x16); // codeguard-ignore: CG-EVAL // codeguard-ignore: CG-XSS-INNERHTML
const k = "x"; // codeguard-ignore-next-line: SEC-GENERIC -- test fixture value
const api_secret = "Qw8#Er5$Ty2@Ui";
const s3 = "it's"; eval(x17); // codeguard-ignore
const s4 = "it\'s"; eval(x18); // codeguard-ignore
eval(x19); //codeguard-ignore:CG-EVAL,CG-NEW-FUNCTION--no space before the dashes
eval(x20); // codeguard-ignore:   CG-EVAL   ,   CG-EXEC    --   padded
eval(x21); // codeguard-ignore: CG-EVAL --
eval(last); // codeguard-ignore-next-line
