// JSX comments and a multi-line template literal in TypeScript.
export function View({ html, query }: { html: string; query: string }) {
  const sql = `
    SELECT * FROM t WHERE q = ${eval(query)} // codeguard-ignore
  `;
  return (
    <section>
      {/* codeguard-ignore-next-line */}
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <div dangerouslySetInnerHTML={{ __html: html }} /> {/* codeguard-ignore -- sanitized */}
      <p dangerouslySetInnerHTML={{ __html: html }} />
    </section>
  );
}
