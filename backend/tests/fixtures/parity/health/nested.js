// Deep nesting, swallowed errors and many decision points.
const braces = "{{{{ not code }}}}";
const tpl = `{ ${braces} }`;
/* { block comment braces { } */
function walk(tree, visit) {
  if (tree) {
    for (const node of tree.children) {
      while (node.next) {
        if (node.kind === "a" && node.ok || node.force) {
          switch (node.type) {
            case "x": {
              try { visit(node); } catch (e) {}
              break;
            }
            case "y": {
              try { visit(node?.child ?? node); } catch {}
              break;
            }
            default:
              node.done = node.count > 3 ? true : false;
          }
        }
        node.next = node.next?.next;
      }
    }
  }
  try { visit(null); } catch (err) { }
}
const pick = (a, b) => (a ? a : b);
const run = async () => { await walk(null, () => {}); };
