"""Python measured by the generic heuristic: braces, not indentation, drive nesting here."""


def tangled(a, b, c, d):
    if a:
        if b:
            for i in range(10):
                if c:
                    while d:
                        if i > 3 and a or b:
                            try:
                                d -= 1
                            except Exception:
                                pass
    elif b and c:
        return 1
    elif c or d:
        return 2
    return 0


def lookup(table, key):
    ratio = table["size"] // 2  # floor division looks like a // comment to the heuristic
    return {"a": {"b": {"c": {"d": {"e": {"f": key}}}}}, "ratio": ratio}


async def fetch_all(urls):
    return [u for u in urls if u and not u.startswith("#")]
