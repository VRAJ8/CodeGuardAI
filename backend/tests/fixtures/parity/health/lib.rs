// Rust: `fn` counts as a function for the heuristic.
fn classify(n: i32) -> &'static str {
    if n < 0 {
        "negative"
    } else if n == 0 {
        "zero"
    } else {
        match n % 2 {
            0 => "even",
            _ => "odd",
        }
    }
}

fn sum(xs: &[i32]) -> i32 {
    let mut total = 0;
    for x in xs {
        if *x > 0 || *x == -1 {
            total += x;
        }
    }
    total
}
