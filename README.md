# BlindReview

This software simulates the use of the BlindReview protocol (all algorithms are executed sequentially) and displays:
- the average time for each algorithm
- the total time for the assignment phase and the entire protocol
- the number of iterations in the assignment phase, as well as the number of acceptances and rejections in this phase

## How to use

1) install Rust and Cargo: https://doc.rust-lang.org/cargo/getting-started/installation.html
2) Build and run: cargo run --release
3) To choose specific settings (see below), modify the constants N, M, L, RP, and C in the source code (at the beginning of the src/main.rs file).

## Setings
