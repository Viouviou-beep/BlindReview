# BlindReview

## Overview

This software simulates the use of the BlindReview protocol (all algorithms are executed sequentially) and displays:
- the average time for each algorithm
- the total time for the assignment phase and the full protocol
- the number of iterations in the assignment phase, as well as the number of acceptances and rejections in this phase

## How to use

1) install Rust and Cargo: https://doc.rust-lang.org/cargo/getting-started/installation.html
2) Build and run: cargo run --release (do not forget the --release option!)
3) To choose specific settings (see below), modify the constants N, M, L, RP, and C in the source code (at the beginning of the BlindReview/src/main.rs file).

## Setings

By default, the software is configured with data from the IMACC 2023 conference. To evaluate the performance of the protocol on other data, you can assign different values to the following constants:

const N : usize = 34; // The number of submissions
const M : usize = 21; // The number of reviewers
const L : usize = 6; // The maximum number of reviews per reviewer (must be strictly greater than N*RP/M)
const RP : usize = 3; // The number of reviews per paper
const C : usize = 1; // The number of conflicts per paper

The C conflicts per paper are chosen randomly among the reviewers. If the assignment phase gets blocked for a paper (if all reviewers have either reached the paper limit set to L  at the start of the run, or are in conflict), the review limit per reviewer is increased for that paper.
