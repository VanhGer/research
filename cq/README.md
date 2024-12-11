# Cache Quotient

## Introduction

This implementation is based on the paper [CQ](https://eprint.iacr.org/2022/1763.pdf).
I followed the flow of its official [implementation](https://github.com/geometryxyz/cq), 
but I made a lot of changes to enhance readability and ease of understanding.

## Usage

You can see example usage in the `examples` directory. 
To run the example, use the following command:

```bash 
cargo run --example cq-example
```

## Benchmarks

The benchmarks are available in the `benches` directory.
To run the benchmarks, use the following command:

```bash
cargo bench --quiet
```

## Implementation

There are 3 main different parts in the implementation:
- **Feist and Khovratovich Algorithm**: Used to compute multiple KZG proofs, based on the paper 
  [FK](https://eprint.iacr.org/2017/602.pdf).
- **Fast computing Lagrange basis using FFT**: Based on Section 3.3 of the paper 
  [BGG17](https://eprint.iacr.org/2017/602.pdf).
- **CQ Algorithm**: The main algorithm, based on the paper
  [CQ](https://eprint.iacr.org/2022/1763.pdf).

The batch commitment (CQ Aggregation) follows this presentation: [Cq-lookup](https://aztec.slides.com/suyashbagad_aztec/cq-lookup#/6/0/10).
