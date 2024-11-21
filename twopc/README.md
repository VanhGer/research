# Two-Party Computation

## Introduction

This is a raw implementation of Yao’s Garbled Circuits (Yao GC), as described in the [Intro book](https://github.com/0xPARC/0xparc-intro-book) of **0xparc**. This code closely follows the content presented in Chapter 2 of the book.


## Circuit

To define the circuit, I referred to a previous implementation of YaoGC algorithm: [yao-gc](https://github.com/cronokirby/yao-gc).
For example, let's define an XOR gates, which takes one bit of each party as input.

The XOR truth table is:

| x   | y   | x XOR y |
| --- | --- | ------- |
| 0   | 0   | 0       |
| 0   | 1   | 1       |
| 1   | 0   | 1       |
| 1   | 1   | 0       |

The gate is presented as:

```rust
let xor_circuit = Gate(
	GateInfo(0b0110), 
	Box::new(Input(PartyInput::A(0))), 
	Box::new(Input(PartyInput::B(0)))
);
```

The `GateInfo` contains the information of the gate. As shown, the value `0b0110` has 4 lowest bits which represent the values of $x$ XOR $y$ in the truth table. This definition makes it clear that the gate is an XOR gate.

The two inputs of the gate are the first bits from parties A and B, represented as `A(0)` and `B(0)` respectively.

## Encryption / Decryption

The algorithm mentioned in the book uses symmetric encryption to encrypt the passwords,  ensuring that without the key, other parties cannot deduce anything about the values. However, I chose the asymmetric encryption for this process (ECIES over elliptic curve),  because the library I used was easier to work with.  Although this choice does not affect the functionality of the algorithm, it may make the performance worse. If optimization is a priority, symmetric encryption algorithms like AES or ChaCha20 would be better alternatives.

## Oblivious Transfer (OT)

I implemented the one-step OT, using public-key cryptography. I chose RSA, because it is simple in forming public keys with an arithmetic progression with a common diﬀerence $r$. I constructed 2 consecutive public keys with a difference $r$ in both the modulus and the exponent:

```rust
let mut new_pk = pub_key.clone();  
new_pk.modulus -= BigUint::from(secret_value[i] - j) * diff.clone();  
new_pk.exponent -= BigUint::from(secret_value[i] - j) * diff.clone();

```


## Examples

Examples can be found in the `/examples` directory of this repository.

## Reference

- [0xparc Intro Book](https://github.com/0xPARC/0xparc-intro-book) by **0xPARC**
- [Yao-gc](https://github.com/cronokirby/yao-gc) by **Cronokirby** 