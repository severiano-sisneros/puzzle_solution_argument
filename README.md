This is a simple protocol for arguing the knowledge of a solution to a puzzle. Solutions are expected to take the form of an ordered set of strings.

The following protocol is adapted from the $\Sigma$-protocol from *[Proofs, Arguments, and Zero Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)* (Chapter 12, Protocol 3).

**Setup**
1. Let $G$ be a (multiplicative) cyclic group of prime order with generator $g$
2. Commitment key is initialized with $g$

**Author Posting Puzzle**
1. Author computes puzzle witness $w = puzzleHash(puzzleSolution)$
2. Author computes puzzle commitment $h = g^w$, where only the Author knows $w$

**Player Proving Solution**
1. Player computes $w' = puzzleHash(puzzleGuess)$
2. Player checks that they know the solution by checking that $g^{w'} = h$ 
3. Player picks a random number $r$ in ${0,...,|G|−1}$ and computes $a ← g^r$
4. Player computes Fiat-Shamir challenge $e = hash(g, h, a)$
5. Player computes $z ← (w'e+r) mod |G|$.
6. Player submits $(a, z)$ to CrosswordCourt.

**Verifying Solution**
1. Compute Fiat-Shamir challenge $e = hash(g, h, a)$, 
2. Check that $a · h^e = g^z$.