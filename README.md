This is a simple protocol for arguing the knowledge of a solution to a puzzle. Solutions are expected to take the form of an ordered set of strings.

Treat $w$ as a private key used for signing. Then, the solver signs a message which contains their public address. The awards go to the address in the signed message.

For compatibility with Ethereum, we could simply use ECDSA with secp256k1.

**Setup**
1. Let $G$ be a (multiplicative) cyclic group of prime order with generator $g$ derived from the $SECP256k1$ elliptic curve
2. CrosswordCourt is initialized with $g$ 

*In practice this is already handled by the EVM by default, since we will be using the pre-compiled contracts for signature verification.*

**Author Posting Puzzle**
1. Author computes puzzle witness $w = puzzleHash(puzzleSolution)$
2. Author posts puzzle commitment $h = g^w$ to the CrosswordCourt. 

*Effectively, $w$ is the private signing key and $h$ is the public key*

**Player Proving Solution**
1. Player computes $w' = puzzleHash(puzzleGuess)$
2. Player checks that they know the solution by checking that $g^{w'} = h$, i.e. $w' = w$ with high probability.
3. Player computes $a = ECDSA\_sign_w(m_p)$, where $m_p$ is the player's public address.
6. Player submits $(a, m_p)$ to CrosswordCourt.

**Crossword Court Verifying Solution**
1. Check $ECDSA\_verify_h(a, m_p) == true$