use ark_ec::Group;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::SerializationError;
use digest::Digest;
use rand::{rngs::StdRng, SeedableRng};

/// PuzzleSolution is a struct that contains a set of `solutions` to a puzzle and the key `g` used to commit to them.
/// The solutions are expected as strings.
pub struct PuzzleSolution<G: Group> {
    solutions: Vec<String>,
    g: G,
}

/// PuzzleSolutionProof is a struct that contains a proof that a given solution is a valid solution to a puzzle.
/// The proof is essentially a Schnorr proof of knowledge of the discrete logarithm of a commitment to the solution.
pub struct PuzzleSolutionProof<G: Group> {
    a: G,
    z: G::ScalarField,
}

impl<G: Group> PuzzleSolution<G> {
    pub fn new(solutions: Vec<String>, g: G) -> Self {
        Self { solutions, g }
    }

    /// get_solution_commitment returns the commitment to the solution set.
    pub fn get_solution_commitment<H: Digest>(&self) -> (G::ScalarField, G) {
        // Compute chain of hashes of each solution in the solution set
        // and commit to the last hash in the chain
        let mut hasher = H::new();

        for solution in &self.solutions {
            hasher.update(solution.as_bytes());
        }

        let w_bytes = hasher.finalize();
        let w = G::ScalarField::from_be_bytes_mod_order(&w_bytes);
        (w, self.g.mul(&w))
    }

    /// get_solution_proof returns a proof that the given solution is a valid solution to the puzzle.
    pub fn get_solution_proof<H: Digest>(
        &self,
        w: G::ScalarField,
        solution_commitment: G,
    ) -> Result<PuzzleSolutionProof<G>, SerializationError> {
        // Check that w is correct solution
        //TODO: Better error handling
        match self.g.mul(&w) == solution_commitment {
            true => (),
            false => return Err(SerializationError::InvalidData),
        }

        // Draw a random blinding number, r
        let mut rng = StdRng::from_entropy();
        let r = G::ScalarField::rand(&mut rng);

        // Send blinding commitment
        let a = self.g.mul(&r);

        // Compute Fiat-Shamir challenge, e
        let e = compute_fiat_shamir_challenge::<G, H>(vec![self.g, solution_commitment, a]);

        // Compute challenge response, z
        let z = w * e + r;
        Ok(PuzzleSolutionProof { a, z })
    }
}

impl<G: Group> PuzzleSolutionProof<G> {
    /// verify returns true if the proof is valid and false otherwise.
    pub fn verify<H: Digest>(
        &self,
        g: G,
        solution_commitment: G,
    ) -> Result<bool, SerializationError> {
        // Compute Fiat-Shamir challenge, e
        let e = compute_fiat_shamir_challenge::<G, H>(vec![g, solution_commitment, self.a]);

        // Verify proof
        let lhs = self.a + solution_commitment.mul(&e);
        let rhs = g.mul(&self.z);
        Ok(lhs == rhs)
    }
}

fn compute_fiat_shamir_challenge<G: Group, H: Digest>(input_elements: Vec<G>) -> G::ScalarField {
    let mut hasher = H::new();
    for element in input_elements {
        let mut element_bytes = Vec::new();
        element.serialize_uncompressed(&mut element_bytes).unwrap();
        hasher.update(element_bytes);
    }
    G::ScalarField::from_be_bytes_mod_order(&hasher.finalize())
}
// Tests
#[cfg(test)]
// test for get_solution_root
mod tests {
    use super::*;
    use ark_bn254;
    use sha2;

    #[test]
    fn test_get_solution_root() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let g = ark_bn254::G1Projective::generator();
        let puzzle_solution = PuzzleSolution::<ark_bn254::G1Projective>::new(solutions, g);
        let puzzle_commitment = puzzle_solution.get_solution_commitment::<sha2::Sha256>();

        let wrong_solutions = vec![
            "Solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let wrong_puzzle_solution =
            PuzzleSolution::<ark_bn254::G1Projective>::new(wrong_solutions, g);
        let wrong_puzzle_commitment =
            wrong_puzzle_solution.get_solution_commitment::<sha2::Sha256>();

        assert!(puzzle_commitment != wrong_puzzle_commitment);
    }

    // Test for get_solution_proof and verify
    #[test]
    fn test_get_solution_proof() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let g = ark_bn254::G1Projective::generator();
        let puzzle_solution = PuzzleSolution::<ark_bn254::G1Projective>::new(solutions, g);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof::<sha2::Sha256>(w, puzzle_commitment)
            .unwrap();

        assert!(
            puzzle_solution_proof
                .verify::<sha2::Sha256>(g, puzzle_commitment)
                .unwrap()
                == true
        );

        let wrong_solutions = vec![
            "Solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let wrong_puzzle_solution =
            PuzzleSolution::<ark_bn254::G1Projective>::new(wrong_solutions, g);
        let (w, wrong_puzzle_commitment) =
            wrong_puzzle_solution.get_solution_commitment::<sha2::Sha256>();
        let wrong_puzzle_solution_proof = wrong_puzzle_solution
            .get_solution_proof::<sha2::Sha256>(w, wrong_puzzle_commitment)
            .unwrap();

        assert!(
            wrong_puzzle_solution_proof
                .verify::<sha2::Sha256>(g, puzzle_commitment)
                .unwrap()
                == false
        );
    }

    // check that the get_solution_proof returns error if solution is wrong
    #[test]
    fn test_get_solution_proof_error() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let g = ark_bn254::G1Projective::generator();
        let puzzle_solution = PuzzleSolution::<ark_bn254::G1Projective>::new(solutions, g);
        let (_, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>();

        let wrong_solutions = vec![
            "Solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let wrong_puzzle_solution =
            PuzzleSolution::<ark_bn254::G1Projective>::new(wrong_solutions, g);
        let (wrong_w, _) = wrong_puzzle_solution.get_solution_commitment::<sha2::Sha256>();

        assert!(puzzle_solution
            .get_solution_proof::<sha2::Sha256>(wrong_w, puzzle_commitment)
            .is_err());
    }
}
