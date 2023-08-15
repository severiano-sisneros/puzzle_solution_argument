
use ark_ec::{Group, CurveGroup, AffineRepr};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{SerializationError, CanonicalSerialize};
use digest::Digest;
use rand::{rngs::StdRng, SeedableRng};

/// PuzzleSolution is a struct that contains a set of `solutions` to a puzzle and the key `g` used to commit to them.
/// The solutions are expected as strings.
pub struct PuzzleSolution<G: Group + CurveGroup> {
    solutions: Vec<String>,
    g: G,
}

/// PuzzleSolutionProof is a struct that contains a proof that a given solution is a valid solution to a puzzle.
/// The proof is essentially a Schnorr proof of knowledge of the discrete logarithm of a commitment to the solution.
pub struct PuzzleSolutionProof<G: Group + CurveGroup> {
    a: G,
    z: G::ScalarField,
}

impl<G: Group + CurveGroup> PuzzleSolution<G> {
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
        (w, self.g.mul(w))
    }

    /// get_solution_proof returns a proof that the given solution is a valid solution to the puzzle.
    pub fn get_solution_proof<H: Digest>(
        &self,
        w: G::ScalarField,
        solution_commitment: G,
    ) -> Result<PuzzleSolutionProof<G>, SerializationError> {
        // Check that w is correct solution
        //TODO: Better error handling
        match self.g.mul(w) == solution_commitment {
            true => (),
            false => return Err(SerializationError::InvalidData),
        }

        // Draw a random blinding number, r
        let mut rng = StdRng::from_entropy();
        let r = G::ScalarField::rand(&mut rng);

        // Send blinding commitment
        let a = self.g.mul(r);

        // Compute Fiat-Shamir challenge, e
        let e = compute_fiat_shamir_challenge::<G, H>(vec![self.g, solution_commitment, a])?;

        // Compute challenge response, z
        let z = w * e + r;

        Ok(PuzzleSolutionProof { a, z })
    }
}

impl<G: Group + CurveGroup> PuzzleSolutionProof<G> {
    /// verify returns true if the proof is valid and false otherwise.
    pub fn verify<H: Digest>(
        &self,
        g: G,
        solution_commitment: G,
    ) -> Result<bool, SerializationError> {
        // Compute Fiat-Shamir challenge, e
        let e = compute_fiat_shamir_challenge::<G, H>(vec![g, solution_commitment, self.a])?;

        // Verify proof
        let lhs = self.a + solution_commitment.mul(&e);
        let rhs = g.mul(self.z);
        Ok(lhs == rhs)
    }

    /// verify returns serialized bytes for self.a, self.z, g, and solution_commitment if the proof is valid and error otherwise.
    pub fn verify_and_export<H: Digest>(
        &self,
        g: G,
        solution_commitment: G,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), SerializationError> {
        // Compute Fiat-Shamir challenge, e
        let e = compute_fiat_shamir_challenge::<G, H>(vec![g, solution_commitment, self.a])?;
        let a = self.a;
        let z = self.z;

        // Verify proof
        let lhs = a + solution_commitment.mul(&e);
        let rhs = g.mul(&z);
        match lhs == rhs {
            true => {
                let (ax_bytes, ay_bytes) = serialize_point(a)?;
                let (gx_bytes, gy_bytes) = serialize_point(g)?;
                let (solution_commitment_x_bytes, solution_commitment_y_bytes) =
                    serialize_point(solution_commitment)?;
                let z_bytes = serialize_scalar::<G>(z)?;

                Ok((
                    ax_bytes,
                    ay_bytes,
                    gx_bytes,
                    gy_bytes,
                    solution_commitment_x_bytes,
                    solution_commitment_y_bytes,
                    z_bytes
                ))
            }
            false => Err(SerializationError::InvalidData),
        }
    }
}

fn serialize_scalar<G: Group >(input_element: G::ScalarField) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    input_element.serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

// This serializes a point in uncompressed format. 
// Just running the serialize_uncompressed function on the projective point results in a y that is sometimes not reduced mod p (maybe when y is negative).
// This causes issues with Ethereum's precompiles when checking if the point is on the curve. 
// So the code here is to make sure that the y is reduced mod p.

fn serialize_point<G: Group + CurveGroup>(p: G) -> Result<(Vec<u8>, Vec<u8>), SerializationError> {
    let p_x = match p.into_affine().x(){
        Some(x) => *x,
        None => return Err(SerializationError::InvalidData),
    };
    
    let p_y = match p.into_affine().y(){
        Some(y) => *y,
        None => return Err(SerializationError::InvalidData),
    };

    let mut x_bytes = Vec::new();
    p_x.serialize_uncompressed(&mut x_bytes)?;
    let mut y_bytes = Vec::new();
    p_y.serialize_uncompressed(&mut y_bytes)?;
    Ok((x_bytes, y_bytes))
}

fn compute_fiat_shamir_challenge<G: Group + CurveGroup, H: Digest>(input_elements: Vec<G>) -> Result<G::ScalarField, SerializationError> {
    let mut hasher = H::new();
    let mut element_bytes = Vec::new();
    
    // Ethereum expects numbers in big endian format so need to reverse each element separately
    for element in input_elements {
        let (x, y) = serialize_point(element)?;
        element_bytes.extend(x.iter().rev().collect::<Vec<_>>());
        element_bytes.extend(y.iter().rev().collect::<Vec<_>>());
    }

    hasher.update(element_bytes);
    let hash_out = hasher.finalize();

    // Mask to 254 bits, we don't want the value to be larger than the group order. Makes it easier for smart contract.
    let mut hash_254 = vec![hash_out[0]&0x3f];
    (1..32)
        .into_iter()
        .for_each(|i| hash_254.push(hash_out[i] & 0xff));

    Ok(G::ScalarField::from_be_bytes_mod_order(&hash_254))
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

    // Test for verify_and_export
    #[test]
    fn test_verify_and_export() {
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

        let (
            ax_bytes,
            ay_bytes,
            gx_bytes,
            gy_bytes,
            solution_commitment_x_bytes,
            solution_commitment_y_bytes,
            z_bytes
        ) = puzzle_solution_proof
            .verify_and_export::<sha2::Sha256>(g, puzzle_commitment)
            .unwrap();

        assert!(z_bytes.len() > 0);
        assert!(ax_bytes.len() > 0);
        assert!(gx_bytes.len() > 0);
        assert!(solution_commitment_x_bytes.len() > 0);
        assert!(ay_bytes.len() > 0);
        assert!(gy_bytes.len() > 0);
        assert!(solution_commitment_y_bytes.len() > 0);
    }
}
