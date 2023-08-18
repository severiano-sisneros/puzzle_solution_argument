

use ethers_core::k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use digest::Digest;
use anyhow::Result;

/// PuzzleSolution is a struct that contains a set of `solutions` to a puzzle and the key `g` used to commit to them.
/// The solutions are expected as strings.
pub struct PuzzleSolution {
    solutions: Vec<String>,
}

/// PuzzleSolutionProof is a struct that contains a proof that a given solution is a valid solution to a puzzle.
/// The proof is essentially a Schnorr proof of knowledge of the discrete logarithm of a commitment to the solution.
pub struct PuzzleSolutionProof {
    a: Signature,
    m_s: Vec<u8>,
}

impl PuzzleSolution{
    pub fn new(solutions: Vec<String>) -> Self {
        Self { solutions}
    }

    /// get_solution_commitment returns the commitment to the solution set.
    pub fn get_solution_commitment<H: Digest>(&self) -> Result<(SigningKey, VerifyingKey)>  {
        // Compute chain of hashes of each solution in the solution set
        // and commit to the last hash in the chain
        let mut hasher = H::new();

        for solution in &self.solutions {
            hasher.update(solution.as_bytes());
        }

        let w_bytes = hasher.finalize();

        let w = SigningKey::from_slice(&w_bytes)?;
        let binding = w.clone();
        let h = binding.verifying_key();
        Ok((w, *h))
    }

    /// get_solution_proof returns a proof that the given solution is a valid solution to the puzzle.
    pub fn get_solution_proof(
        &self,
        w_bytes: Vec<u8>,
        solution_commitment: VerifyingKey,
        m_s: Vec<u8>,
    ) -> Result<PuzzleSolutionProof> {
        // Check that w is correct solution
        //TODO: Better error handling
        let w = SigningKey::from_slice(&w_bytes)?;
        let h = w.verifying_key();
        match *h == solution_commitment {
            true => (),
            false => return Err(anyhow::Error::msg("Invalid solution")),
        }

        // Send blinding commitment
        let a = w.sign(m_s.as_slice());

        Ok(PuzzleSolutionProof{ a, m_s})
    }
}

impl PuzzleSolutionProof {
    /// verify returns true if the proof is valid and false otherwise.
    pub fn verify<H: Digest>(
        &self,
        solution_commitment: VerifyingKey,
    ) -> Result<bool> {

        // Verify proof
        let result = solution_commitment.verify(self.m_s.as_slice(), &self.a);
        Ok(result.is_ok())
    }

    /// verify returns serialized bytes for self.a, self.z, g, and solution_commitment if the proof is valid and error otherwise.
    pub fn verify_and_export(
        &self,
        solution_commitment: VerifyingKey,
    ) -> Result<(Vec<u8>, Vec<u8>   )> {
  
        // Verify proof
        let result = solution_commitment.verify(&self.m_s.as_slice(), &self.a);
        match result.is_ok() {
            true => {
                let a_bytes = self.a.to_vec();

                Ok((
                    a_bytes,
                    self.m_s.clone()
                ))
            }
            false => Err(anyhow::Error::msg("Invalid proof")),
        }
    }
}

// Tests
#[cfg(test)]
// test for get_solution_root
mod tests {
    use super::*;
    use sha2;
    use ethers_signers::{Signer, LocalWallet};

    #[test]
    fn test_get_solution_commitment() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();

        assert!(*w.verifying_key() == puzzle_commitment);
    }
    // Test for get_solution_proof and verify
    #[test]
    fn test_get_solution_proof() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let m_s = LocalWallet::new(&mut rand::thread_rng()).address().as_bytes().to_vec();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof(w.to_bytes().to_vec(), puzzle_commitment, m_s.clone())
            .unwrap();

        assert!(
            puzzle_solution_proof
                .verify::<sha2::Sha256>(puzzle_commitment)
                .unwrap()
                == true
        );

        let wrong_solutions = vec![
            "Solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let wrong_puzzle_solution =
            PuzzleSolution::new(wrong_solutions);
        let (wrong_w, wrong_puzzle_commitment) =
            wrong_puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let wrong_puzzle_solution_proof = wrong_puzzle_solution
            .get_solution_proof(wrong_w.to_bytes().to_vec(), wrong_puzzle_commitment, m_s)
            .unwrap();

        assert!(
            wrong_puzzle_solution_proof
                .verify::<sha2::Sha256>(puzzle_commitment)
                .unwrap()
                == false
        );
    }

    // Test for verify_and_export
    #[test] 
    fn test_verify_and_export() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let m_s = LocalWallet::new(&mut rand::thread_rng()).address().as_bytes().to_vec();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof(w.to_bytes().to_vec(), puzzle_commitment, m_s)
            .unwrap();

        let (
            a_bytes,
            m_s_bytes,
        ) = puzzle_solution_proof
            .verify_and_export(puzzle_commitment)
            .unwrap();

        assert!(a_bytes.len() > 0);
        assert!(m_s_bytes.len() > 0);
    }
}
