

use ethers_core::abi::AbiEncode;
use ethers_core::types::{Signature, Address, H256};
use ethers_core::utils::keccak256;
use ethers_signers::{Signer, Wallet};
use digest::Digest;
use anyhow::Result;

/// PuzzleSolution is a struct that contains a set of `solutions` to a puzzle and the key `g` used to commit to them.
/// The solutions are expected as strings.
pub struct PuzzleSolution {
    solutions: Vec<String>,
}

/// PuzzleSolutionProof is a struct that contains a proof that a given solution is a valid solution to a puzzle.
/// The proof is a signed message that uses the solution digest as the secret key.
/// To link the proof to the solver, the solver's Ethereum address is used as the message that is signed.
pub struct PuzzleSolutionProof {
    pub a: Signature,
    pub m_s: Address,
}

impl PuzzleSolution{
    pub fn new(solutions: Vec<String>) -> Self {
        Self { solutions}
    }

    /// get_solution_commitment returns the commitment to the solution set.
    pub fn get_solution_commitment<H: Digest>(&self) -> Result<( Wallet<ecdsa::SigningKey<k256::Secp256k1>>, Address)>  {
        // Compute chain of hashes of each solution in the solution set
        // and commit to the last hash in the chain
        let mut hasher = H::new();

        for solution in &self.solutions {
            hasher.update(solution.as_bytes());
        }

        let w_bytes = hasher.finalize();

        let w: Wallet<ecdsa::SigningKey<k256::Secp256k1>> = Wallet::from_bytes(&w_bytes)?;
        let binding = w.clone();
        let h = binding.address();
        Ok((w, h))
    }

    /// get_solution_proof returns a proof that the given solution is a valid solution to the puzzle.
    pub async fn get_solution_proof(
        &self,
        w: Wallet<ecdsa::SigningKey<k256::Secp256k1>>,
        solution_commitment: Address,
        m_s: Address,
    ) -> Result<PuzzleSolutionProof> {
        // Check that w is correct solution
        //TODO: Better error handling
        let h = w.address();
        match h == solution_commitment {
            true => (),
            false => return Err(anyhow::Error::msg("Invalid solution")),
        }

        // Compute hash of m_s
        let m_s_hash = H256::from(keccak256(m_s.encode()));

        // Sign hash of m_s
        let a = w.sign_hash(m_s_hash)?;

        Ok(PuzzleSolutionProof{ a, m_s})
    }
}

impl PuzzleSolutionProof {
    /// verify returns true if the proof is valid and false otherwise.
    pub fn verify(
        &self,
        solution_commitment: Address,
    ) -> Result<bool> {

        // Verify proof
        let m_s_hash = H256::from(keccak256(self.m_s.encode()));
        let result = self.a.recover(m_s_hash)?;
        Ok(result==solution_commitment)
    }

    /// verify returns serialized bytes for self.a, self.z, g, and solution_commitment if the proof is valid and error otherwise.
    pub fn verify_and_export(
        &self,
        solution_commitment: Address,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u8, Vec<u8> )> {
  
        // Verify proof
        let m_s_bytes = self.m_s.clone();
        let m_s_hash = H256::from(keccak256(self.m_s.clone().encode()));
        let result = self.a.recover(m_s_hash)?;
        match result == solution_commitment {
            true => {
                let a_bytes = self.a.to_vec();
                let r_abi = self.a.r.encode();
                let s_abi = self.a.s.encode();
                let v_abi = self.a.recovery_id()?.to_byte();

                Ok((
                    a_bytes,
                    r_abi,
                    s_abi,
                    v_abi,
                    m_s_bytes.as_bytes().to_vec(),
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
    use ethers_signers::{Signer, LocalWallet};
    use tokio;

    #[tokio::test]
    async fn test_get_solution_commitment() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let m_s = LocalWallet::new(&mut rand::thread_rng()).address();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof(w, puzzle_commitment, m_s)
            .await.unwrap();

        assert!(
            puzzle_solution_proof
                .verify(puzzle_commitment)
                .unwrap()
                == true
        );
    }

    // Test for get_solution_proof and verify
    #[tokio::test]
    async fn test_get_solution_proof() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let m_s = LocalWallet::new(&mut rand::thread_rng()).address();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof(w, puzzle_commitment, m_s.clone())
            .await.unwrap();

        assert!(
            puzzle_solution_proof
                .verify(puzzle_commitment)
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
            .get_solution_proof(wrong_w, wrong_puzzle_commitment, m_s)
            .await.unwrap();

        assert!(
            wrong_puzzle_solution_proof
                .verify(puzzle_commitment)
                .unwrap()
                == false
        );
    }

    // Test for verify_and_export
    #[tokio::test]
    async fn test_verify_and_export() {
        let solutions = vec![
            "solution1".to_string(),
            "solution2".to_string(),
            "solution3".to_string(),
        ];
        let puzzle_solution = PuzzleSolution::new(solutions);
        let (w, puzzle_commitment) = puzzle_solution.get_solution_commitment::<sha2::Sha256>().unwrap();
        let m_s = LocalWallet::new(&mut rand::thread_rng()).address();
        let puzzle_solution_proof = puzzle_solution
            .get_solution_proof(w, puzzle_commitment, m_s.clone())
            .await.unwrap();

        let (
            a_bytes,
            r_abi,
            s_abi,
            v_abi,
            m_s_bytes,
        ) = puzzle_solution_proof
            .verify_and_export(puzzle_commitment)
            .unwrap();

        assert!(a_bytes.len() == 65);
        assert!(r_abi.len() == 32);
        assert!(s_abi.len() == 32);
        assert!(v_abi == 0 || v_abi == 1 );
        assert!(m_s_bytes.len() == 20);
    }
}
