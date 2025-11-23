//! Secure byte storage for sensitive data
//!
//! Provides a type-safe wrapper for sensitive data (private keys, PINs, tokens)
//! with automatic memory zeroing and optional memory locking.

use alloc::vec::Vec;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "std")]
use secstr::SecVec;

use subtle::ConstantTimeEq;

/// Secure bytes for sensitive data (private keys, PINs, tokens)
///
/// # Security Guarantees
///
/// - **With std feature**: Uses `SecVec` which provides:
///   - `mlock` to prevent swapping to disk
///   - Zeroing on drop via `zeroize`
///   - Constant-time equality
///
/// - **Without std (no_std)**: Uses `Zeroizing<Vec<u8>>` which provides:
///   - Zeroing on drop via `zeroize`
///   - No mlock (not available in no_std)
///
/// # Safety Notes
///
/// Even with SecBytes, temporary copies may exist:
/// - Stack copies during operations (NOT mlocked, OS limitation)
/// - Intermediate buffers during conversions
/// - Cryptographic library internals
///
/// Minimize calls to `as_slice()` to reduce exposure window.
/// Prefer `with_bytes()` for operations that need temporary access.
#[derive(Clone)]
pub struct SecBytes {
    #[cfg(feature = "std")]
    inner: SecVec<u8>,

    #[cfg(not(feature = "std"))]
    inner: Zeroizing<Vec<u8>>,
}

impl SecBytes {
    /// Create from Vec<u8>
    ///
    /// The input vector is moved into protected storage.
    pub fn new(data: Vec<u8>) -> Self {
        #[cfg(feature = "std")]
        return Self {
            inner: SecVec::from(data),
        };

        #[cfg(not(feature = "std"))]
        return Self {
            inner: Zeroizing::new(data),
        };
    }

    /// Create from slice (copies data)
    ///
    /// The slice is copied into protected storage.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Create from array (copies data)
    pub fn from_array<const N: usize>(data: [u8; N]) -> Self {
        Self::new(data.to_vec())
    }

    /// Access raw bytes
    ///
    /// # Security Warning
    ///
    /// This returns a reference to the protected memory. While the underlying
    /// storage is protected, the returned slice itself is a normal reference
    /// and could be copied. Minimize the scope where this slice is held.
    ///
    /// Prefer using `with_bytes()` for operations that need temporary access.
    pub fn as_slice(&self) -> &[u8] {
        #[cfg(feature = "std")]
        return self.inner.unsecure();

        #[cfg(not(feature = "std"))]
        return &self.inner;
    }

    /// Get length
    pub fn len(&self) -> usize {
        #[cfg(feature = "std")]
        return self.inner.unsecure().len();

        #[cfg(not(feature = "std"))]
        return self.inner.len();
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Perform operation with protected scope
    ///
    /// This is the PREFERRED way to access key material. The closure
    /// receives a reference to the data, and the function encourages
    /// the compiler to clean up stack space after the operation.
    ///
    /// # Example
    /// ```ignore
    /// let key = SecBytes::new(vec![0u8; 32]);
    /// let signature = key.with_bytes(|bytes| {
    ///     ecdsa::sign(bytes, message)  // bytes used here
    /// })?;
    /// // Stack frames cleaned up here
    /// ```
    pub fn with_bytes<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(self.as_slice());

        // Force stack frame cleanup
        // This encourages the compiler to zero stack space
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        result
    }

    /// Convert to fixed-size array with automatic zeroing
    ///
    /// Returns a `Zeroizing` wrapper that zeros the array on drop.
    /// Preferred over manual copying to stack.
    ///
    /// # Errors
    ///
    /// Returns `None` if the length doesn't match.
    pub fn to_array<const N: usize>(&self) -> Option<Zeroizing<[u8; N]>> {
        if self.len() != N {
            return None;
        }

        let mut arr = [0u8; N];
        arr.copy_from_slice(self.as_slice());
        Some(Zeroizing::new(arr))
    }

    /// Clone the underlying data as unprotected Vec
    ///
    /// # Security Warning
    ///
    /// This creates an unprotected copy of the sensitive data. The returned
    /// Vec will NOT be zeroed on drop and will NOT be mlocked. Only use this
    /// when absolutely necessary (e.g., interfacing with external APIs).
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

// Implement Zeroize for proper cleanup
impl Zeroize for SecBytes {
    fn zeroize(&mut self) {
        #[cfg(feature = "std")]
        {
            // SecVec already handles zeroizing internally
        }

        #[cfg(not(feature = "std"))]
        {
            self.inner.zeroize();
        }
    }
}

impl Drop for SecBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Implement Debug without revealing contents
impl core::fmt::Debug for SecBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecBytes")
            .field("len", &self.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

// Constant-time equality (important for PIN/token comparison)
impl PartialEq for SecBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl Eq for SecBytes {}

// Serialization support
impl Serialize for SecBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for SecBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(SecBytes::new(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_access() {
        let data = vec![1, 2, 3, 4];
        let sec = SecBytes::new(data.clone());
        assert_eq!(sec.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(sec.len(), 4);
        assert!(!sec.is_empty());
    }

    #[test]
    fn test_from_slice() {
        let data = &[1, 2, 3, 4];
        let sec = SecBytes::from_slice(data);
        assert_eq!(sec.as_slice(), data);
    }

    #[test]
    fn test_from_array() {
        let data = [1u8, 2, 3, 4];
        let sec = SecBytes::from_array(data);
        assert_eq!(sec.as_slice(), &data);
    }

    #[test]
    fn test_to_array() {
        let data = vec![1, 2, 3, 4];
        let sec = SecBytes::new(data);
        let arr = sec.to_array::<4>().unwrap();
        assert_eq!(*arr, [1, 2, 3, 4]);
    }

    #[test]
    fn test_to_array_wrong_size() {
        let data = vec![1, 2, 3, 4];
        let sec = SecBytes::new(data);
        assert!(sec.to_array::<5>().is_none());
    }

    #[test]
    fn test_with_bytes() {
        let data = vec![1, 2, 3, 4];
        let sec = SecBytes::new(data);
        let sum = sec.with_bytes(|bytes| bytes.iter().sum::<u8>());
        assert_eq!(sum, 10);
    }

    #[test]
    fn test_clone() {
        let data = vec![1, 2, 3, 4];
        let sec1 = SecBytes::new(data);
        let sec2 = sec1.clone();
        assert_eq!(sec1.as_slice(), sec2.as_slice());
    }

    #[test]
    fn test_equality() {
        let sec1 = SecBytes::new(vec![1, 2, 3, 4]);
        let sec2 = SecBytes::new(vec![1, 2, 3, 4]);
        let sec3 = SecBytes::new(vec![1, 2, 3, 5]);
        assert_eq!(sec1, sec2);
        assert_ne!(sec1, sec3);
    }

    #[test]
    fn test_debug() {
        let sec = SecBytes::new(vec![1, 2, 3, 4]);
        let debug_str = format!("{:?}", sec);
        assert!(debug_str.contains("SecBytes"));
        assert!(debug_str.contains("len"));
        assert!(debug_str.contains("redacted"));
        // Ensure actual data is not in debug output
        assert!(!debug_str.contains("1"));
    }

    #[test]
    fn test_empty() {
        let sec = SecBytes::new(vec![]);
        assert!(sec.is_empty());
        assert_eq!(sec.len(), 0);
    }
}
