#[macro_export]
macro_rules! fixed_bytes_type {
    ($(#[$meta:meta])* $vis:vis struct $name:ident($len:expr);) => {
        $(#[$meta])*
        $vis struct $name(pub [u8; $len]);

        impl $name {
            pub const ZERO: Self = Self([0u8; $len]);

            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() == $len {
                    let mut arr = [0u8; $len];
                    arr.copy_from_slice(bytes);
                    Some(Self(arr))
                } else {
                    None
                }
            }

            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; $len]
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }
    };
}
