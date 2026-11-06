// SPDX-License-Identifier: Apache-2.0

//! The canary for the one `clippy.toml` ban that `uaos-egress`'s canaries cannot name: entropy
//! comes only from the platform's own source. See `crates/uaos-egress/tests/bans.rs`.

mod canaries {
    #![allow(dead_code, reason = "canaries are compiled by clippy and never run")]

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn getrandom_fill() {
        // canary: `getrandom::fill`
        let mut buf = [0u8; 1];
        let _canary = getrandom::fill(&mut buf);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn getrandom_fill_uninit() {
        // canary: `getrandom::fill_uninit`
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1];
        let _canary = getrandom::fill_uninit(&mut buf);
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn getrandom_u32() {
        // canary: `getrandom::u32`
        let _canary = getrandom::u32();
    }

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn getrandom_u64() {
        // canary: `getrandom::u64`
        let _canary = getrandom::u64();
    }

    #[expect(clippy::disallowed_types, reason = "canary")]
    fn getrandom_sys_rng(
        // canary: `getrandom::SysRng`
        _canary: &[getrandom::SysRng],
    ) {
    }
}
