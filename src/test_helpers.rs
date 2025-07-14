#[cfg(test)]
pub mod test_helpers {
    use nfsserve::nfs::nfsstring;

    pub fn filename(s: &[u8]) -> nfsstring {
        nfsstring(s.to_vec())
    }
}
