use runtrue_model::ContentDigest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseCompletion {
    pub final_state: String,
    pub result_digest: ContentDigest,
}
