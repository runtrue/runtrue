impl CacheStore {
    pub fn promote(
        &self,
        source_identity: &CacheIdentity,
        target_identity: CacheIdentity,
        evidence: PromotionEvidence,
        expected_target_head: Option<&CacheHead>,
        fencing_generation: u64,
    ) -> Result<CacheEntry, CacheError> {
        source_identity.validate(self.limits)?;
        target_identity.validate(self.limits)?;
        validate_fence(fencing_generation)?;
        validate_promotion_evidence(&evidence, self.limits)?;
        if !source_identity.same_content_key_except_trust(&target_identity) {
            return Err(CacheError::InvalidPromotion(
                "promotion may change only the trust domain".to_owned(),
            ));
        }
        if !source_identity
            .trust_domain
            .can_promote_to(&target_identity.trust_domain)
        {
            return Err(CacheError::InvalidPromotion(
                "trust-domain promotion direction or scope is not allowed".to_owned(),
            ));
        }

        let source = self
            .inspect(source_identity)?
            .ok_or(CacheError::SourceNotFound)?;
        self.verify_tree_content(&source.manifest.tree)?;

        let target_digest = target_identity.digest(self.limits)?;
        let current = self.read_head(&target_digest)?;
        require_expected_head(expected_target_head, current.as_ref())?;
        require_fresh_fence(fencing_generation, current.as_ref())?;
        let generation = next_generation(current.as_ref())?;
        let manifest = CacheManifest {
            version: CACHE_MANIFEST_VERSION,
            identity: target_identity,
            identity_digest: target_digest.clone(),
            generation,
            fencing_generation,
            tree: source.manifest.tree.clone(),
            producer: source.manifest.producer.clone(),
            claim_ticket_id: None,
            promotion: Some(PromotionRecord {
                source_manifest_digest: source.head.manifest_digest,
                evidence,
            }),
        };
        let manifest_digest = self.store_manifest(&manifest)?;
        let head = CacheHead {
            version: CACHE_HEAD_VERSION,
            identity_digest: target_digest,
            generation,
            fencing_generation,
            manifest_digest,
            claim_ticket_id: None,
        };
        self.append_head(&head)?;
        Ok(CacheEntry { head, manifest })
    }
}
use super::{next_generation, require_expected_head, require_fresh_fence, validate_fence};
use crate::{
    validate_promotion_evidence, CacheEntry, CacheError, CacheHead, CacheIdentity, CacheManifest,
    CacheStore, PromotionEvidence, PromotionRecord, CACHE_HEAD_VERSION, CACHE_MANIFEST_VERSION,
};
