# Lane 22: remaining medium modules

## Goal and ownership

Review and split only files that still combine multiple responsibilities in
`crates/policy`, `crates/backup`, `crates/attest`, `crates/audit`,
`crates/network`, `crates/deploy`, `crates/output-lifecycle`, and
`crates/bisim`. This lane exclusively owns those crates. Start after
lanes 06, 11, 12, 14, 15, 18, and 20.

## Work packets

1. Policy:
   - `active_bundle/{model,simulation,activation,snapshot,canonical,validation}`
   - `cedar/{model,entities,request,evaluation,schema,validation}`
   - `break_glass/{model,lifecycle,validation}`
2. Backup:
   - split `database.rs` into `database/{copy,inspection,schema,integrity,audit}`
   - split `secure_fs.rs` into
     `secure_fs/{identity,directories,copy,hashing,files,paths,sync,cleanup}`
   - keep backup create/verify/restore/activate workflows intact.
3. Attest: split image model, verification, update, and validation; preserve
   exact signature domains.
4. Audit: split model, chain, checkpoint, file log, canonical encoding, and
   validation while retaining `signed.rs` if cohesive.
5. Network: split limits/model, tickets, authorization, address policy,
   validation, and errors.
6. Deploy: split environment, policy, subject, request, record, gate, validation,
   and errors.
7. Output lifecycle: split scanner, promotion, worker, GC, and object graph.
8. Conformance: split model, backend, comparison, secret scan, validation, and
   errors.

Process one crate at a time. If a file is under 800 production lines and owns
one cohesive workflow, document it as an intentional exception rather than
fragmenting it. Run standard checks for every changed package.
