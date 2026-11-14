# Local HTTP / loose Git capture audit

Resolve the original capture result_id and artifact_ref for the current task
and target. Audit only the particular disputed claim/quotation. PM's local
validator checks artifact presence, body hash/size and capture linkage. Missing,
foreign or corrupted data remain unverified; do not manufacture a replacement.
For a loose Git object, validate decompression, object type/length and the SHA-1
object identity against its captured path before quoting decoded blob bytes.
For example, /.git/objects/aa/<38 hex> identifies an object, not a proof of the
interpretation of its contents. A claimed hash in stdout is not that artifact.
Return probe.result_id, artifact_ref and an exact quote from the validated body.
No new GET is needed for this audit, and readback creates no independent source.
Flag provenance also rejects values contributed by the request itself. Other
authentic evidence for the same flag must be evaluated independently.

Validation coverage: tests/test_verify_saved_capture.py and
tests/test_flag_evidence.py use real temporary capture storage and local
validators. This path supports HTTP / loose Git objects, not automatic flag
confirmation from SSH/shell output. Missing provenance needs operator review.
