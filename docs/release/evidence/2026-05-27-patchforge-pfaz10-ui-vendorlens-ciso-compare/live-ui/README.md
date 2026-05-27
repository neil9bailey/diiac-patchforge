# PF-AZ10 Live UI Evidence

Date: 2026-05-27

Live URL: `https://patchforge.diiac.io`

API URL: `https://api.patchforge.diiac.io`

Validation user: `n.bailey@diiac.io`

Displayed role: `PatchForge.Admin`

Results:

- UI HTTP 200: PASS.
- API health/readiness HTTP 200: PASS.
- Protected routes unauthenticated HTTP 401: PASS.
- Action Center visual check: PASS.
- Finding Detail visual overflow check: PASS.
- VendorLens catalogue visual check: PASS.
- NVD catalogue refresh: PASS with governed `completed_with_warnings` state when NVD public rate limit was reached.
- Patch Compare large advisory catalogue: PASS, paginated as `1-10 of 730 comparison advisories`.

Screenshots are in `browser-screenshots/`.
