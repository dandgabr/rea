# Binwalk-NG verification record

Validation on Node 24.18.0 and upstream `binwalk-ng/binwalk-ng` commit
`368c3815cb97976ae7ba6092f356933169f06dae`:

- Real user-systemd boundary suite, including late manager environment and
  dynamic-loader controls: 9 passed.
- Public native CLI/MCP acceptance: 7 passed, 3 skipped. The three skips are
  optional feature/build variants and remain unverified.
- `npm run check:fast`, `npm run docs:check`, and `git diff --check` passed.

## Targeted mutation checks

These three non-equivalent mutants were introduced one at a time, tested, and
reverted before the next mutation. Every test exited nonzero on the mutant,
killing it. Run commands used Node 24.18.0 through
`PATH=/tmp/rea-node24-bin:$PATH`.

| Mutant                         | Exact behavior change                                                                                                                                                                   | Test command                                                              | Result                                     |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------ |
| Unavailable provider admission | Add `"extract_firmware"` to the `BinwalkNgProvider` supported-operation allowlist in `src/firmware/binwalkNg/BinwalkNgProvider.ts`.                                                     | `npm run test:local -- src/firmware/binwalkNg/BinwalkNgAdmission.test.ts` | Killed: admission regression failed.       |
| Aggregate transfer budget      | Remove the `if (frame.bytes > limits.maxBytes - bytes) throw new Error("Binwalk-NG transfer exceeds aggregate byte budget");` check from `src/firmware/binwalkNg/BinwalkNgTransfer.ts`. | `npm run test:local -- src/firmware/binwalkNg/BinwalkNgTransfer.test.ts`  | Killed: aggregate-budget assertion failed. |
| Output digest enforcement      | Change `{ sha256: frame.sha256, bytes: frame.bytes }` to `{ bytes: frame.bytes }` in the `SafeOutputTree` write call in `src/firmware/binwalkNg/BinwalkNgTransfer.ts`.                  | `npm run test:local -- src/firmware/binwalkNg/BinwalkNgTransfer.test.ts`  | Killed: digest-integrity assertion failed. |

Targeted score: **3/3 (100%)**. This is not a project-wide mutation score and
does not satisfy the repository's broader mutation threshold. No mutation-test
runner is configured in `package.json`; lifecycle, external-helper and
caller-container paths remain disabled and their mutants were not exercised.
