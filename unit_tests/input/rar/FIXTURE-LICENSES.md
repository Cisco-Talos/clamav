# Fixture licensing

The RAR fixtures in this directory are synthetic test archives created by the
`rars` project and distributed under its Apache License 2.0. They contain test
text, byte patterns, generated noise, or empty data rather than third-party
documents. ClamAV copied them from the following paths at `rars` commit
`e01b925aaf49a40995e1cae23819cb60383121c3`:

| ClamAV fixture | `rars` fixture |
|---|---|
| `rar13-store.rar` | `rar13/README_store.rar` |
| `rar15-normal.rar` | `rar15_40/rar154/readme_154_normal.rar` |
| `rar20-zero-fill.rar` | `rar15_40/zero_fill/rar20.rar` |
| `rar3-comment.rar` | `rar15_40/rar300/with_comment_rar300.rar` |
| `rar3-custom-vm.rar` | `rar15_40/rarvm/generic_static_data_call_ret.rar` |
| `rar3-filter-e8.rar` | `rar15_40/rar300/rarvm_x86_e8_rar300.rar` |
| `rar3-header-encrypted.rar` | `rar15_40/encrypted/header_rar300_password.rar` |
| `rar3-member-encrypted.rar` | `rar15_40/encrypted/per_file_rar300_password.rar` |
| `rar3-solid.rar` | `rar15_40/rar300/solid_simple_rar300.rar` |
| `rar5-comment.rar` | `rar50/with_comment.rar` |
| `rar5-empty.rar` | `rar50/empty_file.rar` |
| `rar5-filter-delta.rar` | `rar50/filter_delta.rar` |
| `rar5-header-encrypted.rar` | `rar50/header_encrypted.rar` |
| `rar5-malformed-member.rar` | `rar50/zero_fill_out_of_window.rar` |
| `rar5-malformed-service.rar` | `rar50/subdata_size_underflow.rar` |
| `rar5-member-encrypted.rar` | `rar50/password_crc32.rar` |
| `rar5-redirections.rar` | `rar50/flat_links.rar` |
| `rar5-services.rar` | `rar50/with_all_services.rar` |
| `rar5-solid.rar` | `rar50/solid.rar` |
| `rar5-split-part1.rar` | `rar50/multivol.part1.rar` |
| `rar5-store.rar` | `rar50/stored.rar` |
| `rar7-store.rar` | `golden/stored_rar70.rar` |

`rar3-sfx.exe` is derived from `rar3-solid.rar` by prepending the first 512
bytes of ClamAV's existing `unit_tests/input/pe_allmatch/test.exe` fixture.
Both components are already distributed in the ClamAV source tree or covered
by the Apache-2.0 terms above.

See `COPYING/COPYING.rars` for the Apache License 2.0 text.
