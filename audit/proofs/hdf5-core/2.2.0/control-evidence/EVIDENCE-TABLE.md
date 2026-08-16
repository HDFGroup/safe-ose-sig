# Evidence table — hdf5-core 2.2.0 control-evidence (H5Policy)

Machine-checked mapping imported from `registry/ssp-control-evidence.yml`
(hdf5-pickles), measured against libhdf5 2.2.0. Authoritative source is
[`imported-contract.yml`](./imported-contract.yml); this table is the
human-readable disposition. The producer checker gates every field
([`checker-output.txt`](./checker-output.txt)).

## Control → evidence mapping

| Control | Record / invariant | Finding (h5policy) | Regression fixture | Oracle decision | libhdf5 2.2.0 outcome |
| --- | --- | --- | --- | --- | --- |
| HDF5-SHINES-VULN-04 | `dataspace_dimension` / `dataspace.nelem_product` | `H5_CORRUPT_DATASPACE_NELEM_OVERFLOW` | `malformed-dataspace_nelem_overflow.yml` | reject_corrupt | family enforced; fixture enforced |
| HDF5-SHINES-TEST-01 | `chunk_index` / `chunk.no_cycle` | `H5_CORRUPT_CHUNK_INDEX_CYCLE` | `malformed-bad_chunk_v2_btree_cycle.yml` | reject_corrupt | family partial; fixture enforced |
| HDF5-SHINES-TEST-05 | `datatypes` / `datatype.compound_member_bounds` | `H5_CORRUPT_DATATYPE_COMPOUND_MEMBER_BOUNDS` | `malformed-compound_member_array_bounds.yml` | reject_corrupt | family partial; fixture diverges |
| HDF5-SHINES-TEST-05 | `dense_index` / `dense.btree_record_size` | `H5_CORRUPT_V2_BTREE_RECORD_SIZE` | `malformed-zero_v2_btree_record_size.yml` | reject_corrupt | family partial; fixture **crashes** (SIGFPE) |
| HDF5-SHINES-HARD-04 | `external_link` / `elink.no_external_traverse` | `H5_POLICY_EXTERNAL_LINK` | `policy-external_link.yml` | reject_policy | family enforced; activation observed: external_open |
| HDF5-SHINES-TM-03 | `virtual_dataset` / `vds.source_path_classified` | `H5_ADVISORY_VDS_ABSOLUTE_SOURCE` | `policy-vds_absolute_source.yml` | accept_with_warnings | family enforced; activation observed: external_open |

Notes:

- **TEST-05 carries two rows**: a control is evidenced by every fixed
  vulnerability class, not one fixture. The second row is the v2 B-tree
  `record_size == 0` divide-by-zero — h5policy rejects the header before
  libhdf5's `H5B2__hdr_init` reaches its SIGFPE, so the native outcome is
  `crashes` (recorded under `dense_index.crashes_on` in the exact-build matrix).
  Root cause: `registry/cases/v2-btree-record-size-zero-assert-only.yml`.
- **HARD-04 / TM-03** are reject_policy / advisory decisions libhdf5 has no
  equivalent of, so the native column reports the activation the exact build was
  observed to take rather than an enforcement verdict.

## SSP reviewer disposition

- [ ] Confirm the imported contract SHA-256 and producer commit in `provenance.json`.
- [ ] Confirm the measured libhdf5 version (2.2.0) matches this release.
- [ ] For each control, record in [`README.md`](./README.md) the residual evidence
      the H5Policy fixture does **not** establish (review records, disclosure,
      ownership, release approval), and where that evidence lives.
