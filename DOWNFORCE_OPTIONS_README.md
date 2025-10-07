# DownForce Compaction Options

This document describes the new configurable options added to control DownForce compaction behavior.

## Overview

The DownForce research implementation introduced several modifications to RocksDB's compaction strategy. These changes have been made configurable through new options so they can be toggled on/off as needed.

## New Options

### 1. `enable_downforce_compaction` (NEW)
**Type**: `bool`  
**Default**: `false`  
**Location**: `include/rocksdb/options.h` (ColumnFamilyOptions)

Controls the DownForce compaction strategy which includes:
- Modified Level 1 file selection based on `need_compaction` flag
- Disabled intra-L0 compaction
- Disabled L0 trivial moves
- Modified overlap checking for compaction candidates
- Allow multiple L0 compactions in progress
- Skip files that are being compacted

**When enabled**:
- For Level 1: selects ALL files marked with `need_compaction=true` instead of just overlapping files
- For other levels: excludes files that are currently being compacted
- Allows more aggressive L0 to L1 compaction behavior
- Bypasses normal restrictions on concurrent L0 compactions

### 2. `in_memory_merge` (EXISTING)
**Type**: `bool`  
**Default**: `true`  
**Location**: `include/rocksdb/options.h`

Enable in-memory merge of memtables before flushing to L0.

### 3. `disable_intra_l0_compaction` (EXISTING)
**Type**: `bool`  
**Default**: `false`  
**Location**: `include/rocksdb/options.h`

Disable intra-L0 compaction (compactions within L0 level).

### 4. `l0_size_based_stop` (EXISTING)
**Type**: `bool`  
**Default**: `false`  
**Location**: `include/rocksdb/options.h`

Enable L0 size-based stop writes trigger instead of file count based.

## Implementation Details

### File Metadata
- `need_compaction` field added to `FileMetaData` (db/version_edit.h)
- `need_compaction` field added to `SstFileMetaData` (include/rocksdb/metadata.h)

### Modified Files

1. **include/rocksdb/options.h**
   - Added `enable_downforce_compaction` option

2. **options/cf_options.h**
   - Added `enable_downforce_compaction` to `MutableCFOptions`

3. **db/compaction/compaction_picker_level.cc**
   - Wrapped DownForce-specific logic with `enable_downforce_compaction` checks
   - Modified file selection and compaction triggering behavior

4. **db/compaction/compaction_picker.cc**
   - Added option checks for allowing files in compaction
   - Modified L0 compaction restrictions

5. **db/version_set.h & db/version_set.cc**
   - Added `enable_downforce` parameter to file selection methods:
     - `GetOverlappingInputs()`
     - `GetCleanInputsWithinInterval()`
     - `GetOverlappingInputsRangeBinarySearch()`
   - Implemented Level 1 special selection logic

## Usage Example

```cpp
rocksdb::Options options;

// Enable the DownForce compaction strategy
options.enable_downforce_compaction = true;

// Optionally configure related options
options.in_memory_merge = true;
options.disable_intra_l0_compaction = false;
options.l0_size_based_stop = true;

rocksdb::DB* db;
rocksdb::Status status = rocksdb::DB::Open(options, "/path/to/db", &db);
```

## Behavior Differences

### With `enable_downforce_compaction = false` (Default/Traditional RocksDB):
- Normal overlapping file selection for all levels
- Intra-L0 compactions allowed
- L0 trivial moves enabled
- Only one L0 compaction at a time
- Standard overlap checking

### With `enable_downforce_compaction = true` (DownForce Mode):
- Level 1: Select ALL files with `need_compaction=true`, not just overlapping
- All levels: Skip files that are being compacted
- Intra-L0 compactions disabled
- L0 trivial moves disabled
- Multiple concurrent L0 compactions allowed
- More aggressive compaction triggering

## Performance Considerations

The DownForce compaction strategy is designed to:
- Reduce write amplification
- Improve compaction efficiency
- Better handle write-heavy workloads
- Optimize for specific hardware configurations (e.g., with tiered storage)

Users should benchmark their specific workload to determine if enabling DownForce compaction provides benefits.

## Compatibility

- Backward compatible: Default value is `false`
- Can be changed dynamically through `SetOptions()` API
- Works with existing RocksDB features

## Research Background

This implementation is based on the DownForce research paper which proposes modified compaction strategies for improved performance in certain scenarios. The original implementation has been refactored to be controllable through options.


