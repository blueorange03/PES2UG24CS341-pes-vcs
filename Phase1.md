Phase 1 Plan
Implement object_write in three steps:
map object types and build the serialized <type> <size>\0<data> buffer
hash the full object and reuse existing objects when the hash already exists
store new objects atomically in sharded directories under .pes/objects
Implement object_read in two steps:
load the full object file and parse the header safely
recompute the SHA-256 hash, reject corrupted objects, and return the payload
Phase 1 Required Screenshots
1A: ./test_objects showing all tests passing
1B: find .pes/objects -type f showing sharded object files
Commit Target
Keep at least six logical commits for this phase
