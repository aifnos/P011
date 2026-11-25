.pragma library
// Process-local counters only. No network, file reads, or shell execution.
var count = 0;
var limit = 32;
function reserve() { if (count >= limit) return 0; count += 1; return count; }
