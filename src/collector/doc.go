package collector

// Collectors are Packet Collection Engines
// Goatherd supports multiple distributed collector, running on disparate hosts
// Each collector must observe at least one capture point (usually a local NIC)
// but may support multiple, for multihomed systems
