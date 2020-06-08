package collectors

// Collectors are Packet Collection Engines
// Goatherd supports multiple distributed collectors, running on disparate hosts
// Each collector must observe at least one capture point (usually a local NIC)
// but may support multiple, for multihomed systems
