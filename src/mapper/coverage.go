package mapper

/*
subnet coverage calculations. the primary heuristic weighting for declaring a specific CIDR subnet


 * track source and destination Address bits, associate them with the MAC address they are observed from

 * mark the bit positions that are observed as changing, on each MAC, grouped by comm that originate
 from this MAC and are delivered to this MAC

 * Eventually you are left with a porous bitmask of variable bits (some bits beyond the mask boundary are still changeable)

 * Assume that the mask with the most longest, clearly defined immutable prefix is "downstream" to that MAC

*/
