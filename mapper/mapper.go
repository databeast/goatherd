package mapper

type Mapper struct {
	ingester *PacketIngester
}

func (m *Mapper) Begin() {

}
func NewMapper() *Mapper {
	newmapper := &Mapper{ingester: &PacketIngester{}}
	return newmapper

}
