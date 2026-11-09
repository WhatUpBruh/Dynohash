#include <bm/bm_sim/calculations.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/phv.h>
#include <bm/bm_sim/headers.h>
#include <iostream>
#include <iomanip>
#include <string>
int main() {
  bm::HeaderType type("tuple",0);
  for (int w : {32,32,16,16,8}) type.push_back_field("f"+std::to_string(type.get_num_fields()),w);
  bm::PHVFactory factory; factory.push_back_header("tuple",0,type);
  auto source=bm::PHVSourceIface::make_phv_source(); source->set_phv_factory(0,&factory);
  auto packet=bm::Packet::make_new(source.get()); packet.get_phv()->get_header(0).mark_valid();
  bm::BufBuilder builder; for(int i=0;i<5;i++) builder.push_back_field(0,i);
  bm::Calculation calc(builder,"crc32");
  uint64_t src,dst,sport,dport,proto;
  while (std::cin >> src >> dst >> sport >> dport >> proto) {
    uint64_t values[]={src,dst,sport,dport,proto};
    for(int i=0;i<5;i++) packet.get_phv()->get_field(0,i).set(values[i]);
    bm::ByteContainer key; builder(packet,&key);
    for(size_t i=0;i<key.size();i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)key[i];
    std::cout << ' ' << std::dec << calc.output(packet) << '\n';
  }
}
