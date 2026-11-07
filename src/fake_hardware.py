from p102 import DEVICE,RECIPE
EP=(15,0,0)
RP=(0,3,2)


class Fake:
    def __init__(self):
        self.ids={EP:DEVICE,RP:0x14831022}
        self.pci={(RP,8):0x06040000,(RP,0x18):0x000F0F00,(EP,0x10):0x50000000,
                  (EP,0x34):0x78,(RP,0x34):0x50,(EP,0x78):0x20010,(RP,0x50):0x20010}
        self.words={(EP,4):6,(EP,0x8A):0x1041,(RP,0x62):0x7041}
        self.pci[(EP,0x84)]=0x00453C41
        self.pci[(RP,0x5C)]=0x00453C83
        self.pci[(EP,0xA4)]=2
        self.regs={o:0 for o,_,_,_ in RECIPE}
        self.regs.update({0x8C040:0x20085800,0x8841C:0x6000})
        self.writes=[]
        self.fail=None
        self.allow_gen2=True

    def read(self,bdf,offset):
        if offset==0: return self.ids.get(bdf,0xFFFFFFFF)
        return self.pci.get((bdf,offset),0)

    def word(self,bdf,offset): return self.words.get((bdf,offset),0)

    def write_word(self,bdf,offset,value):
        self.writes.append(('cfg',bdf,offset,value))
        self.words[(bdf,offset)]=value
        if bdf==RP and offset==0x60 and value&32:
            self.words[(RP,0x60)]=value&~32
            gen=2 if self.regs[0x8C040]&0xC0000==0x40000 and self.allow_gen2 else 1
            self.words[(EP,0x8A)]=0x1040|gen
            self.words[(RP,0x62)]=0x7040|gen

    def mmio(self,bar,offset,value=None):
        if value is not None:
            self.writes.append(('mmio',bar,offset,value))
            if offset==self.fail: raise RuntimeError('injected write failure')
            self.regs[offset]=value
            if offset==0x88610:
                self.pci[(EP,0xA4)]=6
                self.pci[(EP,0x84)]=(self.pci[(EP,0x84)]&~15)|2
        return self.regs[offset]


