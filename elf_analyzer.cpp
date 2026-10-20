#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class ElfAnalyzer {
    std::vector<uint8_t> data;
    bool is64 = false, little = true;
    uint16_t type = 0, machine = 0, phnum = 0, shnum = 0, shstrndx = 0;
    uint64_t entry = 0, phoff = 0, shoff = 0;
    uint16_t phentsize = 0, shentsize = 0;
    struct Section { uint32_t name=0, type=0, link=0, info=0; uint64_t flags=0, addr=0, off=0, size=0, entsize=0; std::string label; };
    struct Program { uint32_t type=0, flags=0; uint64_t off=0, vaddr=0, filesz=0, memsz=0, align=0; };
    std::vector<Section> sections;
    std::vector<Program> programs;
    std::vector<std::string> warnings;

    void requireRange(uint64_t off, uint64_t size, const std::string& what) const {
        if (off > data.size() || size > data.size() - off)
            throw std::runtime_error("Invalid file: " + what + " lies outside the file");
    }
    uint64_t readInt(uint64_t off, unsigned n) const {
        requireRange(off, n, "integer field");
        if (n > 8) throw std::runtime_error("Unsupported integer width");
        uint64_t v = 0;
        if (little) for (unsigned i=0;i<n;i++) v |= uint64_t(data[off+i]) << (8*i);
        else for (unsigned i=0;i<n;i++) v = (v << 8) | data[off+i];
        return v;
    }
    std::string strAt(uint64_t off, uint64_t maxLen) const {
        if (off >= data.size()) return "<bad-string-offset>";
        uint64_t end = std::min<uint64_t>(data.size(), off + std::min<uint64_t>(maxLen, data.size()-off));
        std::string s;
        for (uint64_t i=off;i<end && data[i];i++) s.push_back(static_cast<char>(data[i]));
        return s;
    }
    static std::string machineName(uint16_t m) {
        switch(m) { case 3:return "Intel 80386"; case 40:return "ARM"; case 62:return "x86-64"; case 183:return "AArch64"; case 243:return "RISC-V"; default:return "Unknown ("+std::to_string(m)+")"; }
    }
    static std::string typeName(uint16_t t) {
        switch(t) { case 0:return "NONE"; case 1:return "REL (relocatable)"; case 2:return "EXEC (executable)"; case 3:return "DYN (shared object / often PIE)"; case 4:return "CORE"; default:return "Unknown ("+std::to_string(t)+")"; }
    }
    static std::string sectionType(uint32_t t) {
        switch(t) { case 0:return "NULL"; case 1:return "PROGBITS"; case 2:return "SYMTAB"; case 3:return "STRTAB"; case 4:return "RELA"; case 6:return "DYNAMIC"; case 7:return "NOTE"; case 8:return "NOBITS"; case 9:return "REL"; case 11:return "DYNSYM"; default:return "OTHER("+std::to_string(t)+")"; }
    }
    static std::string programType(uint32_t t) {
        switch(t) { case 0:return "NULL"; case 1:return "LOAD"; case 2:return "DYNAMIC"; case 3:return "INTERP"; case 4:return "NOTE"; case 1685382480:return "GNU_PROPERTY"; case 1685382481:return "GNU_STACK"; case 1685382482:return "GNU_RELRO"; default:return "OTHER("+std::to_string(t)+")"; }
    }
    std::string flags(uint64_t f, bool section=false) const {
        std::string s;
        if (section) { if(f&1)s+='W'; if(f&2)s+='A'; if(f&4)s+='X'; }
        else { if(f&4)s+='R'; if(f&2)s+='W'; if(f&1)s+='E'; }
        return s.empty()?"-":s;
    }
    void parse() {
        requireRange(0,16,"ELF identification");
        if (!(data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F')) throw std::runtime_error("Not an ELF file (missing 0x7F 'ELF' magic)");
        if(data[4]!=1 && data[4]!=2) throw std::runtime_error("Unsupported ELF class");
        if(data[5]!=1 && data[5]!=2) throw std::runtime_error("Unsupported ELF byte order");
        is64=data[4]==2; little=data[5]==1;
        const uint64_t ehsize=is64?64:52;
        requireRange(0,ehsize,"ELF header");
        type=readInt(16,2); machine=readInt(18,2);
        entry=readInt(is64?24:24,is64?8:4);
        phoff=readInt(is64?32:28,is64?8:4); shoff=readInt(is64?40:32,is64?8:4);
        phentsize=readInt(is64?54:42,2); phnum=readInt(is64?56:44,2);
        shentsize=readInt(is64?58:46,2); shnum=readInt(is64?60:48,2); shstrndx=readInt(is64?62:50,2);
        if(shoff && shentsize && shnum==0) { requireRange(shoff,shentsize,"section header 0"); shnum=readInt(shoff+(is64?32:20),is64?8:4); }
        if(shoff && shentsize && shstrndx==0xffff) { requireRange(shoff,shentsize,"section header 0"); shstrndx=readInt(shoff+(is64?40:24),4); }
        if(phnum && phentsize < (is64?56:32)) throw std::runtime_error("Program header entry size is too small");
        if(shnum && shentsize < (is64?64:40)) throw std::runtime_error("Section header entry size is too small");
        if(phnum) requireRange(phoff,uint64_t(phnum)*phentsize,"program header table");
        if(shnum) requireRange(shoff,uint64_t(shnum)*shentsize,"section header table");
        for(uint16_t i=0;i<phnum;i++) {
            uint64_t o=phoff+uint64_t(i)*phentsize; Program p;
            p.type=readInt(o,4);
            if(is64) { p.flags=readInt(o+4,4); p.off=readInt(o+8,8); p.vaddr=readInt(o+16,8); p.filesz=readInt(o+32,8); p.memsz=readInt(o+40,8); p.align=readInt(o+48,8); }
            else { p.off=readInt(o+4,4); p.vaddr=readInt(o+8,4); p.filesz=readInt(o+16,4); p.memsz=readInt(o+20,4); p.flags=readInt(o+24,4); p.align=readInt(o+28,4); }
            if(p.type==1) requireRange(p.off,p.filesz,"LOAD segment contents");
            programs.push_back(p);
        }
        for(uint16_t i=0;i<shnum;i++) {
            uint64_t o=shoff+uint64_t(i)*shentsize; Section s;
            s.name=readInt(o,4); s.type=readInt(o+4,4);
            if(is64) { s.flags=readInt(o+8,8); s.addr=readInt(o+16,8); s.off=readInt(o+24,8); s.size=readInt(o+32,8); s.link=readInt(o+40,4); s.info=readInt(o+44,4); s.entsize=readInt(o+56,8); }
            else { s.flags=readInt(o+8,4); s.addr=readInt(o+12,4); s.off=readInt(o+16,4); s.size=readInt(o+20,4); s.link=readInt(o+24,4); s.info=readInt(o+28,4); s.entsize=readInt(o+36,4); }
            if(s.type!=8 && s.size) requireRange(s.off,s.size,"section contents");
            sections.push_back(s);
        }
        if(shstrndx < sections.size() && sections[shstrndx].type==3) {
            const auto &tab=sections[shstrndx];
            for(auto &s:sections) s.label=(s.name<tab.size)?strAt(tab.off+s.name,tab.size-s.name):"<bad-name-offset>";
        }
    }
    void printSymbols() const {
        size_t total=0;
        for(const auto &s:sections) if((s.type==2 || s.type==11) && s.entsize && s.link<sections.size()) {
            const auto &strings=sections[s.link]; uint64_t count=s.size/s.entsize;
            std::cout << "\nSymbol table: " << (s.label.empty()?"<unnamed>":s.label) << " ("<<count<<" entries)\n";
            std::cout << "  "<<std::left<<std::setw(8)<<"Value"<<std::setw(8)<<"Bind"<<std::setw(8)<<"Type"<<"Name\n";
            for(uint64_t i=0;i<count && total<200;i++,total++) {
                uint64_t o=s.off+i*s.entsize;
                uint32_t no; uint8_t info; uint64_t value;
                if(is64) { no=readInt(o,4); info=readInt(o+4,1); value=readInt(o+8,8); }
                else { no=readInt(o,4); value=readInt(o+4,4); info=readInt(o+12,1); }
                std::string bind=((info>>4)==1)?"GLOBAL":((info>>4)==2)?"WEAK":((info>>4)==0)?"LOCAL":"OTHER";
                uint8_t t=info&0xf; std::string tn=t==2?"FUNC":t==1?"OBJECT":t==3?"SECTION":t==4?"FILE":t==0?"NOTYPE":"OTHER";
                std::string name=no<strings.size?strAt(strings.off+no,strings.size-no):"";
                std::cout << "  0x"<<std::hex<<value<<std::dec<<"  "<<std::setw(8)<<bind<<std::setw(8)<<tn<<(name.empty()?"<no-name>":name)<<"\n";
            }
            if(total>=200) { std::cout << "  ... output capped at 200 symbols\n"; return; }
        }
        if(!total) std::cout << "\nNo readable symbol tables found (binary may be stripped).\n";
    }
    void securityReport() {
        bool stackFound=false, stackExec=false, relro=false, interp=false;
        for(const auto&p:programs) { if(p.type==1685382481) {stackFound=true; stackExec=(p.flags&1)!=0;} if(p.type==1685382482) relro=true; if(p.type==3) interp=true; }
        std::cout << "\n=== Basic Security Indicators ===\n";
        std::cout << "PIE-compatible type: " << ((type==3)?"Yes (ET_DYN; shared libraries are also ET_DYN)":"No / not indicated by ELF type") << "\n";
        std::cout << "NX stack: ";
        if(!stackFound) std::cout << "Unknown (no GNU_STACK program header)\n";
        else std::cout << (stackExec?"Potentially unsafe: stack marked executable":"Stack not marked executable") << "\n";
        std::cout << "GNU RELRO segment: " << (relro?"Present":"Not found") << "\n";
        std::cout << "Dynamic interpreter: " << (interp?"Present":"Not present (may be static or non-executable)") << "\n";
        if(shnum==0) std::cout << "Section headers: absent (common in some stripped/packed binaries; not proof of maliciousness)\n";
        for(const auto &p:programs) if(p.type==1 && (p.flags&1) && (p.flags&2)) warnings.push_back("A LOAD segment is both writable and executable (W+X). Review whether this is expected.");
        if(stackFound && stackExec) warnings.push_back("GNU_STACK is executable.");
        std::cout << "\nNotes: these are static indicators only, not a malware verdict.\n";
        if(!warnings.empty()) { std::cout << "Review items:\n"; for(const auto&w:warnings) std::cout << "  [!] "<<w<<"\n"; }
        else std::cout << "Review items: no flagged conditions from the basic checks. This does not establish that the file is safe.\n";
    }
public:
    explicit ElfAnalyzer(const std::string& path) {
        std::ifstream f(path,std::ios::binary);
        if(!f) throw std::runtime_error("Cannot open file: "+path);
        f.seekg(0,std::ios::end); auto len=f.tellg();
        if(len<0) throw std::runtime_error("Could not determine file size");
        if(static_cast<uint64_t>(len)>512ULL*1024*1024) throw std::runtime_error("File exceeds 512 MiB safety limit");
        data.resize(static_cast<size_t>(len)); f.seekg(0,std::ios::beg);
        if(!data.empty() && !f.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(data.size()))) throw std::runtime_error("Failed to read file");
        parse();
    }
    void report() {
        std::cout << "ELF Binary Analyzer\n===================\n";
        std::cout << "Class: "<<(is64?"ELF64 (64-bit)":"ELF32 (32-bit)")<<"\nByte order: "<<(little?"Little-endian":"Big-endian")<<"\n";
        std::cout << "Architecture: "<<machineName(machine)<<"\nFile type: "<<typeName(type)<<"\n";
        std::cout << "Entry point: 0x"<<std::hex<<entry<<std::dec<<"\nFile size: "<<data.size()<<" bytes\n";
        std::cout << "Program headers: "<<phnum<<"\nSection headers: "<<shnum<<"\n";
        std::cout << "\n=== Program Headers ===\n";
        if(programs.empty()) std::cout << "No program headers.\n";
        for(size_t i=0;i<programs.size();i++) { const auto&p=programs[i]; std::cout<<"["<<i<<"] "<<std::left<<std::setw(14)<<programType(p.type)<<" Off=0x"<<std::hex<<p.off<<" VAddr=0x"<<p.vaddr<<std::dec<<" FileSz="<<p.filesz<<" MemSz="<<p.memsz<<" Flags="<<flags(p.flags)<<"\n"; }
        std::cout << "\n=== Sections ===\n";
        if(sections.empty()) std::cout << "No section headers.\n";
        for(size_t i=0;i<sections.size();i++) { const auto&s=sections[i]; std::cout<<"["<<i<<"] "<<std::left<<std::setw(22)<<(s.label.empty()?"<unnamed>":s.label)<<std::setw(12)<<sectionType(s.type)<<" Size="<<std::setw(10)<<s.size<<" Addr=0x"<<std::hex<<s.addr<<std::dec<<" Flags="<<flags(s.flags,true)<<"\n"; }
        printSymbols(); securityReport();
    }
};
int main(int argc,char**argv) {
    if(argc!=2) { std::cerr<<"Usage: "<<argv[0]<<" <ELF-file>\nExample: "<<argv[0]<<" /bin/ls\n"; return 2; }
    try { ElfAnalyzer analyzer(argv[1]); analyzer.report(); }
    catch(const std::exception&e) { std::cerr<<"Error: "<<e.what()<<"\n"; return 1; }
    return 0;
}
