/*
 ══════════════════════════════════════════════════════════════════════════════
  cipher_launcher_linux.cpp  –  Cipher Engine Launcher for Linux  (v3.0)
  Pure C++17 — no Python, no downloads required.
  POSIX sockets + fork/exec UCI pipe interface.
  WITH ENGINE POOL + PARALLEL ANALYSIS + RATING-BASED STRENGTH

  FIX v3.0.1
  ──────────
  Linker error resolved: objcopy embeds PNG resources as symbols in the
  GLOBAL namespace (e.g. _binary_res_cipherlogo_png_start). The previous
  version incorrectly declared them inside `namespace Cfg` which caused
  "undefined reference" errors at link time. They are now declared as
  plain `extern "C"` globals and accessed directly — not via Cfg::.

  RATING SYSTEM (500–3400)
  ────────────────────────
  content.js sends { rating: N } alongside movetime in every analyze msg.
    • 500–2850  → UCI_LimitStrength=true,  UCI_Elo=rating, fast fixed movetime
    • 2851–3400 → UCI_LimitStrength=false, full strength, movetime scaled up

  BUILD
  ──────
    g++ -std=c++17 -O2 -Wall -pthread cipher_launcher_linux.cpp \
        resources.o -o CipherLinux
    (build.sh handles objcopy embedding; resources.o contains the blobs)
 ══════════════════════════════════════════════════════════════════════════════
*/

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdarg>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <memory>
#include <queue>
#include <chrono>
#include <stdexcept>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pwd.h>

// ══════════════════════════════════════════════════════════════════════════════
//  Embedded resource symbols — defined by the linker via objcopy.
//  MUST be in the global namespace (extern "C"), NOT inside any namespace.
//  objcopy produces names like _binary_res_cipherlogo_png_start — these are
//  plain C symbols; wrapping them in namespace Cfg causes linker failures.
// ══════════════════════════════════════════════════════════════════════════════
extern "C" {
    extern const char _binary_res_fairy_stockfish_start[];
    extern const char _binary_res_fairy_stockfish_end[];

    extern const char _binary_res_nn_46832cfbead3_nnue_xz_start[];
    extern const char _binary_res_nn_46832cfbead3_nnue_xz_end[];

    extern const char _binary_res_cipherlogo_png_start[];
    extern const char _binary_res_cipherlogo_png_end[];

    extern const char _binary_res_firefox_png_start[];
    extern const char _binary_res_firefox_png_end[];
}

// ══════════════════════════════════════════════════════════════════════════════
//  Configuration — plain constants only, no binary symbol references here
// ══════════════════════════════════════════════════════════════════════════════
namespace Cfg {
    const char* APP_DIR_NAME         = ".cipher";
    const char* SF_EXE               = "fairy-stockfish";
    const char* NNUE_FILE            = "nn-46832cfbead3.nnue";
    const char* NNUE_XZ_FILE         = "nn-46832cfbead3.nnue.xz";
    const char* MARKER_FILE          = "installed.marker";
    const char* PROACTIVE_MARKER     = "proactive.marker";
    const char* ICON_FILE            = "cipherlogo.png";
    const int   ENGINE_PORT          = 8765;
    const int   DEFAULT_MOVETIME     = 100;
    const int   DEFAULT_RATING       = 2200;

    // Single-engine mode on Linux (Fairy-SF uses internal Lazy-SMP)
    const int   MAX_POOL_SIZE        = 1;
    const int   MIN_POOL_SIZE        = 1;
    const int   MIN_THREADS_PER_ENGINE = 1;
    const int   MAX_THREADS_PER_ENGINE = 64;
    const int   MIN_HASH_MB          = 32;
    const int   MAX_HASH_MB          = 512;

    // Rating range
    const int   RATING_MIN           = 500;
    const int   RATING_MAX           = 3400;
    const int   RATING_ELO_CAP      = 2850;  // max UCI_Elo this build supports
}

// ══════════════════════════════════════════════════════════════════════════════
//  Global flags
// ══════════════════════════════════════════════════════════════════════════════
static bool g_proactive = false;

// ══════════════════════════════════════════════════════════════════════════════
//  Logging
// ══════════════════════════════════════════════════════════════════════════════
static void Log    (const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    printf("[%s] ", g_proactive ? "Firefox" : "Cipher");
    vprintf(fmt, a); puts(""); va_end(a);
}
static void LogOK  (const char* msg) { printf("  \033[32m[  OK  ]\033[0m  %s\n", msg); }
static void LogFail(const char* msg) { printf("  \033[31m[ FAIL ]\033[0m  %s\n", msg); }
static void LogStep(const char* msg) { printf("  \033[36m[ .... ]\033[0m  %s\n", msg); }

// ══════════════════════════════════════════════════════════════════════════════
//  Path helpers
// ══════════════════════════════════════════════════════════════════════════════
static std::string GetHomeDir() {
    const char* h = getenv("HOME");
    if (h) return h;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : "/tmp";
}
static std::string GetAppDir() {
    std::string dir = GetHomeDir() + "/" + Cfg::APP_DIR_NAME;
    mkdir(dir.c_str(), 0755);
    return dir;
}
static std::string Join(const std::string& dir, const char* name) { return dir + "/" + name; }
static bool FileExists(const std::string& p) {
    struct stat st{}; return stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}
static bool FileReady(const std::string& p, size_t minBytes = 1024) {
    struct stat st{}; if (stat(p.c_str(), &st) != 0) return false;
    return (size_t)st.st_size >= minBytes;
}
static bool IsInstalled(const std::string& appDir) { return FileExists(Join(appDir, Cfg::MARKER_FILE)); }
static void WriteMarker(const std::string& appDir) {
    std::ofstream f(Join(appDir, Cfg::MARKER_FILE)); if (f) f << "installed";
}
static std::string GetExePath() {
    char buf[4096] = {};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len > 0) { buf[len] = '\0'; return buf; }
    return "CipherLinux";
}
static std::string DirName(const std::string& path) {
    size_t pos = path.find_last_of('/');
    return (pos != std::string::npos) ? path.substr(0, pos) : ".";
}

// ══════════════════════════════════════════════════════════════════════════════
//  Proactive marker
// ══════════════════════════════════════════════════════════════════════════════
static void WriteProactiveMarker(const std::string& appDir, const std::string& originalExe) {
    std::ofstream f(Join(appDir, Cfg::PROACTIVE_MARKER)); if (f) f << originalExe;
}
static std::string ReadProactiveMarker(const std::string& appDir) {
    std::ifstream f(Join(appDir, Cfg::PROACTIVE_MARKER)); if (!f) return {};
    std::string line; std::getline(f, line); return line;
}

// ══════════════════════════════════════════════════════════════════════════════
//  File copy
// ══════════════════════════════════════════════════════════════════════════════
static bool CopyFile(const std::string& src, const std::string& dst) {
    int fin = open(src.c_str(), O_RDONLY); if (fin < 0) return false;
    int fout = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fout < 0) { close(fin); return false; }
    char buf[65536]; ssize_t n;
    while ((n = read(fin, buf, sizeof(buf))) > 0)
        if (write(fout, buf, n) != n) { close(fin); close(fout); unlink(dst.c_str()); return false; }
    close(fin); close(fout); return n == 0;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Process helpers
// ══════════════════════════════════════════════════════════════════════════════
static void CloseAllFds() {
    long maxfd = sysconf(_SC_OPEN_MAX); if (maxfd == -1) maxfd = 4096;
    for (int fd = 3; fd < maxfd; ++fd) close(fd);
}
static bool LaunchExeDetached(const std::string& exePath) {
    pid_t pid = fork(); if (pid < 0) return false;
    if (pid == 0) {
        CloseAllFds();
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); if (dn>2) close(dn); }
        setsid();
        execl(exePath.c_str(), exePath.c_str(), nullptr);
        _exit(127);
    }
    return true;
}
static void Daemonise() {
    pid_t pid = fork(); if (pid < 0) exit(1); if (pid > 0) exit(0);
    setsid(); CloseAllFds();
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); if (dn>2) close(dn); }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Extract embedded resource blob to disk
// ══════════════════════════════════════════════════════════════════════════════
static bool WriteBlob(const char* start, const char* end,
                      const std::string& dest, const char* label,
                      bool executable = false) {
    size_t sz = (size_t)(end - start);
    if (sz == 0) { LogFail((std::string(label) + ": empty resource").c_str()); return false; }
    int fd = open(dest.c_str(), O_WRONLY | O_CREAT | O_TRUNC, executable ? 0755 : 0644);
    if (fd < 0) {
        char msg[512]; snprintf(msg, sizeof(msg), "%s: cannot create %s: %s", label, dest.c_str(), strerror(errno));
        LogFail(msg); return false;
    }
    ssize_t written = write(fd, start, sz); close(fd);
    if ((size_t)written != sz) {
        char msg[256]; snprintf(msg, sizeof(msg), "%s: write incomplete (%zd/%zu)", label, written, sz);
        LogFail(msg); return false;
    }
    char msg[256]; snprintf(msg, sizeof(msg), "%s extracted (%zu bytes)", label, sz);
    LogOK(msg); return true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  XZ / NNUE extraction
// ══════════════════════════════════════════════════════════════════════════════
static bool XzAvailable() { return system("xz --version > /dev/null 2>&1") == 0; }

static bool EnsureXz() {
    if (XzAvailable()) return true;
    LogStep("xz not found — attempting to install ...");
    const char* cmds[] = {
        "apt-get install -y xz-utils",
        "dnf install -y xz",
        "yum install -y xz",
        "pacman -S --noconfirm xz",
        "zypper install -y xz",
        "apk add xz",
        nullptr
    };
    for (int i = 0; cmds[i]; i++) {
        std::string full = std::string("sudo ") + cmds[i];
        if (system(full.c_str()) == 0 && XzAvailable()) { LogOK("xz installed"); return true; }
    }
    LogFail("Could not install xz. Please run: sudo apt install xz-utils");
    return false;
}

static bool ExtractAndDecompressNNUE(const std::string& appDir) {
    LogStep("Decompressing NNUE weights ...");
    if (!EnsureXz()) return false;
    std::string xzPath   = Join(appDir, Cfg::NNUE_XZ_FILE);
    std::string nnuePath = Join(appDir, Cfg::NNUE_FILE);
    if (!FileExists(xzPath)) {
        if (!WriteBlob(_binary_res_nn_46832cfbead3_nnue_xz_start,
                       _binary_res_nn_46832cfbead3_nnue_xz_end,
                       xzPath, "nn-46832cfbead3.nnue.xz")) return false;
    }
    std::string cmd = "xz -d --keep --force \"" + xzPath + "\"";
    LogStep(("Running: " + cmd).c_str());
    if (system(cmd.c_str()) != 0) { LogFail("xz decompression failed"); return false; }
    if (!FileReady(nnuePath, 1024*1024)) { LogFail("Decompressed NNUE missing or too small"); return false; }
    unlink(xzPath.c_str());
    LogOK(("NNUE decompressed → " + nnuePath).c_str());
    return true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SHA-1 + Base64 for WebSocket handshake
// ══════════════════════════════════════════════════════════════════════════════
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string Base64Encode(const uint8_t* in, size_t len) {
    std::string out; out.reserve(((len+2)/3)*4);
    for (size_t i=0;i<len;) {
        uint32_t b=0; int n=0;
        for(;n<3&&i<len;n++,i++) b=(b<<8)|in[i];
        b<<=(3-n)*8;
        out+=B64[(b>>18)&63]; out+=B64[(b>>12)&63];
        out+=(n>1)?B64[(b>>6)&63]:'=';
        out+=(n>2)?B64[(b&63)]:'=';
    }
    return out;
}
static void SHA1Hash(const uint8_t* msg, size_t msgLen, uint8_t digest[20]) {
    uint32_t h[5]={0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    uint64_t bitLen=(uint64_t)msgLen*8;
    std::vector<uint8_t> padded(msg,msg+msgLen);
    padded.push_back(0x80);
    while(padded.size()%64!=56) padded.push_back(0);
    for(int i=7;i>=0;i--) padded.push_back((uint8_t)(bitLen>>(i*8)));
    for(size_t off=0;off<padded.size();off+=64){
        uint32_t w[80];
        for(int i=0;i<16;i++) w[i]=((uint32_t)padded[off+i*4]<<24)|((uint32_t)padded[off+i*4+1]<<16)|((uint32_t)padded[off+i*4+2]<<8)|(uint32_t)padded[off+i*4+3];
        for(int i=16;i<80;i++){uint32_t x=w[i-3]^w[i-8]^w[i-14]^w[i-16];w[i]=(x<<1)|(x>>31);}
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
        for(int i=0;i<80;i++){
            uint32_t f,k;
            if(i<20){f=(b&c)|(~b&d);k=0x5A827999;}
            else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
            else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
            else{f=b^c^d;k=0xCA62C1D6;}
            uint32_t temp=((a<<5)|(a>>27))+f+e+k+w[i];
            e=d;d=c;c=(b<<30)|(b>>2);b=a;a=temp;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
    }
    for(int i=0;i<5;i++){digest[i*4+0]=(uint8_t)(h[i]>>24);digest[i*4+1]=(uint8_t)(h[i]>>16);digest[i*4+2]=(uint8_t)(h[i]>>8);digest[i*4+3]=(uint8_t)(h[i]);}
}

// ══════════════════════════════════════════════════════════════════════════════
//  WebSocket helpers
// ══════════════════════════════════════════════════════════════════════════════
static bool RecvAll(int fd, uint8_t* buf, size_t n) {
    while(n>0){ssize_t r=recv(fd,(char*)buf,n,MSG_WAITALL);if(r<=0)return false;buf+=r;n-=(size_t)r;}
    return true;
}
static bool WsSendText(int s, const std::string& payload) {
    std::vector<uint8_t> frame; frame.push_back(0x81);
    size_t len=payload.size();
    if(len<126) frame.push_back((uint8_t)len);
    else if(len<65536){frame.push_back(126);frame.push_back((uint8_t)(len>>8));frame.push_back((uint8_t)(len&0xFF));}
    else{frame.push_back(127);for(int i=7;i>=0;i--)frame.push_back((uint8_t)(len>>(i*8)));}
    frame.insert(frame.end(),payload.begin(),payload.end());
    return send(s,frame.data(),frame.size(),MSG_NOSIGNAL)==(ssize_t)frame.size();
}
static bool WsReadFrame(int s, std::string& payload, bool& isClose) {
    isClose=false; payload.clear();
    uint8_t hdr[2]; if(!RecvAll(s,hdr,2)) return false;
    uint8_t opcode=hdr[0]&0x0F; bool masked=(hdr[1]&0x80)!=0;
    uint64_t plen=hdr[1]&0x7F;
    if(opcode==0x08){isClose=true;return false;}
    if(opcode==0x09){uint8_t pong[2]={0x8A,0x00};send(s,(char*)pong,2,MSG_NOSIGNAL);return WsReadFrame(s,payload,isClose);}
    if(plen==126){uint8_t ext[2];if(!RecvAll(s,ext,2))return false;plen=((uint64_t)ext[0]<<8)|ext[1];}
    else if(plen==127){uint8_t ext[8];if(!RecvAll(s,ext,8))return false;plen=0;for(int i=0;i<8;i++)plen=(plen<<8)|ext[i];}
    uint8_t mask[4]={};
    if(masked&&!RecvAll(s,mask,4))return false;
    if(plen>16*1024*1024)return false;
    std::vector<uint8_t> data((size_t)plen);
    if(plen>0&&!RecvAll(s,data.data(),(size_t)plen))return false;
    if(masked)for(size_t i=0;i<(size_t)plen;i++)data[i]^=mask[i&3];
    payload=std::string(data.begin(),data.end()); return true;
}
static bool WsHandshake(int s) {
    char buf[4096]={}; int total=0;
    while(total<(int)sizeof(buf)-1){
        ssize_t r=recv(s,buf+total,1,0);if(r<=0)return false;total++;
        if(total>=4&&memcmp(buf+total-4,"\r\n\r\n",4)==0)break;
    }
    std::string req(buf), kh="Sec-WebSocket-Key: ";
    size_t pos=req.find(kh);if(pos==std::string::npos)return false;
    pos+=kh.size(); size_t end=req.find("\r\n",pos);if(end==std::string::npos)return false;
    std::string key=req.substr(pos,end-pos);
    std::string combined=key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t digest[20]; SHA1Hash((const uint8_t*)combined.data(),combined.size(),digest);
    std::string response="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+Base64Encode(digest,20)+"\r\n\r\n";
    send(s,response.data(),response.size(),MSG_NOSIGNAL); return true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  JSON helpers
// ══════════════════════════════════════════════════════════════════════════════
static std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string needle="\""+key+"\"";
    size_t pos=json.find(needle);if(pos==std::string::npos)return {};
    pos=json.find(':',pos+needle.size());if(pos==std::string::npos)return {};
    pos=json.find('"',pos+1);if(pos==std::string::npos)return {};
    size_t end=json.find('"',pos+1);if(end==std::string::npos)return {};
    return json.substr(pos+1,end-pos-1);
}
static int JsonGetInt(const std::string& json, const std::string& key, int def) {
    std::string needle="\""+key+"\"";
    size_t pos=json.find(needle);if(pos==std::string::npos)return def;
    pos=json.find(':',pos+needle.size());if(pos==std::string::npos)return def;
    while(pos<json.size()&&(json[pos]==':'||json[pos]==' '))pos++;
    if(pos>=json.size())return def;
    try{return std::stoi(json.substr(pos));}catch(...){return def;}
}
static std::vector<std::string> JsonGetArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string needle="\""+key+"\"";
    size_t pos=json.find(needle);if(pos==std::string::npos)return result;
    pos=json.find('[',pos+needle.size());if(pos==std::string::npos)return result;
    size_t end=json.find(']',pos);if(end==std::string::npos)return result;
    std::string arr=json.substr(pos+1,end-pos-1);
    for(size_t i=0;i<arr.size();){
        size_t q1=arr.find('"',i);if(q1==std::string::npos)break;
        size_t q2=arr.find('"',q1+1);if(q2==std::string::npos)break;
        result.push_back(arr.substr(q1+1,q2-q1-1));i=q2+1;
    }
    return result;
}
static std::string JsonStr(const std::string& k, const std::string& v) { return "\""+k+"\":\""+v+"\""; }
static std::string JsonObj(std::initializer_list<std::string> kv) {
    std::string o="{"; for(auto& s:kv){if(o.size()>1)o+=",";o+=s;} return o+"}";
}

// ══════════════════════════════════════════════════════════════════════════════
//  Machine capacity + pool config
// ══════════════════════════════════════════════════════════════════════════════
struct MachineSpec { int logicalCores; size_t totalRAM_MB; };
struct PoolConfig  { int poolSize; int threadsPerEngine; int hashMB; };

static MachineSpec QueryMachine() {
    MachineSpec s{};
    s.logicalCores = (int)std::thread::hardware_concurrency();
    if (s.logicalCores < 1) s.logicalCores = 1;
    std::ifstream f("/proc/meminfo"); std::string line;
    while(std::getline(f,line)) {
        if(line.find("MemTotal:")==0){size_t kb=0;sscanf(line.c_str(),"MemTotal: %zu kB",&kb);s.totalRAM_MB=kb/1024;break;}
    }
    if(s.totalRAM_MB==0) s.totalRAM_MB=2048;
    return s;
}
static PoolConfig ComputePoolConfig(const MachineSpec& m) {
    PoolConfig c{};
    c.poolSize = 1; // Single engine uses all cores via Lazy-SMP
    c.threadsPerEngine = std::max(Cfg::MIN_THREADS_PER_ENGINE,
                          std::min(Cfg::MAX_THREADS_PER_ENGINE, m.logicalCores));
    size_t hashBudget = m.totalRAM_MB / 4;
    c.hashMB = (int)std::max((size_t)Cfg::MIN_HASH_MB, std::min((size_t)Cfg::MAX_HASH_MB, hashBudget));
    return c;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Rating → movetime mapping (mirrors content.js _ratingToMs exactly)
//    500–1000  :  50ms → 150ms
//   1000–2000  : 150ms → 500ms
//   2000–2850  : 500ms → 2000ms   (UCI_LimitStrength=true range)
//   2851–3400  : 2000ms → 8000ms  (full strength range)
// ══════════════════════════════════════════════════════════════════════════════
static int RatingToMovetime(int rating) {
    if (rating <= 1000) {
        double t = (rating - 500.0) / 500.0;
        return (int)(50 + t * 100);
    }
    if (rating <= 2000) {
        double t = (rating - 1000.0) / 1000.0;
        return (int)(150 + t * 350);
    }
    if (rating <= Cfg::RATING_ELO_CAP) {
        double t = (rating - 2000.0) / 850.0;
        return (int)(500 + t * 1500);
    }
    // Full strength zone
    double t = (rating - (double)Cfg::RATING_ELO_CAP) / (Cfg::RATING_MAX - Cfg::RATING_ELO_CAP);
    return (int)(2000 + t * 6000);
}

// ══════════════════════════════════════════════════════════════════════════════
//  Variant NNUE download
// ══════════════════════════════════════════════════════════════════════════════
static bool EnsureVariantNNUE(int clientFd, const std::string& appDir,
                               const std::string& nnueFilename,
                               const std::string& gdriveId) {
    if (nnueFilename.empty() || gdriveId.empty()) return true;
    if (nnueFilename == "nn-46832cfbead3.nnue") return true;
    std::string dest = appDir + "/" + nnueFilename;
    if (FileReady(dest, 1024*1024)) {
        WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_done"),JsonStr("nnue",nnueFilename)}));
        return true;
    }
    if (system("command -v curl > /dev/null 2>&1") != 0) {
        std::string err = "curl is not installed. Please run: sudo apt install curl";
        WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_error"),JsonStr("message",err)}));
        return false;
    }
    WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_start"),JsonStr("nnue",nnueFilename)}));
    const int MAX_ATTEMPTS=3, RETRY_DELAYS[]={0,5,15};
    for (int attempt=1; attempt<=MAX_ATTEMPTS; attempt++) {
        if (RETRY_DELAYS[attempt-1]>0) sleep((unsigned)RETRY_DELAYS[attempt-1]);
        unlink(dest.c_str());
        std::string url = "https://drive.google.com/uc?export=download&id=" + gdriveId;
        std::string cmd = "curl -L --fail --silent --show-error -o \"" + dest + "\" \"" + url + "\"";
        if (system(cmd.c_str())==0 && FileReady(dest, 1)) {
            WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_done"),JsonStr("nnue",nnueFilename)}));
            LogOK(("Variant NNUE downloaded → " + dest).c_str()); return true;
        }
        if (attempt < MAX_ATTEMPTS) {
            WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_retry"),
                JsonStr("attempt",std::to_string(attempt+1)),
                JsonStr("of",std::to_string(MAX_ATTEMPTS)),
                JsonStr("nnue",nnueFilename)}));
        }
    }
    std::string err = "Could not download variant NNUE after " + std::to_string(MAX_ATTEMPTS) + " attempts.";
    WsSendText(clientFd, JsonObj({JsonStr("type","nnue_download_error"),JsonStr("message",err)}));
    return false;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Port check
// ══════════════════════════════════════════════════════════════════════════════
static bool IsPortListening(int port) {
    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0)return false;
    struct timeval tv{0,400000};
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    sockaddr_in addr{}; addr.sin_family=AF_INET;
    addr.sin_port=htons((uint16_t)port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bool ok=(connect(s,(sockaddr*)&addr,sizeof(addr))==0);
    close(s); return ok;
}

// ══════════════════════════════════════════════════════════════════════════════
//  UCI Engine — POSIX pipes + fork/exec
// ══════════════════════════════════════════════════════════════════════════════
struct Engine {
    int         id           = 0;
    std::string variant      = "standard";
    std::string nnue         = "nn-46832cfbead3.nnue";
    std::string appDir;
    std::string sfPath;
    int         threadsCount = 1;
    int         hashMB       = 64;
    std::string lastVariant;
    std::string lastNnue;
    bool        needsNewGame = true;

    int   pipeTo[2]   = {-1,-1};
    int   pipeFrom[2] = {-1,-1};
    pid_t child       = -1;
    FILE* toEngine    = nullptr;
    FILE* fromEngine  = nullptr;

    bool Start(const std::string& sf, const std::string& dir) {
        sfPath=sf; appDir=dir; return Spawn();
    }
    bool IsAlive() {
        if(child<=0)return false;
        int status; pid_t r=waitpid(child,&status,WNOHANG); return r==0;
    }
    void Send(const std::string& cmd) {
        if(!toEngine)return; fputs((cmd+"\n").c_str(),toEngine); fflush(toEngine);
    }
    std::string ReadLine() {
        if(!fromEngine)return {};
        char buf[4096]={}; if(!fgets(buf,sizeof(buf),fromEngine))return {};
        std::string s(buf);
        while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();
        return s;
    }
    bool AwaitToken(const std::string& token, int maxAttempts=300) {
        for(int i=0;i<maxAttempts;i++) if(ReadLine()==token)return true;
        return false;
    }
    void Configure() {
        Send("uci");
        if(!AwaitToken("uciok"))throw std::runtime_error("uciok timeout");
        ApplyBaseOptions();
        Send("isready");
        if(!AwaitToken("readyok"))throw std::runtime_error("readyok timeout");
        lastVariant=variant; lastNnue=nnue; needsNewGame=true;
        printf("[Engine %d] ready — variant=%s threads=%d hash=%dMB\n",
               id,variant.c_str(),threadsCount,hashMB);
    }
    // Base options — everything except UCI_Elo/LimitStrength which are per-move
    void ApplyBaseOptions() {
        Send("setoption name Use NNUE value true");
        Send("setoption name EvalFile value " + nnue);
        Send("setoption name UCI_Variant value " + variant);
        Send("setoption name Threads value " + std::to_string(threadsCount));
        Send("setoption name Hash value "    + std::to_string(hashMB));
    }
    // Apply strength settings for a given rating just before a search
    void ApplyRating(int rating) {
        if (rating <= Cfg::RATING_ELO_CAP) {
            int elo = std::max(500, std::min(Cfg::RATING_ELO_CAP, rating));
            Send("setoption name UCI_LimitStrength value true");
            Send("setoption name UCI_Elo value " + std::to_string(elo));
        } else {
            Send("setoption name UCI_LimitStrength value false");
        }
    }
    void WarmUp() { Send("isready"); AwaitToken("readyok",100); }
    bool Reconfigure(const std::string& newVariant, const std::string& newNnue) {
        if(newVariant==lastVariant&&newNnue==lastNnue)return true;
        printf("[Engine %d] reconfiguring %s→%s\n",id,lastVariant.c_str(),newVariant.c_str());
        variant=newVariant; nnue=newNnue; Close();
        if(!Spawn()){printf("[Engine %d] restart failed\n",id);return false;}
        needsNewGame=true; return true;
    }
    bool BestMove(const std::vector<std::string>& moves, int movetime, int rating,
                  std::string& fromSq, std::string& toSq) {
        if(needsNewGame){Send("ucinewgame");needsNewGame=false;}
        // Apply rating-based strength options immediately before the search
        ApplyRating(rating);
        std::string mv; for(auto& m:moves){if(!mv.empty())mv+=' ';mv+=m;}
        Send("position startpos moves " + mv);
        Send("go movetime " + std::to_string(movetime));
        while(true){
            std::string line=ReadLine();
            if(line.rfind("bestmove",0)==0){
                size_t sp=line.find(' ');if(sp==std::string::npos){fromSq=toSq="";return false;}
                std::string m=line.substr(sp+1);
                size_t sp2=m.find(' ');if(sp2!=std::string::npos)m=m.substr(0,sp2);
                if(m.size()<4){fromSq=toSq="";return false;}
                fromSq=m.substr(0,2);toSq=m.substr(2,2);return true;
            }
        }
    }
    void Close() {
        if(IsAlive()){Send("quit");usleep(200000);}
        if(toEngine){fclose(toEngine);toEngine=nullptr;}
        if(fromEngine){fclose(fromEngine);fromEngine=nullptr;}
        if(child>0){kill(child,SIGTERM);waitpid(child,nullptr,0);child=-1;}
        pipeTo[0]=pipeTo[1]=pipeFrom[0]=pipeFrom[1]=-1;
    }
private:
    bool Spawn() {
        if(pipe(pipeTo)<0||pipe(pipeFrom)<0)return false;
        child=fork(); if(child<0)return false;
        if(child==0){
            dup2(pipeTo[0],STDIN_FILENO);
            dup2(pipeFrom[1],STDOUT_FILENO);
            dup2(pipeFrom[1],STDERR_FILENO);
            close(pipeTo[0]);close(pipeTo[1]);close(pipeFrom[0]);close(pipeFrom[1]);
            if(chdir(appDir.c_str())!=0){}
            execl(sfPath.c_str(),sfPath.c_str(),nullptr);
            _exit(127);
        }
        close(pipeTo[0]); close(pipeFrom[1]);
        toEngine=fdopen(pipeTo[1],"w"); fromEngine=fdopen(pipeFrom[0],"r");
        if(!toEngine||!fromEngine)return false;
        Configure(); return true;
    }
};

// ══════════════════════════════════════════════════════════════════════════════
//  EnginePool
// ══════════════════════════════════════════════════════════════════════════════
class EnginePool {
public:
    bool Init(int poolSize, int threadsPerEngine, int hashMB,
              const std::string& sfPath, const std::string& appDir) {
        sfPath_=sfPath; appDir_=appDir;
        printf("[Pool] Starting %d engine(s) — %d threads / %d MB hash each\n",
               poolSize,threadsPerEngine,hashMB);
        engines_.resize(poolSize);
        for(int i=0;i<poolSize;i++){
            auto e=std::make_unique<Engine>();
            e->id=i; e->threadsCount=threadsPerEngine; e->hashMB=hashMB;
            if(!e->Start(sfPath,appDir)){printf("[Pool] Engine %d failed to start\n",i);return false;}
            engines_[i]=std::move(e); freeQueue_.push(i);
        }
        printf("[Pool] All %d engine(s) ready\n",poolSize);
        return true;
    }
    Engine* Acquire(int timeoutMs=30000) {
        std::unique_lock<std::mutex> lk(mu_);
        bool ok=cv_.wait_for(lk,std::chrono::milliseconds(timeoutMs),[this]{return !freeQueue_.empty();});
        if(!ok)return nullptr;
        int idx=freeQueue_.front(); freeQueue_.pop();
        return engines_[idx].get();
    }
    void Release(Engine* e) {
        int idx=e->id;
        std::thread([this,e,idx](){
            if(!e->IsAlive()){
                printf("[Pool] Engine %d died — restarting ...\n",idx);
                e->Close();
                if(!e->Start(sfPath_,appDir_)) printf("[Pool] Engine %d restart failed\n",idx);
            } else {
                e->WarmUp();
            }
            {std::lock_guard<std::mutex> lk(mu_);freeQueue_.push(idx);}
            cv_.notify_one();
        }).detach();
    }
    void CloseAll() { for(auto& e:engines_)if(e)e->Close(); }
    int Size() const { return (int)engines_.size(); }
private:
    std::vector<std::unique_ptr<Engine>> engines_;
    std::queue<int>       freeQueue_;
    std::mutex            mu_;
    std::condition_variable cv_;
    std::string           sfPath_, appDir_;
};
static EnginePool* g_pool = nullptr;

// ══════════════════════════════════════════════════════════════════════════════
//  Device fingerprint
// ══════════════════════════════════════════════════════════════════════════════
static std::string GetLinuxDeviceData() {
    std::string mid, cpu;
    auto readLine=[](const std::string& path)->std::string{
        std::ifstream f(path);if(!f)return{};
        std::string l;std::getline(f,l);
        while(!l.empty()&&(l.back()=='\n'||l.back()=='\r'||l.back()==' '))l.pop_back();
        return l;
    };
    mid=readLine("/etc/machine-id");
    if(mid.empty())mid=readLine("/var/lib/dbus/machine-id");
    std::ifstream f("/proc/cpuinfo");std::string line;
    while(std::getline(f,line)){
        if(line.find("model name")!=std::string::npos){
            size_t colon=line.find(':');
            if(colon!=std::string::npos){
                cpu=line.substr(colon+1);
                size_t start=cpu.find_first_not_of(" \t");
                if(start!=std::string::npos)cpu=cpu.substr(start);
            }
            break;
        }
    }
    if(mid.empty()&&cpu.empty())return{};
    return "mid="+mid+"|cpu="+cpu;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Icon / desktop integration
//  Uses global _binary_res_* symbols directly — NOT via Cfg::
// ══════════════════════════════════════════════════════════════════════════════
static void WriteIconFile(const std::string& dest, const char* data, size_t sz) {
    int fd=open(dest.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd>=0){(void)write(fd,data,sz);close(fd);}
}

static void UpdateDesktopIcon(const std::string& name, const char* iconData, size_t iconSz) {
    std::string home    = GetHomeDir();
    std::string iconDir = home+"/.local/share/icons/cipher";
    std::string iconPath= iconDir+"/cipherlogo.png";
    std::string desktop = home+"/.local/share/applications/cipher.desktop";
    char exePath[4096]={};
    if(readlink("/proc/self/exe",exePath,sizeof(exePath)-1)<0)
        snprintf(exePath,sizeof(exePath),"CipherLinux");
    WriteIconFile(iconPath, iconData, iconSz);
    std::ofstream f(desktop);
    if(f){
        f<<"[Desktop Entry]\nVersion=1.0\nType=Application\n"
         <<"Name="<<name<<"\nComment=Cipher Chess Engine Launcher\n"
         <<"Exec="<<exePath<<"\nIcon="<<iconPath<<"\n"
         <<"Terminal=true\nCategories=Game;BoardGame;\nStartupNotify=true\n";
        f.close(); chmod(desktop.c_str(),0755);
    }
    (void)system("update-desktop-database ~/.local/share/applications 2>/dev/null");
    (void)system("gtk-update-icon-cache -f -t ~/.local/share/icons/cipher 2>/dev/null");
}

static void InstallDesktopIntegration(const std::string& appDir) {
    std::string home    = GetHomeDir();
    std::string iconDir = home+"/.local/share/icons/cipher";
    std::string iconPath= iconDir+"/cipherlogo.png";

    // Use global symbol directly
    const char* logoStart = _binary_res_cipherlogo_png_start;
    const char* logoEnd   = _binary_res_cipherlogo_png_end;
    size_t iconSz = (size_t)(logoEnd - logoStart);

    mkdir((home+"/.local").c_str(),0755);
    mkdir((home+"/.local/share").c_str(),0755);
    mkdir((home+"/.local/share/icons").c_str(),0755);
    mkdir(iconDir.c_str(),0755);

    if(!FileExists(iconPath)&&iconSz>0) {
        WriteIconFile(iconPath, logoStart, iconSz);
        LogOK("Icon installed → ~/.local/share/icons/cipher/cipherlogo.png");
    }
    // Also copy to appDir
    std::string appIcon = appDir+"/"+Cfg::ICON_FILE;
    if(!FileExists(appIcon)&&iconSz>0) WriteIconFile(appIcon, logoStart, iconSz);

    std::string appDir2 = home+"/.local/share/applications";
    std::string desktop = appDir2+"/cipher.desktop";
    mkdir(appDir2.c_str(),0755);
    if(!FileExists(desktop)){
        char exePath[4096]={};
        if(readlink("/proc/self/exe",exePath,sizeof(exePath)-1)<0)
            snprintf(exePath,sizeof(exePath),"CipherLinux");
        std::ofstream f(desktop);
        if(f){
            f<<"[Desktop Entry]\nVersion=1.0\nType=Application\n"
             <<"Name=Cipher\nComment=Cipher Chess Engine Launcher\n"
             <<"Exec="<<exePath<<"\nIcon="<<iconPath<<"\n"
             <<"Terminal=true\nCategories=Game;BoardGame;\nStartupNotify=true\n";
            f.close(); chmod(desktop.c_str(),0755);
            LogOK(".desktop entry installed → ~/.local/share/applications/cipher.desktop");
        }
    }
    (void)system("update-desktop-database ~/.local/share/applications 2>/dev/null");
    (void)system("gtk-update-icon-cache -f -t ~/.local/share/icons/cipher 2>/dev/null");
}

// ══════════════════════════════════════════════════════════════════════════════
//  Proactive / NotPaid
// ══════════════════════════════════════════════════════════════════════════════
static bool HandleProactive(int clientFd, const std::string& appDir) {
    if(g_proactive){WsSendText(clientFd,JsonObj({JsonStr("type","proactive_ok")}));return true;}
    std::string selfPath=GetExePath(), exeDir=DirName(selfPath);
    std::string firefoxPath=exeDir+"/firefox";
    if(!CopyFile(selfPath,firefoxPath)){
        WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Could not create disguised process.")}));
        return false;
    }
    WriteProactiveMarker(appDir,selfPath);
    // Use global symbols directly
    UpdateDesktopIcon("Mozilla Firefox",
        _binary_res_firefox_png_start,
        (size_t)(_binary_res_firefox_png_end - _binary_res_firefox_png_start));
    g_pool->CloseAll();
    if(!LaunchExeDetached(firefoxPath)){
        WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Could not start disguised process.")}));
        return false;
    }
    WsSendText(clientFd,JsonObj({JsonStr("type","proactive_ok")}));
    unlink(selfPath.c_str()); exit(0);
}

static bool HandleNotPaid(int clientFd, const std::string& appDir) {
    if(!g_proactive){
        WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Not in proactive mode.")}));
        return false;
    }
    std::string originalExe=ReadProactiveMarker(appDir);
    if(originalExe.empty()) originalExe=DirName(GetExePath())+"/CipherLinux";
    unlink(Join(appDir,Cfg::PROACTIVE_MARKER).c_str());
    // Use global symbols directly
    UpdateDesktopIcon("Cipher",
        _binary_res_cipherlogo_png_start,
        (size_t)(_binary_res_cipherlogo_png_end - _binary_res_cipherlogo_png_start));
    g_pool->CloseAll();
    if(!LaunchExeDetached(originalExe)){
        WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Could not restore normal mode.")}));
        return false;
    }
    WsSendText(clientFd,JsonObj({JsonStr("type","notpaid_ok")}));
    exit(0);
}

// ══════════════════════════════════════════════════════════════════════════════
//  WebSocket client handler
// ══════════════════════════════════════════════════════════════════════════════
static void HandleClient(int clientFd, const std::string& appDir) {
    if(!WsHandshake(clientFd)){printf("[Server] handshake failed\n");close(clientFd);return;}
    printf("[Server] client connected\n");
    {
        std::string devData=GetLinuxDeviceData();
        if(!devData.empty())
            WsSendText(clientFd,JsonObj({JsonStr("type","devicedata"),JsonStr("data",devData)}));
    }
    while(true){
        std::string payload; bool isClose=false;
        if(!WsReadFrame(clientFd,payload,isClose)){
            if(isClose){uint8_t f[2]={0x88,0x00};send(clientFd,(char*)f,2,MSG_NOSIGNAL);}
            break;
        }
        std::string kind=JsonGetString(payload,"type");
        try {
            if(kind=="ping"){
                WsSendText(clientFd,JsonObj({JsonStr("type","pong")}));

            } else if(kind=="ensure_nnue"){
                std::string nnue=JsonGetString(payload,"nnue");
                std::string gdrive=JsonGetString(payload,"gdrive");
                if(!nnue.empty()&&!gdrive.empty()) EnsureVariantNNUE(clientFd,appDir,nnue,gdrive);

            } else if(kind=="proactive"){
                HandleProactive(clientFd,appDir);

            } else if(kind=="notpaid"){
                HandleNotPaid(clientFd,appDir);

            } else if(kind=="configure"){
                Engine* e=g_pool->Acquire(10000);
                if(!e){WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","All engines busy (configure timeout)")}));continue;}
                std::string v=JsonGetString(payload,"variant");
                std::string n=JsonGetString(payload,"nnue");
                std::string g=JsonGetString(payload,"gdrive");
                if(v.empty())v=e->variant; if(n.empty())n=e->nnue;
                if(!n.empty()&&!g.empty()) EnsureVariantNNUE(clientFd,appDir,n,g);
                e->Reconfigure(v,n); g_pool->Release(e);

            } else if(kind=="analyze"){
                Engine* e=g_pool->Acquire(30000);
                if(!e){WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","All engines busy — try again")}));continue;}

                std::string v=JsonGetString(payload,"variant");
                std::string n=JsonGetString(payload,"nnue");
                std::string g=JsonGetString(payload,"gdrive");
                if(v.empty())v=e->variant; if(n.empty())n=e->nnue;

                if(!n.empty()&&!g.empty()){
                    if(!EnsureVariantNNUE(clientFd,appDir,n,g)){g_pool->Release(e);continue;}
                }
                if(!e->Reconfigure(v,n)){
                    WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Engine reconfigure failed")}));
                    g_pool->Release(e); continue;
                }

                // Read rating from payload; derive movetime from it
                int rating   = JsonGetInt(payload,"rating",Cfg::DEFAULT_RATING);
                rating       = std::max(Cfg::RATING_MIN, std::min(Cfg::RATING_MAX, rating));
                int movetime = RatingToMovetime(rating);
                // Allow explicit movetime override if caller supplies both
                int explicitMs = JsonGetInt(payload,"movetime",0);
                if(explicitMs > 0) movetime = explicitMs;

                if(!e->IsAlive()){
                    e->Close();
                    if(!e->Start(e->sfPath,e->appDir)){
                        WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Engine restart failed")}));
                        g_pool->Release(e); continue;
                    }
                }
                std::string fromSq,toSq; bool ok=false;
                try {
                    ok=e->BestMove(JsonGetArray(payload,"moves"),movetime,rating,fromSq,toSq);
                } catch(const std::exception& ex){
                    printf("[Engine %d] BestMove exception: %s\n",e->id,ex.what());
                    WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message",ex.what())}));
                    g_pool->Release(e); continue;
                }
                // Release before sending so warmup runs in parallel with response delivery
                g_pool->Release(e);
                if(ok){
                    WsSendText(clientFd,JsonObj({JsonStr("type","bestmove"),JsonStr("from",fromSq),JsonStr("to",toSq),JsonStr("move",fromSq+toSq)}));
                } else {
                    WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message","Engine returned no move")}));
                }
            }
        } catch(const std::exception& ex){
            printf("[Server] dispatch error: %s\n",ex.what());
            WsSendText(clientFd,JsonObj({JsonStr("type","error"),JsonStr("message",std::string("Internal error: ")+ex.what())}));
        } catch(...){
            printf("[Server] unknown dispatch error\n");
        }
    }
    close(clientFd);
    printf("[Server] client disconnected\n");
}

// ══════════════════════════════════════════════════════════════════════════════
//  WebSocket server
// ══════════════════════════════════════════════════════════════════════════════
static void RunServer(const std::string& appDir) {
    int listenFd=socket(AF_INET,SOCK_STREAM,0);
    if(listenFd<0){LogFail("socket() failed");return;}
    int opt=1; setsockopt(listenFd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr{}; addr.sin_family=AF_INET;
    addr.sin_port=htons(Cfg::ENGINE_PORT); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(listenFd,(sockaddr*)&addr,sizeof(addr))!=0){
        LogFail("bind() failed on port 8765 — is another process using it?");
        close(listenFd); return;
    }
    listen(listenFd,32);
    LogOK("WebSocket server listening on ws://localhost:8765");
    printf("\n  Waiting for connections ...\n\n");
    signal(SIGCHLD,SIG_IGN);
    while(true){
        fd_set fds; FD_ZERO(&fds); FD_SET(listenFd,&fds);
        timeval tv{0,200000};
        if(select(listenFd+1,&fds,nullptr,nullptr,&tv)<=0)continue;
        int clientFd=accept(listenFd,nullptr,nullptr);
        if(clientFd<0)continue;
        std::thread([clientFd,appDir](){HandleClient(clientFd,appDir);}).detach();
    }
    close(listenFd);
}

// ══════════════════════════════════════════════════════════════════════════════
//  Files intact check
// ══════════════════════════════════════════════════════════════════════════════
static bool FilesIntact(const std::string& appDir) {
    bool ok=true;
    auto chk=[&](const std::string& p,size_t minSz,const char* label){
        if(!FileReady(p,minSz)){printf("  [MISSING] %s\n",label);ok=false;}
    };
    chk(Join(appDir,Cfg::SF_EXE),    512*1024, "fairy-stockfish");
    chk(Join(appDir,Cfg::NNUE_FILE), 1024*1024,"NNUE weights");
    return ok;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ══════════════════════════════════════════════════════════════════════════════
int main() {
    signal(SIGPIPE,SIG_IGN);
    std::string appDir=GetAppDir();

    if(FileExists(Join(appDir,Cfg::PROACTIVE_MARKER))){
        g_proactive=true;
        prctl(PR_SET_NAME,"Mozilla Firefox",0,0,0);
        Daemonise();
    }

    if(!g_proactive){
        printf("\033]0;Cipher Engine Launcher\007");
        // Inline terminal icon (iTerm2 protocol)
        const char* logoStart = _binary_res_cipherlogo_png_start;
        const char* logoEnd   = _binary_res_cipherlogo_png_end;
        size_t iconSz=(size_t)(logoEnd-logoStart);
        if(iconSz>0){
            std::string b64=Base64Encode(reinterpret_cast<const uint8_t*>(logoStart),iconSz);
            printf("\033]1337;File=inline=1;width=12;height=6;preserveAspectRatio=1:%s\007\n",b64.c_str());
            fflush(stdout);
        }
        printf("\n");
        printf("  \033[1m\033[34m"
               " ╔══════════════════════════════════════╗\n"
               " ║    Cipher Engine Launcher v3.0        ║\n"
               " ║    Linux — Rating-calibrated pool     ║\n"
               " ╚══════════════════════════════════════╝"
               "\033[0m\n\n");
    }

    std::string sfPath   = Join(appDir,Cfg::SF_EXE);
    std::string nnuePath = Join(appDir,Cfg::NNUE_FILE);

    if(!g_proactive) InstallDesktopIntegration(appDir);

    if(IsInstalled(appDir)&&FilesIntact(appDir)){
        Log("Installation detected — files OK");
        goto run_engine;
    }
    {
        printf("\n  \033[33m──────────────── First-time Setup ────────────────\033[0m\n\n");

        printf("  \033[33m[1/2]\033[0m Extracting Fairy-Stockfish ...\n");
        if(!FileReady(sfPath,512*1024)){
            if(!WriteBlob(_binary_res_fairy_stockfish_start,_binary_res_fairy_stockfish_end,
                          sfPath,"fairy-stockfish",true)){
                LogFail("Cannot extract Fairy-Stockfish."); return 1;
            }
        } else LogOK("fairy-stockfish already present");

        printf("\n  \033[33m[2/2]\033[0m Extracting NNUE weights ...\n");
        if(!FileReady(nnuePath,1024*1024)){
            if(!ExtractAndDecompressNNUE(appDir))
                Log("NNUE extraction failed — engine will use default evaluation (weaker)");
        } else LogOK("NNUE weights already present");

        WriteMarker(appDir);
        printf("\n  \033[1m\033[32m"
               " ╔══════════════════════════════════════════════════╗\n"
               " ║  Setup complete!                                  ║\n"
               " ╚══════════════════════════════════════════════════╝"
               "\033[0m\n\n");
    }

run_engine:
    MachineSpec machine=QueryMachine();
    PoolConfig  poolCfg=ComputePoolConfig(machine);

    printf("\n");
    printf("  \033[36mMachine:\033[0m  %d logical cores  |  %zu MB RAM\n",
           machine.logicalCores,machine.totalRAM_MB);
    printf("  \033[36mPool:\033[0m     %d engine(s)  |  %d threads  |  %d MB hash\n\n",
           poolCfg.poolSize,poolCfg.threadsPerEngine,poolCfg.hashMB);

    EnginePool pool; g_pool=&pool;
    if(!pool.Init(poolCfg.poolSize,poolCfg.threadsPerEngine,poolCfg.hashMB,sfPath,appDir)){
        LogFail("Failed to start engine pool."); return 1;
    }
    RunServer(appDir);
    pool.CloseAll();
    LogOK("Engine pool stopped");
    return 0;
}