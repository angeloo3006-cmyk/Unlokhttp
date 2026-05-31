/**
 * ES: Sidecar de Tauri para capturar paquetes de red.
 * EN: Tauri sidecar for network packet capture.
 *
 * ES: stdin recibe comandos JSONL y stdout emite eventos JSONL.
 * EN: stdin receives JSONL commands and stdout emits JSONL events.
 */

// ES: Deteccion de plataforma y cabeceras pcap. / EN: Platform detection and pcap headers.
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#  include <fcntl.h>
#  include <io.h>
   // ES: El SDK de Npcap expone la misma interfaz pcap.h. / EN: The Npcap SDK exposes the same pcap.h interface.
#  include <pcap/pcap.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "wpcap.lib")
#    pragma comment(lib, "ws2_32.lib")
#  endif
   // ES: Compatibilidad para inet_ntop y ntohs en versiones antiguas de MSVC. / EN: Compatibility for inet_ntop and ntohs on older MSVC versions.
#  include <ws2tcpip.h>
#  ifndef INET_ADDRSTRLEN
#    define INET_ADDRSTRLEN 16
#  endif
#else
#  include <pcap/pcap.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

// ES: Cabeceras estandar. / EN: Standard headers.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ES: nlohmann/json usa una sola cabecera ubicada junto a main.cpp. / EN: nlohmann/json uses one header placed next to main.cpp.
#include "json.hpp"

using json = nlohmann::json;
using namespace std::chrono;

// ES: Estructuras binarias empaquetadas sin relleno del compilador. / EN: Packed wire-format structs without compiler padding.
#pragma pack(push, 1)

struct EtherHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;       // ES: big-endian. / EN: big-endian.
};

struct IpHeader {
    uint8_t  ihl_ver;    // ES: version (4 bits) | IHL (4 bits). / EN: version (4 bits) | IHL (4 bits).
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct TcpHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;   // ES: offset de datos en los 4 bits altos. / EN: data offset in the high 4 bits.
    uint8_t  flags;      // ES/EN: CWR ECE URG ACK PSH RST SYN FIN.
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct UdpHeader {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;
};

struct ArpHeader {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint32_t spa;
    uint8_t  tha[6];
    uint32_t tpa;
};

#pragma pack(pop)

// ES: Estado global compartido por los hilos. / EN: Global state shared by threads.
namespace g {
    std::mutex          output_mtx;       // ES: Serializa escrituras a stdout. / EN: Serializes stdout writes.
    std::mutex          capture_mtx;      // ES: Protege el handle y el estado. / EN: Protects the handle and state.
    pcap_t*             handle   = nullptr;
    std::atomic<bool>   running  { false };
    std::atomic<uint64_t> pkt_id { 0 };
    std::atomic<uint64_t> captured { 0 };
    std::atomic<uint64_t> dropped  { 0 };
    std::string         current_filter;
    int                 current_iface = -1;
    std::thread         capture_thread;
    std::thread         stats_thread;
    std::thread         stdin_thread;
}

// ES: Salida JSON segura entre hilos. / EN: Thread-safe JSON output.
static void emit(const json& j) {
    std::lock_guard<std::mutex> lk(g::output_mtx);
    std::cout << j.dump() << "\n";
    std::cout.flush();
}

static void emit_error(const std::string& msg) {
    emit({ {"type","error"}, {"msg", msg} });
}

// ES: Utilidades internas. / EN: Internal helpers.

// ES: Devuelve una fecha ISO-8601 con milisegundos. / EN: Returns an ISO-8601 timestamp with milliseconds.
static std::string iso8601_now() {
    auto now  = system_clock::now();
    auto tt   = system_clock::to_time_t(now);
    auto ms   = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}

static std::string ip4_to_str(uint32_t addr_be) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr ia{};
    ia.s_addr = addr_be;
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    return std::string(buf);
}

static std::string bytes_to_hex(const uint8_t* data, size_t len, size_t max_bytes = 256) {
    size_t take = std::min(len, max_bytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < take; ++i)
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    return oss.str();
}

static std::string bytes_to_ascii(const uint8_t* data, size_t len, size_t max_bytes = 128) {
    size_t take = std::min(len, max_bytes);
    std::string out;
    out.reserve(take);
    for (size_t i = 0; i < take; ++i) {
        uint8_t c = data[i];
        out += (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
    }
    return out;
}

// ES: Mascaras de bits para flags TCP. / EN: TCP flag bitmasks.
static const uint8_t FLAG_FIN = 0x01;
static const uint8_t FLAG_SYN = 0x02;
static const uint8_t FLAG_RST = 0x04;
static const uint8_t FLAG_PSH = 0x08;
static const uint8_t FLAG_ACK = 0x10;

static std::string tcp_flags_str(uint8_t f) {
    bool syn = f & FLAG_SYN, ack = f & FLAG_ACK,
         fin = f & FLAG_FIN, rst = f & FLAG_RST,
         psh = f & FLAG_PSH;

    if (syn && ack)  return "SYN-ACK";
    if (syn)         return "SYN";
    if (fin)         return "FIN";
    if (rst)         return "RST";
    if (psh && ack)  return "PSH";
    if (ack)         return "ACK";
    return "";
}

// ES: Enumeracion de interfaces de red. / EN: Network interface enumeration.
static json enumerate_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devs = nullptr;
    json ifaces = json::array();

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        emit_error(std::string("pcap_findalldevs: ") + errbuf);
        return ifaces;
    }

    int idx = 0;
    for (pcap_if_t* d = devs; d; d = d->next, ++idx) {
        json entry;
        entry["id"]   = idx;
        entry["name"] = d->name ? d->name : "";
        entry["desc"] = d->description ? d->description : "";
        entry["loopback"] = static_cast<bool>(d->flags & PCAP_IF_LOOPBACK);
        entry["up"]       = static_cast<bool>(d->flags & PCAP_IF_UP);
        ifaces.push_back(entry);
    }
    pcap_freealldevs(devs);
    return ifaces;
}

// ES: Devuelve el nombre del dispositivo por indice o "" si falla. / EN: Returns the device name by index or "" on failure.
static std::string iface_name_by_id(int idx) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devs = nullptr;
    std::string name;

    if (pcap_findalldevs(&devs, errbuf) == -1) return "";

    int i = 0;
    for (pcap_if_t* d = devs; d; d = d->next, ++i) {
        if (i == idx) { name = d->name ? d->name : ""; break; }
    }
    pcap_freealldevs(devs);
    return name;
}

// ES: Procesa paquetes desde el hilo de pcap. / EN: Handles packets from the pcap dispatch thread.
static void packet_handler(u_char* /* ES/EN: user data. */,
                            const struct pcap_pkthdr* hdr,
                            const u_char* pkt)
{
    if (!hdr || !pkt) return;

    json out;
    out["id"] = g::pkt_id.fetch_add(1, std::memory_order_relaxed);
    out["ts"] = iso8601_now();
    out["length"] = hdr->len;

    // ES: Valores predeterminados del evento. / EN: Default event values.
    out["src_ip"]   = nullptr;
    out["dst_ip"]   = nullptr;
    out["src_port"] = nullptr;
    out["dst_port"] = nullptr;
    out["protocol"] = "OTHER";
    out["ttl"]      = nullptr;
    out["flags"]    = "";

    const uint8_t* data = reinterpret_cast<const uint8_t*>(pkt);
    uint32_t cap_len    = hdr->caplen;

    // ES/EN: Ethernet.
    if (cap_len < sizeof(EtherHeader)) {
        out["payload_hex"] = bytes_to_hex(data, cap_len);
        out["raw_ascii"]   = bytes_to_ascii(data, cap_len);
        emit(out);
        ++g::captured;
        return;
    }
    const auto* eth = reinterpret_cast<const EtherHeader*>(data);
    uint16_t eth_type = ntohs(eth->type);

    const uint8_t* l3   = data + sizeof(EtherHeader);
    uint32_t l3_len = cap_len - sizeof(EtherHeader);

    // ES/EN: ARP.
    if (eth_type == 0x0806) {
        out["protocol"] = "ARP";
        if (l3_len >= sizeof(ArpHeader)) {
            const auto* arp = reinterpret_cast<const ArpHeader*>(l3);
            out["src_ip"] = ip4_to_str(arp->spa);
            out["dst_ip"] = ip4_to_str(arp->tpa);
        }
        out["payload_hex"] = bytes_to_hex(l3, l3_len);
        out["raw_ascii"]   = bytes_to_ascii(l3, l3_len);
        emit(out);
        ++g::captured;
        return;
    }

    // ES/EN: IPv4.
    if (eth_type != 0x0800) {
        // ES: Para protocolos distintos de IP y ARP emite informacion minima. / EN: Emit minimal information for non-IP, non-ARP protocols.
        out["payload_hex"] = bytes_to_hex(l3, l3_len);
        out["raw_ascii"]   = bytes_to_ascii(l3, l3_len);
        emit(out);
        ++g::captured;
        return;
    }

    if (l3_len < sizeof(IpHeader)) {
        out["payload_hex"] = bytes_to_hex(l3, l3_len);
        out["raw_ascii"]   = bytes_to_ascii(l3, l3_len);
        emit(out);
        ++g::captured;
        return;
    }

    const auto* ip = reinterpret_cast<const IpHeader*>(l3);
    uint8_t  ip_ver = (ip->ihl_ver >> 4) & 0x0F;
    uint8_t  ip_ihl = (ip->ihl_ver & 0x0F) * 4;

    if (ip_ver != 4 || ip_ihl < 20 || ip_ihl > l3_len) {
        out["payload_hex"] = bytes_to_hex(l3, l3_len);
        out["raw_ascii"]   = bytes_to_ascii(l3, l3_len);
        emit(out);
        ++g::captured;
        return;
    }

    out["src_ip"] = ip4_to_str(ip->saddr);
    out["dst_ip"] = ip4_to_str(ip->daddr);
    out["ttl"]    = static_cast<int>(ip->ttl);

    const uint8_t* l4   = l3 + ip_ihl;
    uint32_t l4_len = l3_len - ip_ihl;

    // ES/EN: ICMP.
    if (ip->protocol == IPPROTO_ICMP) {
        out["protocol"] = "ICMP";
        out["payload_hex"] = bytes_to_hex(l4, l4_len);
        out["raw_ascii"]   = bytes_to_ascii(l4, l4_len);
        emit(out);
        ++g::captured;
        return;
    }

    // ES/EN: UDP.
    if (ip->protocol == IPPROTO_UDP) {
        if (l4_len < sizeof(UdpHeader)) {
            out["protocol"]    = "UDP";
            out["payload_hex"] = bytes_to_hex(l4, l4_len);
            out["raw_ascii"]   = bytes_to_ascii(l4, l4_len);
            emit(out);
            ++g::captured;
            return;
        }
        const auto* udp = reinterpret_cast<const UdpHeader*>(l4);
        uint16_t sport = ntohs(udp->source);
        uint16_t dport = ntohs(udp->dest);
        out["src_port"] = sport;
        out["dst_port"] = dport;

        // ES: Detecta protocolos de aplicacion por puerto. / EN: Detect application protocols by port.
        if (sport == 53 || dport == 53)
            out["protocol"] = "DNS";
        else
            out["protocol"] = "UDP";

        const uint8_t* payload = l4 + sizeof(UdpHeader);
        uint32_t payload_len = (l4_len > sizeof(UdpHeader)) ? l4_len - sizeof(UdpHeader) : 0;
        out["payload_hex"] = bytes_to_hex(payload, payload_len);
        out["raw_ascii"]   = bytes_to_ascii(payload, payload_len);
        emit(out);
        ++g::captured;
        return;
    }

    // ES/EN: TCP.
    if (ip->protocol == IPPROTO_TCP) {
        if (l4_len < sizeof(TcpHeader)) {
            out["protocol"]    = "TCP";
            out["payload_hex"] = bytes_to_hex(l4, l4_len);
            out["raw_ascii"]   = bytes_to_ascii(l4, l4_len);
            emit(out);
            ++g::captured;
            return;
        }
        const auto* tcp = reinterpret_cast<const TcpHeader*>(l4);
        uint16_t sport = ntohs(tcp->source);
        uint16_t dport = ntohs(tcp->dest);
        out["src_port"] = sport;
        out["dst_port"] = dport;
        out["flags"]    = tcp_flags_str(tcp->flags);

        // ES: Detecta protocolos de aplicacion por puerto. / EN: Detect application protocols by port.
        auto is_port = [&](uint16_t p) { return sport == p || dport == p; };
        if (is_port(53))
            out["protocol"] = "DNS";
        else if (is_port(443))
            out["protocol"] = "HTTPS";
        else if (is_port(80) || is_port(8080))
            out["protocol"] = "HTTP";
        else
            out["protocol"] = "TCP";

        uint8_t tcp_off = (tcp->data_off >> 4) * 4;
        if (tcp_off < sizeof(TcpHeader) || tcp_off > l4_len) {
            tcp_off = sizeof(TcpHeader);
        }
        const uint8_t* payload = l4 + tcp_off;
        uint32_t payload_len = (l4_len > tcp_off) ? l4_len - tcp_off : 0;
        out["payload_hex"] = bytes_to_hex(payload, payload_len);
        out["raw_ascii"]   = bytes_to_ascii(payload, payload_len);
        emit(out);
        ++g::captured;
        return;
    }

    // ES: Otros protocolos IP. / EN: Other IP protocols.
    out["payload_hex"] = bytes_to_hex(l4, l4_len);
    out["raw_ascii"]   = bytes_to_ascii(l4, l4_len);
    emit(out);
    ++g::captured;
}

// ES: Cuerpo del hilo de captura. / EN: Capture thread body.
static void capture_loop(pcap_t* handle) {
    // ES: pcap_loop bloquea hasta llamar pcap_breakloop() o hasta un error. / EN: pcap_loop blocks until pcap_breakloop() is called or an error occurs.
    pcap_loop(handle, 0 /* ES: infinito. / EN: infinite. */, packet_handler, nullptr);
}

// ES: El hilo de estadisticas emite una linea por segundo. / EN: The stats thread emits one line per second.
static void stats_loop() {
    using clock = steady_clock;
    auto prev_time = clock::now();
    uint64_t prev_cap = 0;

    while (true) {
        std::this_thread::sleep_for(seconds(1));

        auto now     = clock::now();
        double dt    = duration<double>(now - prev_time).count();
        prev_time    = now;

        uint64_t cap = g::captured.load(std::memory_order_relaxed);
        uint64_t drp = g::dropped.load(std::memory_order_relaxed);

        // ES: Actualiza descartados desde pcap si existe un handle. / EN: Update dropped packets from pcap when a handle is open.
        {
            std::lock_guard<std::mutex> lk(g::capture_mtx);
            if (g::handle) {
                struct pcap_stat ps{};
                if (pcap_stats(g::handle, &ps) == 0) {
                    g::dropped.store(ps.ps_drop + ps.ps_ifdrop,
                                     std::memory_order_relaxed);
                    drp = g::dropped.load(std::memory_order_relaxed);
                }
            }
        }

        double rate = (dt > 0) ? static_cast<double>(cap - prev_cap) / dt : 0.0;
        prev_cap = cap;

        emit({
            {"type",     "stats"},
            {"captured", cap},
            {"dropped",  drp},
            {"rate_pps", std::round(rate * 10.0) / 10.0}
        });
    }
}

// ES: Inicia captura en la interfaz indicada. / EN: Start capture on the requested interface.
static void do_stop();

static bool do_start(int iface_id) {
    // ES: Detiene el loop anterior antes de bloquear; hacer join con capture_mtx causaria deadlock.
    // EN: Stop the prior loop before locking; joining with capture_mtx held would deadlock.
    do_stop();

    std::lock_guard<std::mutex> lk(g::capture_mtx);

    std::string name = iface_name_by_id(iface_id);
    if (name.empty()) {
        emit_error("Interface id " + std::to_string(iface_id) + " not found");
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // ES/EN: snaplen=65535, promiscuous=1, timeout=100ms.
    pcap_t* h = pcap_open_live(name.c_str(), 65535, 1, 100, errbuf);
    if (!h) {
        emit_error(std::string("pcap_open_live: ") + errbuf);
        return false;
    }

    // ES: Aplica el filtro actual si existe. / EN: Apply the current filter if present.
    if (!g::current_filter.empty()) {
        struct bpf_program fp{};
        if (pcap_compile(h, &fp, g::current_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            emit_error(std::string("pcap_compile: ") + pcap_geterr(h));
        } else {
            if (pcap_setfilter(h, &fp) == -1)
                emit_error(std::string("pcap_setfilter: ") + pcap_geterr(h));
            pcap_freecode(&fp);
        }
    }

    g::handle           = h;
    g::current_iface    = iface_id;
    g::running          = true;

    g::capture_thread = std::thread(capture_loop, h);
    return true;
}

// ES: Detiene la captura. / EN: Stop capture.
static void do_stop() {
    {
        std::lock_guard<std::mutex> lk(g::capture_mtx);
        if (!g::running.load() || !g::handle) return;
        pcap_breakloop(g::handle);
    }
    if (g::capture_thread.joinable())
        g::capture_thread.join();

    std::lock_guard<std::mutex> lk(g::capture_mtx);
    if (g::handle) {
        pcap_close(g::handle);
        g::handle  = nullptr;
    }
    g::running = false;
}

// ES: Aplica o reaplica el filtro BPF. / EN: Apply or re-apply the BPF filter.
static void do_set_filter(const std::string& bpf) {
    std::lock_guard<std::mutex> lk(g::capture_mtx);
    g::current_filter = bpf;

    if (!g::handle) return;   // ES: Se aplicara en el proximo inicio. / EN: It will be applied on the next start.

    struct bpf_program fp{};
    if (pcap_compile(g::handle, &fp, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        emit_error(std::string("pcap_compile: ") + pcap_geterr(g::handle));
        return;
    }
    if (pcap_setfilter(g::handle, &fp) == -1)
        emit_error(std::string("pcap_setfilter: ") + pcap_geterr(g::handle));
    pcap_freecode(&fp);
}

// ES: Loop de comandos recibidos por stdin. / EN: stdin command loop.
static void stdin_loop() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json cmd;
        try {
            cmd = json::parse(line);
        } catch (const std::exception& e) {
            emit_error(std::string("JSON parse error: ") + e.what());
            continue;
        }

        if (!cmd.contains("cmd") || !cmd["cmd"].is_string()) {
            emit_error("Missing or invalid 'cmd' field");
            continue;
        }

        std::string c = cmd["cmd"].get<std::string>();

        if (c == "start") {
            int iface_id = cmd.value("interface_id", 0);
            if (!do_start(iface_id)) {
                // ES: Permite que Rust detecte el fin del proceso y cierre la sesion. / EN: Let Rust observe process termination and close the session.
                return;
            } else {
                emit({ {"type","info"}, {"msg","capture started"},
                       {"interface_id", iface_id} });
            }

        } else if (c == "stop") {
            do_stop();
            emit({ {"type","info"}, {"msg","capture stopped"} });

        } else if (c == "set_filter") {
            std::string bpf = cmd.value("bpf", "");
            do_set_filter(bpf);
            emit({ {"type","info"}, {"msg","filter applied"}, {"bpf", bpf} });

        } else if (c == "set_interface") {
            // ES: Solo guarda el id; el cambio real ocurre con el siguiente "start". / EN: Only store the id; the actual change happens on the next "start".
            int id = cmd.value("interface_id", 0);
            g::current_iface = id;
            emit({ {"type","info"}, {"msg","interface selected"},
                   {"interface_id", id} });

        } else if (c == "list_interfaces") {
            json ifaces = enumerate_interfaces();
            emit({ {"type","interfaces"}, {"interfaces", ifaces} });

        } else {
            emit_error("Unknown command: " + c);
        }
    }

    // ES: Si stdin se cierra, finaliza limpiamente. / EN: Shut down cleanly when stdin closes.
    do_stop();
}

// ES: Punto de entrada. / EN: Entry point.
int main() {
    // ES: stdout sin buffer para que Tauri reciba lineas inmediatamente. / EN: Use unbuffered stdout so Tauri receives lines immediately.
    std::cout.setf(std::ios::unitbuf);

#ifdef _WIN32
    // ES: Npcap requiere WSAStartup en Windows. / EN: Npcap requires WSAStartup on Windows.
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    // ES: Usa stdout binario para evitar conversion a \r\n. / EN: Use binary stdout to avoid \r\n conversion.
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin),  _O_BINARY);
#endif

    // ES: Emite ready y la lista de interfaces. / EN: Emit ready and the interface list.
    json ifaces = enumerate_interfaces();
    emit({ {"type","ready"}, {"interfaces", ifaces} });

    // ES: Inicia el emisor de estadisticas. / EN: Start the stats emitter.
    g::stats_thread = std::thread(stats_loop);
    g::stats_thread.detach();

    // ES: Espera comandos hasta cerrar stdin o terminar el proceso. / EN: Wait for commands until stdin closes or the process is killed.
    stdin_loop();

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
