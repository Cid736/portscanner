/*
 * portscanner.c  —  TCP Port Scanner for Windows
 * Style  : nmap-inspired output
 * Build  : gcc portscanner.c -o portscanner.exe -lws2_32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define VERSION      "3.0"
#define MAX_HOST     253
#define MAX_PORTS    65535
#define BANNER_RAW   256
#define BANNER_SHOW  48
#define VER_SIZE     48
#define SVC_SIZE     16

/* ─── Timing templates ─────────────────────────────────────────────────── */
typedef struct { const char *name; int timeout_ms; int threads; } Timing;
static const Timing TIMINGS[] = {
    { "T1 Silencioso",  2000, 10  },
    { "T2 Educado",     1200, 30  },
    { "T3 Normal",       700, 75  },
    { "T4 Agresivo",     350, 100 },
};
static int g_timeout  = 700;
static int g_threads  = 75;

/* ─── Port states ───────────────────────────────────────────────────────── */
typedef enum { ST_OPEN, ST_CLOSED, ST_FILTERED } State;

/* ─── Service database ──────────────────────────────────────────────────── */
typedef struct { int port; const char *name; } Svc;
static const Svc DB[] = {
    {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},
    {67,"dhcp"},{69,"tftp"},{79,"finger"},{80,"http"},{88,"kerberos"},
    {110,"pop3"},{111,"rpcbind"},{119,"nntp"},{123,"ntp"},{135,"msrpc"},
    {137,"netbios-ns"},{139,"netbios-ssn"},{143,"imap"},{161,"snmp"},
    {179,"bgp"},{194,"irc"},{389,"ldap"},{443,"https"},{445,"smb"},
    {465,"smtps"},{500,"isakmp"},{514,"syslog"},{515,"printer"},
    {587,"submission"},{631,"ipp"},{636,"ldaps"},{873,"rsync"},
    {902,"vmware-auth"},{993,"imaps"},{995,"pop3s"},{1080,"socks"},
    {1194,"openvpn"},{1433,"ms-sql"},{1521,"oracle"},{1723,"pptp"},
    {1883,"mqtt"},{2049,"nfs"},{2181,"zookeeper"},{2375,"docker"},
    {2376,"docker-ssl"},{3000,"http-dev"},{3306,"mysql"},{3389,"rdp"},
    {4444,"metasploit"},{5000,"upnp"},{5432,"postgresql"},{5672,"amqp"},
    {5900,"vnc"},{5985,"winrm"},{5986,"winrm-ssl"},{6379,"redis"},
    {6443,"kubernetes"},{7001,"weblogic"},{8000,"http-alt"},
    {8080,"http-proxy"},{8443,"https-alt"},{8888,"jupyter"},
    {9000,"php-fpm"},{9090,"prometheus"},{9200,"elasticsearch"},
    {9418,"git"},{9929,"nping-echo"},{10000,"webmin"},{11211,"memcached"},
    {15672,"rabbitmq"},{27017,"mongodb"},{31337,"elite"},{50000,"db2"},
    {0,NULL}
};

static const char *svc_name(int port) {
    for (int i = 0; DB[i].name; i++)
        if (DB[i].port == port) return DB[i].name;
    return NULL;
}

/* ─── Console colors ────────────────────────────────────────────────────── */
static HANDLE g_con;
#define C_WHITE   7
#define C_CYAN    11
#define C_GREEN   10
#define C_YELLOW  14
#define C_RED     12
#define C_GRAY    8
#define C_MAGENTA 13
static void color(int c) { SetConsoleTextAttribute(g_con, c); }
static void reset(void)  { color(C_WHITE); }

/* ─── Helpers ───────────────────────────────────────────────────────────── */
static void hline(char ch, int n) {
    printf("  ");
    for (int i = 0; i < n; i++) putchar(ch);
    putchar('\n');
}

/* Safe fgets-based line reader */
static int readline(const char *prompt, char *buf, int sz) {
    if (sz <= 0) return 0;
    color(C_CYAN); printf("%s", prompt); reset();
    fflush(stdout);
    if (!fgets(buf, sz, stdin)) { buf[0]='\0'; return 0; }
    buf[strcspn(buf,"\r\n")] = '\0';
    return (int)strlen(buf);
}

/* Validated integer input */
static int readint(const char *prompt, int lo, int hi) {
    char buf[16];
    while (1) {
        readline(prompt, buf, sizeof(buf));
        char *end; long v = strtol(buf, &end, 10);
        if (*end == '\0' && v >= lo && v <= hi) return (int)v;
        color(C_RED); printf("  [!] Valor invalido (%d-%d).\n", lo, hi); reset();
    }
}

static int launched_from_explorer(void) {
    HWND w = GetConsoleWindow(); if (!w) return 1;
    DWORD pid; GetWindowThreadProcessId(w, &pid);
    return (pid == GetCurrentProcessId());
}

static void wait_key(void) {
    color(C_GRAY); printf("\n  Presiona Enter para salir...");
    reset(); fflush(stdout);
    int c; while ((c=getchar())!='\n'&&c!=EOF);
}

/* ─── Networking ────────────────────────────────────────────────────────── */
static int is_local_ip(const char *ip) {
    unsigned long a = ntohl(inet_addr(ip));
    return ((a & 0xFF000000UL) == 0x0A000000UL) ||  /* 10.0.0.0/8      */
           ((a & 0xFFF00000UL) == 0xAC100000UL) ||  /* 172.16.0.0/12   */
           ((a & 0xFFFF0000UL) == 0xC0A80000UL) ||  /* 192.168.0.0/16  */
           ((a & 0xFF000000UL) == 0x7F000000UL);    /* 127.0.0.0/8     */
}

static int resolve(const char *host, char *out, int outsz) {
    if (!host || strlen(host) > MAX_HOST) return 0;
    struct addrinfo h={0},*r=NULL;
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(host,NULL,&h,&r)||!r) return 0;
    inet_ntop(AF_INET,&((struct sockaddr_in*)r->ai_addr)->sin_addr,out,outsz);
    freeaddrinfo(r); return 1;
}

/* Returns OPEN / CLOSED / FILTERED */
static State scan_port(const char *ip, int port) {
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (s==INVALID_SOCKET) return ST_FILTERED;

    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);

    struct sockaddr_in a={0};
    a.sin_family=AF_INET; a.sin_port=htons((u_short)port);
    inet_pton(AF_INET,ip,&a.sin_addr);
    connect(s,(struct sockaddr*)&a,sizeof(a));

    fd_set wf,ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s,&wf); FD_SET(s,&ef);
    struct timeval tv={g_timeout/1000,(g_timeout%1000)*1000};
    int r=select(0,NULL,&wf,&ef,&tv);

    State st;
    if      (r  < 0)                           st=ST_FILTERED;  /* error    */
    else if (r == 0)                           st=ST_FILTERED;  /* timeout  */
    else if (FD_ISSET(s,&ef))                  st=ST_CLOSED;    /* RST      */
    else if (FD_ISSET(s,&wf))                  st=ST_OPEN;      /* SYN-ACK  */
    else                                        st=ST_FILTERED;

    closesocket(s); return st;
}

/* Grab raw banner and derive service / version strings */
static int grab_banner(const char *ip, int port,
                       char *svc_out,  int svc_sz,
                       char *ver_out,  int ver_sz) {
    svc_out[0]=ver_out[0]='\0';

    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (s==INVALID_SOCKET) return 0;

    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    struct sockaddr_in a={0};
    a.sin_family=AF_INET; a.sin_port=htons((u_short)port);
    inet_pton(AF_INET,ip,&a.sin_addr);
    connect(s,(struct sockaddr*)&a,sizeof(a));

    fd_set wf,ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s,&wf); FD_SET(s,&ef);
    struct timeval tv={g_timeout/1000,(g_timeout%1000)*1000};
    int r=select(0,NULL,&wf,&ef,&tv);
    if (r<=0||FD_ISSET(s,&ef)||!FD_ISSET(s,&wf)){closesocket(s);return 0;}

    u_long bl=0; ioctlsocket(s,FIONBIO,&bl);

    const char *probe="GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    send(s,probe,(int)strlen(probe),0);

    fd_set rf; FD_ZERO(&rf); FD_SET(s,&rf);
    struct timeval bv={g_timeout/1000,(g_timeout%1000)*1000};
    if (select(0,&rf,NULL,NULL,&bv)<=0){closesocket(s);return 0;}

    char raw[BANNER_RAW+1]={0};
    int got=recv(s,raw,BANNER_RAW,0);
    closesocket(s);
    if (got<=0 || got>BANNER_RAW) return 0;
    raw[got]='\0';

    /* ── Parse common banner formats ── */

    /* SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" */
    if (strncmp(raw,"SSH-",4)==0) {
        strncpy(svc_out,"ssh",svc_sz-1); svc_out[svc_sz-1]='\0';
        char *dash=strchr(raw+4,'-');
        if (dash) {
            char *sp=strchr(dash+1,' ');
            char impl[48]={0};
            if (sp) snprintf(impl,sizeof(impl),"%.*s",(int)(sp-dash-1),dash+1);
            else    snprintf(impl,sizeof(impl),"%s",dash+1);
            impl[strcspn(impl,"\r\n")]='\0';
            snprintf(ver_out,ver_sz,"%s",impl);
        }
        return 1;
    }

    /* HTTP: extract Server header */
    if (strncmp(raw,"HTTP/",5)==0) {
        strncpy(svc_out,"http",svc_sz-1); svc_out[svc_sz-1]='\0';
        char *nl=strchr(raw,'\n');
        char status[32]={0};
        if (nl) {
            snprintf(status,sizeof(status),"%.*s",(int)(nl-raw),raw);
            status[strcspn(status,"\r")]='\0';
        }
        char *sv=strstr(raw,"Server:");
        if (!sv) sv=strstr(raw,"server:");
        if (sv) {
            sv+=7; while(*sv==' ')sv++;
            char tmp[VER_SIZE]={0};
            snprintf(tmp,sizeof(tmp),"%s",sv);
            tmp[strcspn(tmp,"\r\n")]='\0';
            snprintf(ver_out,ver_sz,"%s",tmp);
        } else {
            snprintf(ver_out,ver_sz,"%s",status);
        }
        return 1;
    }

    /* FTP: "220" on port 21 / SMTP: "220" on port 25, 465, 587 */
    if (strncmp(raw,"220",3)==0 && (raw[3]==' '||raw[3]=='-')) {
        int is_smtp=(port==25||port==465||port==587||port==2525);
        strncpy(svc_out, is_smtp?"smtp":"ftp", svc_sz-1); svc_out[svc_sz-1]='\0';
        char *p=(raw[3]==' ')?raw+4:raw+4;
        p[strcspn(p,"\r\n")]='\0';
        snprintf(ver_out,ver_sz,"%.*s",ver_sz-1,p);
        return 1;
    }

    /* POP3: "+OK" */
    if (strncmp(raw,"+OK",3)==0) {
        strncpy(svc_out,"pop3",svc_sz-1); svc_out[svc_sz-1]='\0';
        char *p=raw+3; while(*p==' ')p++;
        p[strcspn(p,"\r\n")]='\0';
        snprintf(ver_out,ver_sz,"%.*s",ver_sz-1,p);
        return 1;
    }

    /* IMAP: "* OK" */
    if (strncmp(raw,"* OK",4)==0) {
        strncpy(svc_out,"imap",svc_sz-1); svc_out[svc_sz-1]='\0';
        char *p=raw+4; while(*p==' ')p++;
        p[strcspn(p,"\r\n")]='\0';
        snprintf(ver_out,ver_sz,"%.*s",ver_sz-1,p);
        return 1;
    }

    /* RDP / other binary protocols — just note as open */
    if (got > 0) {
        /* Check if it's printable enough to show */
        int printable=0;
        for(int i=0;i<got&&i<16;i++) if((unsigned char)raw[i]>=32) printable++;
        if (printable < 4) return 0;   /* binary, skip */

        char clean[BANNER_SHOW+1]={0}; int ci=0;
        for(int i=0;i<got&&ci<BANNER_SHOW;i++){
            unsigned char c=(unsigned char)raw[i];
            if(c=='\r'||c=='\n'){if(ci&&clean[ci-1]!=' ')clean[ci++]=' ';}
            else if(c>=32&&c<127) clean[ci++]=(char)c;
        }
        while(ci>0&&clean[ci-1]==' ')ci--;
        clean[ci]='\0';
        if(ci>0) snprintf(ver_out,ver_sz,"%s",clean);
        return (ci>0)?1:0;
    }

    return 0;
}

/* ─── Thread worker ─────────────────────────────────────────────────────── */
typedef struct {
    const char *ip;
    int   port;
    State state;
    int   has_info;
    char  svc[SVC_SIZE];
    char  ver[VER_SIZE];
} Task;

static DWORD WINAPI worker(LPVOID arg) {
    Task *t=(Task*)arg;
    t->state=scan_port(t->ip,t->port);
    if (t->state==ST_OPEN)
        t->has_info=grab_banner(t->ip,t->port,t->svc,sizeof(t->svc),t->ver,sizeof(t->ver));
    return 0;
}

/* ─── Header / examples ─────────────────────────────────────────────────── */
static void print_header(void) {
    color(C_CYAN);
    printf("\n");
    hline('=',70);
    printf("  |%68s|\n"," ");
    printf("  |  ____   ___  ____ _____   ____   ____    _    _   _            |\n");
    printf("  | |  _ \\ / _ \\|  _ \\_   _| / ___| / ___|  / \\  | \\ | |           |\n");
    printf("  | | |_) | | | | |_) || |   \\___ \\| |     / _ \\ |  \\| |           |\n");
    printf("  | |  __/| |_| |  _ < | |    ___) | |___ / ___ \\| |\\  |           |\n");
    printf("  | |_|    \\___/|_| \\_\\|_|   |____/ \\____/_/   \\_\\_| \\_|           |\n");
    printf("  |%68s|\n"," ");
    reset();
    printf("  |           TCP Port Scanner v%s  //  C + Winsock2                 |\n",VERSION);
    color(C_GRAY);
    printf("  |  Use responsibly. Only scan systems you own or have permission  |\n");
    color(C_CYAN);
    printf("  |%68s|\n"," ");
    hline('=',70);
    reset(); printf("\n");
}

static void print_examples(void) {
    color(C_YELLOW); printf("  EJEMPLOS\n");
    color(C_GRAY);   hline('-',70); reset();
    printf("  Desde terminal (sin menu):\n\n");
    color(C_GRAY);
    printf("    portscanner.exe 192.168.1.1 1 1024\n");
    printf("    portscanner.exe scanme.nmap.org 1 65535\n");
    printf("    portscanner.exe 10.0.0.5 22 22\n\n");
    printf("  Host publico para practicar: ");
    color(C_CYAN); printf("scanme.nmap.org\n"); reset();
    printf("  (Nmap autoriza escaneos en este host)\n\n");
}

/* ─── Scan engine ───────────────────────────────────────────────────────── */
static void run_scan(const char *host, const char *ip, int start, int end, FILE *log) {
    int total = end - start + 1;
    int n_open=0, n_closed=0, n_filtered=0;
    time_t t0=time(NULL);

    /* Auto-cap threads for remote hosts to avoid SYN flooding path */
    int batch = g_threads;
    int remote = !is_local_ip(ip);
    if (remote && batch > 25) batch = 25;

    /* Header */
    color(C_CYAN); hline('-',70);
    color(C_YELLOW); printf("  PORT SCAN REPORT\n");
    color(C_CYAN);   hline('-',70); reset();
    printf("  Host    : "); color(C_WHITE); printf("%s",host);
    if(strcmp(host,ip)!=0){color(C_GRAY);printf(" (%s)",ip);}
    reset(); printf("\n");
    printf("  Puertos : "); color(C_WHITE);
    printf("%d - %d (%d puertos)\n",start,end,total); reset();
    printf("  Timing  : "); color(C_WHITE);
    printf("%d ms timeout / %d threads paralelos",g_timeout,batch);
    if (remote && batch < g_threads) {
        color(C_GRAY); printf("  (auto-cap: host remoto)");
    }
    reset(); printf("\n");
    color(C_CYAN); hline('-',70); reset();
    printf("\n");

    if (log) {
        fprintf(log,"PORT SCAN REPORT\n");
        fprintf(log,"Host    : %s (%s)\n",host,ip);
        fprintf(log,"Range   : %d-%d (%d ports)\n\n",start,end,total);
        fprintf(log,"%-10s %-10s %-14s %s\n","PORT","STATE","SERVICE","VERSION");
        fprintf(log,"%-10s %-10s %-14s %s\n","----------","----------","--------------","-------");
    }

    /* Column headers */
    color(C_YELLOW);
    printf("  %-10s %-10s %-14s %s\n","PORT","STATE","SERVICE","VERSION");
    color(C_GRAY);
    printf("  %-10s %-10s %-14s %s\n","----------","----------","--------------","-------");
    reset();

    /* Allocate task arrays */
    Task   *tasks   = (Task*)calloc(batch, sizeof(Task));
    HANDLE *handles = (HANDLE*)malloc(batch * sizeof(HANDLE));
    if (!tasks||!handles) {
        color(C_RED); printf("  [!] Error de memoria.\n"); reset();
        free(tasks); free(handles); return;
    }

    for (int bs=start; bs<=end; bs+=batch) {
        int be=bs+batch-1; if(be>end)be=end;
        int bc=be-bs+1;

        /* Progress */
        int done=bs-start, pct=done*100/total, bars=pct/5;
        color(C_GRAY); printf("  [");
        color(C_CYAN);
        for(int i=0;i<bars;i++) putchar('#');
        color(C_GRAY);
        for(int i=bars;i<20;i++) putchar('.');

        /* ETA */
        time_t elapsed=time(NULL)-t0;
        int eta=0;
        if(done>0) eta=(int)((double)elapsed*(total-done)/done);
        printf("] %3d%%  ",pct);
        if(eta>0) { color(C_GRAY); printf("ETA %ds  puertos %d-%d\r",eta,bs,be); }
        else       printf("puertos %d-%d\r",bs,be);
        reset(); fflush(stdout);

        /* Launch threads */
        for(int i=0;i<bc;i++){
            tasks[i].ip=ip; tasks[i].port=bs+i;
            tasks[i].state=ST_FILTERED; tasks[i].has_info=0;
            tasks[i].svc[0]=tasks[i].ver[0]='\0';
            handles[i]=CreateThread(NULL,0,worker,&tasks[i],0,NULL);
        }
        /* Wait */
        for(int i=0;i<bc;i++){
            if(handles[i]){WaitForSingleObject(handles[i],INFINITE);CloseHandle(handles[i]);}
        }

        /* Print results in port order */
        for(int i=0;i<bc;i++){
            Task *t=&tasks[i];
            if(t->state==ST_CLOSED){n_closed++;continue;}
            if(t->state==ST_FILTERED){n_filtered++;continue;}
            /* OPEN */
            n_open++;
            printf("%-70s\r","");  /* clear progress */

            /* Port/proto */
            color(C_GREEN);
            printf("  %-10s", ""); /* spacing */
            printf("\r");
            char portstr[16]; snprintf(portstr,sizeof(portstr),"%d/tcp",t->port);
            printf("  "); color(C_GREEN); printf("%-10s",portstr);

            /* State */
            color(C_GREEN); printf("%-10s","open");

            /* Service: prefer banner-detected, fallback to DB */
            const char *svc = t->has_info && t->svc[0] ? t->svc : svc_name(t->port);
            color(C_WHITE); printf("%-14s", svc ? svc : "-");

            /* Version */
            color(C_GRAY);
            if(t->has_info && t->ver[0]) printf("%s",t->ver);
            else printf("-");
            reset(); printf("\n");

            if(log){
                char ps[16]; snprintf(ps,sizeof(ps),"%d/tcp",t->port);
                fprintf(log,"%-10s %-10s %-14s %s\n",ps,"open",
                        svc?svc:"-", t->has_info&&t->ver[0]?t->ver:"-");
                fflush(log);
            }
        }
    }

    free(tasks); free(handles);
    printf("%-70s\r","");  /* clear last progress line */

    time_t elapsed=time(NULL)-t0;

    /* Summary footer */
    printf("\n");
    color(C_CYAN); hline('-',70);
    color(C_YELLOW); printf("  RESUMEN\n"); color(C_GRAY); hline('-',70); reset();
    printf("  Host escaneado : "); color(C_WHITE); printf("%s\n",host); reset();
    printf("  Puertos        : ");
    color(C_GREEN);  printf("%d open  ",n_open);
    color(C_GRAY);   printf("%d closed  ",n_closed);
    color(C_YELLOW); printf("%d filtered\n",n_filtered);
    reset();
    printf("  Duracion       : "); color(C_WHITE); printf("%ld segundos\n",(long)elapsed); reset();
    if(n_open==0){
        color(C_YELLOW);
        printf("\n  [?] 0 puertos abiertos. Posibles causas:\n");
        reset();
        printf("      - Firewall descarta paquetes (filtered = sin respuesta)\n");
        printf("      - Host inactivo en esa IP\n");
        printf("      - Puertos abiertos fuera del rango escaneado\n\n");
    }
    color(C_CYAN); hline('-',70); reset();

    if(log){
        fprintf(log,"\nSummary: %d open | %d closed | %d filtered | %ld sec\n",
                n_open,n_closed,n_filtered,(long)elapsed);
    }
}

/* ─── Main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    WSADATA wsa;
    char host[MAX_HOST+1]={0}, ip[INET_ADDRSTRLEN]={0};
    int start_port=0, end_port=0;
    int explorer=launched_from_explorer();

    g_con=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);

    print_header();

    /* ── Terminal mode: portscanner.exe <host> <start> <end> ── */
    if (argc==4) {
        strncpy(host,argv[1],MAX_HOST);
        host[MAX_HOST]='\0';  /* explicit null-termination guarantee */
        char *e1,*e2;
        long s=strtol(argv[2],&e1,10), en=strtol(argv[3],&e2,10);
        if(*e1||*e2||s<1||en>MAX_PORTS||s>en){
            color(C_RED);
            printf("  [!] Uso: portscanner.exe <host> <puerto_inicio> <puerto_fin>\n\n");
            reset(); print_examples();
            if(WSAStartup(MAKEWORD(2,2),&wsa)==0)WSACleanup();
            if(explorer){wait_key();} return 1;
        }
        start_port=(int)s; end_port=(int)en;

    /* ── Interactive menu ── */
    } else {
        print_examples();

        color(C_YELLOW); printf("  CONFIGURACION\n");
        color(C_GRAY);   hline('-',70); reset(); printf("\n");

        /* Host */
        char buf[MAX_HOST+2];
        do {
            readline("  IP o dominio > ",buf,sizeof(buf));
            if(strlen(buf)==0||strlen(buf)>MAX_HOST){
                color(C_RED); printf("  [!] Entrada invalida.\n"); reset();
            } else break;
        } while(1);
        strncpy(host,buf,MAX_HOST);
        host[MAX_HOST]='\0';  /* explicit null-termination guarantee */

        /* Timing */
        printf("\n");
        color(C_YELLOW); printf("  VELOCIDAD\n\n"); reset();
        printf("  [1]  T1 Silencioso   — 2000ms / 10 threads   (IDS-evasion, internet)\n");
        printf("  [2]  T2 Educado      — 1200ms / 30 threads   (internet recomendado)\n");
        printf("  [3]  T3 Normal       — 700ms  / 75 threads   (recomendado local)\n");
        printf("  [4]  T4 Agresivo     — 350ms  / 100 threads  (red local rapida)\n\n");
        int tc=readint("  Opcion > ",1,4);
        g_timeout=TIMINGS[tc-1].timeout_ms;
        g_threads=TIMINGS[tc-1].threads;
        printf("\n");

        /* Port range */
        color(C_YELLOW); printf("  RANGO DE PUERTOS\n\n"); reset();
        printf("  [1]  Comunes           1 - 1024\n");
        printf("  [2]  Web               80, 443, 8080, 8443\n");
        printf("  [3]  Acceso remoto     21, 22, 23, 3389, 5900\n");
        printf("  [4]  Bases de datos    1433, 3306, 5432, 6379, 27017\n");
        printf("  [5]  Todos             1 - 65535\n");
        printf("  [6]  Un solo puerto\n");
        printf("  [7]  Rango manual\n\n");
        int pc=readint("  Opcion > ",1,7);
        printf("\n");

        /* Port lists for preset scans (use -1 as sentinel) */
        static const int WEB_PORTS[]  = {80,443,8080,8443,-1};
        static const int SSH_PORTS[]  = {21,22,23,3389,5900,-1};
        static const int DB_PORTS[]   = {1433,3306,5432,6379,27017,-1};
        const int *preset_list = NULL;

        switch(pc){
            case 1: start_port=1;    end_port=1024;  break;
            case 2: preset_list=WEB_PORTS;            break;
            case 3: preset_list=SSH_PORTS;            break;
            case 4: preset_list=DB_PORTS;             break;
            case 5: start_port=1;    end_port=65535;
                    color(C_YELLOW);
                    printf("  [!] Escaneo total: puede tardar varios minutos.\n\n");
                    reset(); break;
            case 6: {
                start_port=readint("  Puerto > ",1,MAX_PORTS);
                end_port=start_port; printf("\n"); break;
            }
            case 7: {
                start_port=readint("  Puerto inicio > ",1,MAX_PORTS);
                end_port  =readint("  Puerto fin    > ",start_port,MAX_PORTS);
                printf("\n"); break;
            }
        }

        /* Handle preset list scans */
        if (preset_list) {
            if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
                color(C_RED); printf("  [!] Error Winsock.\n"); reset();
                if(explorer){wait_key();} return 1;
            }
            if(!resolve(host,ip,sizeof(ip))){
                color(C_RED); printf("  [!] No se pudo resolver: %s\n",host); reset();
                WSACleanup(); if(explorer){wait_key();} return 1;
            }
            char sv[4]; readline("  Guardar resultados en archivo? [s/N] > ",sv,sizeof(sv));
            printf("\n");
            FILE *log=NULL;
            if(sv[0]=='s'||sv[0]=='S'){
                char fn[64]; time_t now=time(NULL); struct tm *lt=localtime(&now);
                snprintf(fn,sizeof(fn),"scan_%04d%02d%02d_%02d%02d%02d.txt",
                         lt->tm_year+1900,lt->tm_mon+1,lt->tm_mday,
                         lt->tm_hour,lt->tm_min,lt->tm_sec);
                log=fopen(fn,"w");
                if(log){color(C_GREEN);printf("  Guardando en: %s\n\n",fn);reset();}
            }
            /* Scan each port individually */
            int count=0; while(preset_list[count]>=0) count++;
            color(C_CYAN); hline('-',70);
            color(C_YELLOW); printf("  PORT SCAN REPORT\n");
            color(C_CYAN);   hline('-',70); reset();
            printf("  Host    : "); color(C_WHITE); printf("%s",host);
            if(strcmp(host,ip)!=0){color(C_GRAY);printf(" (%s)",ip);}
            reset(); printf("\n");
            printf("  Puertos : "); color(C_WHITE);
            for(int i=0;i<count;i++){printf("%d",preset_list[i]);if(i<count-1)printf(", ");}
            printf("\n"); reset();
            printf("  Timing  : "); color(C_WHITE);
            printf("%d ms timeout / %d threads paralelos\n",g_timeout,g_threads); reset();
            if(!is_local_ip(ip) && g_threads>50){
                color(C_YELLOW);
                printf("  [!] Host remoto: considera T2/T3 para mejores resultados.\n");
                reset();
            }
            color(C_CYAN); hline('-',70); reset(); printf("\n");
            color(C_YELLOW);
            printf("  %-10s %-10s %-14s %s\n","PORT","STATE","SERVICE","VERSION");
            color(C_GRAY);
            printf("  %-10s %-10s %-14s %s\n","----------","----------","--------------","-------");
            reset();
            if(log){
                fprintf(log,"PORT SCAN REPORT\nHost: %s (%s)\n\n",host,ip);
                fprintf(log,"%-10s %-10s %-14s %s\n","PORT","STATE","SERVICE","VERSION");
            }

            Task   *tasks   = (Task*)calloc(count, sizeof(Task));
            HANDLE *handles = (HANDLE*)malloc(count * sizeof(HANDLE));
            time_t t0 = time(NULL);
            int n_open=0, n_closed=0, n_filtered=0;
            if (tasks && handles) {
                for (int i=0; i<count; i++) {
                    tasks[i].ip=ip; tasks[i].port=preset_list[i];
                    tasks[i].state=ST_FILTERED; tasks[i].has_info=0;
                    tasks[i].svc[0]=tasks[i].ver[0]='\0';
                    handles[i]=CreateThread(NULL,0,worker,&tasks[i],0,NULL);
                }
                for(int i=0;i<count;i++){
                    if(handles[i]){WaitForSingleObject(handles[i],INFINITE);CloseHandle(handles[i]);}
                }
                for(int i=0;i<count;i++){
                    Task *t=&tasks[i];
                    char portstr[16]; snprintf(portstr,sizeof(portstr),"%d/tcp",t->port);
                    const char *svc=t->has_info&&t->svc[0]?t->svc:svc_name(t->port);
                    if(t->state==ST_OPEN){
                        n_open++;
                        color(C_GREEN); printf("  %-10s%-10s",portstr,"open");
                        color(C_WHITE); printf("%-14s",svc?svc:"-");
                        color(C_GRAY);
                        if(t->has_info&&t->ver[0]) printf("%s",t->ver); else printf("-");
                        reset(); printf("\n");
                        if(log) fprintf(log,"%-10s %-10s %-14s %s\n",portstr,"open",svc?svc:"-",t->has_info&&t->ver[0]?t->ver:"-");
                    } else if(t->state==ST_CLOSED){
                        n_closed++;
                        color(C_GRAY); printf("  %-10s%-10s%-14s-\n",portstr,"closed",svc?svc:"-"); reset();
                    } else {
                        n_filtered++;
                        color(C_YELLOW); printf("  %-10s%-10s%-14s-\n",portstr,"filtered",svc?svc:"-"); reset();
                    }
                }
            }
            free(tasks); free(handles);

            time_t elapsed=time(NULL)-t0;
            printf("\n");
            color(C_CYAN); hline('-',70);
            color(C_YELLOW); printf("  RESUMEN\n"); color(C_GRAY); hline('-',70); reset();
            printf("  Host escaneado : "); color(C_WHITE); printf("%s\n",host); reset();
            printf("  Puertos        : ");
            color(C_GREEN);printf("%d open  ",n_open);
            color(C_GRAY);printf("%d closed  ",n_closed);
            color(C_YELLOW);printf("%d filtered\n",n_filtered); reset();
            printf("  Duracion       : "); color(C_WHITE); printf("%ld segundos\n",(long)elapsed); reset();
            color(C_CYAN); hline('-',70); reset();
            if(log){fprintf(log,"\nSummary: %d open | %d closed | %d filtered | %lds\n",n_open,n_closed,n_filtered,(long)elapsed);fclose(log);}
            WSACleanup();
            if(explorer)wait_key();
            return 0;
        }

        /* Save to file */
        char sv[4]; readline("  Guardar resultados en archivo? [s/N] > ",sv,sizeof(sv));
        printf("\n");

        if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
            color(C_RED); printf("  [!] Error Winsock.\n"); reset();
            if(explorer){wait_key();} return 1;
        }
        if(!resolve(host,ip,sizeof(ip))){
            color(C_RED); printf("  [!] No se pudo resolver: %s\n",host); reset();
            WSACleanup(); if(explorer){wait_key();} return 1;
        }

        FILE *log=NULL;
        if(sv[0]=='s'||sv[0]=='S'){
            char fn[64]; time_t now=time(NULL); struct tm *lt=localtime(&now);
            snprintf(fn,sizeof(fn),"scan_%04d%02d%02d_%02d%02d%02d.txt",
                     lt->tm_year+1900,lt->tm_mon+1,lt->tm_mday,
                     lt->tm_hour,lt->tm_min,lt->tm_sec);
            log=fopen(fn,"w");
            if(log){color(C_GREEN);printf("  Guardando en: %s\n\n",fn);reset();}
        }

        run_scan(host,ip,start_port,end_port,log);
        if(log)fclose(log);
        WSACleanup();
        if(explorer)wait_key();
        return 0;
    }

    /* Terminal mode continued */
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
        color(C_RED); printf("  [!] Error Winsock.\n"); reset(); return 1;
    }
    if(!resolve(host,ip,sizeof(ip))){
        color(C_RED); printf("  [!] No se pudo resolver: %s\n",host); reset();
        WSACleanup(); return 1;
    }
    run_scan(host,ip,start_port,end_port,NULL);
    WSACleanup();
    return 0;
}
