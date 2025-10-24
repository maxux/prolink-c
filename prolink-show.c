#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>

#define EPOLL_EVENTS_LENGTH  64
#define EPOLL_EVENT_TIMEOUT  200

#define COLOR_RED      "\033[31;1m"
#define COLOR_YELLOW   "\033[33;1m"
#define COLOR_BLUE     "\033[34;1m"
#define COLOR_GREEN    "\033[32;1m"
#define COLOR_CYAN     "\033[36;1m"
#define COLOR_DARK     "\033[1;38;5;238m"
#define COLOR_MAGENTA  "\033[1;35m"
#define COLOR_LIGHT    "\033[1;38;5;85m"
#define COLOR_DK_LIME  "\033[1;38;5;22m"
#define COLOR_DK_CYAN  "\033[1;38;5;23m"
#define COLOR_BLUECOLA "\033[1;38;5;32m"
#define COLOR_CARIB    "\033[1;38;5;43m"
#define COLOR_ORANGE   "\033[1;38;5;208m"
#define COLOR_INDIAN   "\033[1;38;5;167m"

#define COLOR_RESET    "\033[0m"

#define debug_raw(fmt, ...) { timelog(); printf(fmt, ##__VA_ARGS__); printf(COLOR_RESET); }
#define debug(fmt, ...) { debug_raw("<> " fmt, ##__VA_ARGS__); }
#define debug_info(fmt, ...) { printf(COLOR_DARK); debug_raw(".. " fmt, ##__VA_ARGS__); }
#define debug_success(fmt, ...) { printf(COLOR_GREEN); debug_raw("** " fmt, ##__VA_ARGS__); }

#define debug_recv(fmt, ...) { printf(COLOR_MAGENTA); debug_raw(">> " fmt, ##__VA_ARGS__); }
#define debug_send(fmt, ...) { printf(COLOR_LIGHT); debug_raw("<< " fmt, ##__VA_ARGS__); }

#define debug_background(fmt, ...) { printf(COLOR_DK_CYAN); debug_raw(".. " fmt, ##__VA_ARGS__); }
#define debug_background_info(fmt, ...) { printf(COLOR_DK_LIME); debug_raw("-- " fmt, ##__VA_ARGS__); }
#define debug_background_send(fmt, ...) { printf(COLOR_DK_LIME); debug_raw("<< " fmt, ##__VA_ARGS__); }

#define debug_event(fmt, ...) { printf(COLOR_ORANGE); debug_raw("-- " fmt, ##__VA_ARGS__); }
#define debug_packet(fmt, ...) { printf(COLOR_BLUECOLA); debug_raw("-- " fmt, ##__VA_ARGS__); }
#define debug_metric(source, name, valfmt, value) { printf(COLOR_INDIAN); debug_raw("// %-15s: %-15s:" COLOR_ORANGE " " valfmt "\n", source, name, value); }
#define debug_metric_size(req, name, value) { printf(COLOR_INDIAN); debug_raw("// %s: %-20s: " COLOR_LIGHT "%u" COLOR_ORANGE " bytes (" COLOR_LIGHT "%.2f" COLOR_ORANGE " KB)\n" , req->devrid, name, value, value / 1024.0); }

#define debug_error(fmt, ...) { printf(COLOR_RED); debug_raw("!! " fmt, ##__VA_ARGS__); }

typedef struct net_info_t {
    char *ifname;
    uint8_t macaddr[6];
    uint32_t ipaddr;
    uint32_t brdaddr;

} net_info_t;

typedef struct kntxt_t {
    struct timeval runstart;
    struct timeval lastka;

    // Sockets File Descriptors
    int sockfds[5];

    // Local Interface Information
    net_info_t netinfo;

    // Keep Alive Packet crafted
    uint8_t *keepalive;
    int keeplength;

} kntxt_t;

kntxt_t *__kntxt = NULL;

void diep(char *str) {
    fprintf(stderr, "[-] %s: %s\n", str, strerror(errno));
    exit(EXIT_FAILURE);
}

double timediff(struct timeval *base, struct timeval *target) {
    double value;

    value = (double)(target->tv_usec - base->tv_usec) / 1000000;
    value += (double)(target->tv_sec - base->tv_sec);

    return value;
}

void timelog() {
    struct timeval n;
    gettimeofday(&n, NULL);

    double value = timediff(&__kntxt->runstart, &n);
    printf("[% 15.6f] ", value);
}

static char *bufmac(char *strbuf, uint8_t *source) {
    ssize_t offset = 0;

    for(int i = 0; i < 6; i++)
        offset += sprintf(strbuf + offset, "%02x:", source[i]);

    strbuf[17] = '\0';

    return strbuf;
}

void fulldump(void *_data, size_t len, uint8_t header) {
    uint8_t *data = _data;
    unsigned int i, j;

    if(header)
        debug_info("  dump: [%p -> %p] (%lu bytes)\n", data, data + len, len);

    debug_info("0x0000: ");

    for(i = 0; i < len; ) {
        printf(COLOR_DARK "%02x ", data[i++]);

        if(i % 16 == 0) {
            printf("|");

            for(j = i - 16; j < i; j++)
                printf("%c", ((isprint(data[j]) ? data[j] : '.')));

            printf("|\n");

            if(i != len)
                debug_info("0x%04x: ", i);
        }
    }

    if(i % 16) {
        printf("%-*s |", (3 * (16 - (i % 16))) - 1, " ");

        for(j = i - (i % 16); j < len; j++)
            printf("%c", ((isprint(data[j]) ? data[j] : '.')));

        printf("%-*s|\n", 16 - ((int) len % 16), " ");
    }

    printf(COLOR_RESET);
}

// ProLink Packet Header [Qspt1WmJOL]
uint8_t prolinkid[10] = {0x51, 0x73, 0x70, 0x74, 0x31, 0x57, 0x6d, 0x4a, 0x4f, 0x4c};

#define PROLINK_ANNOUNCE_CHANNEL_CLAIM_INIT  0x00
#define PROLINK_ANNOUNCE_CHANNEL_CLAIM_SYN   0x02
#define PROLINK_ANNOUNCE_CHANNEL_CLAIM_ACK   0x04

#define PROLINK_ANNOUNCE_KEEP_ALIVE          0x06
#define PROLINK_ANNOUNCE_INITIALIZE          0x0a

typedef struct prolink_announce_t {
    uint8_t preambule[10];
    uint8_t type;
    uint8_t __skip;
    char devname[20];

} __attribute__((packed)) prolink_announce_t;

typedef struct prolink_keepalive_t {
    uint8_t preambule[10];    //
    uint8_t frame_type;       //
    uint8_t __skip_a;         // Unknown
    uint8_t device_name[20];  //
    uint8_t __skip_b;         // Unknown
    uint8_t device_type;      //
    uint16_t packet_length;   // Entire packet length
    uint8_t player_id;        //
    uint8_t __skip_c;         // Unknown
    uint8_t mac_address[6];   //
    uint32_t ip_address;      //
    uint8_t network_peers;    //
    uint8_t __skip_d[5];      // Unknown

} __attribute__((packed)) prolink_keepalive_t;

#define PROLINK_SLOT_NOT_LOADED       0x00
#define PROLINK_SLOT_CD_DRIVE         0x01
#define PROLINK_SLOT_SD_DRIVE         0x02
#define PROLINK_SLOT_USB_DRIVE        0x03
#define PROLINK_SLOT_REKORDBOX        0x04

#define PROLINK_TRACK_NOT_LOADED      0x00
#define PROLINK_TRACK_ANALYZED        0x01
#define PROLINK_TRACK_UNANALYZED      0x02
#define PROLINK_TRACK_CD              0x05

#define PROLINK_LOCAL_LOADED          0x00
#define PROLINK_LOCAL_EJECT_REQUEST   0x02   // ??
#define PROLINK_LOCAL_UNMOUNTING      0x03   // ??
#define PROLINK_LOCAL_UNLOADED        0x04

#define PROLINK_PLAYMODE_UNLOADED     0x00   // No track is loaded.
#define PROLINK_PLAYMODE_LOADING      0x02   // A track is in the process of loading.
#define PROLINK_PLAYMODE_PLAYING      0x03   // Player is playing normally.
#define PROLINK_PLAYMODE_LOOP         0x04   // Player is playing a loop.
#define PROLINK_PLAYMODE_PAUSED       0x05   // Player is paused anywhere other than the cue point.
#define PROLINK_PLAYMODE_CUE_PAUSE    0x06   // Player is paused at the cue point.
#define PROLINK_PLAYMODE_CUE_PLAY     0x07   // Cue Play is in progress (playback while the cue button is held down).
#define PROLINK_PLAYMODE_CUE_SCRATCH  0x08   // Cue scratch is in progress.
#define PROLINK_PLAYMODE_SEEKING      0x09   // Player is searching forwards or backwards.
#define PROLINK_PLAYMODE_ENDED        0x11   // Player reached the end of the track and stopped.

typedef struct prolink_device_status_t {
    uint8_t preambule[10];    //
    uint8_t frame_type;       //
    uint8_t device_name[20];  //
    uint8_t packet_type;
    uint8_t packet_subtype;
    uint8_t player_id;
    uint16_t packet_length;
    uint8_t player_id_b;

    uint8_t __skip_a[2];
    uint8_t activity;
    uint8_t loaded_from;
    uint8_t loaded_slot;
    uint8_t track_type;

    uint8_t __skip_b;
    uint32_t rekordboxid;

    uint8_t __skip_d[2];
    uint16_t track_number;

    uint8_t __skip_e[54];
    uint8_t usb_activity;
    uint8_t sd_activity;

    uint8_t __skip_f[3];
    uint8_t usb_local;

    uint8_t __skip_g[3];
    uint8_t sd_local;
    uint8_t __skip_h;
    uint8_t link_available;

    uint8_t __skip_i[5];
    uint8_t play_mode;
    uint8_t firmware[4];

    uint8_t __skip_j[4];
    uint32_t sync;

    uint8_t __skip_k;
    uint8_t status_flags;

    uint8_t __skip_l;
    uint8_t play_jog;

    union {
        uint8_t bytes[4];
        uint32_t value;

    } __attribute__((scalar_storage_order("big-endian"))) pitch;

    uint8_t master_bpm[2];
    union {
        uint8_t bytes[2];
        uint16_t value;

    } __attribute__((scalar_storage_order("big-endian"))) bpm;

    uint8_t __skip_m[4];
    uint8_t pitch2[4];

    uint8_t __skip_n;
    uint8_t play_mode_xt;
    uint8_t master_mean;
    uint8_t master_handoff;
    uint32_t beat_count;
    uint16_t next_cue;
    uint8_t downbeat;

    uint8_t __skip_o[16];
    uint8_t media_presence;
    uint8_t usb_unsafe;
    uint8_t sd_unsafe;
    uint8_t emergency;

    uint8_t __skip_p[5];
    uint32_t pitch3;
    uint32_t pitch4;
    uint32_t packet_counter;
    uint8_t player_type;
    uint8_t touch_audio;

    uint8_t __skip_q[44];
    uint8_t waveform_color;

    uint8_t __skip_r[2];
    uint8_t waveform_position;

    uint8_t __skip_s[31];
    uint8_t buffer_forward;
    uint8_t buffer_backward;
    uint8_t buffer_status;

    // CDJ-3000
    // uint8_t __skip_t[56];
    // uint8_t master_tempo;

} __attribute__((packed, scalar_storage_order("big-endian"))) prolink_device_status_t;

#define PROLINK_BEATSYNC_FADER_START                 0x02
#define PROLINK_BEATSYNC_CHANNEL_ON_AIR              0x03
#define PROLINK_BEATSYNC_ABSOLUTE_POSITION           0x0b
#define PROLINK_BEATSYNC_MASTER_HANDOFF_REQUEST      0x26
#define PROLINK_BEATSYNC_MASTER_HANDOFF_RESPONSE     0x27
#define PROLINK_BEATSYNC_BEAT                        0x28
#define PROLINK_BEATSYNC_SYNC_CONTROL                0x2a

typedef struct prolink_beatsync_t {
    uint8_t preambule[10];
    uint8_t type;
    char devname[20];

} __attribute__((packed)) prolink_beatsync_t;

void parse_announce(char *source, uint8_t *message, size_t length) {
    uint8_t *packet = message;
    prolink_announce_t *frame = (prolink_announce_t *) packet;

    if(length < 32) {
        debug_info("%-15s: Packet Length too short, ignoring\n", source);
        return;
    }

    if(memcmp(frame->preambule, prolinkid, sizeof(prolinkid)) != 0) {
        debug_info("%-15s: Packet identifier malformed, ignoring\n", source);
        return;
    }

    if(frame->type == PROLINK_ANNOUNCE_CHANNEL_CLAIM_INIT) {
        debug_packet("%-15s: [%-20s] Channel Claim (Stage 1/3)\n", source, frame->devname);
    }

    if(frame->type == PROLINK_ANNOUNCE_CHANNEL_CLAIM_SYN) {
        debug_packet("%-15s: [%-20s] Channel Claim (Stage 2/3)\n", source, frame->devname);
    }

    if(frame->type == PROLINK_ANNOUNCE_CHANNEL_CLAIM_ACK) {
        debug_packet("%-15s: [%-20s] Channel Claim (Stage 3/3)\n", source, frame->devname);
    }

    if(frame->type == PROLINK_ANNOUNCE_KEEP_ALIVE) {
        debug_packet("%-15s: [%-20s] Keep-Alive\n", source, frame->devname);
    }

    if(frame->type == PROLINK_ANNOUNCE_INITIALIZE) {
        debug_packet("%-15s: [%-20s] Initial Announcement\n", source, frame->devname);
    }
}

void parse_beatsync(char *source, uint8_t *message, size_t length) {
    uint8_t *packet = message;
    prolink_beatsync_t *frame = (prolink_beatsync_t *) packet;

    if(length < 32) {
        debug_info("%-15s: Packet Length too short, ignoring\n", source);
        return;
    }

    if(memcmp(frame->preambule, prolinkid, sizeof(prolinkid)) != 0) {
        debug_info("%-15s: Packet identifier malformed, ignoring\n", source);
        return;
    }

    if(frame->type == PROLINK_BEATSYNC_FADER_START) {
        debug_packet("%-15s: [%-20s] Fader Start\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_CHANNEL_ON_AIR) {
        debug_packet("%-15s: [%-20s] Channels On Air\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_ABSOLUTE_POSITION) {
        debug_packet("%-15s: [%-20s] Absolute Position\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_MASTER_HANDOFF_REQUEST) {
        debug_packet("%-15s: [%-20s] Master Handoff Request\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_MASTER_HANDOFF_RESPONSE) {
        debug_packet("%-15s: [%-20s] Master Handoff Response\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_BEAT) {
        debug_packet("%-15s: [%-20s] Beat Information\n", source, frame->devname);
    }

    if(frame->type == PROLINK_BEATSYNC_SYNC_CONTROL) {
        debug_packet("%-15s: [%-20s] Sync Control\n", source, frame->devname);
    }
}

void parse_cdjstatus(char *source, uint8_t *message, size_t length) {
    (void) length;
    prolink_device_status_t *status = (prolink_device_status_t *) message;

    if(status->player_id == 0x02)
        return;

    fulldump(message, length, 1);

    debug_metric(source, "Device Name   ", "%.20s", status->device_name);
    debug_metric(source, "Packet Type   ", "0x%02x", status->packet_type);
    debug_metric(source, "Packet SubType", "0x%02x", status->packet_subtype);
    debug_metric(source, "Player ID     ", "0x%02x", status->player_id);
    debug_metric(source, "Packet Length ", "0x%02x", status->packet_length);
    debug_metric(source, "Player ID 2   ", "0x%02x", status->player_id_b);
    debug_metric(source, "Activity      ", "0x%02x", status->activity);
    debug_metric(source, "Loaded From ID", "0x%02x", status->loaded_from);
    debug_metric(source, "Loaded Slot   ", "0x%02x", status->loaded_slot);
    debug_metric(source, "Track Type    ", "0x%02x", status->track_type);
    debug_metric(source, "Rekordbox ID  ", "0x%02x", status->rekordboxid);
    debug_metric(source, "Track Number  ", "0x%02x", status->track_number);
    debug_metric(source, "USB Activity  ", "0x%02x", status->usb_activity);
    debug_metric(source, "SD Activity   ", "0x%02x", status->sd_activity);
    debug_metric(source, "USB Local     ", "0x%02x", status->usb_local);
    debug_metric(source, "SD Local      ", "0x%02x", status->sd_local);
    debug_metric(source, "Link Available", "0x%02x", status->link_available);
    debug_metric(source, "Play Mode     ", "0x%02x", status->play_mode);
    debug_metric(source, "Firmware      ", "%.4s", status->firmware);
    debug_metric(source, "Sync Info     ", "0x%08x", status->sync);
    debug_metric(source, "Status Flags  ", "0x%02x", status->status_flags);
    debug_metric(source, "Jog           ", "0x%02x", status->play_jog);
    debug_metric(source, "Pitch         ", "0x%08x", status->pitch.value);
    debug_metric(source, "Track BPM     ", "0x%04x", status->bpm.value);
    debug_metric(source, "Play Mode Exte", "0x%02x", status->play_mode_xt);
    debug_metric(source, "Master Meaning", "0x%02x", status->master_mean);
    debug_metric(source, "Master Handoff", "0x%02x", status->master_handoff);
    debug_metric(source, "Current Beat  ", "0x%08x", status->beat_count);
    debug_metric(source, "Next Cue Beat ", "0x%04x", status->next_cue);
    debug_metric(source, "Down Beat     ", "0x%02x", status->downbeat);
    debug_metric(source, "Media Presence", "0x%02x", status->media_presence);
    debug_metric(source, "USB Unsafe    ", "0x%02x", status->usb_unsafe);
    debug_metric(source, "SD Unsafe     ", "0x%02x", status->sd_unsafe);
    debug_metric(source, "Emergency Loop", "0x%02x", status->emergency);
    debug_metric(source, "Packet Counter", "0x%02x", status->packet_counter);
    debug_metric(source, "Player Type   ", "0x%02x", status->player_type);
    debug_metric(source, "Waveform Color", "0x%02x", status->waveform_color);
    debug_metric(source, "Waveform Locat", "0x%02x", status->waveform_position);
    debug_metric(source, "Buffer Forward", "0x%02x", status->buffer_forward);
    debug_metric(source, "Buffer Backwar", "0x%02x", status->buffer_backward);
    debug_metric(source, "Buffer Status ", "0x%02x", status->buffer_status);


    debug_info("--------------------------\n");

    ssize_t bbpitch = 0, bpitch;
    bbpitch += status->pitch.bytes[1] * 0x10000;
    bbpitch += status->pitch.bytes[2] * 0x100;
    bbpitch += status->pitch.bytes[3];
    bpitch = bbpitch - 0x100000;

    double pitch = 100.0 * (bpitch / (double) 0x100000);
    debug_metric(source, "Pitch Computed", "%3.3f %%", pitch);

    ssize_t bbpm = (status->bpm.bytes[0] * 256) + status->bpm.bytes[1];
    double bpm = bbpm / 100.0;
    debug_metric(source, "Track BPM Comp", "%f", bpm);

    double cbpm = ((double) (bbpm * bbpitch) / 0x100000) / 100;
    debug_metric(source, "Current BPM Co", "%3.3f", cbpm);
}

uint8_t *prolink_keepalive(kntxt_t *kntxt, uint8_t *source, size_t length) {
    prolink_keepalive_t *keepalive;

    // Allocate buffer to store local Keep-Alive packet
    if(!(kntxt->keepalive = malloc(length)))
        diep("malloc");

    // Copy Keep-Alive from live CDJ
    memcpy(kntxt->keepalive, source, length);
    kntxt->keeplength = length;

    keepalive = (prolink_keepalive_t *) kntxt->keepalive;
    strcpy((char *) keepalive->device_name, "CDJ-VIRTUAL");

    keepalive->player_id = 0x01;
    keepalive->network_peers += 1;

    memcpy(keepalive->mac_address, kntxt->netinfo.macaddr, sizeof(kntxt->netinfo.macaddr));
    keepalive->ip_address = kntxt->netinfo.ipaddr;

    return kntxt->keepalive;
}

/*
int testsent = 0;
int dbsock = 0;

#define DBSRV_TYPE_UINT8   0x0f
#define DBSRV_TYPE_UINT16  0x10
#define DBSRV_TYPE_UINT32  0x11
#define DBSRV_TYPE_BLOB    0x14  // Followed by 4 bytes length
#define DBSRV_TYPE_STRING  0x26  // Followed by 4 bytes length

typedef struct dbsrv_uint8_t {
    uint8_t type;
    uint8_t value;

} __attribute__((packed, scalar_storage_order("big-endian"))) dbsrv_uint8_t;

typedef struct dbsrv_uint16_t {
    uint8_t type;
    uint16_t value;

} __attribute__((packed, scalar_storage_order("big-endian"))) dbsrv_uint16_t;

typedef struct dbsrv_uint32_t {
    uint8_t type;
    uint32_t value;

} __attribute__((packed, scalar_storage_order("big-endian"))) dbsrv_uint32_t;

typedef struct dbsrv_message_t {
    dbsrv_uint32_t init;
    dbsrv_uint32_t txid;
    dbsrv_uint16_t type;
    dbsrv_uint8_t args;
    uint8_t tags_header;
    uint32_t tags_blob;
    uint8_t tags[12];
    dbsrv_uint32_t player;

} __attribute__((packed, scalar_storage_order("big-endian"))) dbsrv_message_t;

void dbserver() {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(12523);

    inet_aton("169.254.203.213", (struct in_addr *) &(address.sin_addr.s_addr));

    connect(client_socket, (struct sockaddr *) &address, sizeof(address));

    uint8_t message[64];
    uint8_t preambule[4] = {0x00, 0x00, 0x00, 0x0f};
    memset(message, 0x00, sizeof(message));
    memcpy(message, preambule, sizeof(preambule));
    memcpy(message + 4, "RemoteDBServer", 14);

    send(client_socket, message, 19, 0);

    memset(message, 0x00, sizeof(message));
    int bytes = recv(client_socket, message, sizeof(message), 0);

    close(client_socket);

    uint16_t *buffer = (uint16_t *) message;
    uint16_t port = ntohs(*buffer);

    printf(">> %d\n", port);

    //////////////////////////////////////////////////////////////////

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    inet_aton("169.254.203.213", (struct in_addr *) &(address.sin_addr.s_addr));

    connect(client_socket, (struct sockaddr *) &address, sizeof(address));

    dbsrv_uint32_t init = {.type = 0x11, .value = 1};
    send(client_socket, &init, sizeof(init), 0);

    memset(message, 0x00, sizeof(message));
    bytes = recv(client_socket, message, sizeof(message), 0);

    fulldump(message, bytes, 1);
    memset(message, 0x00, sizeof(message));

    dbsrv_message_t cursor = {
        .init = {.type = DBSRV_TYPE_UINT32, .value = 0x872349ae},
        .txid = {.type = DBSRV_TYPE_UINT32, .value = 0xfffffffe},
        .type = {.type = DBSRV_TYPE_UINT16, .value = 0},
        .args = {.type = DBSRV_TYPE_UINT8,  .value = 1},
        .tags_header = 0x14,
        .tags_blob = 0x0c,
        .tags = {0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        .player = {.type = DBSRV_TYPE_UINT32, .value = 0x01},
    };

    fulldump(&cursor, sizeof(cursor), 1);
    send(client_socket, &cursor, sizeof(cursor), 0);

    memset(message, 0x00, sizeof(message));
    bytes = recv(client_socket, message, sizeof(message), 0);
    fulldump(message, bytes, 1);


    //////////////////////////////////////////////////////////

    cursor.txid.value = 1;
    cursor.type.value = 0x2002;
    cursor.args.value = 2;
    cursor.tags[1] = 0x06;

    uint8_t qbuf[128];
    memset(qbuf, 0x00, sizeof(qbuf));
    memcpy(qbuf, &cursor, sizeof(cursor));

    qbuf[33] = 0x01;
    qbuf[34] = 0x01;
    qbuf[35] = 0x02;

    qbuf[36] = 0x11;
    // ...
    qbuf[41] = 0x11;

    printf("out\n");
    fulldump(qbuf, 42, 1);
    send(client_socket, qbuf, 42, 0);

    printf("in\n");
    bytes = recv(client_socket, message, sizeof(message), 0);
    fulldump(message, bytes, 1);
}
*/

void prolink_keepalive_send(kntxt_t *kntxt) {
    struct sockaddr_in broadcast;

    memset(&broadcast, 0x00, sizeof(broadcast));
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(50000);

    memcpy(&broadcast.sin_addr, &kntxt->netinfo.brdaddr, sizeof(kntxt->netinfo.brdaddr));
    int broadcastlen = sizeof(broadcast);

    char target[32];
    inet_ntop(AF_INET, &broadcast.sin_addr, target, sizeof(target));
    // debug_send("%-15s: ANNOUNCE: Keep-Alive\n", target);

    if(sendto(kntxt->sockfds[0], kntxt->keepalive, kntxt->keeplength, 0, (struct sockaddr *) &broadcast, broadcastlen) < 0)
        diep("sendto");

    gettimeofday(&kntxt->lastka, NULL);

    /*
    if(testsent == 0) {
        dbserver();
        testsent = 1;
    }
    */
}

int socket_udp_bind(int port) {
    struct sockaddr_in interface;
    int flags, fd;

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        diep("socket");

    memset(&interface, 0x00, sizeof(interface));
    interface.sin_family = AF_INET;
    interface.sin_addr.s_addr = htonl(INADDR_ANY);
    interface.sin_port = htons(port);

    if(bind(fd, (struct sockaddr *) &interface, sizeof(interface)) < 0)
        diep("bind");

    if((flags = fcntl(fd, F_GETFL, 0)) < 0)
        diep("fcntl: getfl");

    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        diep("fcntl: nonblock");

    int yes = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes)) < 0)
        diep("setsockopt: broadcast");

    return fd;
}

net_info_t netinfo_interface(char *interface) {
    int sockfd;
    int ifindex = -1;
    struct ifreq ifr;
    net_info_t netinfo;

    if((ifindex = if_nametoindex(interface)) <= 0)
        diep("if_nametoindex");

    if((sockfd = socket(AF_PACKET, SOCK_RAW, 0)) < 0)
        diep("socket");

    // Get interface MAC Address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    memcpy(netinfo.macaddr, (uint8_t *) ifr.ifr_hwaddr.sa_data, 6);

    // Get interface IPv4 Address
    ioctl(sockfd, SIOCGIFADDR, &ifr);
    netinfo.ipaddr = (uint32_t) ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

    ioctl(sockfd, SIOCGIFBRDADDR, &ifr);
    netinfo.brdaddr = (uint32_t) ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

    // Keep interface name reference
    netinfo.ifname = interface;

    return netinfo;
}

const char *__play_mode(uint8_t mode) {
    switch(mode) {
        case PROLINK_PLAYMODE_UNLOADED: return "Unloaded";
        case PROLINK_PLAYMODE_LOADING: return "Loading";
        case PROLINK_PLAYMODE_PLAYING: return "Playing";
        case PROLINK_PLAYMODE_LOOP: return "In Loop";
        case PROLINK_PLAYMODE_PAUSED: return "Paused";
        case PROLINK_PLAYMODE_CUE_PAUSE: return "Cue";
        case PROLINK_PLAYMODE_CUE_PLAY: return "Cueing";
        case PROLINK_PLAYMODE_CUE_SCRATCH: return "Cue Scratch";
        case PROLINK_PLAYMODE_SEEKING: return "Seeking";
        case PROLINK_PLAYMODE_ENDED: return "Ended";
    }

    return "Unknown";
}










typedef struct console_pane_t {
    size_t top;
    size_t left;
    size_t height;
    size_t width;
    const char *name;
    size_t namelen;
    int brdcolor;
    int bgcolor;
    int textcolor;

} console_pane_t;

void console_clear_screen() {
    printf("\033[2J\033[H");
}

void console_cursor_move(int line, int col) {
    printf("\033[%d;%df", line, col);
}

void console_cursor_visible(int visible) {
    printf("\033[?25%c", visible ? 'h' : 'l');
}

void console_reset_default() {
    printf("\033[0m");
}

console_pane_t *console_pane_new(size_t top, size_t left, size_t height, size_t width) {
    console_pane_t *pane;

    if(!(pane = malloc(sizeof(console_pane_t))))
        return NULL;

    pane->top = top;
    pane->left = left;
    pane->height = height;
    pane->width = width;
    pane->name = "(Unnamed)";
    pane->namelen = 9;
    pane->brdcolor = 239;
    pane->bgcolor = -1;
    pane->textcolor = 239;

    return pane;
}

void console_pane_update_name(console_pane_t *pane, const char *name) {
    pane->name = name;
    pane->namelen = strlen(name);
}

void console_pane_border_color(console_pane_t *pane, int color) {
    pane->brdcolor = color;
}

void console_pane_text_color(console_pane_t *pane, int color) {
    pane->textcolor = color;
}

void console_pane_background_color(console_pane_t *pane, int color) {
    pane->bgcolor = color;
}

void console_pane_set_colors(console_pane_t *pane) {
    if(pane->bgcolor < 0) {
        printf("\033[0m");

    } else {
        printf("\033[48;5;%dm", pane->bgcolor);
    }

    printf("\033[1;38;5;%dm", pane->textcolor);
}

void console_pane_footer_write(console_pane_t *pane, size_t left, const char *fmt, ...) {
    console_cursor_move(pane->top + pane->height + 1, pane->left + 1 + left);
    console_pane_set_colors(pane);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void console_pane_content_write(console_pane_t *pane, size_t line, size_t left, const char *fmt, ...) {
    console_cursor_move(pane->top + line, pane->left + 1 + left);
    console_pane_set_colors(pane);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void console_pane_top(console_pane_t *pane) {
    console_pane_set_colors(pane);

    printf("\033[1;38;5;%dm", pane->brdcolor);
    printf("┌──┤ ");
    printf("\033[1;38;5;15m%s", pane->name);
    printf("\033[1;38;5;%dm ", pane->brdcolor);
    printf("├");

    for(size_t i = 0; i < pane->width - pane->namelen - 6; i++)
        printf("─");

    printf("┐\033[0m");
}

void console_pane_content(console_pane_t *pane, size_t height) {
    printf("\033[1;38;5;%dm", pane->brdcolor);

    for(size_t i = 0; i < height; i++)
        printf("│%-90s│\n", "");

    printf("\033[0m");
}

void console_pane_bottom(console_pane_t *pane) {
    printf("\033[1;38;5;%dm", pane->brdcolor);

    printf("├");

    for(size_t i = 0; i < pane->width; i++)
        printf("─");

    printf("┤\n");

    console_pane_content(pane, 1);
    printf("\033[1;38;5;%dm", pane->brdcolor);

    printf("└");

    for(size_t i = 0; i < pane->width; i++)
        printf("─");

    printf("┘");
}

void console_pane_refresh(console_pane_t *pane) {
    console_cursor_move(pane->top, pane->left);
    console_pane_top(pane);

    console_cursor_move(pane->top + 1, pane->left);
    console_pane_content(pane, pane->height);

    console_cursor_move(pane->top + pane->height, pane->left);
    console_pane_bottom(pane);
}



////
///
void cdj_mediainfo_color(console_pane_t *pane) {
    // FIXME

    // Media not present
    console_pane_text_color(pane, 238);
    console_pane_background_color(pane, -1);

    // Media present but inactive
    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, -1);

    // Media present and active
    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, 56);

    // Media error or non-clean
    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, 160);

    // Media warning
    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, 160);
}

void draw_cdj_mediainfo(console_pane_t *pane, void *info) {
    (void) info;

    console_pane_text_color(pane, 237);
    console_pane_background_color(pane, -1);
    console_pane_content_write(pane, 1, pane->width - 4, " USB ");

    console_pane_text_color(pane, 255);
    console_pane_content_write(pane, 2, pane->width - 4, " SD  ");

    console_pane_background_color(pane, 235);
    console_pane_content_write(pane, 3, pane->width - 4, " CD  ");

    console_pane_content_write(pane, 4, pane->width - 4, " ERR ");

    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, 202);
    console_pane_content_write(pane, 5, pane->width - 4, " NET ");

    console_pane_text_color(pane, 255);
    console_pane_background_color(pane, -1);
}

void draw_cdjstatus(console_pane_t **panes, char *source, uint8_t *message) {
    prolink_device_status_t *status = (prolink_device_status_t *) message;

    int pid = status->player_id;
    console_pane_t *pane = panes[pid - 1];

    if(pane->brdcolor == 239) {
        console_pane_border_color(pane, 37);
        console_pane_refresh(pane);
    }

    ssize_t bbpitch = 0, bpitch;
    bbpitch += status->pitch.bytes[1] * 0x10000;
    bbpitch += status->pitch.bytes[2] * 0x100;
    bbpitch += status->pitch.bytes[3];
    bpitch = bbpitch - 0x100000;

    double pitch = 100.0 * (bpitch / (double) 0x100000);

    ssize_t bbpm = (status->bpm.bytes[0] * 256) + status->bpm.bytes[1];
    double bpm = bbpm / 100.0;

    double cbpm = ((double) (bbpm * bbpitch) / 0x100000) / 100;


    char devname[48];
    sprintf(devname, "%s v%s", status->device_name, status->firmware);

    console_pane_text_color(pane, 96);
    console_pane_footer_write(pane, 1, "%-15s", source);
    console_pane_text_color(pane, 74);
    console_pane_footer_write(pane, 20, "%*s", pane->width - 20, devname);

    console_pane_text_color(pane, 15);
    console_cursor_move(pane->top + 1, pane->left + 2);
    console_pane_content_write(pane, 1, 1, "Load from: %d", status->loaded_from);

    console_cursor_move(pane->top + 2, pane->left + 2);

    printf("Track: % 05d | ", status->track_number);
    printf("Play: %-15s | ", __play_mode(status->play_mode));
    printf("Pitch %5.3f | ", pitch);
    printf("BPM %5.3f -> %5.3f", bpm, cbpm);

    console_cursor_move(pane->top + 3, pane->left + 2);

    printf("Beat : % 5d | ", status->beat_count);
    if(status->downbeat == 1) {
        printf("#...");

    } else if(status->downbeat == 2) {
        printf(".#..");

    } else if(status->downbeat == 3) {
        printf("..#.");

    } else if(status->downbeat == 4) {
        printf("...#");

    } else {
        printf("....");
    }

    printf(" > % 5d | ", status->next_cue);
    printf("%s | ", status->usb_activity == 0x06 ? "USB" : "   ");
    printf("Buffer: % 02d % 02d %s", status->buffer_forward, status->buffer_backward, status->buffer_status ? "OK" : "");

    fflush(stdout);
}

///
///
void signaler(int signo, siginfo_t *info, void *context) {
    (void) info;
    (void) context;

    if(signo == SIGINT) {
        console_cursor_move(42, 0);
        console_cursor_visible(1);
        console_reset_default();

        fflush(stdout);
        _exit(EXIT_SUCCESS);
    }
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Missing interface name\n");
        return 1;
    }

    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &signaler;

    if(sigaction(SIGINT, &act, NULL) == -1)
        diep("sigaction");

    console_clear_screen();
    console_pane_t *panes[4];

    for(int a = 0; a < 4; a++) {
        const char *name = malloc(32);
        sprintf((char *) name, "Deck %d", a + 1);

        panes[a] = console_pane_new((a * 10) + 1, 0, 6, 90);
        console_pane_t *pane = panes[a];

        console_pane_update_name(pane, name);
        console_pane_border_color(pane, 239);
        console_pane_refresh(pane);

        console_pane_footer_write(pane, 1, "Player offline");
        draw_cdj_mediainfo(pane, NULL);
    }

    console_cursor_visible(0);
    fflush(stdout);

    kntxt_t kntxt;
    __kntxt = &kntxt;
    memset(&kntxt, 0x00, sizeof(kntxt_t));

    // Initialize Main Context
    gettimeofday(&kntxt.runstart, NULL);

    // char *fdname[] = {"ANNOUNCE", "BEATSYNC", "CDJSTATUS", "PORT50003", "PORT50004"};

    kntxt.netinfo = netinfo_interface(argv[1]);

    struct epoll_event event;
    struct epoll_event *events = NULL;
    int evfd;


    //
    // dump interface address
    //
    char macaddr[24], ipaddr[24], brdaddr[24];

    bufmac(macaddr, kntxt.netinfo.macaddr);
    inet_ntop(AF_INET, &kntxt.netinfo.ipaddr, ipaddr, sizeof(ipaddr));
    inet_ntop(AF_INET, &kntxt.netinfo.brdaddr, brdaddr, sizeof(brdaddr));

    /*
    debug_info("Interface name       : " COLOR_CYAN "%s" COLOR_RESET "\n", kntxt.netinfo.ifname);
    debug_info("Interface MAC Address: " COLOR_CYAN "%s" COLOR_RESET "\n", macaddr);
    debug_info("Interface IP Address : " COLOR_CYAN "%s" COLOR_RESET "\n", ipaddr);
    debug_info("Interface Broadcast  : " COLOR_CYAN "%s" COLOR_RESET "\n", brdaddr);
    */

    //
    // setting up socket events handler
    //
    memset(&event, 0, sizeof(struct epoll_event));

    if((evfd = epoll_create1(0)) < 0)
        diep("epoll_create1");

    // Listening on:
    // UDP Port 50000: Announcement
    // UDP Port 50001: Beat Information
    // UDP Port 50002: CDJ Status
    // UDP Port 50003:
    // UDP Port 50004:
    for(int i = 0; i < 5; i++) {
        kntxt.sockfds[i] = socket_udp_bind(50000 + i);
        event.data.fd = kntxt.sockfds[i];
        event.events = EPOLLIN;

        if(epoll_ctl(evfd, EPOLL_CTL_ADD, kntxt.sockfds[i], &event) < 0)
            diep("epoll_ctl");
    }

    events = calloc(EPOLL_EVENTS_LENGTH, sizeof(event));

    while(1) {
        int n = epoll_wait(evfd, events, EPOLL_EVENTS_LENGTH, EPOLL_EVENT_TIMEOUT);
        if(n < 0)
            diep("epoll_wait");

        // Check if we need to send a keep-alive frame
        if(kntxt.keepalive) {
            struct timeval n;
            gettimeofday(&n, NULL);

            double value = timediff(&kntxt.lastka, &n);

            if(value > 1.4) {
                prolink_keepalive_send(&kntxt);
            }
        }

        if(n == 0) {
            continue;
        }

        for(int i = 0; i < n; i++) {
            struct epoll_event *ev = events + i;

            if(ev->events & EPOLLIN) {
                uint8_t message[1024];
                char source[32];
                struct sockaddr_in client;
                socklen_t clientlen = sizeof(client);

                int bytes = recvfrom(ev->data.fd, message, sizeof(message), 0, (struct sockaddr *) &client, &clientlen);
                inet_ntop(AF_INET, &client.sin_addr, source, sizeof(source));

                // fulldump(message, bytes, 1);

                /*
                for(size_t a = 0; a < sizeof(kntxt.sockfds) / sizeof(kntxt.sockfds[0]); a++) {
                    if(kntxt.sockfds[a] == ev->data.fd) {
                        debug_recv("%-15s: %s\n", source, fdname[a]);
                    }
                }
                */

                // Announce
                if(ev->data.fd == kntxt.sockfds[0]) {
                    // parse_announce(source, message, bytes);

                    // Keep Alive
                    if(message[10] == 0x06) {
                        if(kntxt.keepalive == NULL) {
                            prolink_keepalive(&kntxt, message, bytes);
                            prolink_keepalive_send(&kntxt);
                        }
                    }
                }

                if(ev->data.fd == kntxt.sockfds[1]) {
                    // parse_beatsync(source, message, bytes);
                }

                if(ev->data.fd == kntxt.sockfds[2]) {
                    // parse_cdjstatus(source, message, bytes);
                    draw_cdjstatus(panes, source, message);
                }
            }
        }
    }

    return 0;
}
