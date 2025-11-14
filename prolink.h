#ifndef PROLINK_H
#define PROLINK_H

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

typedef struct prolink_computed_t {
    double pitch;
    double bpm;
    double live_bpm;

} prolink_computed_t;

typedef struct prolink_state_t {
    char source[32];
    int refreshed;

    prolink_device_status_t *status;
    prolink_device_status_t *status_ref;

    prolink_computed_t computed;
    prolink_computed_t computed_ref;


} prolink_state_t;


#endif
