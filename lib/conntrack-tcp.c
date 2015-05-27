/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "conntrack-private.h"
#include "dp-packet.h"
#include "util.h"

enum tcp_state {
    TCPS_CLOSED,
    TCPS_LISTEN,
    TCPS_SYN_SENT,
    TCPS_SYN_RECEIVED,
    TCPS_ESTABLISHED,
    TCPS_CLOSE_WAIT,
    TCPS_FIN_WAIT_1,
    TCPS_CLOSING,
    TCPS_LAST_ACK,
    TCPS_FIN_WAIT_2,
    TCPS_TIME_WAIT,
};

struct tcp_peer {
    enum tcp_state state;
    uint32_t       seqlo;          /* Max sequence number sent     */
    uint32_t       seqhi;          /* Max the other end ACKd + win */
    uint16_t       max_win;        /* largest window (pre scaling) */
    uint16_t       mss;            /* Maximum segment size option  */
    uint8_t        wscale;         /* window scaling factor        */
};

struct conn_tcp {
    struct conn up;
    struct tcp_peer peer[2];
};

enum {
    TCPOPT_EOL,
    TCPOPT_NOP,
    TCPOPT_WINDOW = 3,
};

/* TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers. */
#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)

#define SEQ_MIN(a, b)   ((SEQ_LT(a, b)) ? (a) : (b))
#define SEQ_MAX(a, b)   ((SEQ_GT(a, b)) ? (a) : (b))

static struct conn_tcp*
conn_tcp_cast(struct conn* conn)
{
    return CONTAINER_OF(conn, struct conn_tcp, up);
}

/* XXX pf does this in in pf_normalize_tcp(), and it is called
 * only if scrub is enabled.  We're not scrubbing, but this check
 * seems reasonable.  */
static inline bool
tcp_totally_invalid(uint16_t flags)
{

    if (flags & TCP_SYN) {
        if (flags & TCP_RST) {
            return true;
        }
        if (flags & TCP_FIN) {
            /* XXX here pf removes the fin flag.  Should we mark the packet as
             * invalid? */
            return true;
        }
    } else {
        /* Illegal packet */
        if (!(flags & (TCP_ACK|TCP_RST))) {
            return true;
        }
    }

    if (!(flags & TCP_ACK)) {
        /* These flags are only valid if ACK is set */
        if ((flags & TCP_FIN) || (flags & TCP_PSH) || (flags & TCP_URG)) {
            return true;
        }
    }

    return false;
}

#define TCP_MAX_WSCALE 14
#define CT_WSCALE_FLAG 0x80
#define CT_WSCALE_MASK 0xf

static uint8_t
tcp_get_wscale(const struct tcp_header *tcp)
{
    unsigned len = TCP_OFFSET(tcp->tcp_ctl) * 4 - sizeof *tcp;
    const uint8_t *opt = (const uint8_t *)(tcp + 1);
    uint8_t wscale = 0;
    uint8_t optlen;

    while (len >= 3) {
        if (*opt == TCPOPT_EOL) {
            break;
        }
        switch (*opt) {
        case TCPOPT_NOP:
            opt++;
            len--;
            break;
        case TCPOPT_WINDOW:
            wscale = MIN(opt[2], TCP_MAX_WSCALE);
            wscale |= CT_WSCALE_FLAG;
            /* fall through */
        default:
            optlen = opt[2];
            if (optlen < 2) {
                optlen = 2;
            }
            len -= optlen;
            opt += optlen;
        }
    }

    return wscale;
}

static void
update_expiration(struct conn_tcp *conn, long long now, long long interval)
{
    conn->up.expiration = now + interval;
}


static bool
tcp_conn_update(struct conn* conn_, struct dp_packet *pkt, bool reply,
                long long now)
{
    struct conn_tcp *conn = conn_tcp_cast(conn_);
    struct tcp_header *tcp = dp_packet_l4(pkt);
    /* The peer that sent 'pkt' */
    struct tcp_peer *src = &conn->peer[reply ? 1 : 0];
    /* The peer that should receive 'pkt' */
    struct tcp_peer *dst = &conn->peer[reply ? 0 : 1];
    uint8_t sws = 0, dws = 0;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    uint16_t win = ntohs(tcp->tcp_winsz);
    uint32_t ack, end, seq, orig_seq;
    uint32_t p_len =  (char *) dp_packet_tail(pkt)
                      - (char *) dp_packet_get_tcp_payload(pkt);
    int ackskew;

    if (tcp_totally_invalid(tcp_flags)) {
        return false;
    }

    if (((tcp_flags & (TCP_SYN|TCP_ACK)) == TCP_SYN) &&
            dst->state >= TCPS_FIN_WAIT_2 &&
            src->state >= TCPS_FIN_WAIT_2) {
        /* XXX ORIG make sure it's the same direction ?? */
        src->state = dst->state = TCPS_CLOSED;
        /* XXX remove connection */
        return false;
    }

    if (src->wscale && dst->wscale && !(tcp_flags & TCP_SYN)) {
        sws = src->wscale & CT_WSCALE_MASK;
        dws = dst->wscale & CT_WSCALE_MASK;
    }

    /*
     * Sequence tracking algorithm from Guido van Rooij's paper:
     *   http://www.madison-gurkha.com/publications/tcp_filtering/
     *      tcp_filtering.ps
     */

    orig_seq = seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    if (src->state < TCPS_SYN_SENT) {
        /* First packet from this end. Set its state */

        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));

        end = seq + p_len;
        if (tcp_flags & TCP_SYN) {
            end++;
            if (dst->wscale & CT_WSCALE_FLAG) {
                src->wscale = tcp_get_wscale(tcp);
                if (src->wscale & CT_WSCALE_FLAG) {
                    /* Remove scale factor from initial
                     * window */
                    sws = src->wscale & CT_WSCALE_MASK;
                    win = ((u_int32_t)win + (1 << sws) - 1)
                        >> sws;
                    dws = dst->wscale & CT_WSCALE_MASK;
                } else {
                    /* fixup other window */
                    dst->max_win <<= dst->wscale &
                        CT_WSCALE_MASK;
                    /* in case of a retrans SYN|ACK */
                    dst->wscale = 0;
                }
            }
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }

        src->seqlo = seq;
        if (src->state < TCPS_SYN_SENT) {
            src->state = TCPS_SYN_SENT;
        }
        /*
         * May need to slide the window (seqhi may have been set by
         * the crappy stack check or if we picked up the connection
         * after establishment)
         */
        if (src->seqhi == 1 ||
                SEQ_GEQ(end + MAX(1, dst->max_win << dws), src->seqhi)) {
            src->seqhi = end + MAX(1, dst->max_win << dws);
        }
        if (win > src->max_win) {
            src->max_win = win;
        }

    } else {
        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));
        end = seq + p_len;
        if (tcp_flags & TCP_SYN) {
            end++;
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }
    }

    if ((tcp_flags & TCP_ACK) == 0) {
        /* Let it pass through the ack skew check */
        ack = dst->seqlo;
    } else if ((ack == 0
                && (tcp_flags & (TCP_ACK|TCP_RST)) == (TCP_ACK|TCP_RST))
               /* broken tcp stacks do not set ack */
               || dst->state < TCPS_SYN_SENT) {
        /* Many stacks (ours included) will set the ACK number in an
         * FIN|ACK if the SYN times out -- no sequence to ACK. */
        ack = dst->seqlo;
    }

    if (seq == end) {
        /* Ease sequencing restrictions on no data packets */
        seq = src->seqlo;
        end = seq;
    }

    ackskew = dst->seqlo - ack;
#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */
    if (SEQ_GEQ(src->seqhi, end)
        /* Last octet inside other's window space */
        && SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))
        /* Retrans: not more than one window back */
        && (ackskew >= -MAXACKWINDOW)
        /* Acking not more than one reassembled fragment backwards */
        && (ackskew <= (MAXACKWINDOW << sws))
        /* Acking not more than one window forward */
        && ((tcp_flags & TCP_RST) == 0 || orig_seq == src->seqlo
            || (orig_seq == src->seqlo + 1) || (orig_seq + 1 == src->seqlo))) {
        /* Require an exact/+1 sequence match on resets when possible */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /* update states */
        if (tcp_flags & TCP_SYN && src->state < TCPS_SYN_SENT) {
                src->state = TCPS_SYN_SENT;
        }
        if (tcp_flags & TCP_FIN && src->state < TCPS_CLOSING) {
                src->state = TCPS_CLOSING;
        }
        if (tcp_flags & TCP_ACK) {
            if (dst->state == TCPS_SYN_SENT) {
                dst->state = TCPS_ESTABLISHED;
            } else if (dst->state == TCPS_CLOSING) {
                dst->state = TCPS_FIN_WAIT_2;
            }
        }
        if (tcp_flags & TCP_RST) {
            src->state = dst->state = TCPS_TIME_WAIT;
        }

        /* XXX properly update expire time, based on state */
        conn->up.expiration = now + 30 * 1000;

        if (src->state >= TCPS_FIN_WAIT_2 && dst->state >= TCPS_FIN_WAIT_2) {
            update_expiration(conn, now, 30 * 1000);
        } else if (src->state >= TCPS_CLOSING && dst->state >= TCPS_CLOSING) {
            update_expiration(conn, now, 45 * 1000);
        } else if (src->state < TCPS_ESTABLISHED
                   || dst->state < TCPS_ESTABLISHED) {
            update_expiration(conn, now, 30 * 1000);
        } else if (src->state >= TCPS_CLOSING || dst->state >= TCPS_CLOSING) {
            update_expiration(conn, now, 15 * 60 * 1000);
        } else {
            update_expiration(conn, now, 24 * 60 * 60 * 1000);
        }
    } else if ((dst->state < TCPS_SYN_SENT
                || dst->state >= TCPS_FIN_WAIT_2
                || src->state >= TCPS_FIN_WAIT_2)
               && SEQ_GEQ(src->seqhi + MAXACKWINDOW, end)
               /* Within a window forward of the originating packet */
               && SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW)) {
               /* Within a window backward of the originating packet */

        /*
         * This currently handles three situations:
         *  1) Stupid stacks will shotgun SYNs before their peer
         *     replies.
         *  2) When PF catches an already established stream (the
         *     firewall rebooted, the state table was flushed, routes
         *     changed...)
         *  3) Packets get funky immediately after the connection
         *     closes (this should catch Solaris spurious ACK|FINs
         *     that web servers like to spew after a close)
         *
         * This must be a little more careful than the above code
         * since packet floods will also be caught here. We don't
         * update the TTL here to mitigate the damage of a packet
         * flood and so the same code can handle awkward establishment
         * and a loosened connection close.
         * In the establishment case, a correct peer response will
         * validate the connection, go through the normal state code
         * and keep updating the state TTL.
         */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /*
         * Cannot set dst->seqhi here since this could be a shotgunned
         * SYN and not an already established connection.
         */

        if (tcp_flags & TCP_FIN && src->state < TCPS_CLOSING) {
                src->state = TCPS_CLOSING;
        }

        if (tcp_flags & TCP_RST) {
            src->state = dst->state = TCPS_TIME_WAIT;
        }
    } else {
        return false;
    }

    return true;
}

static bool
tcp_valid_new(struct dp_packet *pkt)
{
    struct tcp_header *tcp = dp_packet_l4(pkt);
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    if (tcp_totally_invalid(tcp_flags)) {
        return false;
    }

    /* A syn+ack is not allowed to create a connection.  We want to allow
     * totally new connections (syn) or already established, not partially
     * open (syn+ack). */
    if ((tcp_flags & TCP_SYN) && (tcp_flags & TCP_ACK)) {
        return false;
    }

    return true;
}

static struct conn *
tcp_new_conn(struct dp_packet *pkt, long long now)
{
    struct conn_tcp* newconn = NULL;
    struct tcp_header *tcp = dp_packet_l4(pkt);
    struct tcp_peer *src, *dst;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    newconn = xzalloc(sizeof(struct conn_tcp));

    src = &newconn->peer[0];
    dst = &newconn->peer[1];

    src->seqlo = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    /* XXX ugly */
    src->seqhi = src->seqlo + (char *) dp_packet_get_tcp_payload(pkt)
                 - (char *) dp_packet_tail(pkt) + 1;

    if (tcp_flags & TCP_SYN) {
        src->seqhi++;
        src->wscale = tcp_get_wscale(tcp);
    }
    src->max_win = MAX(ntohs(tcp->tcp_winsz), 1);
    /* XXX ugly (and maybe unnecessary) */
    if (src->wscale & CT_WSCALE_MASK) {
        /* Remove scale factor from initial window */
        int win = src->max_win;
        win += 1 << (src->wscale & CT_WSCALE_MASK);
        src->max_win = (win - 1) >>
            (src->wscale & CT_WSCALE_MASK);
    }
    if (tcp_flags & TCP_FIN) {
        src->seqhi++;
    }
    dst->seqhi = 1;
    dst->max_win = 1;
    src->state = TCPS_SYN_SENT;
    dst->state = TCPS_CLOSED;

    update_expiration(newconn, now, 30 * 1000);

    return &newconn->up;
}

struct ct_l4_proto ct_proto_tcp = {
    .new_conn = tcp_new_conn,
    .valid_new = tcp_valid_new,
    .conn_update = tcp_conn_update,
};
