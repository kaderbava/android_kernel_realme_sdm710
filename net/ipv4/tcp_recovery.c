#include <linux/tcp.h>
#include <net/tcp.h>

int sysctl_tcp_recovery __read_mostly = TCP_RACK_LOST_RETRANS;

static void tcp_rack_mark_skb_lost(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_skb_mark_lost_uncond_verify(tp, skb);
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
		/* Account for retransmits that are lost again */
		TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
		tp->retrans_out -= tcp_skb_pcount(skb);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSTRETRANSMIT);
	}
}

/* Marks a packet lost, if some packet sent later has been (s)acked.
 * The underlying idea is similar to the traditional dupthresh and FACK
 * but they look at different metrics:
 *
 * dupthresh: 3 OOO packets delivered (packet count)
 * FACK: sequence delta to highest sacked sequence (sequence space)
 * RACK: sent time delta to the latest delivered packet (time domain)
 *
 * The advantage of RACK is it applies to both original and retransmitted
 * packet and therefore is robust against tail losses. Another advantage
 * is being more resilient to reordering by simply allowing some
 * "settling delay", instead of tweaking the dupthresh.
 *
 * The current version is only used after recovery starts but can be
 * easily extended to detect the first loss.
 */
static void tcp_rack_detect_loss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 min_rtt = tcp_min_rtt(tp);
	struct sk_buff *skb;
	u32 reo_wnd;

	/* To be more reordering resilient, allow min_rtt/4 settling delay
	 * (lower-bounded to 1000uS). We use min_rtt instead of the smoothed
	 * RTT because reordering is often a path property and less related
	 * to queuing or delayed ACKs.
	 *
	 * TODO: measure and adapt to the observed reordering delay, and
	 * use a timer to retransmit like the delayed early retransmit.
	 */
	reo_wnd = 1000;
	if (tp->rack.reord && min_rtt != ~0U) {
		reo_wnd = max((min_rtt >> 2) * tp->rack.reo_wnd_steps, reo_wnd);
		reo_wnd = min(reo_wnd, tp->srtt_us >> 3);
	}

	tcp_for_write_queue(skb, sk) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

		if (skb == tcp_send_head(sk))
			break;

		/* Skip ones already (s)acked */
		if (!after(scb->end_seq, tp->snd_una) ||
		    scb->sacked & TCPCB_SACKED_ACKED)
			continue;

		if (skb_mstamp_after(&tp->rack.mstamp, &skb->skb_mstamp)) {

			if (skb_mstamp_us_delta(&tp->rack.mstamp,
						&skb->skb_mstamp) <= reo_wnd)
				continue;

			/* skb is lost if packet sent later is sacked */
			tcp_rack_mark_skb_lost(sk, skb);
		} else if (!(scb->sacked & TCPCB_RETRANS)) {
			/* Original data are sent sequentially so stop early
			 * b/c the rest are all sent after rack_sent
			 */
			break;
		}
	}
}

void tcp_rack_mark_lost(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state < TCP_CA_Recovery || !tp->rack.advanced)
		return;
	/* Reset the advanced flag to avoid unnecessary queue scanning */
	tp->rack.advanced = 0;
	tcp_rack_detect_loss(sk);
}

/* Record the most recently (re)sent time among the (s)acked packets */
void tcp_rack_advance(struct tcp_sock *tp,
		      const struct skb_mstamp *xmit_time, u8 sacked)
{
	if (tp->rack.mstamp.v64 &&
	    !skb_mstamp_after(xmit_time, &tp->rack.mstamp))
		return;

	if (sacked & TCPCB_RETRANS) {
		struct skb_mstamp now;

		/* If the sacked packet was retransmitted, it's ambiguous
		 * whether the retransmission or the original (or the prior
		 * retransmission) was sacked.
		 *
		 * If the original is lost, there is no ambiguity. Otherwise
		 * we assume the original can be delayed up to aRTT + min_rtt.
		 * the aRTT term is bounded by the fast recovery or timeout,
		 * so it's at least one RTT (i.e., retransmission is at least
		 * an RTT later).
		 */
		skb_mstamp_get(&now);
		if (skb_mstamp_us_delta(&now, xmit_time) < tcp_min_rtt(tp))
			return;
	}

	tp->rack.mstamp = *xmit_time;
	tp->rack.advanced = 1;
}

/* Updates the RACK's reo_wnd based on DSACK and no. of recoveries.
 *
 * If DSACK is received, increment reo_wnd by min_rtt/4 (upper bounded
 * by srtt), since there is possibility that spurious retransmission was
 * due to reordering delay longer than reo_wnd.
 *
 * Persist the current reo_wnd value for TCP_RACK_RECOVERY_THRESH (16)
 * no. of successful recoveries (accounts for full DSACK-based loss
 * recovery undo). After that, reset it to default (min_rtt/4).
 *
 * At max, reo_wnd is incremented only once per rtt. So that the new
 * DSACK on which we are reacting, is due to the spurious retx (approx)
 * after the reo_wnd has been updated last time.
 *
 * reo_wnd is tracked in terms of steps (of min_rtt/4), rather than
 * absolute value to account for change in rtt.
 */
void tcp_rack_update_reo_wnd(struct sock *sk, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sysctl_tcp_recovery & TCP_RACK_STATIC_REO_WND ||
	    !rs->prior_delivered)
		return;

	/* Disregard DSACK if a rtt has not passed since we adjusted reo_wnd */
	if (before(rs->prior_delivered, tp->rack.last_delivered))
		tp->rack.dsack_seen = 0;

	/* Adjust the reo_wnd if update is pending */
	if (tp->rack.dsack_seen) {
		tp->rack.reo_wnd_steps = min_t(u32, 0xFF,
					       tp->rack.reo_wnd_steps + 1);
		tp->rack.dsack_seen = 0;
		tp->rack.last_delivered = tp->delivered;
		tp->rack.reo_wnd_persist = TCP_RACK_RECOVERY_THRESH;
	} else if (!tp->rack.reo_wnd_persist) {
		tp->rack.reo_wnd_steps = 1;
	}
}
