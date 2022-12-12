// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/core/congestion_control/bbr2_misc.h"

#include "gquiche/quic/core/congestion_control/bandwidth_sampler.h"
#include "gquiche/quic/core/quic_bandwidth.h"
#include "gquiche/quic/core/quic_time.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_flag_utils.h"
#include "gquiche/quic/platform/api/quic_flags.h"
#include "gquiche/quic/platform/api/quic_logging.h"

namespace quic {

RoundTripCounter::RoundTripCounter() : round_trip_count_(0) {}

void RoundTripCounter::OnPacketSent(QuicPacketNumber packet_number) {
  QUICHE_DCHECK(!last_sent_packet_.IsInitialized() ||
                last_sent_packet_ < packet_number);
  last_sent_packet_ = packet_number;
}

bool RoundTripCounter::OnPacketsAcked(QuicPacketNumber last_acked_packet) {
  if (!end_of_round_trip_.IsInitialized() ||
      last_acked_packet > end_of_round_trip_) {
    round_trip_count_++;
    end_of_round_trip_ = last_sent_packet_;
    return true;
  }
  return false;
}

void RoundTripCounter::RestartRound() {
  end_of_round_trip_ = last_sent_packet_;
}

MinRttFilter::MinRttFilter(QuicTime::Delta initial_min_rtt,
                           QuicTime initial_min_rtt_timestamp)
    : min_rtt_(initial_min_rtt),
      min_rtt_timestamp_(initial_min_rtt_timestamp) {}

void MinRttFilter::Update(QuicTime::Delta sample_rtt, QuicTime now) {
  if (sample_rtt < min_rtt_ || min_rtt_timestamp_ == QuicTime::Zero()) {
    min_rtt_ = sample_rtt;
    min_rtt_timestamp_ = now;
  }
}

void MinRttFilter::ForceUpdate(QuicTime::Delta sample_rtt, QuicTime now) {
  min_rtt_ = sample_rtt;
  min_rtt_timestamp_ = now;
}

Bbr2NetworkModel::Bbr2NetworkModel(const Bbr2Params* params,
                                   QuicTime::Delta initial_rtt,
                                   QuicTime initial_rtt_timestamp,
                                   float cwnd_gain, float pacing_gain,
                                   const BandwidthSampler* old_sampler)
    : params_(params),
      bandwidth_sampler_([](QuicRoundTripCount max_height_tracker_window_length,
                            const BandwidthSampler* old_sampler) {
        if (old_sampler != nullptr) {
          return BandwidthSampler(*old_sampler);
        }
        return BandwidthSampler(/*unacked_packet_map=*/nullptr,
                                max_height_tracker_window_length);
      }(params->initial_max_ack_height_filter_window, old_sampler)),
      min_rtt_filter_(initial_rtt, initial_rtt_timestamp),
      cwnd_gain_(cwnd_gain),
      pacing_gain_(pacing_gain),
      last_round_rtt_(QuicTime::Delta::Zero()),
      rtt_diff_(QuicTime::Delta::Zero()),
      pre_min_rtt_(QuicTime::Delta::Infinite()),
      pre_max_rtt_(QuicTime::Delta::Zero()),
      is_link_full_(false),
      rtt_weight_(1),
      extra_loss_threshold_(0),
      min_packet_lost_(0),
      is_update_min_packet_lost_(false),
      is_update_min_packet_lost_old_(false),
      is_use_bandwidth_list_(false),
      is_use_decrease_pacing_rate_by_rtt_(false),
      is_use_rtt_determine_congested_by_random_(false),
      update_packet_lost_range_time_(QuicTime::Delta::FromSeconds(2)),
      packet_lost_update_time_(QuicTime::Zero()) {}

void Bbr2NetworkModel::OnPacketSent(QuicTime sent_time,
                                    QuicByteCount bytes_in_flight,
                                    QuicPacketNumber packet_number,
                                    QuicByteCount bytes,
                                    HasRetransmittableData is_retransmittable) {
  // Updating the min here ensures a more realistic (0) value when flows exit
  // quiescence.
  if (bytes_in_flight < min_bytes_in_flight_in_round_) {
    min_bytes_in_flight_in_round_ = bytes_in_flight;
  }
  round_trip_counter_.OnPacketSent(packet_number);

  bandwidth_sampler_.OnPacketSent(sent_time, packet_number, bytes,
                                  bytes_in_flight, is_retransmittable);
}

void Bbr2NetworkModel::OnCongestionEventStart(
    QuicTime event_time, const AckedPacketVector& acked_packets,
    const LostPacketVector& lost_packets,
    Bbr2CongestionEvent* congestion_event,
    const Bbr2Mode mode) {
  const QuicByteCount prior_bytes_acked = total_bytes_acked();
  const QuicByteCount prior_bytes_lost = total_bytes_lost();

  congestion_event->event_time = event_time;
  congestion_event->end_of_round_trip =
      acked_packets.empty() ? false
                            : round_trip_counter_.OnPacketsAcked(
                                  acked_packets.rbegin()->packet_number);

  BandwidthSamplerInterface::CongestionEventSample sample =
      bandwidth_sampler_.OnCongestionEvent(event_time, acked_packets,
                                           lost_packets, MaxBandwidth(mode),
                                           bandwidth_lo(), RoundTripCount());

  if (sample.extra_acked == 0) {
    cwnd_limited_before_aggregation_epoch_ =
        congestion_event->prior_bytes_in_flight >= congestion_event->prior_cwnd;
  }

  if (sample.last_packet_send_state.is_valid) {
    congestion_event->last_packet_send_state = sample.last_packet_send_state;
  }

  // Avoid updating |max_bandwidth_filter_| if a) this is a loss-only event, or
  // b) all packets in |acked_packets| did not generate valid samples. (e.g. ack
  // of ack-only packets). In both cases, total_bytes_acked() will not change.
  if (prior_bytes_acked != total_bytes_acked()) {
    QUIC_LOG_IF(WARNING, sample.sample_max_bandwidth.IsZero())
        << total_bytes_acked() - prior_bytes_acked << " bytes from "
        << acked_packets.size()
        << " packets have been acked, but sample_max_bandwidth is zero.";
    congestion_event->sample_max_bandwidth = sample.sample_max_bandwidth;
    if (!sample.sample_is_app_limited ||
        sample.sample_max_bandwidth > MaxBandwidth(mode)) {
      if (is_use_bandwidth_list_) {
        max_bandwidth_list_filter_.Update(congestion_event->sample_max_bandwidth);
      } 
      if (!is_use_bandwidth_list_ || mode == Bbr2Mode::STARTUP) {
          max_bandwidth_filter_.Update(congestion_event->sample_max_bandwidth);
      }
    }
  }

  if (!sample.sample_rtt.IsInfinite()) {
    congestion_event->sample_min_rtt = sample.sample_rtt;
    min_rtt_filter_.Update(congestion_event->sample_min_rtt, event_time);
    if (is_use_rtt_determine_congested_by_random_) {
      int64_t gmin = 0;
      gmin = sample.sample_rtt.ToMicroseconds() - pre_min_rtt_.ToMicroseconds();
      pre_min_rtt_ = sample.sample_rtt;
      if (!sample.sample_max_rtt.IsZero()) {
        int64_t gmax = 0;
        gmax = sample.sample_max_rtt.ToMicroseconds() - pre_max_rtt_.ToMicroseconds();
        pre_max_rtt_ = sample.sample_max_rtt;
        if (!is_link_full_ && gmin > 0 && gmax <= 0) {
          is_link_full_ = true;
        } else if (is_link_full_ && ((gmin > 0 && gmax > 0)|| gmax < 0)) {
          is_link_full_ = false;
        }
      }
    }
  }

  congestion_event->bytes_acked = total_bytes_acked() - prior_bytes_acked;
  congestion_event->bytes_lost = total_bytes_lost() - prior_bytes_lost;
  bytes_send_in_round_ = total_bytes_sent() - bytes_send_in_prior_round_;

  float tmp_packet_lost = (float)congestion_event->bytes_lost / (float)(congestion_event->bytes_lost + congestion_event->bytes_acked) / 100;
  if ((is_update_min_packet_lost_old_) && ((min_packet_lost_ > tmp_packet_lost) || (event_time > packet_lost_update_time_))) {
    min_packet_lost_ = tmp_packet_lost;
  }
  if ((is_update_min_packet_lost_old_) && (event_time > packet_lost_update_time_)) {
    packet_lost_update_time_ = event_time + update_packet_lost_range_time_;
  }
  if (congestion_event->prior_bytes_in_flight >=
      congestion_event->bytes_acked + congestion_event->bytes_lost) {
    congestion_event->bytes_in_flight =
        congestion_event->prior_bytes_in_flight -
        congestion_event->bytes_acked - congestion_event->bytes_lost;
  } else {
    QUIC_LOG_FIRST_N(INFO, 1)
        << "prior_bytes_in_flight:" << congestion_event->prior_bytes_in_flight
        << " is smaller than the sum of bytes_acked:"
        << congestion_event->bytes_acked
        << " and bytes_lost:" << congestion_event->bytes_lost;
    congestion_event->bytes_in_flight = 0;
  }

  if (congestion_event->bytes_lost > 0) {
    bytes_lost_in_round_ += congestion_event->bytes_lost;
    loss_events_in_round_++;
  }

  if (congestion_event->bytes_acked > 0 &&
      congestion_event->last_packet_send_state.is_valid &&
      total_bytes_acked() >
          congestion_event->last_packet_send_state.total_bytes_acked) {
    QuicByteCount bytes_delivered =
        total_bytes_acked() -
        congestion_event->last_packet_send_state.total_bytes_acked;
    max_bytes_delivered_in_round_ =
        std::max(max_bytes_delivered_in_round_, bytes_delivered);
  }
  // TODO(ianswett) Consider treating any bytes lost as decreasing inflight,
  // because it's a sign of overutilization, not underutilization.
  if (congestion_event->bytes_in_flight < min_bytes_in_flight_in_round_) {
    min_bytes_in_flight_in_round_ = congestion_event->bytes_in_flight;
  }

  // |bandwidth_latest_| and |inflight_latest_| only increased within a round.
  if (sample.sample_max_bandwidth > bandwidth_latest_) {
    bandwidth_latest_ = sample.sample_max_bandwidth;
  }

  if (sample.sample_max_inflight > inflight_latest_) {
    inflight_latest_ = sample.sample_max_inflight;
  }

  // Adapt lower bounds(bandwidth_lo and inflight_lo).
  AdaptLowerBounds(*congestion_event, mode);

  if (!congestion_event->end_of_round_trip) {
    return;
  }

  if (!sample.sample_max_bandwidth.IsZero()) {
    bandwidth_latest_ = sample.sample_max_bandwidth;
  }

  if (!sample.sample_rtt.IsInfinite() && is_use_decrease_pacing_rate_by_rtt_) {
    rtt_diff_ = min_rtt_filter_.Get() - sample.sample_rtt;
    last_round_rtt_ = sample.sample_rtt;
    if (rtt_diff_.ToMicroseconds() < 0) {
      rtt_weight_ = 1 + (rtt_diff_.ToMicroseconds() / sample.sample_rtt.ToMicroseconds());
    } 
  }

  if (sample.sample_max_inflight > 0) {
    inflight_latest_ = sample.sample_max_inflight;
  }
}

void Bbr2NetworkModel::AdaptLowerBounds(
    const Bbr2CongestionEvent& congestion_event,
    const Bbr2Mode mode) {
  if (Params().bw_lo_mode_ == Bbr2Params::DEFAULT) {
    if (!congestion_event.end_of_round_trip ||
        congestion_event.is_probing_for_bandwidth) {
      return;
    }

    if (bytes_lost_in_round_ > 0) {
      if (bandwidth_lo_.IsInfinite()) {
        bandwidth_lo_ = MaxBandwidth(mode);
      }
      bandwidth_lo_ =
          std::max(bandwidth_latest_, bandwidth_lo_ * (1.0 - Params().beta));
      QUIC_DVLOG(3) << "bandwidth_lo_ updated to " << bandwidth_lo_
                    << ", bandwidth_latest_ is " << bandwidth_latest_;

      if (Params().ignore_inflight_lo) {
        return;
      }
      if (inflight_lo_ == inflight_lo_default()) {
        inflight_lo_ = congestion_event.prior_cwnd;
      }
      inflight_lo_ = std::max<QuicByteCount>(
          inflight_latest_, inflight_lo_ * (1.0 - Params().beta));
    }
    return;
  }

  // Params().bw_lo_mode_ != Bbr2Params::DEFAULT
  if (congestion_event.bytes_lost == 0) {
    return;
  }
  // Ignore losses from packets sent when probing for more bandwidth in
  // STARTUP or PROBE_UP when they're lost in DRAIN or PROBE_DOWN.
  if (pacing_gain_ < 1) {
    return;
  }
  // Decrease bandwidth_lo whenever there is loss.
  // Set bandwidth_lo_ if it is not yet set.
  if (bandwidth_lo_.IsInfinite()) {
    bandwidth_lo_ = MaxBandwidth(mode);
  }
  // Save bandwidth_lo_ if it hasn't already been saved.
  if (prior_bandwidth_lo_.IsZero()) {
    prior_bandwidth_lo_ = bandwidth_lo_;
  }
  switch (Params().bw_lo_mode_) {
    case Bbr2Params::MIN_RTT_REDUCTION:
      bandwidth_lo_ =
          bandwidth_lo_ - QuicBandwidth::FromBytesAndTimeDelta(
                              congestion_event.bytes_lost, MinRtt());
      break;
    case Bbr2Params::INFLIGHT_REDUCTION: {
      // Use a max of BDP and inflight to avoid starving app-limited flows.
      const QuicByteCount effective_inflight =
          std::max(BDP(mode), congestion_event.prior_bytes_in_flight);
      // This could use bytes_lost_in_round if the bandwidth_lo_ was saved
      // when entering 'recovery', but this BBRv2 implementation doesn't have
      // recovery defined.
      bandwidth_lo_ =
          bandwidth_lo_ * ((effective_inflight - congestion_event.bytes_lost) /
                           static_cast<double>(effective_inflight));
      break;
    }
    case Bbr2Params::CWND_REDUCTION:
      bandwidth_lo_ =
          bandwidth_lo_ *
          ((congestion_event.prior_cwnd - congestion_event.bytes_lost) /
           static_cast<double>(congestion_event.prior_cwnd));
      break;
    case Bbr2Params::DEFAULT:
      QUIC_BUG(quic_bug_10466_1) << "Unreachable case DEFAULT.";
  }
  QuicBandwidth last_bandwidth = bandwidth_latest_;
  // sample_max_bandwidth will be Zero() if the loss is triggered by a timer
  // expiring.  Ideally we'd use the most recent bandwidth sample,
  // but bandwidth_latest is safer than Zero().
  if (!congestion_event.sample_max_bandwidth.IsZero()) {
    // bandwidth_latest_ is the max bandwidth for the round, but to allow
    // fast, conservation style response to loss, use the last sample.
    last_bandwidth = congestion_event.sample_max_bandwidth;
  }
  if (pacing_gain_ > Params().startup_full_bw_threshold) {
    // In STARTUP, pacing_gain_ is applied to bandwidth_lo_ in
    // UpdatePacingRate, so this backs that multiplication out to allow the
    // pacing rate to decrease, but not below
    // last_bandwidth * startup_full_bw_threshold.
    // TODO(ianswett): Consider altering pacing_gain_ when in STARTUP instead.
    bandwidth_lo_ = std::max(
        bandwidth_lo_,
        last_bandwidth * (Params().startup_full_bw_threshold / pacing_gain_));
  } else {
    // Ensure bandwidth_lo isn't lower than last_bandwidth.
    bandwidth_lo_ = std::max(bandwidth_lo_, last_bandwidth);
  }
  // If it's the end of the round, ensure bandwidth_lo doesn't decrease more
  // than beta.
  if (congestion_event.end_of_round_trip) {
    bandwidth_lo_ =
        std::max(bandwidth_lo_, prior_bandwidth_lo_ * (1.0 - Params().beta));
    prior_bandwidth_lo_ = QuicBandwidth::Zero();
  }
  // These modes ignore inflight_lo as well.
}

void Bbr2NetworkModel::OnCongestionEventFinish(
    QuicPacketNumber least_unacked_packet,
    const Bbr2CongestionEvent& congestion_event) {
  if (congestion_event.end_of_round_trip) {
    OnNewRound(congestion_event.event_time);
  }

  bandwidth_sampler_.RemoveObsoletePackets(least_unacked_packet);
}

void Bbr2NetworkModel::UpdateNetworkParameters(QuicTime::Delta rtt) {
  if (!rtt.IsZero()) {
    min_rtt_filter_.Update(rtt, MinRttTimestamp());
  }
}

bool Bbr2NetworkModel::MaybeExpireMinRtt(
    const Bbr2CongestionEvent& congestion_event) {
  if (congestion_event.event_time <
      (MinRttTimestamp() + Params().probe_rtt_period)) {
    return false;
  }
  if (congestion_event.sample_min_rtt.IsInfinite()) {
    return false;
  }
  QUIC_DVLOG(3) << "Replacing expired min rtt of " << min_rtt_filter_.Get()
                << " by " << congestion_event.sample_min_rtt << "  @ "
                << congestion_event.event_time;
  min_rtt_filter_.ForceUpdate(congestion_event.sample_min_rtt,
                              congestion_event.event_time);
  return true;
}

bool Bbr2NetworkModel::IsInflightTooHigh(
    const Bbr2CongestionEvent& congestion_event,
    int64_t max_loss_events) const {
  const SendTimeState& send_state = congestion_event.last_packet_send_state;
  if (!send_state.is_valid) {
    // Not enough information.
    return false;
  }

  if (loss_events_in_round() < max_loss_events) {
    return false;
  }

  if (is_use_rtt_determine_congested_by_random_) {
    if (is_link_full_) {
      return true;
    } else {
      return false;
    }
  }

  const QuicByteCount inflight_at_send = BytesInFlight(send_state);
  // TODO(wub): Consider total_bytes_lost() - send_state.total_bytes_lost, which
  // is the total bytes lost when the largest numbered packet was inflight.
  // bytes_lost_in_round_, OTOH, is the total bytes lost in the "current" round.
  const QuicByteCount bytes_lost_in_round = bytes_lost_in_round_;

  QUIC_DVLOG(3) << "IsInflightTooHigh: loss_events_in_round:"
                << loss_events_in_round()

                << " bytes_lost_in_round:" << bytes_lost_in_round
                << ", lost_in_round_threshold:"
                << inflight_at_send * Params().loss_threshold;

  if (inflight_at_send > 0 && bytes_lost_in_round > 0) {
    QuicByteCount lost_in_round_threshold;
    if (is_update_min_packet_lost_) {
      lost_in_round_threshold = inflight_at_send * (Params().loss_threshold + extra_loss_threshold_ + 1.3 * min_packet_lost_list_filter_.Get());
    } else if (is_update_min_packet_lost_old_) {
      lost_in_round_threshold = inflight_at_send * (Params().loss_threshold + extra_loss_threshold_ + min_packet_lost_);
    } else {
      lost_in_round_threshold = inflight_at_send * (Params().loss_threshold + extra_loss_threshold_);
    }
    if (bytes_lost_in_round > lost_in_round_threshold) {
      return true;
    }
  }

  return false;
}

void Bbr2NetworkModel::RestartRoundEarly(QuicTime now) {
  OnNewRound(now);
  round_trip_counter_.RestartRound();
}

void Bbr2NetworkModel::OnNewRound(QuicTime now) {
  float tmp_packet_lost = bytes_send_in_round_ == 0 ? 0 :(float)bytes_lost_in_round_ / (float)(bytes_send_in_round_);
  if ((is_update_min_packet_lost_) && (now > packet_lost_update_time_)) {
    min_packet_lost_list_filter_.Advance();
    packet_lost_update_time_ = now + update_packet_lost_range_time_;
  }
  if (is_update_min_packet_lost_) {
    min_packet_lost_list_filter_.Update(tmp_packet_lost);
  }
  bytes_lost_in_round_ = 0;
  loss_events_in_round_ = 0;
  bytes_send_in_prior_round_ = total_bytes_sent();
  bytes_send_in_round_ = 0;
  max_bytes_delivered_in_round_ = 0;
  min_bytes_in_flight_in_round_ = std::numeric_limits<uint64_t>::max();
}

void Bbr2NetworkModel::cap_inflight_lo(QuicByteCount cap) {
  if (Params().ignore_inflight_lo) {
    return;
  }
  if (inflight_lo_ != inflight_lo_default() && inflight_lo_ > cap) {
    inflight_lo_ = cap;
  }
}

QuicByteCount Bbr2NetworkModel::inflight_hi_with_headroom() const {
  QuicByteCount headroom = inflight_hi_ * Params().inflight_hi_headroom;

  return inflight_hi_ > headroom ? inflight_hi_ - headroom : 0;
}

bool Bbr2NetworkModel::HasBandwidthGrowth(
    const Bbr2CongestionEvent& congestion_event,
    const Bbr2Mode mode) {
  QUICHE_DCHECK(!full_bandwidth_reached_);
  QUICHE_DCHECK(congestion_event.end_of_round_trip);

  QuicBandwidth threshold =
      full_bandwidth_baseline_ * Params().startup_full_bw_threshold;

  if (MaxBandwidth(mode) >= threshold) {
    QUIC_DVLOG(3) << " CheckBandwidthGrowth at end of round. max_bandwidth:"
                  << MaxBandwidth(mode) << ", threshold:" << threshold
                  << " (Still growing)  @ " << congestion_event.event_time;
    full_bandwidth_baseline_ = MaxBandwidth(mode);
    rounds_without_bandwidth_growth_ = 0;
    return true;
  }
  ++rounds_without_bandwidth_growth_;

  // full_bandwidth_reached is only set to true when not app-limited, except
  // when exit_startup_on_persistent_queue is true.
  if (rounds_without_bandwidth_growth_ >= Params().startup_full_bw_rounds &&
      !congestion_event.last_packet_send_state.is_app_limited) {
    full_bandwidth_reached_ = true;
  }
  QUIC_DVLOG(3) << " CheckBandwidthGrowth at end of round. max_bandwidth:"
                << MaxBandwidth(mode) << ", threshold:" << threshold
                << " rounds_without_growth:" << rounds_without_bandwidth_growth_
                << " full_bw_reached:" << full_bandwidth_reached_ << "  @ "
                << congestion_event.event_time;

  return false;
}

bool Bbr2NetworkModel::CheckPersistentQueue(
    const Bbr2CongestionEvent& congestion_event, float bdp_gain, const Bbr2Mode mode) {
  QUICHE_DCHECK(congestion_event.end_of_round_trip);
  QUICHE_DCHECK_NE(min_bytes_in_flight_in_round_,
                   std::numeric_limits<uint64_t>::max());
  QuicByteCount target = bdp_gain * BDP(mode);
  if (bdp_gain >= 2) {
    // Use a more conservative threshold for STARTUP because CWND gain is 2.
    if (target <= QueueingThresholdExtraBytes()) {
      return false;
    }
    target -= QueueingThresholdExtraBytes();
  } else {
    target += QueueingThresholdExtraBytes();
  }
  if (min_bytes_in_flight_in_round_ > target) {
    full_bandwidth_reached_ = true;
    return true;
  }
  return false;
}

void Bbr2MinPacketLostListFilter::Update(
    float sample) {
  if (min_packet_lost_queue_.size() < min_packet_lost_queue_size_) {
    min_packet_lost_.second.insert(sample);
    min_packet_lost_queue_.push(sample);
  } else {
    float tmp_pop_packet_lost = min_packet_lost_queue_.front();
    min_packet_lost_queue_.pop();
    auto it = min_packet_lost_.second.find(tmp_pop_packet_lost);
    if (it != min_packet_lost_.second.end()) {
      min_packet_lost_.second.erase(it);
    }
    min_packet_lost_.second.insert(sample);
    min_packet_lost_queue_.push(sample);
  }
}

void Bbr2MinPacketLostListFilter::Advance() {
  if (min_packet_lost_.second.size() == 0) {
    return;
  }
  min_packet_lost_.first.clear();
  min_packet_lost_.first.swap(min_packet_lost_.second);
  min_packet_lost_queue_ = std::queue<float>();
}

float Bbr2MinPacketLostListFilter::Get() const {
  auto it = min_packet_lost_.first.begin();
  for (int j =0; (it != min_packet_lost_.first.end() && j < (int)round(min_packet_lost_.first.size() * min_packet_lost_index_)); j++) {
    it++;
  }
  auto  min_packet_lost_first = it == min_packet_lost_.first.end() ? 0 : *it;

  it = min_packet_lost_.second.begin();
  for (int j =0; (it != min_packet_lost_.second.end() && j < (int)round(min_packet_lost_.second.size() * min_packet_lost_index_)); j++) {
    it++;
  }
  auto  min_packet_lost_second = it == min_packet_lost_.second.end() ? 0 : *it;

  return std::min(min_packet_lost_first, min_packet_lost_second);
}

void Bbr2MaxBandwidthListFilter::Update(
    QuicBandwidth sample) {
  if (max_bandwidth_queue_.size() < max_bandwidth_queue_size_) {
    max_bandwidth_.second.insert(sample);
    max_bandwidth_queue_.push(sample);
  } else {
    QuicBandwidth tmp_pop_bandwidth = max_bandwidth_queue_.front();
    max_bandwidth_queue_.pop();
    auto it = max_bandwidth_.second.find(tmp_pop_bandwidth);
    if (it != max_bandwidth_.second.end()) {
      max_bandwidth_.second.erase(it);
    }
    max_bandwidth_.second.insert(sample);
    max_bandwidth_queue_.push(sample);
  }
}

void Bbr2MaxBandwidthListFilter::Advance() {
  if (max_bandwidth_.second.size() == 0) {
    return;
  }
  max_bandwidth_.first.clear();
  max_bandwidth_.first.swap(max_bandwidth_.second);
  max_bandwidth_queue_ = std::queue<QuicBandwidth>();
}

QuicBandwidth Bbr2MaxBandwidthListFilter::Get() const {
  auto it = max_bandwidth_.first.rbegin();
    for (int j =0; (it != max_bandwidth_.first.rend()&& j < (int)round(max_bandwidth_.first.size() * max_bandwidth_index_)); j++) {
      it++;
    }
    auto  max_bandwidth_first = it == max_bandwidth_.first.rend() ? QuicBandwidth::Zero() : *it;

    it = max_bandwidth_.second.rbegin();
    for (int j =0; (it != max_bandwidth_.second.rend()&& j < (int)round(max_bandwidth_.second.size() * max_bandwidth_index_)); j++) {
      it++;
    }
    auto  max_bandwidth_second = it == max_bandwidth_.second.rend() ? QuicBandwidth::Zero() : *it;

    return std::max(max_bandwidth_first, max_bandwidth_second);
}
}  // namespace quic
