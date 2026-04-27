use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use poem::web::websocket::Message;
use tokio::sync::mpsc::error::TrySendError;
use tokio_tungstenite::tungstenite::{self, Utf8Bytes};

pub trait TungsteniteCompatibleWebsocketMessage {
    fn to_tungstenite_message(self) -> tungstenite::Message;
    fn from_tungstenite_message(m: tungstenite::Message) -> Self;
}

impl TungsteniteCompatibleWebsocketMessage for Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        match self {
            Self::Binary(data) => tungstenite::Message::Binary(data.into()),
            Self::Text(text) => tungstenite::Message::Text(text.into()),
            Self::Ping(data) => tungstenite::Message::Ping(data.into()),
            Self::Pong(data) => tungstenite::Message::Pong(data.into()),
            Self::Close(data) => {
                tungstenite::Message::Close(data.map(|data| tungstenite::protocol::CloseFrame {
                    code: u16::from(data.0).into(),
                    reason: Utf8Bytes::from(data.1),
                }))
            }
        }
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        match msg {
            tungstenite::Message::Binary(data) => Self::Binary(data.to_vec()),
            tungstenite::Message::Text(text) => Self::Text(text.to_string()),
            tungstenite::Message::Ping(data) => Self::Ping(data.to_vec()),
            tungstenite::Message::Pong(data) => Self::Pong(data.to_vec()),
            tungstenite::Message::Close(data) => {
                Self::Close(data.map(|data| (u16::from(data.code).into(), data.reason.to_string())))
            }
            tungstenite::Message::Frame(_) => unreachable!(),
        }
    }
}

impl TungsteniteCompatibleWebsocketMessage for reqwest_websocket::Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        match self {
            Self::Binary(data) => tungstenite::Message::Binary(data),
            Self::Text(text) => tungstenite::Message::Text(Utf8Bytes::from(text)),
            Self::Ping(data) => tungstenite::Message::Ping(data),
            Self::Pong(data) => tungstenite::Message::Pong(data),
            Self::Close { code, reason } => {
                tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                    code: u16::from(code).into(),
                    reason: Utf8Bytes::from(reason),
                }))
            }
        }
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        match msg {
            tungstenite::Message::Binary(data) => Self::Binary(data),
            tungstenite::Message::Text(text) => Self::Text(text.to_string()),
            tungstenite::Message::Ping(data) => Self::Ping(data),
            tungstenite::Message::Pong(data) => Self::Pong(data),
            tungstenite::Message::Close(data) => Self::Close {
                code: data
                    .as_ref()
                    .map_or(reqwest_websocket::CloseCode::Normal, |data| {
                        u16::from(data.code).into()
                    }),
                reason: data.map(|data| data.reason.to_string()).unwrap_or_default(),
            },
            tungstenite::Message::Frame(_) => unreachable!(),
        }
    }
}

impl TungsteniteCompatibleWebsocketMessage for tungstenite::Message {
    fn to_tungstenite_message(self) -> tungstenite::Message {
        self
    }

    fn from_tungstenite_message(msg: tungstenite::Message) -> Self {
        msg
    }
}

/// Upper bound on the pump's internal read→write queue, in *messages*.
///
/// The queue exists to decouple reading from writing (see [`pump_websocket`]),
/// but it must not be unbounded: on a multi-tenant gateway an untrusted peer
/// streaming frames at a stalled sink would otherwise grow a heap-resident
/// queue without limit. Handing a message to the queue never awaits, so the
/// source is still polled at line rate; a peer that runs more than this many
/// messages ahead of its sink has its pump torn down with an error rather than
/// being buffered indefinitely.
///
/// This caps the queue's per-item overhead and the number of frames a peer may
/// run ahead. It says nothing about how much memory those frames occupy — that
/// is [`PUMP_QUEUE_HIGH_WATER_BYTES`]'s job, and the two bounds are enforced
/// independently.
pub const PUMP_QUEUE_HIGH_WATER: usize = 4096;

/// Upper bound on the pump's internal read→write queue, in *payload bytes*.
///
/// A message count is not a memory bound. tungstenite's defaults accept frames
/// up to 16 MiB and messages up to 64 MiB, so 4096 queued messages can be
/// several gigabytes of heap — reachable by any authenticated user of the
/// gateway, since the hand-off to the queue never awaits and therefore never
/// slows the peer down. The queue is consequently bounded by bytes as well as
/// by count; whichever bound is reached first fails the pump.
///
/// 32 MiB is comfortably more than two maximum-size (16 MiB) frames, so a sink
/// that is merely slow is never killed for carrying legitimately large frames,
/// while a stalled pump is capped at 32 MiB (64 MiB for a bidirectional
/// connection, which runs two pumps) instead of being unbounded.
///
/// The accounting is a live gauge, not a running total: bytes are reserved
/// immediately before the hand-off and released as the writer takes each
/// message off the queue. A sink that keeps making progress therefore never
/// accumulates towards the bound — only a genuinely stalled one does.
pub const PUMP_QUEUE_HIGH_WATER_BYTES: usize = 32 << 20;

/// Bidirectional WS pump that decouples reading from writing.
///
/// The source is drained by a reader half that pushes into a bounded in-process
/// queue, while a writer half forwards that queue into the sink. Both halves run
/// concurrently *inside this future* (`tokio::try_join!`) — there are no
/// detached tasks, so dropping or aborting the returned future stops both halves
/// and drops `source` and `sink` immediately. Callers depend on that:
/// `proxy_ws_inner` tears pumps down with `JoinHandle::abort()`, and a detached
/// half would go on owning — and holding open — the peer's socket forever.
///
/// The decoupling avoids the WS protocol violation that occurs when
/// `source.next()` is paused while `sink.send()` awaits — tokio_tungstenite
/// requires the source to be polled at all times to keep its internal frame
/// state machine healthy. The original sequential implementation
/// (`while let Some(msg) = source.next().await { sink.send(msg).await?; }`)
/// permanently jammed `source.next()` under sustained bidirectional traffic
/// (cove lobby/terminal repro: WS keystrokes silently lost after ~30–200
/// frames; both endpoints showed "OPEN" but no further bytes flowed through).
///
/// Backpressure contract:
/// * The queue hand-off never awaits, so sink latency alone can never stop the
///   source being polled; overrunning either [`PUMP_QUEUE_HIGH_WATER`]
///   (messages) or [`PUMP_QUEUE_HIGH_WATER_BYTES`] (payload bytes) fails the
///   pump instead of buffering without bound. Both bounds are live gauges of
///   what is *currently* queued, so a slow-but-draining sink trips neither.
/// * `callback` **is** awaited between source polls, so a callback that blocks
///   does throttle the reader. The Kubernetes call sites push into a *bounded*
///   recorder channel with `.send().await`, so a lagging recorder pauses the
///   source there; a callback that must not throttle the pump has to be
///   non-blocking.
/// * Either half erroring fails the whole pump promptly: `try_join!` returns on
///   the first error and drops the other half, so a broken sink no longer lets
///   the reader drain on until the source EOFs.
pub async fn pump_websocket<
    DM: TungsteniteCompatibleWebsocketMessage + Send + 'static,
    D: Sink<DM> + Send + Unpin + 'static,
    SM: TungsteniteCompatibleWebsocketMessage + Send,
    SE: Send + 'static,
    S: Stream<Item = Result<SM, SE>> + Send + Unpin + 'static,
    FE: Send + 'static,
    F: FnMut(tungstenite::Message) -> Fut + Send + 'static,
    Fut: Future<Output = Result<tungstenite::Message, FE>> + Send + 'static,
>(
    source: S,
    sink: D,
    mut callback: F,
    instr_label: &'static str,
) -> anyhow::Result<()>
where
    anyhow::Error: From<D::Error> + From<SE> + From<FE>,
{
    // Each queued item carries its own payload size so the writer can release
    // the reservation without needing a length accessor on `DM`.
    let (tx, rx) = tokio::sync::mpsc::channel::<(DM, usize)>(PUMP_QUEUE_HIGH_WATER);

    // Live gauge of the bytes currently sitting in the queue. Reserved by the
    // reader before the hand-off, released by the writer on take.
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let queued_bytes_writer = queued_bytes.clone();

    // Reader: `try_for_each` continuously drives source.next(). The hand-off to
    // the writer is `try_send`, which never awaits, so a slow sink can never
    // pause the source. (`callback` is awaited — see the backpressure contract.)
    let reader = async move {
        source
            .map_err(anyhow::Error::from)
            .try_for_each(|msg| {
                let m = msg.to_tungstenite_message();
                let fut = callback(m);
                let tx = tx.clone();
                let queued_bytes = queued_bytes.clone();
                async move {
                    let m = fut.await.map_err(anyhow::Error::from)?;
                    // Size the message while it is still a tungstenite message.
                    // `DM::from_tungstenite_message` is a lossless re-wrap of
                    // the same payload, and none of the three concrete `DM`
                    // types at the call sites (`poem::web::websocket::Message`,
                    // `reqwest_websocket::Message`, `tungstenite::Message`)
                    // share a length accessor — so measure here rather than
                    // widening the trait.
                    let len = m.len();
                    if queued_bytes.fetch_add(len, Ordering::AcqRel) + len
                        > PUMP_QUEUE_HIGH_WATER_BYTES
                    {
                        queued_bytes.fetch_sub(len, Ordering::AcqRel);
                        anyhow::bail!(
                            "WebSocket pump queue exceeded its high-water mark of {PUMP_QUEUE_HIGH_WATER_BYTES} bytes; peer is outrunning a stalled sink"
                        );
                    }
                    tx.try_send((DM::from_tungstenite_message(m), len))
                        .map_err(|e| {
                            // The hand-off failed, so nothing was queued.
                            queued_bytes.fetch_sub(len, Ordering::AcqRel);
                            match e {
                                TrySendError::Full(_) => anyhow::anyhow!(
                                    "WebSocket pump queue exceeded its high-water mark of {PUMP_QUEUE_HIGH_WATER} messages; peer is outrunning a stalled sink"
                                ),
                                TrySendError::Closed(_) => {
                                    anyhow::anyhow!("WebSocket pump writer half has gone away")
                                }
                            }
                        })?;
                    Ok::<_, anyhow::Error>(())
                }
            })
            .await?;
        tracing::debug!(target: "ws_pump", label = instr_label, "source ended");
        Ok::<_, anyhow::Error>(())
    };

    // Writer: forward the queue into the sink. `forward` polls both the queue
    // and the sink within a single combinator, mirroring upstream.
    let writer = async move {
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        stream
            .map(move |(m, len)| {
                // Released on take: the gauge measures what is queued, not what
                // has ever passed through, so a draining sink stays under the
                // bound no matter how much traffic it carries.
                queued_bytes_writer.fetch_sub(len, Ordering::AcqRel);
                Ok::<_, anyhow::Error>(m)
            })
            .forward(sink.sink_map_err(anyhow::Error::from))
            .await?;
        tracing::debug!(target: "ws_pump", label = instr_label, "writer drained");
        Ok::<_, anyhow::Error>(())
    };

    // One future, two halves: cancelling this future cancels both, and the
    // first error tears the other down. The reader dropping its `tx` on source
    // EOF is what lets the writer finish draining and return.
    tokio::try_join!(reader, writer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    /// Regression test for browser→backend pump stall observed in cove-web /lobby/ws.
    ///
    /// Real-world symptom: while `sink.send(...).await` is awaiting downstream
    /// progress, the upstream `source.next().await` is NOT polled. tokio_tungstenite
    /// requires the source to be polled continuously — failing to do so violates the
    /// WS protocol invariant and causes `source.next()` to permanently jam.
    ///
    /// This test asserts that the pump drains its source independently of sink
    /// latency. Buggy serial implementation: only ~1 message drained while sink slow.
    /// Fixed implementation: all messages drained quickly, queued internally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_drains_source_concurrently_with_slow_sink() {
        let drained = Arc::new(AtomicUsize::new(0));

        // 1000 source messages of 4 bytes each — comfortably below both
        // `PUMP_QUEUE_HIGH_WATER` and `PUMP_QUEUE_HIGH_WATER_BYTES`, so neither
        // bound can fire and what is under test is purely that a slow sink
        // never throttles the reader. A pump that awaited the sink (or awaited
        // a queue slot) would drain only a handful in the window below.
        const N: u32 = 1000;
        const _: () = assert!(N as usize <= PUMP_QUEUE_HIGH_WATER);
        const _: () = assert!(N as usize * 4 <= PUMP_QUEUE_HIGH_WATER_BYTES);

        let drained_src = drained.clone();
        let source = futures::stream::iter(0..N)
            .inspect(move |_| {
                drained_src.fetch_add(1, Ordering::SeqCst);
            })
            .map(|i| {
                Ok::<_, anyhow::Error>(tungstenite::Message::Binary(
                    (i.to_le_bytes().to_vec()).into(),
                ))
            });

        // Sink: drained slowly (10ms per message). With N=1000, the sink
        // alone needs ≥10s to consume — far longer than our 100ms observation
        // window. Source must still drain promptly.
        let (sink_tx, mut sink_rx) = futures::channel::mpsc::channel::<tungstenite::Message>(1);
        tokio::spawn(async move {
            while let Some(_msg) = sink_rx.next().await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let pump = pump_websocket(
            source,
            sink_tx,
            |msg| async move { anyhow::Ok(msg) },
            "test",
        );
        let handle = tokio::spawn(pump);

        // Within 100ms, the reader should have drained the entire source
        // (1000 messages) into the queue, even though the sink will take ~10s
        // to actually consume them.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let count = drained.load(Ordering::SeqCst);
        handle.abort();
        let _ = handle.await;

        assert_eq!(
            count as u32, N,
            "source must drain fully ({N} expected) regardless of sink speed; only {count} drained in 100ms"
        );
    }

    /// The queue is bounded by message count. A peer that runs further than
    /// `PUMP_QUEUE_HIGH_WATER` ahead of a stalled sink has its pump failed
    /// rather than being buffered, so an untrusted client on one end of a
    /// multi-tenant gateway cannot grow an unbounded heap queue inside it.
    ///
    /// The messages here are 8 bytes, so the byte bound cannot fire: this
    /// pins the count bound specifically.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_fails_when_the_queue_high_water_mark_is_exceeded() {
        let source = futures::stream::iter(0..(PUMP_QUEUE_HIGH_WATER + 64)).map(|i| {
            Ok::<_, anyhow::Error>(tungstenite::Message::Binary(
                (i.to_le_bytes().to_vec()).into(),
            ))
        });

        // A sink that is never drained. `_sink_rx` is held alive on purpose: a
        // dropped receiver would fail the pump for the wrong reason.
        let (sink_tx, _sink_rx) = futures::channel::mpsc::channel::<tungstenite::Message>(1);

        let error = pump_websocket(
            source,
            sink_tx,
            |msg| async move { anyhow::Ok(msg) },
            "test",
        )
        .await
        .expect_err("pump must fail rather than buffer without bound");

        assert!(
            error.to_string().contains(&format!(
                "high-water mark of {PUMP_QUEUE_HIGH_WATER} messages"
            )),
            "expected the message-count bound to fire, got: {error}"
        );
    }

    /// A message count is not a memory bound: tungstenite accepts 16 MiB
    /// frames, so `PUMP_QUEUE_HIGH_WATER` messages can be gigabytes of heap.
    /// A peer feeding large messages at a stalled sink must therefore trip the
    /// *byte* bound while the count bound is still far away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_fails_on_the_byte_high_water_mark_before_the_count_mark() {
        const MESSAGE_BYTES: usize = 1 << 20;
        // Enough messages to reach the count bound if the byte bound did not
        // exist; `stream::iter` is lazy, so only those actually pulled are
        // allocated.
        const N: usize = PUMP_QUEUE_HIGH_WATER;
        const BUDGET: usize = PUMP_QUEUE_HIGH_WATER_BYTES / MESSAGE_BYTES;
        const _: () = assert!(BUDGET < N);

        let produced = Arc::new(AtomicUsize::new(0));
        let produced_src = produced.clone();
        let source = futures::stream::iter(0..N)
            .inspect(move |_| {
                produced_src.fetch_add(1, Ordering::SeqCst);
            })
            .map(|_| {
                Ok::<_, anyhow::Error>(tungstenite::Message::Binary(
                    vec![0u8; MESSAGE_BYTES].into(),
                ))
            });

        // A sink that is never drained. `_sink_rx` is held alive on purpose: a
        // dropped receiver would fail the pump for the wrong reason.
        let (sink_tx, _sink_rx) = futures::channel::mpsc::channel::<tungstenite::Message>(1);

        let error = pump_websocket(
            source,
            sink_tx,
            |msg| async move { anyhow::Ok(msg) },
            "test",
        )
        .await
        .expect_err("pump must fail rather than buffer without bound");

        assert!(
            error.to_string().contains(&format!(
                "high-water mark of {PUMP_QUEUE_HIGH_WATER_BYTES} bytes"
            )),
            "expected the byte bound to fire, got: {error}"
        );

        // The point of the byte bound: it fires while the count bound is still
        // orders of magnitude away. The slack covers the handful of messages
        // the writer has already taken off the queue into the sink's own
        // buffer by the time the reader trips.
        let produced = produced.load(Ordering::SeqCst);
        assert!(
            produced < N,
            "byte bound must fire before the count bound; {produced} of {N} messages drained"
        );
        assert!(
            produced <= BUDGET + 8,
            "queued {produced} messages of {MESSAGE_BYTES} B — more than the byte bound allows"
        );
    }

    /// Cancellation safety. `proxy_ws_inner` tears pumps down with
    /// `JoinHandle::abort()`, so aborting the pump must actually stop reading
    /// the peer and drop both WS halves. An implementation that `tokio::spawn`s
    /// its reader/writer detaches them: they keep running after the abort,
    /// holding the client socket open for as long as the peer keeps it alive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_the_pump_stops_both_halves() {
        let polled = Arc::new(AtomicUsize::new(0));

        // Endless source, one message per millisecond.
        let source = Box::pin(futures::stream::unfold(
            polled.clone(),
            |counter| async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                counter.fetch_add(1, Ordering::SeqCst);
                Some((
                    Ok::<_, anyhow::Error>(tungstenite::Message::Binary(vec![0u8].into())),
                    counter,
                ))
            },
        ));

        let (sink_tx, mut sink_rx) = futures::channel::mpsc::channel::<tungstenite::Message>(1);
        let sink_dropped = Arc::new(AtomicBool::new(false));
        let sink_dropped_observer = sink_dropped.clone();
        tokio::spawn(async move {
            while sink_rx.next().await.is_some() {}
            sink_dropped_observer.store(true, Ordering::SeqCst);
        });

        let handle = tokio::spawn(pump_websocket(
            source,
            sink_tx,
            |msg| async move { anyhow::Ok(msg) },
            "test",
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            polled.load(Ordering::SeqCst) > 0,
            "pump never started reading the source"
        );

        handle.abort();
        let _ = handle.await;
        let polled_at_abort = polled.load(Ordering::SeqCst);

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            polled.load(Ordering::SeqCst),
            polled_at_abort,
            "reader half kept draining the source after the pump was aborted"
        );
        assert!(
            sink_dropped.load(Ordering::SeqCst),
            "sink half was not dropped when the pump was aborted"
        );
    }
}
