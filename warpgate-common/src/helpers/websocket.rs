use std::future::Future;

use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use poem::web::websocket::Message;
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

/// Bidirectional WS pump that decouples reading from writing.
///
/// The source is drained continuously by a dedicated reader task (pushing into
/// an in-process mpsc channel), while a writer task forwards messages from that
/// channel into the sink. This avoids the WS protocol violation that occurs
/// when source.next() is paused while sink.send() awaits — tokio_tungstenite
/// requires the source to be polled at all times to keep its internal frame
/// state machine healthy. The original sequential implementation
/// (`while let Some(msg) = source.next().await { sink.send(msg).await?; }`)
/// permanently jammed source.next() under sustained bidirectional traffic
/// (cove lobby/terminal repro: WS keystrokes silently lost after ~30–200
/// frames; both endpoints showed "OPEN" but no further bytes flowed through).
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
    // Unbounded channel: tx.send() never awaits, so the reader's drive
    // (`try_for_each`) is guaranteed to keep polling source at full speed
    // regardless of how slow the writer's sink.send() is. A bounded channel
    // re-creates the protocol violation as soon as the channel fills.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<DM>();

    // Reader: `try_for_each` continuously drives source.next() and runs the
    // closure synchronously (no `.await` between source polls). We hand the
    // converted message to the unbounded channel — `tx.send` is sync. This
    // matches the snapview/tokio-tungstenite chat-server example pattern.
    let reader = async move {
        source
            .map_err(anyhow::Error::from)
            .try_for_each(|msg| {
                let m = msg.to_tungstenite_message();
                let fut = callback(m);
                let tx = tx.clone();
                async move {
                    let m = fut.await.map_err(anyhow::Error::from)?;
                    let _ = tx.send(DM::from_tungstenite_message(m));
                    Ok::<_, anyhow::Error>(())
                }
            })
            .await?;
        tracing::debug!(target: "ws_pump", label = instr_label, "source ended");
        Ok::<_, anyhow::Error>(())
    };

    // Writer: forward channel into sink. `forward` polls both sink and
    // source-side concurrently within a single combinator, mirroring upstream.
    let writer = async move {
        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        stream
            .map(Ok::<_, anyhow::Error>)
            .forward(sink.sink_map_err(anyhow::Error::from))
            .await?;
        tracing::debug!(target: "ws_pump", label = instr_label, "writer drained");
        Ok::<_, anyhow::Error>(())
    };

    // Run reader and writer concurrently in dedicated tasks. Reader naturally
    // ends on source EOF/error; dropping its tx then ends the writer once the
    // channel drains. If either task panics or returns an error, propagate.
    let reader_task = tokio::spawn(reader);
    let writer_task = tokio::spawn(writer);
    reader_task.await??;
    writer_task.await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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

        // 1000 source messages — any internal bounded channel with capacity
        // less than this would re-introduce the bug (tx.send().await would
        // block once the channel fills, pausing source.next() and violating
        // the WS protocol invariant). The fix must use an unbounded queue so
        // the reader is never throttled by the writer.
        const N: u32 = 1000;

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
        let (sink_tx, mut sink_rx) =
            futures::channel::mpsc::channel::<tungstenite::Message>(1);
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

        // Within 100ms, the reader task should have drained the entire source
        // (1000 messages) into its unbounded queue, even though the sink will
        // take ~10s to actually consume them. Any bounded channel under 1000
        // would jam the source somewhere short of the full N.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let count = drained.load(Ordering::SeqCst);
        handle.abort();
        let _ = handle.await;

        assert_eq!(
            count as u32, N,
            "source must drain fully ({N} expected) regardless of sink speed; only {count} drained in 100ms"
        );
    }
}
