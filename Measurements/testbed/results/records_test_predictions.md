# One write per TLS record: pre-registered test on full handshakes at MTU 1500 (records_test_predict.py, before the measurement)

| suite | depth | response (B) | model, one write per message (ms) | model, one write per record (ms) | difference | kind |
|---|---|---|---|---|---|---|
| ML-DSA-65 | 1 | 67500 | 125.71 | 125.78 | +0.1 | control |
| ML-DSA-65 | 1 | 67900 | 125.74 | 125.81 | +0.1 | control |
| ML-DSA-65 | 1 | 68300 | 125.78 | 152.13 | +26.4 | flip |
| ML-DSA-65 | 1 | 68500 | 125.79 | 152.15 | +26.4 | flip |
| ML-DSA-65 | 1 | 68700 | 125.81 | 152.16 | +26.4 | flip |
| ML-DSA-65 | 1 | 68900 | 125.82 | 152.18 | +26.4 | flip |
| ML-DSA-65 | 1 | 69300 | 152.14 | 152.21 | +0.1 | control |
| ML-DSA-65 | 1 | 69700 | 152.17 | 152.25 | +0.1 | control |
| ML-DSA-65 | 2 | 30400 | 153.38 | 153.38 | +0.0 | control |
| ML-DSA-65 | 2 | 30700 | 153.41 | 153.41 | +0.0 | control |
| ML-DSA-65 | 2 | 31000 | 153.43 | 180.98 | +27.6 | flip |
| ML-DSA-65 | 2 | 31200 | 153.45 | 181.0 | +27.6 | flip |
| ML-DSA-65 | 2 | 31400 | 153.46 | 181.02 | +27.6 | flip |
| ML-DSA-65 | 2 | 31500 | 153.47 | 181.02 | +27.6 | flip |
| ML-DSA-65 | 2 | 31900 | 180.99 | 181.06 | +0.1 | control |
| ML-DSA-65 | 2 | 32300 | 181.02 | 181.09 | +0.1 | control |
| ECDSA-P256 | 2 | 22500 | 121.21 | 121.21 | +0.0 | control |
| ECDSA-P256 | 2 | 31200 | 121.94 | 121.94 | +0.0 | control |
| ECDSA-P256 | 2 | 40000 | 122.67 | 122.67 | +0.0 | control |
| ECDSA-P256 | 2 | 68700 | 152.79 | 152.79 | +0.0 | control |

Flip cells: 8 (model with records one round trip above the model without). Controls: 12 (the two models agree within 1 ms).

Criteria (scored by analyze_records_test.py):
- R1 flip cells: the measured excess is closer to the model with records than to the model without it in at least 7 of 8.
- R2 accuracy of the model with records over all 20 cells: MAE at most 2.5 ms and no cell more than 0.4 RTT (12 ms) from it.
- R3 controls: at least 11 of 12 within 12 ms of the model (either).
- Rejection: if the model without records is closer in 5 or more of the 8 flip cells, the record explanation is rejected for full handshakes at MTU 1500 and the sentence of Paper 1 that offers it is withdrawn.
- Machine offsets of 1 to 3 ms do not matter for R1 (the two predictions differ by 26 to 28 ms).
