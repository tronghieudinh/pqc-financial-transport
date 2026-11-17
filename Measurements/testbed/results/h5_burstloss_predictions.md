# G8 (draft): bursty packet loss against the independent-loss model (written 2026-11-11 18:49:25)

DRAFT: the authors must review the criteria below before this file is committed; after the push it is fixed.
Predictions: `h5_burstloss_predictions.csv` (sha256 b51f500e9cb04254429d4f10fbcf323ac92fad6cada2c7d423b20889773aadf7; `loss_sim.py` sha256 457a99bb7535d7fa43fcc33aa7786cd35421015901404467228aaf407b24f4ec).

**Design.** Full handshakes, mutual TLS, depth 2 and 3, RTT 30 ms, 100 Mbit/s, MTU 1500; mean loss 0.5, 1, 2 %; three arms: independent loss (netem `loss p%`),
Gilbert loss with mean burst 4 packets and with mean burst 16 packets (netem `loss gemodel`, all packets lost in the bad state, none in the good state, same mean rate).
n per configuration as run.sh (default 500; the tails need n >= 500).

**Prediction.** Independent-loss model: columns iid_* of the csv (transport time T - T_cpu).

**Criteria (DRAFT, to be fixed by the authors).**
* P1 (control): in the independent arm the measured mean is within 10 % of iid_mean_ms in at least 70 % of the configurations (the model's earlier result under loss was only loosely validated).
* P2: the measured p99 of the burst-4 arm is at least iid_p99_ms in at least 70 % of the configurations (bursts cannot make the tail shorter than independent loss at the same mean rate).
* P3 (exploratory): the gap measured p99 / iid_p99 grows from burst 4 to burst 16.
* Reports: the netem model's realised loss rate is checked from the client's retransmission counter; a configuration whose realised loss differs from the target by more than 30 % is reported, not used.


## Duyệt 2026-11-13 (tác giả)

**Status: APPROVED 2026-11-13 (author).** Các tiêu chí P1-P3 ở trên được tác giả duyệt NGUYÊN VĂN, chưa có số đo nào của kịch bản này; từ commit này chúng cố định. Mọi thay đổi sau này phải là một sửa đổi có ngày ở cuối tệp, làm TRƯỚC khi phân tích dữ liệu bị ảnh hưởng. Tệp dự đoán `h5_burstloss_predictions.csv` (sha256 b51f500e9cb04254429d4f10fbcf323ac92fad6cada2c7d423b20889773aadf7) không đổi so với commit af2afed. Dòng "DRAFT" ở đầu tệp được thay bằng mục này, không sửa nội dung tiêu chí.
