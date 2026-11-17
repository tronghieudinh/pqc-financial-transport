# G7 (draft): predictions for RTT below 1 ms, with and without background load (written 2026-11-11 18:48:22)

DRAFT: the authors must review the criteria below before this file is committed; after the push it is fixed.
Predictions: `h5_lowrtt_predictions.csv` (sha256 e21bae7706f72e1e7fb1e20eb44873a5e348fa0c35ba1ef19e734e6700749b78; `pqc_sim.py` sha256 2cc467c561681e276d6a2bd31229a8cdc5f9782dac3b20eabcd35a8fb24d3d7d).

**Question.** Does the model's count of extra round trips still hold when a round trip is 0.1-2 ms, i.e. when timer resolution, softirq scheduling and CPU contention are of the same size as the RTT?

**Measured quantity.** Excess latency = median time of a shaped configuration minus median time of the unshaped base of the same suite, depth and mTLS mode (as in Paper 1). n per configuration as run.sh (default 30), two arms: no background load, and 50 % duty background load on three CPUs that the testbed does not use.

**Criteria (DRAFT, to be fixed by the authors).**
* P1: with no background load, the stack model's excess latency is within 0.5 ms of the measured excess in at least 80 % of the configurations.
* P2: the number of extra round trips (measured excess / RTT, rounded) equals the model's in at least 80 % of the configurations with RTT >= 1 ms.
* P3 (exploratory): the background load raises the measured excess by less than 0.2 ms (median over configurations).
* A configuration whose base time exceeds 2 RTT is reported as CPU-dominated, not as a model failure.
**Not covered:** NIC and interrupt coalescing (virtual links only).


## Duyệt 2026-11-13 (tác giả)

**Status: APPROVED 2026-11-13 (author).** Các tiêu chí P1-P3 ở trên được tác giả duyệt NGUYÊN VĂN, chưa có số đo nào của kịch bản này; từ commit này chúng cố định. Mọi thay đổi sau này phải là một sửa đổi có ngày ở cuối tệp, làm TRƯỚC khi phân tích dữ liệu bị ảnh hưởng. Tệp dự đoán `h5_lowrtt_predictions.csv` (sha256 e21bae7706f72e1e7fb1e20eb44873a5e348fa0c35ba1ef19e734e6700749b78) không đổi so với commit af2afed. Dòng "DRAFT" ở đầu tệp được thay bằng mục này, không sửa nội dung tiêu chí.
