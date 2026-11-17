# Dự đoán đã đăng ký: IPv4 và offload trên testbed (Paper 1), 2026-11-15
Cố định TRƯỚC khi đo (commit và push trước). Dữ liệu: `ipv4_offload_predictions.csv` (do `ipv4_offload_predict.py` ghi). Mô hình: stack model (kiểm tra cửa sổ của Linux + mẫu ghi của OpenSSL); excess = T - T_cpu.

## Thí nghiệm A, `ipv4_flip` (14 cấu hình, X250, 7.0.0-42, Reno, quickack, không timestamp, offload tắt)
`results/ipv4_flip_configs.csv`: ECDSA-P256 độ sâu 2 với phản hồi 14 000 / 14 400 / 14 500 / 15 000 B hoặc yêu cầu 11 000 / 11 500 / 11 600 / 12 000 B; ML-DSA-65 độ sâu 1 với phản hồi 22 500 / 23 000 / 23 100 / 23 200 / 23 300 / 24 000 B; RTT 30 ms, 100 Mbit/s, MTU 1 500, icw 10, mTLS.
Với IPv4 tiêu đề là 40 B thay vì 60 B (MSS 1 460 thay vì 1 440): mô hình dự đoán ÍT HƠN MỘT RTT (-28 đến -29 ms) ở 8 ô "flip" (phản hồi 14 400, 14 500, 23 000 đến 23 300 B; yêu cầu 11 500, 11 600 B) và không đổi (|d| < 0,2 ms) ở 6 ô đối chứng.
Đo mỗi cấu hình với IPv6 và với IPv4 (PQC_IP=4), n = 30.
- IPv4-F1: ở 8 ô flip, excess đo IPv4 trừ excess đo IPv6 nằm trong khoảng -35 đến -22 ms ở >= 7 trên 8 ô.
- IPv4-F2: ở 6 ô đối chứng, |IPv4 - IPv6| <= 3 ms ở >= 5 trên 6 ô.
- IPv4-F3: với mô hình tiêu đề 40 (IPv4), sai số tuyệt đối trung bình <= 2 ms trên 14 ô và 0 ô sai hơn 0,4 RTT.
Nếu F1 không đạt, ảnh hưởng của tiêu đề lên cửa sổ không theo phép tính số đoạn của mô hình.

## Thí nghiệm B, `offload` (24 cấu hình của `offload_configs.csv`, IPv6, Reno, quickack, không timestamp, offload BẬT: PQC_OFFLOAD=1)
Mô hình không có số hạng offload; dự đoán là mô hình của lần chạy chuẩn.
- OFF-1: trung vị |excess có offload - excess của lần chạy chuẩn X250 (7.0.0-42, replication)| <= 1 ms trên 24 cấu hình.
- OFF-2: mô hình không đổi không để lại cấu hình nào sai hơn 0,4 RTT.
- Thăm dò: bộ đếm đoạn (data_segs_out) khi có offload; nếu GSO gom đoạn, bộ đếm không còn khớp số đoạn của mô hình.
