# Thiết lập tường lửa Iptables cho Linux
Tác giả: unknown
Ngày đăng: yyyy-mm-dd
Nguồn: http://unknown


<!-- MarkdownTOC -->

- [Phần I: Giới thiệu về Iptables](#phần-i-giới-thiệu-về-iptables)
    - [Cách đổi địa chỉ IP động (dynamic NAT)](#cách-đổi-địa-chỉ-ip-động-dynamic-nat)
    - [Cách đóng giả địa chỉ IP (masquerade)](#cách-đóng-giả-địa-chỉ-ip-masquerade)
    - [Cấu trúc của Iptables](#cấu-trúc-của-iptables)
    - [Quá trình chuyển gói dữ liệu qua Netfilter](#quá-trình-chuyển-gói-dữ-liệu-qua-netfilter)
    - [Các tham số dòng lệnh thường gặp của Iptables](#các-tham-số-dòng-lệnh-thường-gặp-của-iptables)
        - [1. Gọi trợ giúp](#1-gọi-trợ-giúp)
        - [2. Các tuỳ chọn để chỉ định thông số](#2-các-tuỳ-chọn-để-chỉ-định-thông-số)
        - [3. Các tuỳ chọn để thao tác với chain](#3-các-tuỳ-chọn-để-thao-tác-với-chain)
        - [4. Các tuỳ chọn để thao tác với luật](#4-các-tuỳ-chọn-để-thao-tác-với-luật)
    - [Phân biệt giữa ACCEPT, DROP và REJECT packet](#phân-biệt-giữa-accept-drop-và-reject-packet)
    - [Phân biệt giữa NEW, ESTABLISHED và RELATED](#phân-biệt-giữa-new-established-và-related)
    - [Tuỳ chọn `--limit`, `--limit-burst`](#tuỳ-chọn---limit---limit-burst)
    - [Redirect cổng](#redirect-cổng)
    - [SNAT & MASQUERADE](#snat--masquerade)
    - [DNAT](#dnat)
- [Phần II: Lập cấu hình Iptables cho máy chủ phục vụ Web](#phần-ii-lập-cấu-hình-iptables-cho-máy-chủ-phục-vụ-web)
    - [Bước 1: thiết lập các tham số cho nhân](#bước-1-thiết-lập-các-tham-số-cho-nhân)
    - [Bước 2: nạp các môđun cần thiết cho Iptables](#bước-2-nạp-các-môđun-cần-thiết-cho-iptables)
    - [Bước 3: nguyên tắc đặt luật là "drop trước, accept sau"](#bước-3-nguyên-tắc-đặt-luật-là-drop-trước-accept-sau)
    - [Bước 4: lọc ICMP vào và chặn ngập lụt PING](#bước-4-lọc-icmp-vào-và-chặn-ngập-lụt-ping)
    - [Bước 5: reject quét cổng TCP và UDP](#bước-5-reject-quét-cổng-tcp-và-udp)
    - [Bước 6: phát hiện quét cổng bằng Nmap](#bước-6-phát-hiện-quét-cổng-bằng-nmap)
    - [Bước 7: chặn ngập lụt SYN](#bước-7-chặn-ngập-lụt-syn)
    - [Bước 8: giới hạn truy cập SSH cho admin](#bước-8-giới-hạn-truy-cập-ssh-cho-admin)
    - [Bước 9: giới hạn FTP cho web-master](#bước-9-giới-hạn-ftp-cho-web-master)
    - [Bước 10: lọc TCP vào](#bước-10-lọc-tcp-vào)
    - [Bước 11: lọc UDP vào và chặn ngập lụt UDP](#bước-11-lọc-udp-vào-và-chặn-ngập-lụt-udp)

<!-- /MarkdownTOC -->

# Phần I: Giới thiệu về Iptables
Iptables là một tường lửa ứng dụng lọc gói dữ liệu rất mạnh, miễn phí và có sẵn trên Linux.. Netfilter/Iptables gồm 2 phần là Netfilter ở trong nhân Linux và Iptables nằm ngoài nhân. Iptables chịu trách nhiệm giao tiếp giữa người dùng và Netfilter để đẩy các luật của người dùng vào cho Netfiler xử lí. Netfilter tiến hành lọc các gói dữ liệu ở mức IP. Netfilter làm việc trực tiếp trong nhân, nhanh và không làm giảm tốc độ của hệ thống .


## Cách đổi địa chỉ IP động (dynamic NAT)
Trước khi đi vào phần chính, mình cần giới thiệu với các bạn về công nghệ đổi địa chỉ NAT động và đóng giả IP Masquerade. Hai từ này được dùng rất nhiều trong Iptables nên bạn phải biết. Nếu bạn đã biết NAT động và Masquerade, bạn có thể bỏ qua phần này.

NAT động là một trong những kĩ thuật chuyển đổi địa chỉ IP NAT (Network Address Translation). Các địa chỉ IP nội bộ được chuyển sang IP NAT như sau:

NAT Router đảm nhận việc chuyển dãy IP nội bộ 169.168.0.x sang dãy IP mới 203.162.2.x. Khi có gói liệu với IP nguồn là 192.168.0.200 đến router, router sẽ đổi IP nguồn thành 203.162.2.200 sau đó mới gởi ra ngoài. Quá trình này gọi là SNAT (Source-NAT, NAT nguồn). Router lưu dữ liệu trong một bảng gọi là bảng NAT động. Ngược lại, khi có một gói từ liệu từ gởi từ ngoài vào với IP đích là 203.162.2.200, router sẽ căn cứ vào bảng NAT động hiện tại để đổi địa chỉ đích 203.162.2.200 thành địa chỉ đích mới là 192.168.0.200. Quá trình này gọi là DNAT (Destination-NAT, NAT đích). Liên lạc giữa 192.168.0.200 và 203.162.2.200 là hoàn toàn trong suốt (transparent) qua NAT router. NAT router tiến hành chuyển tiếp (forward) gói dữ liệu từ 192.168.0.200 đến 203.162.2.200 và ngược lại.


## Cách đóng giả địa chỉ IP (masquerade)
Đây là một kĩ thuật khác trong NAT.

NAT Router chuyển dãy IP nội bộ 192.168.0.x sang một IP duy nhất là 203.162.2.4 bằng cách dùng các số hiệu cổng (port-number) khác nhau. Chẳng hạn khi có gói dữ liệu IP với nguồn 192.168.0.168:1204, đích 211.200.51.15:80 đến router, router sẽ đổi nguồn thành 203.162.2.4:26314 và lưu dữ liệu này vào một bảng gọi là bảng masquerade động. Khi có một gói dữ liệu từ ngoài vào với nguồn là 221.200.51.15:80, đích 203.162.2.4:26314 đến router, router sẽ căn cứ vào bảng masquerade động hiện tại để đổi đích từ 203.162.2.4:26314 thành 192.168.0.164:1204. Liên lạc giữa các máy trong mạng LAN với máy khác bên ngoài hoàn toàn trong suốt qua router.


## Cấu trúc của Iptables
Iptables được chia làm 4 bảng (table):

- bảng filter dùng để lọc gói dữ liệu,
- bảng nat dùng để thao tác với các gói dữ liệu được NAT nguồn hay NAT đích
- bảng mangle dùng để thay đổi các thông số trong gói IP
- bảng conntrack dùng để theo dõi các kết nối.

Mỗi table gồm nhiều mắc xích (chain). Chain gồm nhiều luật (rule) để thao tác với các gói dữ liệu. Rule có thể là ACCEPT (chấp nhận gói dữ liệu), DROP (thả gói), REJECT (loại bỏ gói) hoặc tham chiếu (reference) đến một chain khác.


## Quá trình chuyển gói dữ liệu qua Netfilter

Gói dữ liệu (packet) chạy trên chạy trên cáp, sau đó đi vào card mạng (chẳng hạn như eth0). Đầu tiên packet sẽ qua chain PREROUTING (trước khi định tuyến). Tại đây, packet có thể bị thay đổi thông số (mangle) hoặc bị đổi địa chỉ IP đích (DNAT). Đối với packet đi vào máy, nó sẽ qua chain INPUT. Tại chain INPUT, packet có thể được chấp nhận hoặc bị huỷ bỏ. Tiếp theo packet sẽ được chuyển lên cho các ứng dụng (client/server) xử lí và tiếp theo là được chuyển ra chain OUTPUT. Tại chain OUTPUT, packet có thể bị thay đổi các thông số và bị lọc chấp nhận ra hay bị huỷ bỏ. Đối với packet forward qua máy, packet sau khi rời chain PREROUTING sẽ qua chain FORWARD. Tại chain FORWARD, nó cũng bị lọc ACCEPT hoặc DENY. Packet sau khi qua chain FORWARD hoặc chain OUTPUT sẽ đến chain POSTROUTING (sau khi định tuyến). Tại chain POSTROUTING, packet có thể được đổi địa chỉ IP nguồn (SNAT) hoặc MASQUERADE. Packet sau khi ra card mạng sẽ được chuyển lên cáp để đi đến máy tính khác trên mạng.


## Các tham số dòng lệnh thường gặp của Iptables
### 1. Gọi trợ giúp
Để gọi trợ giúp về Iptables, bạn gõ lệnh `man iptables` hoặc `iptables --help`. Chẳng hạn nếu bạn cần biết về các tuỳ chọn của match limit, bạn gõ lệnh `iptables -m limit --help`.

### 2. Các tuỳ chọn để chỉ định thông số
- chỉ định tên table: `-t` , ví dụ `-t filter`, `-t nat`, .. nếu không chỉ định table, giá trị mặc định là filter

- chỉ đinh loại giao thức: `-p` , ví dụ `-p tcp`, `-p udp` hoặc `-p ! udp` để chỉ định các giao thức không phải là udp

- chỉ định card mạng vào: `-i` , ví dụ: `-i eth0`, `-i lo`

- chỉ định card mạng ra: `-o` , ví dụ: `-o eth0`, `-o pp0`

- chỉ định địa chỉ IP nguồn: `-s <địa_chỉ_ip_nguồn>`, ví dụ: `-s 192.168.0.0/24` (mạng 192.168.0 với 24 bít mạng), `-s 192.168.0.1-192.168.0.3` (các IP 192.168.0.1, 192.168.0.2, 192.168.0.3).

- chỉ định địa chỉ IP đích: `-d <địa_chỉ_ip_đích>`, tương tự như `-s`

- chỉ định cổng nguồn: `--sport` , ví dụ: `--sport 21` (cổng 21), `--sport 22:88` (các cổng 22 .. 88), `--sport :80` (các cổng <=80), `--sport 22:` (các cổng >=22)

- chỉ định cổng đích: `--dport` , tương tự như `--sport`

### 3. Các tuỳ chọn để thao tác với chain
- tạo chain mới: `iptables -N`

- xoá hết các luật đã tạo trong chain: `iptables -X`

- đặt chính sách cho các chain built-in (INPUT, OUTPUT & FORWARD): `iptables -P` , ví dụ: `iptables -P INPUT ACCEPT` để chấp nhận các packet vào chain INPUT

- liệt kê các luật có trong chain: `iptables -L`

- xoá các luật có trong chain (flush chain): `iptables -F`

- reset bộ đếm packet về 0: `iptables -Z`

### 4. Các tuỳ chọn để thao tác với luật
- thêm luật: -A (append)
- xoá luật: -D (delete)
- thay thế luật: -R (replace)
- chèn thêm luật: -I (insert)

## Phân biệt giữa ACCEPT, DROP và REJECT packet
- ACCEPT: chấp nhận packet
- DROP: thả packet (không hồi âm cho client)
- REJECT: loại bỏ packet (hồi âm cho client bằng một packet khác)

Ví dụ:
```sh
# chấp nhận các packet vào cổng 80 trên card mạng eth0
iptables -A INPUT -i eth0 --dport 80 -j ACCEPT

# thả các packet đến cổng 23 dùng giao thức TCP trên card mạng eth0
iptables -A INPUT -i eth0 -p tcp --dport 23 -j DROP

# gởi gói TCP với cờ RST=1 cho các kết nối không đến từ dãy địa chỉ IP 10.0.0.1..5
# trên cổng 22, card mạng eth1
iptables -A INPUT -i eth1 -s ! 10.0.0.1-10.0.0.5 --dport 22 -j REJECT --reject-with tcp-reset

# gởi gói ICMP `port-unreachable` cho các kết nối đến cổng 139, dùng giao thức UDP
iptables -A INPUT -p udp --dport 139 -j REJECT --reject-with icmp-port-unreachable
```

## Phân biệt giữa NEW, ESTABLISHED và RELATED
- NEW: mở kết nối mới
- ESTABLISHED: đã thiết lập kết nối
- RELATED: mở một kết nối mới trong kết nối hiện tại

Ví dụ:
```sh
# đặt chính sách cho chain INPUT là DROP
iptables -P INPUT DROP

# chỉ chấp nhận các gói TCP mở kết nối đã set cờ SYN=1
iptables -A INPUT -p tcp --syn -m state --state NEW -j ACCEPT

# không đóng các kết nối đang được thiết lập, đồng thời cũng cho phép mở
# các kết nối mới trong kết nối được thiết lập
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# các gói TCP còn lại đều bị DROP
iptables -A INPUT -p tcp -j DROP
```

## Tuỳ chọn `--limit`, `--limit-burst`

`--limit-burst`: mức đỉnh, tính bằng số packet

`--limit`: tốc độ khi chạm mức đỉnh, tính bằng số packet/s (giây), m (phút), h (giờ) hoặc d (ngày)

Mình lấy ví dụ cụ thể để bạn dễ hiểu:
```sh
iptables -N test
iptables -A test -m limit --limit-burst 5 --limit 2/m -j RETURN
iptables -A test -j DROP
iptables -A INPUT -i lo -p icmp --icmp-type echo-request -j test
```
Đầu tiên lệnh `iptables -N` test để tạo một chain mới tên là test (table mặc định là filter). Tuỳ chọn -A test (append) để thêm luật mới vào chain test. Đối với chain test, mình giới hạn limit-burst ở mức 5 gói, limit là 2 gói/phút, nếu thoả luật sẽ trở về (RETURN) còn không sẽ bị DROP. Sau đó mình nối thêm chain test vào chain INPUT với tuỳ chọn card mạng vào là lo, giao thức icmp, loại icmp là echo-request. Luật này sẽ giới hạn các gói PING tới lo là 2 gói/phút sau khi đã đạt tới 5 gói.

Bạn thử ping đến localhost xem sao?
```sh
ping -c 10 localhost
```
Chỉ 5 gói đầu trong phút đầu tiên được chấp nhận, thoả luật RETURN đó. Bây giờ đã đạt đến mức đỉnh là 5 gói, lập tức Iptables sẽ giới hạn PING tới lo là 2 gói trên mỗi phút bất chấp có bao nhiêu gói được PING tới lo đi nữa. Nếu trong phút tới không có gói nào PING tới, Iptables sẽ giảm limit đi 2 gói tức là tốc độ đang là 2 gói/phút sẽ tăng lên 4 gói/phút. Nếu trong phút nữa không có gói đến, limit sẽ giảm đi 2 nữa là trở về lại trạng thái cũ chưa đạt đến mức đỉnh 5 gói. Quá trình cứ tiếp tục như vậy. Bạn chỉ cần nhớ đơn giản là khi đã đạt tới mức đỉnh, tốc độ sẽ bị giới hạn bởi tham số `--limit`. Nếu trong một đơn vị thời gian tới không có gói đến, tốc độ sẽ tăng lên đúng bằng `--limit` đến khi trở lại trạng thái chưa đạt mức `--limit-burst` thì thôi.

Để xem các luật trong Iptables bạn gõ lệnh `iptables -L -nv` (`-L` tất cả các luật trong tất cả các chain, table mặc định là filter, `-n` liệt kê ở dạng số, `-v` để xem chi tiết)
```sh
iptables -L -nv
"""
Chain INPUT (policy ACCEPT 10 packets, 840 bytes)
pkts bytes target prot opt in out source destination
10 840 test icmp — lo * 0.0.0.0/0 0.0.0.0/0 icmp type 8

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
pkts bytes target prot opt in out source destination

Chain OUTPUT (policy ACCEPT 15 packets, 1260 bytes)
pkts bytes target prot opt in out source destination

Chain test (1 references)
pkts bytes target prot opt in out source destination
5 420 RETURN all — * * 0.0.0.0/0 0.0.0.0/0 limit: avg 2/min burst 5
5 420 DROP all — * * 0.0.0.0/0 0.0.0.0/0
"""

# reset counter
iptables -Z

# flush luật
iptables -F

# xoá chain đã tạo
iptables -X
```


## Redirect cổng
Iptables hổ trợ tuỳ chọn `-j REDIRECT` cho phép bạn đổi hướng cổng một cách dễ dàng. Ví dụ như SQUID đang listen trên cổng 3128/tcp. Để redirect cổng 80 đến cổng 3128 này bạn làm như sau:

```sh
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128
```
Lưu ý: tuỳ chọn `-j REDIRECT` cho có trong chain PREROUTING


## SNAT & MASQUERADE
Để tạo kết nối transparent giữa mạng LAN 192.168.0.1 với Internet bạn lập cấu hình cho tường lửa Iptables như sau:
```sh
# cho phép forward các packet qua máy chủ đặt Iptables
echo 1 > /proc/sys/net/ipv4/ip_forward

# đổi IP nguồn cho các packet ra card mạng eth0 là 210.40.2.71. Khi nhận được
# packet vào từ Internet, Iptables sẽ tự động đổi IP đích 210.40.2.71
# thành IP đích tương ứng của máy tính trong mạng LAN 192.168.0/24.
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 210.40.2.71
```

Hoặc bạn có thể dùng MASQUERADE thay cho SNAT như sau:
```
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

(MASQUERADE thường được dùng khi kết nối đến Internet là pp0 và dùng địa chỉ IP động)

## DNAT
Giả sử bạn đặt các máy chủ Proxy, Mail và DNS trong mạng DMZ. Để tạo kết nối trong suốt từ Internet vào các máy chủ này bạn là như sau:
```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.2
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to-destination 192.168.1.3
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j DNAT --to-destination 192.168.1.4
```

# Phần II: Lập cấu hình Iptables cho máy chủ phục vụ Web
Phần này mình sẽ trình bày qua ví dụ cụ thể và chỉ hướng dẫn các bạn lọc packet INPUT. Các packet FORWARD và OUTPUT bạn tự làm nha.

Giả sử như máy chủ phục vụ Web kết nối mạng trực tiếp vào Internet qua card mạng eth0, địa chỉ IP là 1.2.3.4. Bạn cần lập cấu hình tường lửa cho Iptables đáp ứng các yêu cầu sau:

- cổng TCP 80 (chạy apache) mở cho mọi người truy cập web
- cổng 21 (chạy proftpd) chỉ mở cho webmaster (dùng để upload file lên public_html)
- cổng 22 (chạy openssh) chỉ mở cho admin (cung cấp shell `root` cho admin để nâng cấp & patch lỗi cho server khi cần)
- cổng UDP 53 (chạy tinydns) để phục vụ tên miền (đây chỉ là ví dụ)
- chỉ chấp nhận ICMP PING tới với code=0×08, các loại packet còn lại đều bị từ chối.

## Bước 1: thiết lập các tham số cho nhân
```sh
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 10 > /proc/sys/net/ipv4/tcp_fin_timeout
echo 1800 > /proc/sys/net/ipv4/tcp_keepalive_time
echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
echo 0 > /proc/sys/net/ipv4/tcp_sack
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/conf/eth0/accept_source_route
```

tcp_syncookies=1 bật chức năng chống DoS SYN qua syncookie của Linux
tcp_fin_timeout=10 đặt thời gian timeout cho quá trình đóng kết nối TCP là 10 giây
tcp_keepalive_time=1800 đặt thời gian giữ kết nối TCP là 1800 giây
…

Các tham số khác bạn có thể xem chi tiết trong tài liệu đi kèm của nhân Linux.

## Bước 2: nạp các môđun cần thiết cho Iptables
Để sử dụng Iptables, bạn cần phải nạp trước các môđun cần thiết. Ví dụ nếu bạn muốn dùng chức năng LOG trong Iptables, bạn phải nạp môđun ipt_LOG vào trước bằng lệnh # modprobe ipt_LOG.
```sh
MODULES="ip_tables iptable_filter ipt_LOG ipt_limit ipt_REJECT ipt_state"
for i in $MODULES; do
    /sbin/modprobe $MODULES
done
```
## Bước 3: nguyên tắc đặt luật là "drop trước, accept sau"
Đây là nguyên tắc mà bạn nên tuân theo. Đầu tiên hãy đóng hết các cổng, sau đó mở dần cách cổng cần thiết. Cách này tránh cho bạn gặp sai sót trong khi đặt luật cho Iptables.

```sh
# thả packet trước
iptables -P INPUT DROP

# giữ các kết nối hiện tại và chấp nhận các kết nối có liên quan
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# chấp nhận các gói vào looback từ IP 127.0.0.1 và 1.2.3.4
iptables -A INPUT -i lo -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -i lo -s 1.2.3.4 -j ACCEPT

# thả các gói dữ liệu đến từ các IP nằm trong danh sách cấm BANNER_IP
BANNED_IP="10.0.0.0/8 192.168.0.0/16 172.16.0.0/12 224.0.0.0/4 240.0.0.0/5"
for i in $BANNED_IP; do
    iptables -A INPUT -i eth0 -s $i -j DROP
done
```

## Bước 4: lọc ICMP vào và chặn ngập lụt PING
LOG của Iptables sẽ được ghi vào file /var/log/firewall.log. Bạn phải sửa lại cấu hình cho SYSLOG như sau:
```sh
vi /etc/syslog.conf
"""
kern.=debug /var/log/firewall.log
"""

/etc/rc.d/init.d/syslogd restart
```

Đối với các gói ICMP đến, chúng ta sẽ đẩy qua chain CHECK_PINGFLOOD để kiểm tra xem hiện tại đamg bị ngập lụt PING hay không, sau đó mới cho phép gói vào. Nếu đang bị ngập lụt PING, môđun LOG sẽ tiến hành ghi nhật kí ở mức giới hạn `--limit $LOG_LIMIT` và `--limit-burst $LOG_LIMIT_BURST`, các gói PING ngập lụt sẽ bị thả hết.

```sh
LOG_LEVEL="debug"

LOG_LIMIT=3/m
LOG_LIMIT_BURST=1

PING_LIMIT=500/s
PING_LIMIT_BURST=100

iptables -A CHECK_PINGFLOOD -m limit --limit $PING_LIMIT --limit-burst $PING_LIMIT_BURST -j RETURN
iptables -A CHECK_PINGFLOOD -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=PINGFLOOD:warning a=DROP "
iptables -A CHECK_PINGFLOOD -j DROP

iptables -A INPUT -i eth0 -p icmp --icmp-type echo-request -j CHECK_PINGFLOOD
iptables -A INPUT -i eth0 -p icmp --icmp-type echo-request -j ACCEPT
```

## Bước 5: reject quét cổng TCP và UDP
Ở đây bạn tạo sẵn chain reject quét cổng, chúng ta sẽ đẩy vào chain INPUT sau. Đối với gói TCP, chúng ta reject bằng gói TCP với cờ SYN=1 còn đối với gói UDP, chúng ta sẽ reject bằng gói `icmp-port-unreachable`
```sh
iptables -N REJECT_PORTSCAN
iptables -A REJECT_PORTSCAN -p tcp -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=PORTSCAN:tcp a=REJECT "
iptables -A REJECT_PORTSCAN -p udp -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=PORTSCAN:udp a=REJECT "
iptables -A REJECT_PORTSCAN -p tcp -j REJECT --reject-with tcp-reset
iptables -A REJECT_PORTSCAN -p udp -j REJECT --reject-with icmp-port-unreachable
```

## Bước 6: phát hiện quét cổng bằng Nmap
```sh
iptables -N DETECT_NMAP
iptables -A DETECT_NMAP -p tcp --tcp-flags ALL FIN,URG,PSH -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:XMAS a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:XMAS-PSH a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags ALL ALL -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:XMAS-ALL a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags ALL FIN -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:FIN a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags SYN,RST SYN,RST -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:SYN-RST a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:SYN-FIN a=DROP "
iptables -A DETECT_NMAP -p tcp --tcp-flags ALL NONE -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=NMAP:NULL a=DROP "
iptables -A DETECT_NMAP -j DROP
iptables -A INPUT -i eth0 -p tcp ! --syn -m state --state NEW -j DETECT_NMAP
```

Đối với các gói TCP đến eth0 mở kết nối nhưng không đặt SYN=1 chúng ta sẽ chuyển sang chain DETECT_NMAP. Đây là những gói không hợp lệ và hầu như là quét cổng bằng nmap hoặc kênh ngầm. Chain DETECT_NMAP sẽ phát hiện ra hầu hết các kiểu quét của Nmap và tiến hành ghi nhật kí ở mức `--limit $LOG_LIMIT` và `--limit-burst $LOG_LIMIT_BURST`. Ví dụ để kiểm tra quét XMAS, bạn dùng tuỳ chọn `--tcp-flags ALL FIN,URG,PSH` nghĩa là 3 cờ FIN, URG và PSH được bật, các cờ khác đều bị tắt. Các gói qua chain DETECT_NMAP sau đó sẽ bị DROP hết.

## Bước 7: chặn ngập lụt SYN
Gói mở TCP với cờ SYN được set 1 là hợp lệ nhưng không ngoại trừ khả năng là các gói SYN dùng để ngập lụt. Vì vậy, ở dây bạn đẩy các gói SYN còn lại qua chain CHECK_SYNFLOOD để kiểm tra ngập lụt SYN như sau:
```sh
iptables -N CHECK_SYNFLOOD
iptables -A CHECK_SYNFLOOD -m limit --limit $SYN_LIMIT --limit-burst $SYN_LIMIT_BURST -j RETURN
iptables -A CHECK_SYNFLOOD -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=SYNFLOOD:warning a=DROP "
iptables -A CHECK_SYNFLOOD -j DROP
iptables -A INPUT -i eth0 -p tcp --syn -j CHECK_SYNFLOOD
```

## Bước 8: giới hạn truy cập SSH cho admin
```sh
SSH_IP="1.1.1.1"
iptables -N SSH_ACCEPT
iptables -A SSH_ACCEPT -m state --state NEW -j LOG --log-level $LOG_LEVEL --log-prefix "fp=SSH:admin a=ACCEPT "
iptables -A SSH_ACCEPT -j ACCEPT
iptables -N SSH_DENIED
iptables -A SSH_DENIED -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=SSH:attempt a=REJECT "
iptables -A SSH_DENIED -p tcp -j REJECT --reject-with tcp-reset

for i in $SSH_IP; do
    iptables -A INPUT -i eth0 -p tcp -s $i --dport 22 -j SSH_ACCEPT
done

iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW -j SSH_DENIED
```

## Bước 9: giới hạn FTP cho web-master
```sh
FTP_IP="2.2.2.2"
iptables -N FTP_ACCEPT
iptables -A FTP_ACCEPT -m state --state NEW -j LOG --log-level $LOG_LEVEL --log-prefix "fp=FTP:webmaster a=ACCEPT "
iptables -A FTP_ACCEPT -j ACCEPT
iptables -N FTP_DENIED
iptables -A FTP_DENIED -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=FTP:attempt a=REJECT "
iptables -A FTP_DENIED -p tcp -j REJECT --reject-with tcp-reset

for i in $FTP_IP; do
    iptables -A INPUT -i eth0 -p tcp -s $i --dport 21 -j FTP_ACCEPT
done

iptables -A INPUT -i eth0 -p tcp --dport 21 -m state --state NEW -j FTP_DENIED
```

## Bước 10: lọc TCP vào
```sh
iptables -N TCP_INCOMING
iptables -A TCP_INCOMING -p tcp --dport 80 -j ACCEPT
iptables -A TCP_INCOMING -p tcp -j REJECT_PORTSCAN
iptables -A INPUT -i eth0 -p tcp -j TCP_INCOMING
```

## Bước 11: lọc UDP vào và chặn ngập lụt UDP
```sh
iptables -N CHECK_UDPFLOOD
iptables -A CHECK_UDPFLOOD -m limit --limit $UDP_LIMIT --limit-burst $UDP_LIMIT_BURST -j RETURN
iptables -A CHECK_UDPFLOOD -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level $LOG_LEVEL --log-prefix "fp=UDPFLOOD:warning a=DROP "
iptables -A CHECK_UDPFLOOD -j DROP
iptables -A INPUT -i eth0 -p udp -j CHECK_UDPFLOOD

iptables -N UDP_INCOMING
iptables -A UDP_INCOMING -p udp --dport 53 -j ACCEPT
iptables -A UDP_INCOMING -p udp -j REJECT_PORTSCAN
iptables -A INPUT -i eth0 -p udp -j UDP_INCOMING
```

Để hạn chế khả năng bị DDoS và tăng cường tốc độ cho máy chủ phục vụ web, bạn có thể dùng cách tải cân bằng (load-balacing) như sau:

Cách 1: chạy nhiều máy chủ phục vụ web trên các địa chỉ IP Internet khác nhau. Ví dụ, ngoài máy chủ phục vụ web hiện tại 1.2.3.4, bạn có thể đầu tư thêm các máy chủ phục vụ web mới 1.2.3.2, 1.2.3.3, 1.2.3.4, 1.2.3.5. Điểm yếu của cách này là tốn nhiều địa chỉ IP Internet.

Cách 2: đặt các máy chủ phục vụ web trong một mạng DMZ. Cách này tiết kiệm được nhiều địa chỉ IP nhưng bù lại bạn gateway Iptables 1.2.3.4 -- 192.168.0.254 có thể load nặng hơn trước và yêu cầu bạn đầu tư tiền cho đường truyền mạng từ gateway ra Internet.

Bạn dùng DNAT trên gateway 1.2.3.4 để chuyển tiếp các gói dữ liệu từ client đến một trong các máy chủ phục vụ web trong mạng DMZ hoặc mạng LAN như sau:
```sh
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.0.1-192.168.0.4
```

