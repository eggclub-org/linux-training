# Case 2 - iptables và máy đơn có dịch vụ
Tác giả: Hoàng Ngọc Diêu, aka conmale at HVA.
Ngày đăng: 2006-06-20
Nguồn: http://www.hvaonline.net/hvaonline/posts/list/154.hva

<!-- MarkdownTOC depth=0 -->

- [1. Trường hợp](#1-trường-hợp)
- [2. Nhu cầu](#2-nhu-cầu)
- [3. Phương pháp kết nối](#3-phương-pháp-kết-nối)
- [4. Mô hình](#4-mô-hình)
- [5. Nhóm luật](#5-nhóm-luật)
- [6. Phân tích](#6-phân-tích)
- [7. Tổng lượt dạng firewall trên](#7-tổng-lượt-dạng-firewall-trên)
- [8. Mở rộng](#8-mở-rộng)
    - [8.1 Vấn đề chung cho mọi giao thức](#81-vấn-đề-chung-cho-mọi-giao-thức)
        - [8.1.1 Vấn đề các gói tin ở tình trạng INVALID](#811-vấn-đề-các-gói-tin-ở-tình-trạng-invalid)
        - [8.1.2 Vấn đề mạo danh IP của máy chủ](#812-vấn-đề-mạo-danh-ip-của-máy-chủ)
    - [8.2 Vấn đề thuộc giao thức TCP](#82-vấn-đề-thuộc-giao-thức-tcp)
        - [8.2.1 Loại trừ các truy cập mang tính thiếu hợp lệ](#821-loại-trừ-các-truy-cập-mang-tính-thiếu-hợp-lệ)
        - [8.2.2 Cản và log cụ thể cho TCP](#822-cản-và-log-cụ-thể-cho-tcp)
        - [8.2.3 Loại trừ các truy cập hợp lệ nhưng nguy hại](#823-loại-trừ-các-truy-cập-hợp-lệ-nhưng-nguy-hại)
            - [8.2.3.1 Giới hạn truy cập với "connection rate"](#8231-giới-hạn-truy-cập-với-connection-rate)
            - [8.2.3.2 Giới hạn truy cập với "connection limit"](#8232-giới-hạn-truy-cập-với-connection-limit)
        - [8.2.4 Vấn đề độ dài của SYN packet](#824-vấn-đề-độ-dài-của-syn-packet)
    - [8.3 Vấn đề thuộc giao thức UDP](#831-vấn-đề-thuộc-số-lượng-truy-cập-udp)
        - [8.3.1 Vấn đề thuộc số lượng truy cập UDP](#831-vấn-đề-thuộc-số-lượng-truy-cập-udp)
        - [8.3.2 Vấn đề thuộc thực tính của xuất truy cập UDP](#832-vấn-đề-thuộc-thực-tính-của-xuất-truy-cập-udp)
    - [8.4 Vấn đề thuộc giao thức ICMP](#84-vấn-đề-thuộc-giao-thức-icmp)
        - [8.4.1 Chọn lựa và giới hạn ICMP](#841-chọn-lựa-và-giới-hạn-icmp)
        - [8.4.2 Cản ICMP hoặc cản ICMP "một nửa"](#842-cản-icmp-hoặc-cản-icmp-một-nửa)
            - [8.4.2.1 Cản ICMP](#8421-cản-icmp)
            - [8.4.2.2 Cản ICMP "một nửa"](#8422-cản-icmp-một-nửa)
- [9. Thử nghiệm](#9-thử-nghiệm)
- [10. Kết luận](#10-kết-luận)
- [Bị chú](#bị-chú)
- [Tổng kết đoạn script case 2](#tổng-kết-đoạn-script-case-2)

<!-- /MarkdownTOC -->




Trường hợp điển hình thứ nhì trong việc ứng dụng iptables để bảo vệ máy đơn có dịch vụ.

## 1. Trường hợp {#1-trường-hợp}
Firewall cho một máy đơn có dịch vụ.

## 2. Nhu cầu {#2-nhu-cầu}
Bảo vệ máy đơn không bị thâm nhập vào những dịch vụ không dành cho công cộng và cho phép truy cập vào những dịch vụ được ấn định cụ thể.

## 3. Phương pháp kết nối {#3-phương-pháp-kết-nối}
Bất cứ phương tiện nào, (cách tốt nhất) nên có IP tĩnh để có thể tạo dịch vụ công cộng ổn định.

Đòi hỏi tối thiểu:
Đã hoàn tất thành công quy trình kết nối vào Internet và các dịch vụ trên máy đã có thể truy cập được từ Internet.

## 4. Mô hình {#4-mô-hình}
eth0 là NIC tiếp diện với Internet với IP tĩnh. Mô hình này thích hợp cho các máy đơn (dedicated server) với các dịch vụ thông thường như HTTP, SMTP, POP3, DNS và SSH (quản lí từ xa).

## 5. Nhóm luật {#5-nhóm-luật}
Code:
```sh
1. IF=`/sbin/route | grep -i 'default' | awk '{print$8}'`
2. IP=`/sbin/ifconfig $IF | grep "inet addr" | awk -F":" '{print$2}' | awk '{print $1}'`
3. IPT="/usr/local/sbin/iptables"
4. NET="any/0"
5. DNS="xxx.xxx.xxx.xxx yyy.yyy.yyy.yyy.yyy"
6. SERV_TCP="22 25 80 443 110"
7. SERV_UDP="53 123"
8. HI_PORTS="1024:65535"
9.
10. $IPT -F
11. $IPT -P INPUT DROP
12. $IPT -P OUTPUT DROP
13. $IPT -P FORWARD DROP
14.
15. for entry in $DNS, do
16. $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $HI_PORTS -d $entry --dport 53 -m state --state NEW -j ACCEPT
17. $IPT -A INPUT -i $IF -p udp -s $entry --sport 53 -d $IP --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
18. done
19.
20. for port in $SERV_UDP; do
21. if test $port -eq 53
22. then
23. $IPT -A INPUT -i $IF -p udp -s $NET --sport $port -d $IP --dport $port -m state --state NEW,ESTABLISHED -j ACCEPT
24. $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $port -d $NET --dport $port -m state --state ESTABLISHED -j ACCEPT
25. else
26. $IPT -A INPUT -i $IF -p udp -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
27. $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $port -d $NET --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
28. fi
29. done
30.
31. for port in $ SERV_TCP; do
32. $IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
33. $IPT -A OUTPUT -o $IF -p tcp ! --syn -s $IP --sport $port -d $NET --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
34. $IPT -A INPUT -i $IF -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state ESTABLISHED -j ACCEPT
35. done
36.
37. $IPT -A INPUT -i $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_INPUT: "
38. $IPT -A INPUT -i $IF -d $IP -j DROP
39. $IPT -A OUTPUT -o $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_OUTPUT: "
40. $IPT -A OUTPUT -o $IF -d $IP -j DROP
41. $IPT -A FORWARD -i $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_FORWARD: "
42. $IPT -A FORWARD -i $IF -d $IP -j DROP
```

## 6. Phân tích {#6-phân-tích}
- Dòng 1, 2, 3: Đã phân tích trong bài trước (case 1).

- Dòng 4: Ấn định giá trị của biến `NET`. Đối với iptables, việc ấn định `NET=any/0` và ứng dụng trong firewall script không cần thiết (bị thừa) vì nếu không ấn định cụ thể giá trị source (-s) và destination (-d) thì được ngầm hiểu là `any/0`. Giá trị `NET` dùng ở đây với mục đích làm rõ các luật trên phương diện gói tin đến và đi.

- Dòng 5: Ấn định giá trị của biến `DNS`. Đây là một giá trị quan trọng cho trường hợp firewall trên máy đơn và có dịch vụ cho công cộng. Những dịch vụ cho công như web, mail... đều trực tiếp tương tác với cơ chế biên giải giữa IP và tên domain. Giá trị của biến `DNS` ở đây chính là các IP của một DNS server (biểu thị cho primary DNS và secondary DNS). DNS server này có thể là DNS do ISP cung cấp hoặc chính authoritative DNS -1- do bạn tạo ra. Các giá trị trong biến `DNS` này tách rời bởi khoảng trống (space) để tiện việc chạy lệnh sau này.

- Dòng 6: Ấn định giá trị của biến `SERV_TCP`. Biến `SERV_TCP` chứa giá trị các cổng dịch vụ ở giao thức TCP được firewall mở và kiểm soát. Các giá trị này tách rời bởi khoảng trống. Bạn có thể thêm, bớt các giá trị tùy thích. Nên lưu ý cách ấn định giá trị các cổng trong biến `SERV_TCP` chỉ là một cách (trong nhiều cách), bạn có thể khai triển tùy thích, miễn sao iptables "biết được" những cổng nào cần mở và cần kiểm soát. Sử dụng phương thức này chỉ thích hợp cho các cổng dịch vụ có tính chất tương tự nhau và bạn muốn kiểm soát các cổng với chế độ tương tự nhau. Cách ứng dụng khác là ấn định mỗi luật một dòng thay vì nhóm lại trong vòng lặp.

- Dòng 7: Ấn định giá trị của biến `SERV_UDP`. Tương tự như trên, biến `SERV_UDP` chứa các giá trị cổng dịch vụ ở giao thức UDP được firewall mở và kiểm soát. Riêng phần biến `SERV_UDP` này có chứa cổng 53 mang tính chất khá đặc biệt so với các cổng dịch vụ khác. Vấn đề này sẽ được bàn sâu hơn cho dòng 20, 21, 22. Tất nhiên bạn không phải quan tâm đến nó nếu bạn không cung cấp dịch vụ DNS từ máy chủ của mình.

- Dòng 8: Ấn định giá trị của biến `HI_PORTS`. Trong bài viết cho case 1, giá trị này không được nêu lên và sử dụng một cách cụ thể. Trái lại, nó được sử dụng ở đây với mục đích làm rõ các luật bảo vệ và kiểm soát những gói tin ra/vào cần được huy động tới giá trị của biến `HI_PORTS` này. Cần nói thêm, giá trị của biến `HI_PORTS` trải dài từ cổng 1024 đến cổng 65535 là các cổng thuộc chuỗi "high ports" hay "unprivileged ports". Mở một socket trong chuỗi cổng này không cần đến quyền hạn root (trên *nix nói chung) và đây là một trong những điểm quan trọng của việc áp đạt chuỗi `HI_PORTS` trong firewall script sau này.

- Dòng 10, 11, 12, 13: Đã phân tích trong bài trước (case 1).

- Dòng 15-18: Bốn dòng này thuộc một vòng lặp, đặc biệt dùng để xác lập các dòng luật cho phép máy đơn (ở trường hợp này) liên hệ đến các DNS servers (đã ấn định ở biến `$DNS` ở trên). Đây là nhóm luật hết sức quan trọng và sẽ được các chương trình cung cấp dịch vụ trên mày dùng đến thường xuyên cho nên việc xác định luật này đầu tiên là việc cần thiết.

- Diễn dịch nôm na vòng lặp của dòng 15, 16, 17 và 18 như sau: với mỗi giá trị thuộc biến `$DNS`, chạy hai dòng 16 và 17 cho đến khi không còn giá trị nào nữa.

- Dòng 16 có ý nghĩa như sau: cho phép các gói tin với giao thức UDP đi ra ngoài bằng IP hiện có xuyên qua IF. Các gói tin này được khởi tạo từ một socket thuộc chuỗi `HI_PORTS` (nguồn `--sport`) và đi đến các địa chỉ DNS server đã ấn định trong biến `$DNS` đến cổng 53 (đích `--dport`). Thêm vào đó, các gói tin này phải ở tình trạng NEW (trong state table được iptables quản lí). Điều này có nghĩa firewall cho phép máy chủ -2- này khởi tạo các truy cập đến các DNS server đã ấn định (xxx.xxx.xxx.xxx và yyy.yyy.yyy.yyy).

- Dòng 17 có ý nghĩa như sau: cho phép các gói tin với giao thức UDP từ các DNS server đã ấn định được đi đến IP hiện có xuyên qua IF. Các gói tin này được phép trả lời từ cổng 53 của DNS server ấy. Các gói tin ở dạng trả lời này phải ở tình trạng ESTABLISHED (trong state table được iptables quản lí). Điều này có nghĩa firewall cho phép các DNS server đã được ấn định trả lời các truy cập được khởi tạo từ máy chủ. Các gói tin ở tình trạng NEW đến từ các DNS server sẽ bị từ chối.

- Dòng 20-29: tương tự như nhóm dòng 15-18, dòng 20-29 thuộc một vòng lặp để xác lập luật cho các cổng thuộc biến `$SERV_UDP` cho giao thức UDP. Trong vòng lặp này chứa một một cụm điều kiện cách (if/else) để thử nghiệm và ứng dụng đúng luật thích ứng cho cổng dịch vụ.

- Diễn dịch nôm na vòng lặp 20-29 như sau: với mỗi giá trị thuộc biến `$SERV_UDP`, chạy các dòng lệnh 23 và 24 nếu một trong những giá trị thuộc biến `$SERV_UDP` là 53. Nếu không thì chạy các dòng lệnh 26 và 27 cho đến khi không còn giá trị nào nữa.

- Dòng 23 có ý nghĩa như sau: firewall cho phép các gói tin với giao thức UDP đi vào từ bất cứ nơi đâu từ cổng 53 đến cổng 53 của máy chủ. Các gói tin này phải đi đến `$IP` hiện có xuyên qua `$IF` và phải ở tình trạng NEW.

- Dòng 24 có ý nghĩa như sau: firewall cho phép các gói tin với giao thức UDP đi ra từ cổng 53 của máy chủ đến cổng 53 của máy đã đòi hỏi truy cập và đã được firewall tiếp nhận ở dòng 22. Các gói tin đi ra ngoài này phải ở tình trạng ESTABLISHED.

- Dòng 26 có ý nghĩa như sau: firewall cho phép các gói tin với giao thức UDP đi vào từ cổng nào đó thuộc dãy $HI_PORTS đến cổng đã ấn định trong biến `$SERV_UDP` của máy chủ. Các gói tin này phải ở tình trạng NEW.

- Dòng 27 có ý nghĩa như sau: firewall cho phép các gói tin với giao thức UDP đi ra từ cổng đã ấn định trong biến `$SERV_UDP` (và không phải là cổng 53) của máy chủ đến cổng nào đó thuộc dãy `$HI_PORTS` dùng để truy cập và đã được firewall tiếp nhận ở dòng 25. Các gói tin đi ra ngoài này phải ở tình trạng ESTABLISHED.

- Dòng 31-35: tương tự như nhóm dòng 20-29. Đây cũng là một vòng lặp dùng để xác lập luật cho các cổng thuộc biến `$SERV_TCP` cho giao thức TCP. Vòng lặp này không chứa cụm điều kiện cách như nhóm dòng 20-29 vì các cổng dịch vụ đã ấn định trong biến `$SERV_TCP` mang tính chất tương tự nhau -3-.

- Diễn dịch nôm na vòng lặp 31-35 như sau: với mỗi giá trị thuộc biến `$SERV_TCP`, chạy các dòng 32, 33 và 34 rồi lặp lại cho giá trị kế tiếp trong biến `$SERV_TCP` cho đến khi không còn giá trị nào khác.

- Dòng 32 có ý nghĩa như sau: các gói tin ở dạng TCP với cờ hiệu (TCP Flag) là SYN -4- đi vào từ bất cứ nơi nào từ một cổng ở dãy `$HI_PORTS` đến `$IP` hiện có xuyên qua `$IF` để đến cổng `$port` (giá trị hiện tại của vòng lặp) và ở tình trạng NEW thì tiếp nhận.

- Dòng 33 có ý nghĩa như sau: các gói tin ở dạng TCP không mang cờ hiệu là SYN đi từ `$IP` hiện có từ cổng `$port` (giá trị hiện tại của vòng lặp) trả lời cho gói tin yêu cầu truy cập ở trên (đi ra) và ở tình trạng ESTABLISHED thì tiếp nhận.

- Dòng 34 có ý nghĩa như sau: các gói tin ở dạng TCP với cờ hiệu không phải là SYN đi từ nơi gởi gói tin yêu cầu truy cập trên (tiếp tục) đi vào đến cổng `$port` của `$IP` hiện có và ở tình trạng ESTABLISHED thì tiếp nhận.

- Dòng 37-42: clean up rules. Đã phân tích ở case 1.

## 7. Tổng lượt dạng firewall trên {#7-tổng-lượt-dạng-firewall-trên}
Đây là dạng firewall được thiết lập cho một máy đơn hỗ trợ dịch vụ. Điểm cốt lõi và khác biệt giữa dạng này và dạng máy đơn không dịch vụ (như ở case 1) là máy đơn hỗ trợ dịch vụ tiếp nhận yêu cầu truy cập và chỉ trả lời yêu cầu truy cập khi những yêu cầu thoả mãn những luật iptables đưa ra (ngoại trừ luật tạo ra ở dòng 16 và 17). Trong khi đó, máy đơn của case 1 mang vai trò yêu cầu truy cập và các dịch vụ bên chỉ có thể trả lời nếu máy đơn này đòi hỏi.

Thử xét luật ở dòng 16 và 17 thì thấy, máy chủ này cần phải khởi tạo một xuất truy cập đến DNS server (và chỉ cụ thể những DNS server được ấn định trong biến `$DNS` mà thôi). Các DNS server này cũng chỉ có thể trả lời yêu cầu từ máy chủ khi máy chủ "hỏi" và tất nhiên, các DNS server khác sẽ không có cơ hội "trả lời" vì chúng không nằm trong phạm vi cho phép. Điều này cho thấy, máy chủ của chúng ta tin tưởng vào thông tin mà DNS server đã ấn định cung cấp. iptables không thể hạn chế thông tin của các DNS server này cung cấp, ngay cả khi chúng bị hư hoại (poisoned cache chẳng hạn). Ví dụ, www.mypage.net giả định được biên giải thành 123.123.123.123 nhưng DNS server ấy bị nhân nhượng nên www.mypage.net được biên giải thành 124.124.124.124 chẳng hạn thì máy chủ của chúng ta vẫn tiếp nhận gói tin chứa các thông tin này (nếu như chúng thoả mãn các điều kiện iptables đặt ra trên cấp độ ip).

Dòng 23 và 24 có vài điểm cần phân tích. Luật đưa ra ở hai dòng này dùng để kiểm soát và thoả mãn giao thức giữa dịch vụ DNS chạy trên máy chủ của chúng ta và các DNS server khác (server to server). Bởi vậy, thông tin đi và đến xuyên qua cổng 53 từ hai phía (thay vì từ một cổng thuộc `$HI_PORTS` đến cổng 53 và ngược lại). Đó là lí do tại sao chúng ta phải dùng đến cụm điều kiện cách if / else ở đây. Điểm cốt lõi của hai dòng lệnh này là đưa ra luật kiểm soát cho dịch vụ DNS giữa server và server. Máy chủ cung cấp dịch vụ DNS hầu hết chỉ cần "lắng nghe" và "trả lời" trên cổng 53 UDP ngoại trừ trường hợp một yêu cầu nào đó quá lớn hoặc một yêu cầu cho zone transfer thì mới cần đến cổng 53 TCP -5-

Dòng 26 và 27 tương tự như trên nhưng luật đưa ra dùng để kiểm soát gói tin giữa các clients từ bên ngoài và máy chủ (client to server). Tất nhiên các luật này không ứng dụng cho dịch vụ DNS vì đi đến hai dòng này đã thoát ra ngoài cụm điều kiện cách dùng cho DNS ở trên. Ở đây, thông tin đi xuyên qua cổng 53 của máy chủ và $HI_PORTS của máy con.

Dòng 32, 33, 34 có một số điểm lí thú cần bàn đến. Dựa trên tính "stateful" của giao thức TCP, iptables có thể kiểm soát các gói tin TCP sâu sát hơn UDP rất nhiều.

- Dòng 32 chỉ định rất cụ thể là các gói tin ở tình trạng NEW -6- và có tcp-flags là SYN,RST,ACK SYN thì mới được tiếp nhận. Điều này có nghĩa: một yêu cầu truy cập hoàn toàn mới bằng giao thức TCP thì phải có SYN bit và đối với iptables, gói tin khởi đầu cho một cuộc truy cập hoàn toàn mới vì nó chưa hề có trong bảng theo dõi của netfilter (conntrack table). Vậy nếu một gói tin muốn đi vào (truy cập) nhưng chưa hề có trong bảng theo dõi của netfilter (NEW) và không có SYN bit thì sao? Câu trả lời là tất nhiên iptables sẽ chặn nó lại như theo luật đưa ra ở dòng 32 và đây là điều tốt vì các truy cập hợp lệ (legitimate request) không thể có trường hợp một request mới mà không khởi đầu từ SYN. Trường hợp gói tin ở tình trạng NEW nhưng không có SYN bit rất hiếm thấy (ngoại trừ cố tình tạo ra gói tin ở dạng này để thử thâm nhập). Những gói tin ở trường hợp này đôi khi xuất hiện nếu bạn thiết kế hệ thống "high availability" -7- cho nhiều firewall và các firewall này vì lí do nào đó "lỡ" không chuyển giao các "state" của những gói tin hiện lưu hành xuyên qua firewall nên một gói tin nào đó đang ở tình trạng ESTABLISHED với firewall này có thể ở tình trạng NEW với firewall kia. Nếu iptables nằm trong vùng làm việc của các firewall trên thì thỉnh thoảng sẽ va phải một số gói tin như thế và đây là trường hợp (legitimate) rất ít xảy ra.

- Dòng 33 và 34 dùng để hỗ trợ dòng 32 và tiêu điểm của luật trên hai dòng này là dấu chấm thang (!) đi trước `--syn`. Chuyện gì sẽ xảy ra ở đây? Ở dòng 32, chúng ta ấn định các gói tin TCP đi vào mang SYN flag và ở tình trạng NEW thì được tiếp nhận, vậy sau khi được tiếp nhận thì chuyện gì tiếp tục xảy ra? Câu trả lời nằm ở dòng 33:

    + Các gói tin đi ra ngoài để trả lời mà không mang SYN flag -8- và ở tình trạng ESTABLISHED thì được tiếp nhận. Điều cần nhấn mạnh ở đây là gói tin trả lời đi từ máy chủ của chúng ta không nên là gói tin mang SYN flag bởi vì không có lí do gì để máy chủ phải gởi yêu cầu truy cập đến một máy con nào đó trên Internet. Máy chủ chúng ta dùng để tiếp nhận và trả lời các yêu cầu truy cập cho nên luật ở dòng 33 ngầm chứa một quy định rất khắc khe: không những luật firewall cho máy chủ này chỉ tiếp nhận những yêu cầu đi vào một cách hợp lệ mà còn ngăn ngừa những lưu thông đi ra từ máy chủ một cách thiếu hợp lệ (thử hình dung vì lí do gì đó, máy chủ của chúng ta bị biến thành "zombie" và liên tục gởi SYN request đến các máy khác).

    + Tình trạng ESTABLISHED kèm theo trong lệnh này càng nâng cao mức khắc khe. Đối với conntrack table lúc này, gói tin đi ra từ máy chủ để trả lời một yêu cầu truy cập nào đó phải thuộc dạng ESTABLISHED. `--syn` ở đây ứng dụng cụ thể cho gói tin thuộc giao thức TCP và `--state ESTABLISHED` ở đây ứng dụng cụ thể cho tính "stateful" của netfilter.

- Dòng 34 tiếp nối hai dòng lệnh trên. Ở giai đoạn này, gói tin đi vào máy chủ và thuộc xuất truy cập hiện tại phải ở tình trạng ESTABLISHED và không mang SYN flag nữa và đây chính là điều được dòng 33 áp đặt. Từ lúc này trở đi, trong suốt xuất truy cập, luật của dòng 33 và 34 điều tác và kiểm soát lưu thông giữa máy con và máy chủ của chúng ta. Cụ thể hơn:

    + Nếu cũng từ một IP (cùng một client) gởi một gói tin mang SYN flag và hợp lệ thì nó sẽ được xếp loại NEW và được dòng lệnh 32 "xét xử".

    + Nếu cũng từ một IP (cùng một client) gởi một gói tin mang một TCP flag nào đó thiếu hợp lệ và không nằm trong tình trạng được theo dõi bởi conntrack table thì nó bị loại trừ bởi các dòng trong nhóm 37-42 hoặc được quy chế mặc định của firewall xử (còn nhớ `-P`?).

## 8. Mở rộng {#8-mở-rộng}
Mở rộng? rộng thế nào? :smile:. Khó có thể trả lời câu hỏi này thoả đáng vì không có sự cố hoặc nhu cầu thì khó biết được giải pháp? (**no solution for unknown problem**). Tuy nhiên có vài vấn đề có thể mở rộng một cách tổng quát và ứng dụng cho đa số các trường hợp.

### 8.1 Vấn đề chung cho mọi giao thức {#81-vấn-đề-chung-cho-mọi-giao-thức}
#### 8.1.1 Vấn đề các gói tin ở tình trạng INVALID {#811-vấn-đề-các-gói-tin-ở-tình-trạng-invalid}
Như đã phân tích các tình trạng NEW,RELATED,ESTABLISHED,VALID trong bảng theo dõi của netfilter ở bị chú số 6 (bên dưới). Các gói tin ở tình trạng NEW,RELATED,ESTABLISHED có thể được tiếp nhận tùy theo hoàn cảnh. Tuy nhiên, gói tin ở tình trạng INVALID trên bình diện SPI (xem chú thích về SPI ở case 1), không thể được tiếp nhận với bất cứ lí do nào. Bởi vậy, hai dòng luật như sau có thể đưa vào phía trên dòng 15:

Code:
```sh
$IPT -A INPUT -m state --state INVALID -m limit --limit 1/s -j LOG --log-prefix "INVALID_STATE: "
$IPT -A INPUT -m state --state INVALID -j DROP
```

Dòng trên dùng để log và dòng kế tiếp chính thức cản các gói tin thuộc dạng này. Điểm cần chú ý ở đây là hai dòng lệnh trên không quy định cụ thể loại giao thức nào (bằng thông số `-p`) cho nên các luật này ứng hiệu cho mọi giao thức. Dòng trên cản phần lớn các gói tin "lạc loài" đi vào firewall với chủ đích hoặc vô tình. Cách áp đặt luật này phía trên dòng 15 không những log và cản các gói tin vi phạm cụ thể mà còn mang tính hiệu năng. Các gói tin vi phạm sẽ bị cản ngay tại vị trí này thay vì tiếp tục đi xuống cho đến khi nào trùng với một luật xử lí nào đó, nếu không thì chúng sẽ tiếp tục đi xuống đến tận chuỗi "clean-up" rule (rồi cũng sẽ bị log và cản). Để duy trì tính an toàn, chúng không nên được phép đi vào.

#### 8.1.2 Vấn đề mạo danh IP của máy chủ {#812-vấn-đề-mạo-danh-ip-của-máy-chủ}
Kỹ thuật mạo danh IP của một máy nào đó được gọi là "spoofing" theo thuật ngữ chuyên môn. "Spoofing" có nhiều dạng và nhiều mục đích nhưng ở đây chúng ta chỉ đề cập đến trường hợp "ai đó" từ Internet mạo danh địa chỉ của máy chủ chúng ta với mục đích "lừa" firewall mà lẻn vào. Thủ thuật này có độ thành công rất cao khi "thử nghiệm" trên các máy chủ và ngay cả các firewall nếu không điều chỉnh cẩn thận. Thử xét:

Code:
```sh
$IPT -A INPUT -i $IF -s $IP -d $IP -m limit --limit 1/s -j LOG --log-prefix "SPOOFING: "
$IPT -A INPUT -i $IF -s $IP -d $IP -j DROP
```

Các gói tin đi từ bên ngoài vào xuyên qua `$IF` và từ `$IP` không thể đến `$IP` được. Vả lại, làm sao có thể có gói tin được chính IP của máy chủ chúng ta tạo ra lại đi vào từ Internet? Nên nhớ, các gói tin được tạo ra ngay trên chính máy chủ cho chính máy chủ đều đi xuyên qua địa chỉ loopback (127.0.0.1) xuyên qua loopback interface (lo), cho nên, các gói tin đi từ bên ngoài mà mang IP của chính máy chủ chúng ta thì chắc chắn thuộc dạng "spoofing". Tất nhiên để có thể lẻn vào bằng phương thức "spoofing" này, kẻ muốn xâm nhập cần nhiều dữ kiện và điều kiện hơn là chỉ đơn thuần "spoofing" vì SPI là hàng rào cản đầu tiên (xem INVALID state ở trên).

### 8.2 Vấn đề thuộc giao thức TCP {#82-vấn-đề-thuộc-giao-thức-tcp}
#### 8.2.1 Loại trừ các truy cập mang tính thiếu hợp lệ {#821-loại-trừ-các-truy-cập-mang-tính-thiếu-hợp-lệ}
Thử mở rộng một vài TCP flags như đã bàn đến trong phần 7 ở trên -9-

Code:
```sh
a. $IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -s $NET -j DROP
```

Một gói tin mang tcp flag SYN và FIN cùng một lượt không thể là một gói tin bình thường và hợp lệ. SYN-FIN chỉ thường thấy ở các thao tác rà cổng (port scan) hoặc được dùng với ý định không trong sáng. Gói tin ở dạng này nên loại trừ trước khi đi sâu vào hệ thống. Nếu cần phải log, bạn chỉ cần áp đặt một dòng luật tương tự với target là LOG ở trên.

Code:
```sh
b. $IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -s $NET -j DROP
```

Một gói tin mang tcp flag FIN và RST cùng một lượt cũng có thể được xem bất hợp lệ. FIN flag trong một gói tin hợp lệ dùng để thông báo đầu bên kia dòng tin được chấm dứt để xuất truy cập được kết thúc đúng quy cách. Trong khi đó, RST flag dùng để "xé" ngang một xuất truy cập bất chợt. Trường hợp FIN và RST cùng trong một gói tin là điều bất thường và không nên tiếp nhận.

Trường hợp a, b và các trường hợp tương tự đều có thể tạo những tác động không tốt đến dịch vụ trên máy chủ. Chúng khiến cho hệ thống trên máy chủ phải làm việc nhiều hơn một cách không cần thiết và một số trường hợp các gói tin được "nắn ép" cẩn thận có thể dung hại nặng nề đến hệ thống. Tương tự như đã phân tích ở phần 8.1, hai dòng này nên đặt trên dòng 15 (hoặc trên các dòng lệnh bắt đầu cho phép tiếp nhận gói tin) để mang lại tính cụ thể và hiệu năng khi đưa ra các luật cụ thể.

#### 8.2.2 Cản và log cụ thể cho TCP {#822-cản-và-log-cụ-thể-cho-tcp}
Trên dòng chúng ta cho phép các gói tin TCP đi vào phải mang SYN flag và ở tình trạng NEW. Tất nhiên, các gói tin không thoả mãn quy định trên sẽ bị log và cản ở dòng luật 37, 38. Nếu chúng ta không cần phải log chi tiết chuyện gì xảy và thì đoạn firewall script ở trên vừa đủ để hoạt động. Tuy nhiên, nếu chúng ta cần log và cản các gói tin vi phạm một cách cụ thể thì sao?

Code:
```sh
$IPT -A INPUT -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -m limit --limit 1/s -j LOG --log-prefix "INVALID_SERVICE_REQUEST: "
$IPT -A INPUT -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j DROP
```

Hai dòng trên là câu trả lời. Các gói tin TCP không mang SYN flag mà ở tình trạng NEW thì bị log và bị cản một cách cụ thể. Hai dòng này có thể được đưa vào phía trên dòng 32 (còn nhớ đến tính quan trọng với thứ tự của các luật?). Tất nhiên, tính cụ thể và hiệu năng sẽ được hình thành nếu áp đặt chúng ở đúng vị trí.

#### 8.2.3 Loại trừ các truy cập hợp lệ nhưng nguy hại {#823-loại-trừ-các-truy-cập-hợp-lệ-nhưng-nguy-hại}
Có lẽ bạn sẽ hỏi, tại sao các truy cập đã hợp lệ mà lại có thể nguy hại. Cho đến lúc này, chúng ta chỉ áp đặt các luật để cản những gói tin bất hợp lệ. Tuy nhiên, không nhất thiết các gói tin hợp lệ trên bình diện giao thức cũng hợp lệ trên bình diện tinh thần. Trường hợp điển hình nhất là phương thức xử dụng các gói tin hợp lệ để làm cạn kiệt tài nguyên của máy chủ.

Thử hình dung trường hợp 1000 truy cập đến máy chủ trong vòng vài giây chẳng hạn:

- Liệu máy chủ đủ sức đáp ứng hay không?
- Trong 1000 truy cập này, có bao nhiêu truy cập với "thiện ý" và bao nhiêu với "ác ý"?
- Làm sao phân biệt và xử lí những truy cập "ác ý" trong mớ 1000 truy cập ấy?

Trên thực tế, khó có thể phân biệt một cách chính xác các truy cập thiện ý hoặc ác ý nhưng chúng ta có thể biết được những truy cập thiện ý thường có biên độ nhất định -10-

##### 8.2.3.1 Giới hạn truy cập với "connection rate" {#8231-giới-hạn-truy-cập-với-connection-rate}
"Connection rate" có thể thực hiện bằng chọn lựa `-m limit` cho bất cứ giao thức nào. Chúng ta chỉ đề cập ở đây cho giao thức TCP và sẽ ứng dụng cho các giao thức khác theo ý muốn. Thử đổi dòng 32 từ:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
```

trở thành:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m limit --limit 3/s --limit-burst 5 -m state --state NEW -j ACCEPT
```

Chuỗi `-m limit --limit 3/s --limit-burst 3` dùng CONFIG_IP_NF_MATCH_LIMIT trên netfilter, một "match" trong gói căn bản và đã được tích hợp vào Linux kernel. "limit match" này ảnh hưởng lớn lao đến dòng lệnh trên bình diện giới hạn "connection rate". Chuỗi này ấn định các gói tin mang SYN flag từ một IP nào đó truy cập đến cổng dịch vụ của máy chủ ở tình trạng NEW. Trong chuỗi `-m limit --limit 3/s --limit-burst 3` này, khi ứng dụng trong dòng lệnh, một gói tin sẽ được xử lí theo cơ chế:

`--limit-burst` ấn định giá trị số lần (cho phép hoặc không cho phép) một gói tin được đi đến bước kế tiếp trong luật (`-j ACCEPT` hoặc `-j DROP` hoặc bất cứ "jump to" nào). Mỗi giá trị của `--limit-burst` là một "giấy phép", mỗi packet trùng với luật này sẽ dùng hết một "giấy phép". Khi `--limit-burst` bằng 0, gói tin trùng với luật đã hết "giấy phép", thì mọi gói tin mới đi vào dù có trùng với luật quy định hay không đều sẽ không thể "jump" đến target ACCEPT và do đó sẽ bị DROP bởi policy của firewall hoặc các luật đi theo sau. Vì lí do này, `--limit 3/s` chính là cơ chế "nạp" giấy phép lại cho `--limit-burst`. Chuỗi này có ý nghĩa là mỗi 1/3 giây, sẽ tăng `--limit-burst` lên 1, cho đến khi đạt giá trị tối đa ban đầu (= 3 trong trường hợp này) thì sẽ không tăng nữa.

Cụ thể hơn, tưởng tượng đang có một máy con nào đó truy cập vào máy chủ của chúng ta với tốc độ 50 packet/giây, có nghĩa là cứ 1/50 giây có một packet đi đến máy chủ. Rule trên sẽ xử lí như sau:

- Trong vòng (1/50)*5 = 1/10 giây đầu tiên, 5 giấy phép ban đầu đã được sử dụng hết, gọi thời điểm này là T1 (chẳng hạn). Từ thời điểm T1 trở đi cho đến thời điểm T1+1/3 giây, tất cả packet từ IP này truy cập vào máy chủ sẽ bị DROP.
- Tại thời điểm T1 + 1/3 giây, do qui định của chuỗi `--limit 3/s`, một giấy phép được nạp vào cho `--limit-burst`, nhưng gần như ngay tức khắc, giấy phép này được một packet của máy A sử dụng và do đó `--limit-burst` lại trở về 0 (tiếp tục hết "giấy phép"). Cứ tiếp tục như thế, sau 1/3 giây, sẽ có một packet được chấp nhận và chỉ 1 mà thôi nếu máy A cứ tiếp tục truy cập với tốc độ như trên vào máy chủ.

Nếu máy con ngừng truy cập vào máy chủ thì diễn biến sẽ như sau:
- Cứ sau 1/3 giây, một giấy phép sẽ được nạp vào `--limit-burst`, và vì bây giờ không còn packet nào được gửi đến do đó `--limit-burst` sẽ giữ nguyên giá trị. Cứ thể `--limit-burst` tăng dần cho đến khi chạm quy định ban đầu là 3 thì sẽ ngừng lại, "giấy phép" hoàn toàn ở tình trạng nguyên thuỷ. Trong thời gian `--limit-burst` tăng lại giá trị ban đầu, nếu máy A lại tiếp tục gửi packet thì những packet này sẽ sử dụng giấy phép trong limit-burst, và lại giảm limit-burst xuống, nếu limit-brust bằng 0 thì tất nhiên firewall sẽ tiếp tục cản các gói tin ở dạng này nếu vẫn tiếp tục vi phạm luật cho đến khi `--limit-burst` được giải toả (như đã giải thích).

Đây chỉ là một ví dụ minh hoạ ứng dụng `-m limit`. Bạn cần khảo sát số lượng truy cập đến dịch vụ nào đó trên máy chủ trước khi hình thành giá trị thích hợp cho `-m limit`. <span class="coc-highlight">Nên cẩn thận trường hợp một proxy server chỉ có một IP và có thể có hàng ngàn người dùng phía sau proxy; ghi nhận yếu tố này để điều chỉnh limit rate cho hợp lí.</span>

##### 8.2.3.2 Giới hạn truy cập với "connection limit" {#8232-giới-hạn-truy-cập-với-connection-limit}
"Connection limit" cần huy động đến CONFIG_IP_NF_MATCH_CONNLIMIT có từ patch-o-matic trên website chính của iptables http://www.iptables.org). Module này cần được tải và biên dịch -11- trước khi có thể hoạt động. Ứng dụng tính năng này trên dòng 32 như sau:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
```

trở thành:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -m connlimit ! --connlimit-above 2 -j ACCEPT
```

`-m connlimit ! --connlimit-above 2` quyết định tối hậu đến số phận các gói tin đi vào ngoài các áp đặt đi trước (như gói tin TCP phải mang flag SYN và phải ở tình trạng NEW). Tính linh động nằm ở giá trị đảo (!) phía trước `--connlimit-above 2`. Dòng lệnh này áp đặt thêm một tầng kiểm soát: các gói tin truy cập này đến từ một IP mà không nhiều hơn 2 xuất truy cập thì tiếp nhận. 3, 4 hoặc hơn xuất truy cập không thể xảy ra từ cùng một máy con (có cùng IP) đến máy chủ. Tính chất này khác hẳn tính chất "connection rate" đã trình bày trong phần 8.2.3.1, "connection limit" dựa trên tính đồng thời (concurrent) của giao thức TCP mà điều tác -12-

#### 8.2.4 Vấn đề độ dài của SYN packet {#824-vấn-đề-độ-dài-của-syn-packet}
Bạn có thật sự paranoid không? Nếu có thì tiếp tục theo dõi phần mở rộng này. Theo RFC 793, SYN packet không mang theo "payload" (dữ liệu) và nếu các hệ thống ứng dụng đúng theo RFC 793 thì SYN packet chỉ có chiều dài tối đa là ở khoảng 40 đến 60 bytes nếu bao gồm các tcp options. Dựa trên quy định này (hầu hết các ứng dụng trên mọi hệ điều hành đều tuân thủ theo quy định của RFC 793), chúng ta có thể hình thành một luật khác cho dòng 32 ở trên:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
```

trở thành:

Code:
```sh
$IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -m length --length 40:60 -j ACCEPT
```

Nếu cần, bạn vẫn có thể đưa vào một trong hai chọn lựa "connection rate" hoặc "connection limit" cho dòng lệnh trên để thắt chặt. Điều cần nói ở đây là giá trị -m length --length 40:60 ấn định chiều dài của gói tin SYN của giao thức TCP được firewall chúng ta tiếp nhận. Như đã đề cập ở trên, theo đúng quy định, gói SYN không mang dữ liệu cho nên kích thước của chúng không thể (và không nên) lớn hơn 40:60. Luật trên áp đặt một quy định rất khắc khe để loại trừ các gói SYN lại mang dữ liệu (và đặc biệt mang dữ liệu với kích thước lớn). Theo tôi thấy, những gói tin này rất hiếm thấy ngoại trừ trường hợp cố tình tạo ra hoặc thỉnh thoảng có dăm ba gói "lạc loài" ở đâu vào từ một hệ điều hành nào đó không ứng dụng đúng quy cách. Sử dụng luật này hay không là tùy mức khắc khe của bạn. Cách tốt nhất trước khi dùng, bạn nên thử capture các gói SYN cho suốt một ngày (hoặc nhiều) và mang về phân tích xem có bao nhiêu gói SYN thuộc dạng không cho phép, có bao nhiêu gói tin được xếp loại vào nhóm có chiều dài 40:60 bytes và từ đó mới đi đến quyết định cuối cùng.

### 8.3 Vấn đề thuộc giao thức UDP {#831-vấn-đề-thuộc-số-lượng-truy-cập-udp}
Giao thức UDP mang tính chất rất khác với TCP cho nên cơ chế điều hoạt và quản lí có những điểm khác biệt. Bởi UDP hoạt động trên căn bản lặp (interation) -13- nên đối với các gói tin thuộc giao thức này có hai điểm cần chú ý:

#### 8.3.1 Vấn đề thuộc số lượng truy cập UDP {#831-vấn-đề-thuộc-số-lượng-truy-cập-udp}
Bởi UDP là giao thức thuộc dạng "stateless" nên dịch vụ UDP trên máy chủ chỉ có thể nhận và "cố gắng" thoả mãn yêu cầu. Dịch vụ UDP trên máy chủ:

- Không có cách nào kiểm tra xem nguồn truy cập có thật sự hiện hữu hay không. Máy chủ cũng không thể phân biệt gói tin UDP đang đi vào là gói đang trả lời ngược lại (thuộc một xuất truy cập hiện có) hay một gói UDP hoàn toàn mới.
- Chỉ đơn giản "trả lời" và không cần theo dõi xem gói tin trả lời có đi đến đích hay không.

Dựa trên tính chất này, kẻ tấn công có thể tạo hàng loạt gói tin (1000 yêu cầu trong một giây chẳng hạn) đến một dịch vụ UDP. Dịch vụ này sẽ cần mẫn đặt các yêu cầu vào hàng chờ đợi (queue) và tuần tự xử lí. Tuy nhiên, "queue" của dịch vụ có giới hạn trên căn bản tài nguyên, liệu dịch vụ UDP này chứa được bao nhiêu yêu cầu trên "queue" trước khi máy chủ bị cạn kiệt? Hơn nữa, vì tính "stateless" này mà thông tin chuyển tải xuyên qua UDP nhanh hơn TCP rất nhiều, điều này lại càng tiện lợi cho việc "dội" một dịch vụ UDP trên máy. Trong trường hợp này, `-m limit` của iptables trở nên hết sức tiện dụng. Thử xem hai dòng 23, 24 trở thành:

Code:
```sh
$IPT -A INPUT -i $IF -p udp -s $NET --sport $port -d $IP --dport $port -m state --state NEW,ESTABLISHED -m limit --limit 2/s --limit-burst 2 -j ACCEPT
$IPT -A OUTPUT -o $IF -p udp -s $IP --sport $port -d $NET --dport $port -m state --state ESTABLISHED -m limit --limit 2/s --limit-burst 2 -j ACCEPT
```

Chắc chắn sẽ giúp cho dịch vụ DNS này có đủ thời gian và tài nguyên phục vụ các đòi hỏi về name một cách bình thường. Nên biết rằng, hầu hết các DNS server có thể lưu một bản "cache" cho những IP / Name đã được biên giải cho nên rất hiếm khi một DNS server nào đó đòi hỏi dịch vụ DNS trên máy chủ của chúng ta phải tiếp nhận hơn 2 yêu cầu trong một giây và liên tục 2 lần. Thật ra, giới hạn này vẫn còn rất "dễ chịu" cho một dịch vụ DNS. Tuy nhiên, với các dịch vụ khác cũng dùng giao thức UDP và phục vụ những dòng thông tin ở vận tốc cao (như streaming media chẳng hạn) thì giá trị `-m limit` trên cần được điều chỉnh cho thích hợp với nhu cầu này.

#### 8.3.2 Vấn đề thuộc thực tính của xuất truy cập UDP {#832-vấn-đề-thuộc-thực-tính-của-xuất-truy-cập-udp}
Kiểm tra thực tính truy cập cho UDP? Chắc hẳn bạn sẽ hỏi câu này vì ở trên tôi đề cập đến khía cạnh dịch vụ UDP trên máy chủ không có cách nào kiểm tra xem nguồn truy cập có thật sự hiện hữu hay không (nguồn địa chỉ IP). Vậy, giải pháp là sao đây? Phần lớn các cuộc tấn công nghiêm trọng có thể làm tê liệt một dịch vụ bằng giao thức UDP được tạo ra từ các IP giả mạo và các IP thuộc nhóm được IANA phân bố dùng làm IP cho nội mạng -14-. Nếu các địa chỉ dùng để tấn công là các địa chỉ thuộc nhóm public IP thì bạn chỉ có thể giao phó cho `-m limit` và `-m state` ở trên. Nếu `-m limit` được ấn định gắt gao hơn nữa sẽ cản bớt số lượng gói UDP "flood" dịch vụ.

Riêng với các yêu cầu truy cập từ các nhóm IP nội mạng (xem chú thích 14) thì việc lượt bỏ chúng khá đơn giản. Thật ra, việc lọc bỏ này không riêng gì cho giao thức UDP mà còn có thể ứng dụng cho mọi giao thức. Đoạn lệnh sau dùng để thắt chặt vấn đề này:

Code:
```sh
NON_NET="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/5 169.254.0.0/16 192.0.2.0/24"
for entry in $NON_NET; do
    $IPT -A INPUT -i $IF -s $entry -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_NET: "
    $IPT -A INPUT -i $IF -s $entry -j DROP
done
```

Biến `$NON_NET` trên có thể đưa vào nhóm biến được ấn định ở phần trên của firewall script và đoạn lặp "for/done" có thể nằm trên dòng 15 (trước luật đầu tiên ấn định ACCEPT). Dòng luật trong đoạn lặp không ấn định cụ thể giao thức (`-p`) và cũng không ấn định tình trạng (`-m state`) nên mọi giao thức và mọi tình trạng đều có tác dụng. Lệnh này trông rất đơn giản nhưng hàm chứa tính kiểm soát rất rộng -15-. Nếu bạn thích, thử tính xem có bao nhiêu địa chỉ cả thảy trong nhóm NON_NET này để hình dung một dòng lệnh đơn giản có thể loại bỏ bao nhiêu IP.

Điều căn bản là nên xem xét kỹ lưỡng trước khi quyết định chạy một dịch vụ UDP trên máy chủ, đặc biệt cho trường hợp một máy đơn vừa là firewall, vừa phải cung cấp dịch vụ thì càng cẩn thận hơn. Nguyên tắc bảo mật không khuyến khích máy chủ cung cấp dịch vụ cũng là firewall vì kiện toàn mô hình này cực kỳ khó khăn để bảo đảm hiệu năng và bảo mật.


### 8.4 Vấn đề thuộc giao thức ICMP {#84-vấn-đề-thuộc-giao-thức-icmp}
Giao thức ICMP là một giao thức rất tiện dụng trong các giềng mối hoạt động của mạng. Tuy nhiên, nó cũng là phương tiện căn bản dùng trong các quy trình tìm hiểu và tấn công. Có những loại ICMP không nên dùng trên mạng công cộng nếu bảo mật là vấn đề hàng đầu vì những loại ICMP này tiết lộ quá nhiều thông tin quan trọng của hệ thống chúng ta muốn bảo vệ. Hơn nữa, có những loại ICMP còn là phương tiện để đưa hệ thống chúng ta muốn bảo vệ vào tình trạng nguy hiểm. Ở đây chúng ta thử đưa ra hai vấn đề chính về việc xử lí ICMP cho máy chủ.

#### 8.4.1 Chọn lựa và giới hạn ICMP {#841-chọn-lựa-và-giới-hạn-icmp}
ICMP có 15 loại và mỗi loại có ít nhất là một code khác nhau. Riêng ICMP loại 3 có đến 15 code khác nhau. Vậy, chúng ta nên chọn và giới hạn ICMP nào? Sự chọn lựa này mang tính cá nhân vì mỗi người có cách nhìn khác nhau về ICMP. Riêng tôi, ICMP 0, 3, 4, 8 và 11 nên được dùng, số còn lại không nên cho phép ra vào vì chúng mang những tính chất ảnh hưởng đến vấn đề bảo mật cho máy chủ. Nếu đã chọn lựa cụ thể loại ICMP nào được dùng, tại sao không hình thành một luật cụ thể cho ICMP? Thử ứng dụng đoạn kế tiếp:

Code:
```sh
OK_ICMP="0 3 4 8 11"
for item in $OK_ICMP; do
    $IPT -A INPUT -i $IF -s $NET -p icmp --icmp-type $item -j ACCEPT
    $IPT -A OUTPUT -o $IF -s $IP -p icmp --icmp-type $item -j ACCEPT
done
```

Đoạn lặp trên thiết lập nhóm luật xử lí giao thức ICMP cho phép các loại ICMP trong biến `$OK_ICMP`. Thật ra nhóm luật trên chỉ mới giới hạn loại ICMP được dùng nhưng chưa có bất cứ cơ chế nào kiểm soát lượng lưu thông ICMP ra vào. Bởi vậy, muốn vững hơn thì nên đưa vào `-m limit` để tạo nên mức kiểm soát cụ thể:

Code:
```sh
$IPT -A INPUT -i $IF -s $NET -p icmp --icmp-type $item -m limit --limit 1/s --limit-burst 1 -j ACCEPT
$IPT -A OUTPUT -o $IF -s $IP -p icmp --icmp-type $item -m limit --limit 1/s --limit-burst 1 -j ACCEPT
```

`-m limit` trên áp đặt giá trị "rate" rất khắc khe: chỉ tiếp nhận một gói ICMP trong mỗi giây. Với giới hạn này, các cuộc dội ICMP (ICMP flood) gần như vô tác dụng.

#### 8.4.2 Cản ICMP hoặc cản ICMP "một nửa" {#842-cản-icmp-hoặc-cản-icmp-một-nửa}
ICMP được dùng làm bước đầu cho những cuộc khám phá một host/network. Có rất nhiều công cụ rà cổng (port scan) dựa trên hồi báo của ICMP để quyết định các bước khám phá kế tiếp. Những thủ thuật tìm hiểu "chữ ký hệ thống" (system foot-print) cũng trông cậy rất nhiều vào ICMP. Bạn có "paranoid"? Vậy thì hãy thử thắt chặt thêm xem sao.

##### 8.4.2.1 Cản ICMP {#8421-cản-icmp}
Mức độ cản ở đây chỉ dừng lại ở mức độ cản không cho các gói ICMP khởi tạo và đi vào từ bên ngoài. Máy chủ có thể khởi tạo các gói ICMP (trong giới hạn các loại ICMP cho phép thuộc biến `$OK_ICMP`) và các máy bên ngoài chỉ có thể "trả lời" các gói ICMP máy chủ tạo ra. Chức năng `-m state` một lần nữa hữu dụng cho trường hợp này:

Code:
```sh
$IPT -A INPUT -i $IF -s $NET -p icmp --icmp-type $item -m state --state ESTABLISHED -m limit --limit 1/s --limit-burst 1 -j ACCEPT
$IPT -A OUTPUT -o $IF -s $IP -p icmp --icmp-type $item -m state --state NEW,ESTABLISHED -m limit --limit 1/s --limit-burst 1 -j ACCEPT
```

Bạn có thể thấy gói tin đi vào xuyên qua chuỗi INPUT chỉ có thể được tiếp nhận ở tình trạng ESTABLISHED nhưng gói tin đi ra xuyên qua chuỗi OUTPUT thì có thể được tiếp nhận ở cả tình trạng NEW và ESTABLISHED. `-m state` hỗ trợ cho `-m limit` trong trường hợp này tạo nên các luật rất khắc khe cho ICMP. Có những quan điểm cho rằng quá khắc khe với ICMP không tiện dụng cho các hoạt động mạng; lựa chọn thắt chặt hay không là do quyết định của cá nhân bạn.

##### 8.4.2.2 Cản ICMP "một nửa" {#8422-cản-icmp-một-nửa}
Cản "một nửa" là sao nhỉ? Có ai đó hỏi (một là cản, hai là không, không thể có chuyện "một nửa" ở đây). Vậy mà có cách cản "một nửa" nếu bạn thích những ứng dụng "fancy". Bạn còn nhớ `-m length` ở phần 8.2.4? Đây chính là chìa khoá của câu trả lời:

Code:
```sh
$IPT -A INPUT -i $IF -s $NET -p icmp --icmp-type $item -m length 42:43 -m limit --limit 1/s --limit-burst 1 -j ACCEPT
$IPT -A OUTPUT -o $IF -s $IP -p icmp --icmp-type $item -m length 42:43 -m limit --limit 1/s --limit-burst 1 -j ACCEPT
```

Thông thường tiện dụng ping gởi đi một gói dữ liệu nào đó để host được ping theo mặc định -16- . Nếu firewall được ấn định như trên, chỉ có gói tin ICMP nào có chiều dài trong khoảng 42 đến 43 bytes thì mới tiếp nhận. Điều này có nghĩa, khi một ai đó thử ping theo mặc định trên MS-DOS prompt hoặc trên một *nix console chắc chắn sẽ không có kết quả vì không thoả mãn kích thước gói tin đã ấn định. Tính "mở một nửa" nằm ở kích thước cụ thể của gói tin. Chỉ có bạn biết kích thước gói tin là bao nhiêu để ping vào máy chủ thành công (đây chính là tính "mở"); đối với mọi người dùng khác họ sẽ không ping vào máy chủ thành công vì hầu hết họ dùng kích thước gói tin theo mặc định (đây chính là tính "đóng").

Có thể có những cá nhân kiên nhẫn ngồi "rà" từng kích thước gói tin hoặc viết một đoạn script để thực hiện quy trình "rà" này nhưng chuyện này chỉ xảy ra nếu cá nhân ấy nghi ngờ máy chủ chúng ta ấn định kích thước gói tin cụ thể. Đối với người dùng bên ngoài, khả năng cản hoàn toàn và cản "một nửa" ở hai phần 8.4.2.1 và 8.4.2.2 không khác gì nhau vì đơn giản không thể "ping" ngay từ đầu. Với các ứng dụng kiểm soát ICMP trên, mối đe doạ của các dạng tấn công dựa trên ICMP hầu như vô hiệu hoá. Tùy ý bạn mà ứng dụng.

## 9. Thử nghiệm {#9-thử-nghiệm}
Bài viết cho case 2 này sẽ không đưa ra cụ thể quy trình thử nghiệm. Nếu bạn đã đọc kỹ và chú ý từng chi tiết được đưa ra ở trên, bạn hẳn nhận ra có vô số điều cần và nên thử nghiệm. Tính chất phòng bị và bảo vệ máy chủ được phân tích cụ thể cho từng giao thức ở trên; hãy để tính sáng tạo của mình làm việc cho công tác thử nghiệm vậy :smile:.

## 10. Kết luận {#10-kết-luận}
Bài viết phân tích case 2 này không trực tiếp phục vụ mục đích tạo một firewall script có sẵn để người dùng sử dụng ngay. Bài viết này mượn iptables firewall script như một thứ lí do để:

- Đi vào tính năng của iptables/netfilter.
- Đi vào những tình huống có thể xảy ra.
- Mở rộng cách nhìn bảo mật xuyên qua tính năng và hoạt động của một số giao thức thường dùng.

Với tinh thần bảo mật, bài viết quy tụ về một điểm chính: chỉ cho phép lưu thông hợp pháp. Phần bị chú bên dưới có lẽ không chỉ đơn thuần là bị chú mà là một số phân tích mở rộng những điều được phân tích trong thân bài. Nên xem case 2 này là một phương tiện để khám phá và nên khởi đầu mọi khúc mắc bằng câu hỏi "**tôi có vấn đề này**" và thử hình thành câu hỏi kế tiếp "**tôi có thể làm gì để giải quyết**". <span class="coc-highlight">Hay nói một cách khác, bạn cần hiểu rõ vấn đề (problem) trước khi nghĩ đến giải pháp (solution).</span>

## Bị chú {#bị-chú}
-1- Authoritative DNS: là name server có thẩm quyền trả lời các thỉnh cầu về tên của một domain và các host trong domain này ở cấp độ chủ quyền. Xem thêm trang http://en.wikipedia.org/wiki/DNS) để tham khảo "authoritative DNS".

-2- Cách gọi "máy chủ" ở đây để chỉ cho máy đơn có hỗ trợ dịch vụ mà chúng ta đang phân tích. Đừng nhầm lẫn với một máy chủ nào khác trong case 2 này.

-3- Giao thức cho các cổng dịch vụ như 80, 443, 25, 110, 22 cho ví dụ trên mang tính chất tương tự nhau trên phương diện kết nối. Ví dụ, một client nào đó từ Internet muốn truy cập một trong các cổng dịch vụ trên, giữa client ấy và máy chủ sẽ đi xuyên qua quy trình bắt tay (3 way handshake) bình thường và thiết lập xuất truy cập (connection). Xuất truy cập này không đòi hỏi huy động thêm một hoặc nhiều cổng dịch vụ khác hoặc giao thức khác để hoàn tất xuất truy cập. Giao thức như FTP chẳng hạn, ngoài quy trình bắt tay bình thường xảy ra ở cổng 21 thuộc máy chủ còn phải huy động thêm một cổng khác cho dữ liệu (cổng 20 nếu dùng active ftp hoặc `$HI_PORTS` nếu dùng passive ftp). Những giao thức tương tự như FTP không có cùng tính chất như các cổng đưa ra trong ví dụ trên.

-4- `--syn` là cách viết tắt của `--tcp-flags SYN,RST,ACK SYN`. `--tcp-flags` là một chọn lựa trong iptables để xử lí các gói tin với giao thức TCP. Một cách tổng quát mà nói, `--tcp-flags` có hai giá trị tách rời bởi khoảng trống. Với ví dụ này, giá trị thứ nhất là SYN,RST,ACK và giá trị thứ hai là SYN. Giá trị thứ nhất là danh sách các TCP flags bạn muốn iptables duyệt và giá trị thứ nhì là danh sách các TCP flags được ứng hiệu (được iptables kiểm soát và quyết định cho vào hay bị cản dựa trên sự hiện diện của các flags này). Để xác định các TCP flags thích ứng, bạn cần biết rõ mục đích và kết quả của các flags này. Thông thường các truy cập hợp lệ thường khởi đầu bằng `--tcp-flags SYN,RST,ACK SYN` như ở đây, trong đó các TCP packets dùng để khởi tạo một xuất truy cập phải chứa SYN flag. Xem thêm tài liệu packet-filtering-HOWTO trên website http://www.iptables.org và tham khảo một cuốn sách hay về TCP/IP như cuốn TCP Illustrated I của Richard Stevens chẳng hạn.

-5- Khi có ý định cung cấp dịch vụ DNS trên máy chủ, bạn cần kiện toàn dịch vụ này để có thể đáp ứng mọi yêu cầu hợp lệ. Thông thường dịch vụ DNS lắng nghe trên cổng 53 UDP đủ phục vụ name resolution cho hầu hết các trường hợp vì hiếm khi chiều dài của gói tin (cho các request/repsond) với giao thức DNS lớn hơn 512 bytes. Nếu chiều dài gói tin này hơn 512 bytes thì dịch vụ DNS của máy chủ phải đi xuyên qua cổng 53 TCP và trường hợp này rất hiếm thấy với các thông tin hợp lệ và bình thường (ngoại trừ trường hợp zone transfer giữa DNS). iptables trong bài viết này chỉ đóng vai trò kiểm soát các gói tin đi ra và đi vào cho dịch vụ DNS đã được hoàn chỉnh. Kiện toàn bảo mật cho DNS server ở cấp độ "application layer" là vấn đề cần thiết và quan trọng. Vấn đề này nằm ngoài phạm vi bài viết về tính năng của iptables.

-6- Các tình trạng NEW,RELATED,ESTABLISHED,VALID được theo dõi trong bảng theo dõi của netfilter (hay còn được gọi là conntrack table) có ý nghĩa và ứng dụng rộng hơn các "state" của TCP socket connection (được thấy khi chạy netstat) và rất cụ thể cho netfilter. Một gói tin ở dạng NEW đối với netfilter mang ý nghĩa rộng hơn một gói tin mang SYN flag thuộc giao thức TCP (mặc dù trên bình diện TCP, SYN packet tương tự như NEW packet vì chỉ có gói tin TCP ở tình trạng NEW mới mang flag SYN).

Ví dụ, một gói tin TCP mang flag là ACK chưa hề có trong conntrack table đi vào iptables firewall:

- Việc đầu tiên netfilter sẽ ghi nhận: đây là một gói tin "có thể" thuộc dạng NEW và nếu firewall của chúng ta có chứa một luật (trực tiếp hay gián tiếp) chỉ định rằng firewall không thể tiếp nhận các gói tin TCP thuộc dạng NEW mà lại mang TCP flag là ACK thì
- netfilter sẽ xếp loại gói tin này thành INVALID.

Đối với các giao thức "stateless" như UDP, ICMP thì tính ứng hiệu với các tình trạng NEW,RELATED,ESTABLISHED,VALID rất khác so với TCP. Ví dụ, UDP không hề có flags hay sequence number như TCP nên một gói tin UDP chưa hề có trong conntrack table sẽ được xếp loại là NEW và nếu nó thuộc một xuất truy cập đã ghi nhận thì nó được xếp loại ESTABLISHED.

Conntrack (hoặc Connection tracking) là một chức năng rất mạnh và linh động của netfilter. Nếu dùng `-m state` ấn định connection state song song với tính chất của từng loại giao thức của các gói tin thì có thể tạo ra các luật hết sức vững vàng và hiệu năng cho firewall.

-7- High Availability (HA), một thuật ngữ kỹ thuật. Một dịch vụ ở dạng high availability là dịch vụ hiện hữu ở mức cao độ. High availability chỉ thường thấy có (và thật sự có) ở những môi trường enterprise, nơi sự bền bỉ và sự hiện hữu của dịch vụ là đòi hỏi tối quan trọng.

-8- Dấu chấm thang (!) đứng trước giá trị nào đó sẽ nghịch đảo (negate) ý nghĩa của giá trị ấy. Cách dùng này có sẵn trong iptables và rất phổ biến trong các "shell" trên *nix và các ngôn ngữ lập trình nói chung.

-9- Ở đây tôi cố gắng tránh việc cung cấp quá nhiều thông tin cho mỗi chọn lựa có thể ứng dụng. Hai ví dụ trên nhằm mục đích minh hoạ mức uyển chuyển và linh động iptables cho phép chúng ta hình thành các luật ứng dụng cho firewall. Để khai triển góc độ này, kiến thức về giao thức TCP và ứng dụng cụ thể cho nhu cầu của từng trường hợp là hai yếu tố tối quan trọng để hình thành các luật ở cấp độ này.

-10- Vấn đề này thuộc phạm vi "trend analysis" các dạng truy cập đến một dịch vụ. Đây là một công tác phức tạp, đòi hỏi công tác quan sát và phân tích. Tổng quát mà nói, một client truy cập vào một trang web trung bình thường mất vài giây và người ấy thường dừng lại ở trang này ít nhất là vài chục giây để lượt qua xem thông tin ở trang này có phù hợp với nhu cầu hay không. Trọn bộ quá trình truy cập mang tính "thiện ý" này có thể kéo dài ít nhất là trên dưới một phút trước khi người dùng ấy tiếp tục gởi yêu cầu truy cập mới. Bằng cách thu thập và phân tích biên độ truy cập của các người dùng, chúng ta có thể hình thành một con số tương đối cho giá trị truy cập thuộc phạm vi "thiện ý" ở đây.

-11- Vá Linux kernel và iptables cho mục đích dùng thêm các module (không thuộc nhóm base của netfilter) rất đơn giản. Sơ lược các bước như sau:

1. Tải gói patch-o-matic-ng-<yyyymmdd>.tar.bz2 từ website của iptables http://www.iptables.org).
2. Xả nén gói vá này ở nơi nào đó thích hợp.
3. Chuyển vào thư mục chứa mã nguồn Linux và chạy: `make clean mrproper` để dọn dẹp những object cũ có thể tạo trở ngại trước khi vá.
4. Chuyển vào thư mục chứa mã nguồn iptables và chạy: `make distclean`
5. Chuyển vào thư mục chứa các miếng vá sau khi xả nén xong (bước trên).
6. Chạy lệnh: `KERNEL_DIR=<path_to_kernel_src> IPTABLES_DIR=<path_to_iptables_src> ./runme connlimit`. Trong đó connlimit chính là miếng vá cần thiết.
7. Biên dịch lại Linux kernel (tham khảo thêm series 4 bài "Tái biên dịch Linux kernel ở: http://www.diendantinhoc.net/?cat=tute_nix_compilekernel và các bài tiếp theo).
8. Tái khởi động máy sau khi biên dịch Linux kernel hoàn tất và thành công.
9. Chuyển vào thư mục chứa mã nguồn của iptables (đã được patch ở trên) và tái biên dịch lại iptables. Xem thêm chi tiết trong hồ sơ INSTALL có trong thư mục chứa mã nguồn của iptables.

-12- Giao thức TCP mang tính đồng thời (concurrent). Mỗi dịch vụ TCP đang hoạt động ở tình trạng "lắng nghe" (LISTEN) trên một cổng dịch vụ nào đó. Tình trạng này duy trì cho đến khi nào dịch vụ này được tắt bỏ hoặc bị tắt bỏ (vì bị treo, chẳng hạn).

Cứ mỗi xuất truy cập từ một máy con vào dịch vụ TCP trên server của chúng ta sẽ:

- Được tạo ra một socket riêng biệt và socket này tồn tại cho đến khi xuất truy cập giữa máy con và máy chủ kết thúc.
- Mỗi xuất truy cập mang cổng nguồn (source port) khác nhau trên máy con và,
- Máy chủ phải có trách nhiệm phục vụ từng xuất truy cập trên từng cổng của máy con.


Dựa trên tính chất này, chúng ta thấy một máy con có thể đòi hỏi nhiều xuất truy cập cùng một lúc và máy chủ có thể đáp ứng yêu cầu này theo đúng tính chất hoạt động của TCP. Tuy nhiên, điểm cần đưa ra ở đây thuộc phạm trù bảo mật là, nếu máy con yêu cầu nhiều xuất truy cập mang tính "ác ý" (như một dạng DoS) chẳng hạn thì sao? Tình trạng có thể xảy ra:

- Máy chủ vận động nhiều process để tạo các socket đáp ứng máy con.
- Máy chủ có thể bị cạn kiệt tài nguyên dự trữ để tạo socket.
- Dịch vụ được yêu cầu truy cập có thể bị mất hiệu năng vì không đáp ứng kịp với quá nhiều yêu cầu.
- Các dịch vụ liên hệ bị treo hoặc không thể tiếp tục hoạt động vì tài nguyên trên máy bị cạn kiệt.
- Các máy con khác không thể truy cập máy chủ vì máy chủ không còn khả năng đáp ứng,
- Và điều tệ hại nhất là máy chủ bị hoàn toàn tê liệt vì quá tải.

Nói một cách công bằng, dịch vụ trên máy của cố gắng đáp ứng các yêu cầu theo đúng chức năng nhưng vì không đủ tài nguyên nên phải dẫn đến tình trạng trên. Vậy, bao nhiêu tài nguyên thì đủ cho máy chủ? Con số này phải được hình thành từ quá trình theo dõi và đúc kết số lần truy cập, tầng số truy cập... trên máy chủ. Trên bình diện bảo mật, firewall có thể dùng để trợ giúp các dịch vụ bằng cách hạn chế các xuất truy cập "concurrent".

-13- Giao thức UDP mang tính lặp (iteration). Mỗi dịch vụ UDP đang hoạt động trên máy chỉ tiếp nhận yêu cầu từ client ở một cổng (thay vì mở ra socket mới như TCP). Hầu hết dịch vụ UDP trên máy chủ ở trong trạng thái "ngủ" (sleep) cho đến khi một client nào đó gởi yêu cầu truy cập đến, dịch vụ này mới "thức dậy" để trả lời client. Nếu có nhiều client yêu cầu cùng một lúc, các yêu cầu này được sắp hàng và dịch vụ UDP này sẽ trả lời tuần tự nó đã tiếp nhận từng yêu cầu cho đến khi hoàn tất. Header của UDP rất đơn giản so với TCP, hoàn toàn không có cơ chế để kiểm tra đường đi, lối về của các gói tin ngoài thông tin cổng nguồn và cổng đích (source port and destination port). Bởi thế, kiểm tra và quản lí các gói tin UDP nằm ở một bình diện hoàn toàn khác TCP.

-14- Nhóm private IP cho nội mạng, đôi khi còn gọi là "non-routable IP", ám chỉ các IP này không thể route ra ngoài mạng công cộng (thật tế chúng vẫn có thể route được, nhưng chỉ trong nội mạng). Các nhóm private IP này gồm có:

| Class      | Range               |
| -----------| --------------------|
| Class A    | 10.0.0.0/8          |
| Class B    | 172.16.0.0/12       |
| Class C    | 192.168.0.0/16      |
| Class D    | 224.0.0.0/4         |
| Class E    | 240.0.0.0/5         |
| Link Local | 169.254.0.0/16      |
| Test Net   | 192.0.2.0/24        |

IP từ các nhóm này không thể xuất hiện trên mạng công cộng (public network) và tất nhiên không nên cho phép đi vào hệ thống máy chủ. Tham khảo thông tin từ website IANA để nắm thêm chi tiết quy định các network class trên.

-15- Đây chỉ là một đề nghị, hay nói đúng hơn là một chia xẻ từ kinh nghiệm cá nhân. Để hình thành các luật firewall gọn gàng, súc tích và chặt chẽ, có hai nguyên tắc cần nhớ:

- **Luật nào cho phép thì phải cụ thể tối đa.**
- **Luật nào ngăn cản thì phải tổng quát hết mức.**

Để cho phép các gói tin đi vào (hoặc đi ra) và chỉ cho phép những gói tin nào thoả mãn yêu cầu của chúng ta thì luật cho phép phải càng cụ thể càng tốt vì nó loại bỏ những những sơ sót có thể xảy ra khi "cho phép". Trong khi đó, để ngăn cản các gói tin đi vào (hoặc đi ra) thì luật ngăn cản nên tổng quát và bao trùm một tập họp những tình huống, điều kiện mang tính chất tương tự.

-16- Kích thước mặc định của gói tin ICMP gởi đi từ tiện ích "ping" có giá trị tùy theo ứng dụng của hệ điều hành. Ví dụ Windows ping dùng 32 bytes theo mặc định, *nix nói chung dùng 56 bytes. Để ping với kích thước gói tin theo ý muốn thì:

- Trên windows: dùng thông số `-l` (`ping -l <size> <host>`)
- Trên *nix: dùng thông số `-s` (`ping -s <size> host>`)

## Tổng kết đoạn script case 2 {#tổng-kết-đoạn-script-case-2}
Code:
```sh
# các thông số cần thiết
IF=`/sbin/route | grep -i 'default' | awk '{print$8}'`
IP=`/sbin/ifconfig $IF | grep "inet addr" | awk -F":" '{print$2}' | awk '{print $1}'`
IPT="/usr/local/sbin/iptables"
NET="any/0"
DNS="xxx.xxx.xxx.xxx yyy.yyy.yyy.yyy.yyy"
SERV_TCP="22 25 80 443 110"
SERV_UDP="53 123"
HI_PORTS="1024:65535"
NON_NET="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/5 169.254.0.0/16 192.0.2.0/24"
OK_ICMP="0 3 4 8 11"

# quy chế mặc định
$IPT -F
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# xử lí gói tin đi từ nhóm IP không dành cho mạng công cộng
for entry in $NON_NET; do
    $IPT -A INPUT -i $IF -s $entry -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_NET: "
    $IPT -A INPUT -i $IF -s $entry -j DROP
done

# xử lí gói tin ở tình trạng INVALID cho mọi giao thức
$IPT -A INPUT -m state --state INVALID -m limit --limit 1/s -j LOG --log-prefix "INVALID_STATE: "
$IPT -A INPUT -m state --state INVALID -j DROP

# xử lí mạo danh IP của firewall
$IPT -A INPUT -i $IF -s $IP -d $IP -m limit --limit 1/s -j LOG --log-prefix "SPOOFING: "
$IPT -A INPUT -i $IF -s $IP -d $IP -j DROP

# xử lí một số tcp flags không hợp lệ
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -s $NET -m limit --limit 1/s -j LOG --log-prefix "SYN-FIN: "
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -s $NET -j DROP
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -s $NET -m limit --limit 1/s -j LOG --log-prefix "FIN-RST: "
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -s $NET -j DROP

for entry in $DNS; do
    $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $HI_PORTS -d $entry --dport 53 -m state --state NEW -j ACCEPT
    $IPT -A INPUT -i $IF -p udp -s $entry --sport 53 -d $IP --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
done

# ấn định chế độ UDP
for port in $SERV_UDP; do
    if test $port -eq 53; then
        $IPT -A INPUT -i $IF -p udp -s $NET --sport $port -d $IP --dport $port -m state --state NEW,ESTABLISHED -m limit --limit 2/s --limit-burst 2 -j ACCEPT
        $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $port -d $NET --dport $port -m state --state ESTABLISHED -m limit --limit 2/s --limit-burst 2 -j ACCEPT
    else
        $IPT -A INPUT -i $IF -p udp -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j ACCEPT
        $IPT -A OUTPUT -o $IF -p udp -s $IP --sport $port -d $NET --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
    fi
done

# ấn định chế độ TCP
for port in $ SERV_TCP; do
    # xử lí các yêu cầu truy cập không hợp lệ
    $IPT -A INPUT -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -m limit --limit 1/s -j LOG --log-prefix "INVALID_SERVICE_REQUEST: "
    $IPT -A INPUT -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state NEW -j DROP
    $IPT -A INPUT -i $IF -p tcp --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m limit --limit 3/s --limit-burst 5 -m state --state NEW -j ACCEPT
    $IPT -A OUTPUT -o $IF -p tcp ! --syn -s $IP --sport $port -d $NET --dport $HI_PORTS -m state --state ESTABLISHED -j ACCEPT
    $IPT -A INPUT -i $IF -p tcp ! --syn -s $NET --sport $HI_PORTS -d $IP --dport $port -m state --state ESTABLISHED -j ACCEPT
done

# ấn định chế độ ICMP
for item in $OK_ICMP; do
    $IPT -A INPUT -i $IF -s $NET -p icmp --icmp-type $item -m length 42:43 -m limit --limit 1/s --limit-burst 1 -j ACCEPT
    $IPT -A OUTPUT -o $IF -s $IP -p icmp --icmp-type $item -m length 42:43 -m limit --limit 1/s --limit-burst 1 -j ACCEPT
done

# nhóm luật dọn dẹp
$IPT -A INPUT -i $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_INPUT: "
$IPT -A INPUT -i $IF -d $IP -j DROP
$IPT -A OUTPUT -o $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_OUTPUT: "
$IPT -A OUTPUT -o $IF -d $IP -j DROP
$IPT -A FORWARD -i $IF -d $IP -m limit --limit 1/s -j LOG --log-level 5 --log-prefix "BAD_FORWARD: "
$IPT -A FORWARD -i $IF -d $IP -j DROP
```

hnd, vninformatics.com / diendantinhoc.net - 23/07/2004

- Cập nhật 30/1/2005: chi tiết diễn giải `--limit` và `--limit-burst` theo đề nghị và phân tích của thaidn (aka mrro), cám ơn đóng góp của thaidn.

Tác giả: Conmale(hnd)
Nguồn: www.diendantinhoc.net
