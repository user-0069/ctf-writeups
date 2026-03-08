## Phân tích (chưa giải được) 
Plaintext được đưa vào `cipher` được pad tới 80 bytes "\x00" ở đầu cho ta thông tin tới 640 bit của `stream()` và `keystream`=`plaintext`^`ciphertext`.\
Đề bài cho `cipher` được tạo từ 9 cái `LFSR` nhỏ, mình cố gắng đi tìm chu trình hoặc độ phi tuyến của từng "thanh" `LFSR` nhỏ với key ngẫu nhiên. Gọi các thanh là L0 đến L8. 
### Các thanh L1,L2,L3,L4
Dù L1,L2,L3 dù trông N khá to nhưng thực chất độ phi tuyến rất thấp:
```
import secrets
from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey

# --- THÔNG SỐ CƠ BẢN ---
Ns = [14, 32, 24, 48, 8, 8, 8, 8, 10]
MASKS = [1959, 3487505359, 12175963, 144894747199363, 39, 101, 99, 43, 579]
Filters = [
    43673535323473607050899647551732188151,
    69474900172976843852504521249820447513188207961992185137442753975916133181030,
    28448620439946980695145546319125628439828158154718599921182092785732019632576,
    16097126481514198260930631821805544393127389525416543962503447728744965087216,
    7283664602255916497455724627182983825601943018950061893835110648753003906240,
    55629484047984633706625341811769132818865100775829362141410613259552042519543,
    4239659866847353140850509664106411172999885587987448627237497059999417835603,
    106379335904610565198575784689340408012917012758379923896044369424798179675586
]

def extract(x, b):
    res = 0
    for i in range(len(b)): res |= ((x >> int(b[i])) & 1) << i
    return res

def blur(x, i): return (int(Filters[i]) >> int(x)) & 1

def get_bits(idx, seed, length):
    n, mask = int(Ns[idx]), int(MASKS[idx])
    state = int(seed & ((1 << n) - 1))
    bits = []
    for _ in range(length):
        if idx == 1: res = state & 1
        elif idx == 2: res = blur(extract(state, [20, 2, 16, 11, 1, 23, 22, 8]), 1)
        elif idx == 3: res = blur(extract(state, [1, 46, 21, 7, 43, 0, 27, 39]), 2)
        elif idx == 4: res = blur(extract(state, [1, 3, 7, 4, 5, 0, 6, 2]), 3)
        bits.append(res)
        
        f = (state & mask).bit_count() & 1
        state = (state >> 1) | (f << (n - 1))
    return bits

print("="*50)
print("[*] ĐO LINEAR COMPLEXITY BẰNG BERLEKAMP-MASSEY")
print("="*50)

# Lấy 2000 bit là đủ an toàn để BM hội tụ (Định lý: Cần 2L bit)
TEST_LENGTH = 2000 

for idx in [1, 2, 3, 4]:
    seed = secrets.randbits(Ns[idx])
    
    # 1. Sinh chuỗi bit
    bits = get_bits(idx, seed, TEST_LENGTH)
    
    # 2. Đưa vào trường hữu hạn GF(2)
    seq = [GF(2)(b) for b in bits]
    
    # 3. Chạy thuật toán Berlekamp-Massey
    poly = berlekamp_massey(seq)
    degree = poly.degree()
    
    print(f"[+] Thanh L{idx}:")
    print(f"    - Kích thước state gốc : {Ns[idx]} bit")
    print(f"    - Bậc đa thức BM đo được: {degree} biến")
    print("-" * 30)
```
###### Generate by Gemini
```
==================================================
[*] ĐO LINEAR COMPLEXITY BẰNG BERLEKAMP-MASSEY
==================================================
[+] Thanh L1:
    - Kích thước state gốc : 32 bit
    - Bậc đa thức BM đo được: 31 biến
------------------------------
[+] Thanh L2:
    - Kích thước state gốc : 24 bit
    - Bậc đa thức BM đo được: 24 biến
------------------------------
[+] Thanh L3:
    - Kích thước state gốc : 48 bit
    - Bậc đa thức BM đo được: 62 biến
------------------------------
[+] Thanh L4:
    - Kích thước state gốc : 8 bit
    - Bậc đa thức BM đo được: 63 biến
------------------------------
```
Nếu đặt các bit là các ẩn để giải phương trình, thì những thanh này dùng rất ít biến so với 640 bits thông tin của keystream()

### Các thanh L5,L6,L7
Các thanh nhỏ này (n=8) hơn trong bài thì đều được tinh chỉnh để độ phi tuyến tương đối cao. 3 thanh này cùng có bậc đa thức BM đo được gần với $2^n$. Tuy nhiên trong source của
`cipher` thì 3 thanh này được "gộp chung" thành `u`:
```
def bit(self):
        x = blur(extract(self.lfsrs[0].state, [5, 9, 1, 0, 4, 11, 13]), 0)
        y = self.lfsrs[1].state & 1
        z = blur(extract(self.lfsrs[2].state, [20, 2, 16, 11, 1, 23, 22, 8]), 1)
        w = blur(extract(self.lfsrs[3].state, [1, 46, 21, 7, 43, 0, 27, 39]), 2)
        v = blur(extract(self.lfsrs[4].state, [1, 3, 7, 4, 5, 0, 6, 2]), 3)
        u = blur(self.lfsrs[5].state, 4) ^ blur(self.lfsrs[6].state, 5) ^ blur(self.lfsrs[7].state, 6)
        t = blur(extract(self.lfsrs[8].state, [5, 8, 9, 3, 1, 0, 2, 4]), 7)
        for lfsr in self.lfsrs: lfsr()
        return x ^ y ^ z ^ w ^ v ^ u ^ t
```
Và khi ta thử chạy Berlekamp Massey với L5^L6^L7 thì:
```
import secrets
from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey

# --- THÔNG SỐ CƠ BẢN ---
Ns = [14, 32, 24, 48, 8, 8, 8, 8, 10]
MASKS = [1959, 3487505359, 12175963, 144894747199363, 39, 101, 99, 43, 579]
Filters = [
    43673535323473607050899647551732188151,
    69474900172976843852504521249820447513188207961992185137442753975916133181030,
    28448620439946980695145546319125628439828158154718599921182092785732019632576,
    16097126481514198260930631821805544393127389525416543962503447728744965087216,
    7283664602255916497455724627182983825601943018950061893835110648753003906240,
    55629484047984633706625341811769132818865100775829362141410613259552042519543,
    4239659866847353140850509664106411172999885587987448627237497059999417835603,
    106379335904610565198575784689340408012917012758379923896044369424798179675586
]

def blur(x, i): return (int(Filters[i]) >> int(x)) & 1

def get_L567_combined_bits(s5, s6, s7, length):
    # Khởi tạo trạng thái
    state5 = int(s5 & ((1 << 8) - 1))
    state6 = int(s6 & ((1 << 8) - 1))
    state7 = int(s7 & ((1 << 8) - 1))
    
    bits = []
    for _ in range(length):
        # Đầu ra là XOR của 3 hàm blur
        out = blur(state5, 4) ^ blur(state6, 5) ^ blur(state7, 6)
        bits.append(out)
        
        # Nhảy step cho L5
        f5 = (state5 & MASKS[5]).bit_count() & 1
        state5 = (state5 >> 1) | (f5 << 7)
        
        # Nhảy step cho L6
        f6 = (state6 & MASKS[6]).bit_count() & 1
        state6 = (state6 >> 1) | (f6 << 7)
        
        # Nhảy step cho L7
        f7 = (state7 & MASKS[7]).bit_count() & 1
        state7 = (state7 >> 1) | (f7 << 7)
        
    return bits

print("="*50)
print("[*] ĐO LINEAR COMPLEXITY CỤM GỘP L5 ^ L6 ^ L7")
print("="*50)

# Lấy 2000 bit để đảm bảo bao phủ xa hơn mức 256
TEST_LENGTH = 2000 

# Random 3 seed bất kỳ cho L5, L6, L7
seed5 = secrets.randbits(8)
seed6 = secrets.randbits(8)
seed7 = secrets.randbits(8)

print(f"[*] Đang test với các Seed: L5={seed5}, L6={seed6}, L7={seed7}")

# Sinh chuỗi gộp
bits = get_L567_combined_bits(seed5, seed6, seed7, TEST_LENGTH)

# Chuyển vào GF(2) và ném cho Berlekamp-Massey
seq = [GF(2)(b) for b in bits]
poly = berlekamp_massey(seq)
degree = poly.degree()

print(f"[+] Kích thước không gian gốc (3 thanh 8-bit): 2^24 (~16.7 triệu trường hợp)")
print(f"[+] Bậc tuyến tính (BM) thực tế thu được    : {degree} biến")
print("="*50)
```
###### Generated by Gemini
```
==================================================
[*] ĐO LINEAR COMPLEXITY CỤM GỘP L5 ^ L6 ^ L7
==================================================
[*] Đang test với các Seed: L5=79, L6=95, L7=63
[+] Kích thước không gian gốc (3 thanh 8-bit): 2^24 (~16.7 triệu trường hợp)
[+] Bậc tuyến tính (BM) thực tế thu được    : 254 biến
==================================================
```
Vậy sau khi gộp vào thì độ phi tuyến vẫn tương đương các thanh đơn lẻ (do số bit vẫn cố định là 8, có lẽ vậy)
Tính đến đây thì số lượng biến cần dùng để giải key vẫn khá nhỏ so với 640!

### Thanh L0 và L8
Đây có vẻ là 2 thanh khó nhất:
* dù L8 có thể bruteforce key được nhưng vẫn còn thanh L0 không có thông tin. Chuyển về hệ phương trình thì số biến cũng khoảng $2^{10} > 640$ 
* còn L0 thì vừa có $n$ to và cũng có độ phi tuyến lớn

Không biết tiếp kiểu j :'((
## Cảm xúc
Khó quá @_@

