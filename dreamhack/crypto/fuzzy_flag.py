from pwn import *
import ast
import string
#context.log_level = 'debug'
io=remote('host8.dreamhack.games', 19563)
arr=ast.literal_eval(io.recvline().strip().decode())
max=arr
min=arr
con=1
io.close()
while (con):
    io=remote('host8.dreamhack.games', 19563)
    arr=ast.literal_eval(io.recvline().strip().decode())
    io.close()
    max=[max[i] if max[i]>arr[i] else arr[i] for i in range(len(arr))]
    min=[min[i] if min[i]<arr[i] else arr[i] for i in range(len(arr))]
    con=0
    for i in range(len(arr)):
        if (max[i]-min[i]+ 1 < len(string.ascii_letters)):
            con=1
            break
print(bytes(min))
#YISF{my_two_s0luti0ns:_0ne_where_the_average_0f_rand0m_numbers_remains_constant,_and_an0ther_where_the_upper_and_1ower_bounds_of_random_numbers_remain_c0nstant.What_method_d1d_you_use?}
