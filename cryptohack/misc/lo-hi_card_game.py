from pwn import *
import json

#the idea is to gather 3 states of LCG then crack it and predict the future cards
#in order to survive and get the first 3 states, we send h when the value is below average and l otherwise

io = remote('socket.cryptohack.org', 13383)

def send_json(data):
    io.sendline(json.dumps(data).encode())

def recv_json():
    return json.loads(io.recvline().decode())

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']

deck = [f"{value} of {suit}" for suit in SUITS for value in VALUES]
mapping = {card_str: index for index, card_str in enumerate(deck)}

def rebase(n, b=52):
    if n < b:
        return [n]
    else:
        return [n % b] + rebase(n // b, b)

def revert(arr):
    ans = 0
    for i, val in enumerate(arr):
        ans += val * (52 ** (len(arr) - 1 - i))
    return ans

history = []
state_lengths = []
MOD = 2**61 - 1

print("[*] Gathering 3 states (surviving using Basic Strategy)...")

while True:
    kk = recv_json()
    
    if 'error' in kk:
        print("[-] Error or bankrupt:", kk)
        break
        
    if 'msg' in kk and 'reshuffle' in kk['msg']:
        rounds = int(kk['msg'].split(" rounds")[0].split(" ")[-1])
        state_lengths.append(rounds)
    
    if 'hand' in kk:
        point = mapping[kk['hand']]
        history.append(point)
        
        if len(state_lengths) >= 3 and len(history) == sum(state_lengths[:3]):
            break
        
        # Basic Strategy: Maximize survival odds while gathering data
        card_val_idx = VALUES.index(kk['hand'].split(" of ")[0])
        choice = "h" if card_val_idx < 6 else "l"
        send_json({"choice": choice})



l0, l1, l2 = state_lengths[0], state_lengths[1], state_lengths[2]


S0 = revert(history[0 : l0])
S1 = revert(history[l0 : l0 + l1])
S2 = revert(history[l0 + l1 : l0 + l1 + l2])

print(f"\n[+] States recovered:\nS0: {S0}\nS1: {S1}\nS2: {S2}")

# Calculate LCG param
a = ((S2 - S1) % MOD * pow(S1 - S0, -1, MOD)) % MOD
b = (S1 - S0 * a) % MOD
print(f"[+] LCG Cracked! \nMultiplier (a): {a}\nIncrement (b): {b}\n")



master_sequence = []
current_state = S0

# Generate 30 states (more than enough to reach 200 rounds)
for _ in range(30):
    # .pop() deals cards in reverse order, so we reverse the base-52 array here
    master_sequence.extend(rebase(current_state)[::-1])
    current_state = (current_state * a + b) % MOD

# Verify our math is correct (our history must match the start of the master sequence)
assert master_sequence[:len(history)] == history, "[-] Math mismatch!"
print("[+] Future sequence verified. Proceeding to print money...\n")

current_idx = len(history)

# We break out of the Gather loop right as the server asks for our next choice
while True:
    predicted_hidden = master_sequence[current_idx]
    current_hand = master_sequence[current_idx - 1]
    
    hand_val = current_hand % 13
    hidden_val = predicted_hidden % 13
    
    choice = "h" if hidden_val > hand_val else "l"
    send_json({"choice": choice})
    
    kk = recv_json()
    
    if 'error' in kk:
        print("Server Error:", kk)
        break
        
    if 'msg' in kk and 'flag' in kk['msg'].lower():
        print(f"\n[!!!] {kk['msg']}")
        break
        
    current_idx += 1
