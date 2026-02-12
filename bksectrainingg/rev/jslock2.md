## Description
[web](http://jslock2.pages.dev/)
## My solution
Seeing a web, my first reaction is pressing Ctrl-U.
<img width="1004" height="803" alt="image" src="https://github.com/user-attachments/assets/58b9225a-c1de-4e60-9e1e-781311f31589" />
Click on the lock.js file.
<img width="1781" height="738" alt="image" src="https://github.com/user-attachments/assets/81d2b88d-2c27-484f-bae5-d14d78aebbc8" />
We use Z3 solver in this case:\
```
from z3 import *
entered = [Int(f'p{i}') for i in range(12)]
correct = [-4, 11, 8, 10, 31, 0, 28, 4, 1, 25, 10, 11]
s = Solver()
for p in entered:
    s.add(p >= 0, p <= 100) 
s.add(entered[0] * entered[1] - 2 * entered[2] == correct[0])
s.add(entered[1] + 5 * entered[2] - 3 * entered[3] == correct[1])
s.add(entered[2] + entered[3] * entered[4] - entered[0] == correct[2])
s.add(entered[5] + 2 * entered[4] + entered[2] == correct[3])
s.add(20 * entered[1] - 2 * entered[2] - entered[4] == correct[4])
s.add(entered[2] + entered[5] - 2 * entered[1] == correct[5])
s.add(2 * entered[1] + entered[2] + 3 * entered[6] + 4 * entered[7] == correct[6])
s.add(5 * entered[5] - entered[7] - entered[8] + 2 * entered[9] == correct[7])
s.add(3 * entered[8] + 2 * entered[9] + 4 * entered[10] - 3 * entered[6] == correct[8])
s.add(9 * entered[11] + 2 * entered[10] - entered[8] == correct[9])
s.add(4 * entered[7] - entered[8] + entered[10] == correct[10])
s.add(entered[3] ** entered[8] + 3 * entered[11] - 2 * entered[7] + entered[6] + entered[5] + entered[10] == correct[11])
if s.check() == sat:
    m = s.model()
    result = [m[p] for p in entered]
    print(result)
```
```
[1, 2, 3, 2, 3, 1, 3, 3, 2, 2, 0, 3]
```
Type the numbers in and:
<img width="697" height="249" alt="image" src="https://github.com/user-attachments/assets/6ed4f448-e7ab-4110-8dca-8b93e8df06d0" />
