import random
def genotp():
    otp=""
    u_case=[chr(i) for i in range(ord('A'),ord('Z')+1)]
    l_case=[chr(i) for i in range(ord('a'),ord('z')+1)]
    for i in range(0,2):
        otp=otp+random.choice(u_case)+str(random.randint(0,9))+random.choice(l_case)
    return otp
