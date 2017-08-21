f = open("http","r")
f2 = open("test.rules","w")


i = 10000
for host in f.readlines():
    f2.writelines('alert tcp any any -> any 80 (msg:"test rule"; content:"GET /";content:"HOST:"' + host[:-1] + '"; sid:' + str(i) + ";rev:1;)\n" )
    i += 1

f.close()
# http rules


f = open("https","r")

for ip in f.readlines():
    f2.writelines('alert tcp any any -> ' + ip[:-1] + " 443 (msg:test rule; sid:" + str(i) + ";rev:1;)\n")
    i += 1

f.close()

f2.close()
