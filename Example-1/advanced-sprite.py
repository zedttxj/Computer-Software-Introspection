with open('output.bin','rb') as input:
    dat = input.read()
data = []
color = []
for i in range(0x738):
    if dat[i*24+19] == 10: continue
    data.append(dat[i*24+19])
    color += [dat[i*24+7:i*24+18].split(b";")]
colors = [] # colors of the pixel
for i in color:
    colors += [bytes([int(j) for j in i])]
sz = [[0x4b,0x17,1,1,2,1], [0x4b,0,1,1,2,1], [1,0x17,1,1,0x4a,2], [0x4b,1,1,1,2,0x16], [23,10,6,4, 1, 1], [30,9,5,5, 1, 1], [36, 9, 8, 5, 1, 1], [45, 9, 8, 5, 1, 1]]
colors[10*0x4c+23] = colors[10*0x4c+25]
colors[9*0x4c+30] = colors[9*0x4c+31]
colors[9*0x4c+36] = colors[9*0x4c+37]
colors[9*0x4c+45] = colors[9*0x4c+47]
ls = []
with open('output.cimg','wb') as output:
    str = b""
    cnt = 0
    for i in range(len(sz)):
        tmp = b""
        for h in range(sz[i][1],sz[i][1]+sz[i][3]):
            for w in range(sz[i][0],sz[i][0]+sz[i][2]):
                tmp += bytes([data[h*0x4c+w]])
                #str += colors[h*0x4c+w] + bytes([data[h*0x4c+w]])
        if not(tmp in ls):
            ls.append(tmp)
            cnt += 1
            str += b"\x03\x00"+bytes([ls.index(tmp)])+bytes(sz[i][2:4])+tmp
        str += b"\x04\x00"+bytes([ls.index(tmp)])+colors[sz[i][0]+sz[i][1]*0x4c]+bytes(sz[i][:2])+bytes(sz[i][4:])+b"\x00"
        cnt += 1
    str = b"cIMG\x04\x00\x4c\x18" + cnt.to_bytes(4, byteorder='little') + str
    print(len(str), cnt)
    output.write(str)
