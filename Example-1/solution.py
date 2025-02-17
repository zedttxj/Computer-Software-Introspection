with open('output.bin','rb') as input:
    dat = input.read()
data = []
color = []
for i in range(0x738):
    if dat[i*24+19] == 10: continue
    data.append(dat[i*24+19])
    color += [dat[i*24+7:i*24+18].split(b";")]
data = bytes(data)
colors = []
for i in color:
    colors += [bytes([int(j) for j in i])]
# print(colors)
def sqr(tmp, w, h):
    sz = []
    szt = []
    cnt = True
    for i in range(h):
        for j in range(w):
            if tmp[i*w+j]!=ord(" "):
                lw = w
                for l in range(j,w):
                    if tmp[i*w+l]==ord(" "):
                        lw = l
                        break
                kh = h
                br = False
                for k in range(i+1,h):
                    for l in range(j,lw):
                        if tmp[k*w+l]==ord(" "):
                            kh = k
                            br = True
                            break
                    if br: break
                for k in range(i,kh):
                    for l in range(j,lw):
                        tmp[k*w+l] = ord(" ")
                sz.append([j,i,lw-j,kh-i])
                szt.append((kh-i)*(lw-j))
    return sz, szt
sz, szt = sqr(list(data),0x4c,0x18)
ls = []
with open('output.cimg','wb') as output:
    str = b"cIMG\x03\x00\x4c\x18" + bytes([len(sz)*2]) + b"\x00\x00\x00"
    #str += b"\x02\x00\x00\x00\x01\x01\xff\xff\xff\x7e"
    str = b""
    cnt = 0
    for i in range(len(sz)):
        #str += b"\x02\x00"+bytes(sz[i])
        #str += b"\x03\x00"+bytes([i])+bytes(sz[i][2:])
        tmp = b""
        for h in range(sz[i][1],sz[i][1]+sz[i][3]):
            for w in range(sz[i][0],sz[i][0]+sz[i][2]):
                tmp += bytes([data[h*0x4c+w]])
                #str += colors[h*0x4c+w] + bytes([data[h*0x4c+w]])
        if not(tmp in ls):
            ls.append(tmp)
            cnt += 1
            str += b"\x03\x00"+bytes([ls.index(tmp)])+bytes(sz[i][2:])+tmp
        #str += b"\x04\x00"+bytes([ls.index(tmp)])+colors[sz[i][0]+sz[i][1]*0x4c]+bytes(sz[i][:2])
        str += b"\x04\x00"+bytes([ls.index(tmp)])+(ls.index(tmp)*500000).to_bytes(3, byteorder='big')+bytes(sz[i][:2])
        cnt += 1
    str = b"cIMG\x03\x00\x4c\x18" + bytes([cnt]) + b"\x00\x00\x00" + str
    print(len(str), cnt)
    output.write(str)
