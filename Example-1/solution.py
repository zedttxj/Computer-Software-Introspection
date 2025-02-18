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
# print(colors)
# print(len(colors), len(data))
def rec(tmp, w, h): # function that breaks the image into rectangles
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
sz, szt = rec(list(data),0x4c,0x18)
with open('./output.cimg','wb') as output:
    str = b"cIMG\x03\x00\x4c\x18" # 0x4c is the width and 0x18 is the height according to the desired output
    str += len(sz).to_bytes(4, byteorder='big')[::-1] # According to the number of directives used
    for i in range(len(sz)):
        if data[i]!=ord(' '): # filtering out the empty space characters
            str += b"\x02\x00" # calling directive 2, which is handle_2
            str += bytes(sz[i]) # the position where we put the pixel and the size of the rectangle
            for h in range(sz[i][1],sz[i][1]+sz[i][3]):
                for w in range(sz[i][0],sz[i][0]+sz[i][2]):
                    str += colors[h*0x4c+w] + bytes([data[h*0x4c+w]]) # the actual data of the pixel
    print(len(str))
    output.write(str)
