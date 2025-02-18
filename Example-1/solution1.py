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

with open('./output.cimg','wb') as output:
    str = b"cIMG\x03\x00\x4c\x18" # 0x4c is the width and 0x18 is the height according to the desired output
    str += b"\x01\x00\x00\x00" # We only use 1 directive, which is handle_1
    str += b"\x01\x00" # Calling handle_1
    for i in range(0x4c*0x18):
        str += colors[i]+bytes([data[i]])
    print(len(str))
    output.write(str)
