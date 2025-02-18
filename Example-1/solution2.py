with open('output.bin','rb') as input:
    dat = input.read()
data = []
color = []
cnt = 0 # cnt helps counting the number of pixels that are not blank (empty space characters)
for i in range(0x738):
    if dat[i*24+19] == 10: continue
    data.append(dat[i*24+19])
    if data[-1]!=ord(' '): cnt += 1
    color += [dat[i*24+7:i*24+18].split(b";")]
colors = [] # colors of the pixel
for i in color:
    colors += [bytes([int(j) for j in i])]
# print(colors)
# print(len(colors), len(data))
print(cnt)
with open('./output.cimg','wb') as output:
    str = b"cIMG\x03\x00\x4c\x18" # 0x4c is the width and 0x18 is the height according to the desired output
    str += cnt.to_bytes(4, byteorder='big')[::-1] # According to the number of directives used
    for i in range(0x4c*0x18):
        if data[i]!=ord(' '): # filtering out the empty space characters
            str += b"\x02\x00" # calling directive 2, which is handle_2
            str += bytes([i%0x4c,i//0x4c]) # the position where we put the pixel
            str += b"\x01\x01" # the size of the img being process, which is only 1 pixel (width is 0x1 and height is 0x1)
            str += colors[i]+bytes([data[i]]) # the actual data of the pixel
    print(len(str))
    output.write(str)
