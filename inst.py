from mailing import parse_packet


str1 = b'U\x00\\\x0c\xf3\xff\xff\xff\xd7BL\x00\x00\x00\x00\x00g\x0b\t\x03\xd7BL\x00\x10\n\xf7\x05\x00W\x00\x87\x01\x06\t\x03\x10\n\xf7\x05\xab\x03\r7\x07\x00\x00\xd7BL\x00\x10\n\xf7\x05\x13\xae\x03\x14\x00\x04:\x04\x10\n\xf7\x05 \x00\x00\x00\xa0\x0f\x00\x00\x00\x00\t\x03V\x00I\x03\x03\t\x03\x14\r\x15\x08\xd7BL\x00\x10\n\xf7\x05\x01\x13\x08\x1c\x05\x01\xd7BL\x00\x1c\x05\x01\x10\n\xf7\x05@\x1e\xd7BL\x00\x04\x05\x00\x14\x00\x1f\x00\x1a\x00\x04\xc0\x1e\x00\x00e\x15\x00\x00\x97\x0b\x00\x00\x00\x00\x00\x00\xd9\x02\x10\t\x03\x00\x00\x04\x00\r\x00\xf8*\x00\x00\x00\x00\x00\x00\x18#\x01\t\x03\x01\x01\xf8*\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x04ff\xa6?\x00\x00 B\x00\x00\x80@\xcd\xccL=\x00\xd9\x02\x10\t\x03\x00\x00\x04\x00\r\x00\xf8*\x00\x00\x00\x00\x00\x00\x1d\x05 \x10\n\xf7\x05'

str2 = b'U\x00\\\x0c\xf3\xff\xff\xff\xd7BL\x00\x00\x00\x00\x00g\x0b\t\x03\xd7BL\x00\x10\n\xf7\x05\x00W\x00\x87\x01\x06\t\x03\x10\n\xf7\x05\xab\x03\rF\x11\x00\x00\xd7BL\x00\x10\n\xf7\x05\x17\xae\x03\x14\x00\x04:\x04\x10\n\xf7\x05\x1f\x00\x00\x00\xa0\x0f\x00\x00\x00\x00\t\x03V\x00I\x03\x03\t\x03\x14\r\x15\x08\xd7BL\x00\x10\n\xf7\x05\x01\x12\x08\x1c\x05\x01\xd7BL\x00\x1c\x05\x01\x10\n\xf7\x05@\x1e\xd7BL\x00\x04\x05\x00\x14\x00\x1f\x00\x1a\x00\x04\xc0\x1e\x00\x00e\x15\x00\x00\x97\x0b\x00\x00\x00\x00\x00\x00\xd9\x02\x10\t\x03\x00\x00\x04\x00\r\x00\xf8*\x00\x00\x00\x00\x00\x00\x18#\x01\t\x03\x01\x01\xf8*\x00\x00\xb1\x00\x00\x00\x00\x00\x00\x00\x04ff\xa6?\x00\x00 B\x00\x00\x80@\xcd\xccL=\x00\xd9\x02\x10\t\x03\x00\x00\x04\x00\r\x00\xf8*\x00\x00\x00\x00\x00\x00\x1d\x05 \x10\n\xf7\x05'

str1 = parse_packet(str1)
str2 = parse_packet(str2)
counter = 0
for i in range(min(len(str1), len(str2))):
    try:
        if str1[i]==str2[i]:
            str1.remove(str1[i])
            str2.remove(str2[i])
            counter += 1
        else:
            pass
    except:
        pass

print(str1, str2, sep='\n')