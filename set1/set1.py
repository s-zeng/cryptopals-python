#!/usr/bin/python3.6
base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
char_frequency = [ord(c) for c in [' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', ',', '.', 'v', 'k', '(', ')', '_', ';', '"', '=', "'", '-', 'x', '/', '0', '$', '*', '1', 'j', ':', '{', '}', '>', 'q', '[', ']', '2', 'z', '!', '<', '?', '3', '+', '5', '\\', '4', '#', '@', '|', '6', '&', '9', '8', '7', '%', '^', '~', '`']]

def base64(lol):
    if isinstance(lol, str):
        num = int(lol, 16)
        num_equals = (-len(lol)//2)%3
    elif isinstance(lol, bytes):
        num = int.from_bytes(lol, 'big')
        num_equals = (-num.bit_length()//8)%3

    for i in range(num_equals): num *= 2**8

    out = ''
    while num:
        out += base64chars[num%64]
        num = num//64

    out = num_equals*'=' + out[num_equals:]
    return out[::-1]

def xor(data, key):
    if isinstance(data, str): data = bytes.fromhex(data)
    if isinstance(key, str): key = bytes.fromhex(key)
    return bytes(a^b for a, b in zip(data, _cycle(key)))

def _cycle(i):
    counter = 0
    while True:
        yield(i[counter])
        counter = (counter + 1)%len(i)

def single_byte_xor_crack(ciphertext):
    current = [2**31 - 1, '', -1]

    for i in range(256):
        test = xor(ciphertext, bytes([i]))
        score = string_score(test)
        if score < current[0]: current = [score, test, i]

    return current

def detect_single_byte(f):
    ret = [2**31 - 1, '', -1, -1]
    with open(f) as fi:
        lst = fi.readlines()
        for i, line in enumerate(lst):
            test = single_byte_xor_crack(line.strip())
            if test[0] < ret[0]:
                ret = test + [i + 1]
    return ret

def string_char_count(s):
    ret = {}
    for c in s.lower():
        try:
            ret[c] += 1
        except KeyError:
            ret[c] = 1
    return ret

def string_score(s):
    # compare string_char_count(s) with the ordering in char_frequency...
    s = bytes(s)
    char_count = string_char_count(s)
    freq = sorted(char_count, key=char_count.get, reverse=True)
    exp_freq = char_frequency

    score = 0
    for i, c in enumerate(freq):
        try:
            score += abs(i - exp_freq.index(c))
        except ValueError:
            score += 128
    return score

def hamming(s1, s2):
    if isinstance(s1, str): s1 = s1.encode()
    if isinstance(s2, str): s2 = s2.encode()

    out = 0
    for a, b in zip(s1, s2):
        out += bin(a ^ b).count('1')
    return out

def base64decode(s):
    for char in s:
        pass

def naive_vigenere(s):
    naive_chars = [chr(x) for x in char_frequency[1:]]
    char_count = string_char_count(s)
    freq = sorted(char_count, key=char_count.get, reverse=True)
    print(freq)
    out = s
    for i, v in enumerate(freq):
        out.replace(v, naive_chars[i])
    print(out)
