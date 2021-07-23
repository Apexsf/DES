#include "des.hpp"

//对初始key进置换的置换表
const static unsigned char key_permute_1[56] = {
    57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 ,
    58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 ,
    59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
    60 , 52 , 44 , 36 , 63 , 55 , 47 , 39 ,
    31 , 23 , 15 , 7 , 62 , 54 , 46 , 38 ,
    30 , 22 , 14 , 6 , 61 , 53 , 45 , 37 ,
    29 , 21 , 13 , 5 , 28 , 20 , 12 , 4
};

//56位bit到48位bit的置换表
const static unsigned char key_permute_2[48] = {
    14 , 17 , 11 , 24 , 1 , 5 , 3 , 28 ,
    15 , 6 , 21 , 10 , 23 , 19 , 12 , 4 ,
    26 , 8 , 16 , 7 , 27 , 20 , 13 , 2 ,
    41 , 52 , 31 , 37 , 47 , 55 , 30 , 40 ,
    51 , 45 , 33 , 48 , 44 , 49 , 39 , 56 ,
    34 , 53 , 46 , 42 , 50 , 36 , 29 , 32
};

//子密钥的左移bit表
const static unsigned char shift_table[16] = {
    1 , 1 , 2 , 2 , 2 , 2 , 2 , 2 ,
    1 , 2 , 2 , 2 , 2 , 2 , 2 , 1
};

//对输入的待加密block的置换表
const static unsigned char ip_table[64] = {
    58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 ,
    60 , 52 , 44 , 36 , 28 , 20 , 12 , 4 ,
    62 , 54 , 46 , 38 , 30 , 22 , 14 , 6 ,
    64 , 56 , 48 , 40 , 32 , 24 , 16 , 8 ,
    57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 ,
    59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
    61 , 53 , 45 , 37 , 29 , 21 , 13 , 5 ,
    63 , 55 , 47 , 39 , 31 , 23 , 15 , 7
};

//扩展置换，将数据从32位扩展为48位
static const unsigned char bit_select_table[48] = {
    32 , 1 , 2 , 3 , 4 , 5 , 4 , 5 ,
    6 , 7 , 8 , 9 , 8 , 9 , 10 , 11 ,
    12 , 13 , 12 , 13 , 14 , 15 , 16 , 17 ,
    16 , 17 , 18 , 19 , 20 , 21 , 20 , 21 ,
    22 , 23 , 24 , 25 , 24 , 25 , 26 , 27 ,
    28 , 29 , 28 , 29 , 30 , 31 , 32 , 1
};

//S Box置换的置换表
const static unsigned char sbox[8][64] = {
        {//S1 置换表
    14 , 4 , 13 , 1 , 2 , 15 , 11 , 8 , 3 , 10 , 6 , 12 , 5 , 9 , 0 , 7 ,
        0 , 15 , 7 , 4 , 14 , 2 , 13 , 1 , 10 , 6 , 12 , 11 , 9 , 5 , 3 , 8 ,
        4 , 1 , 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5 , 0 ,
        15 , 12 , 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11 , 3 , 14 , 10 , 0 , 6 , 13
} ,
    {//S2 置换表
        15 , 1 , 8 , 14 , 6 , 11 , 3 , 4 , 9 , 7 , 2 , 13 , 12 , 0 , 5 , 10 ,
        3 , 13 , 4 , 7 , 15 , 2 , 8 , 14 , 12 , 0 , 1 , 10 , 6 , 9 , 11 , 5 ,
        0 , 14 , 7 , 11 , 10 , 4 , 13 , 1 , 5 , 8 , 12 , 6 , 9 , 3 , 2 , 15 ,
        13 , 8 , 10 , 1 , 3 , 15 , 4 , 2 , 11 , 6 , 7 , 12 , 0 , 5 , 14 , 9
} ,
    {//S3 置换表
        10 , 0 , 9 , 14 , 6 , 3 , 15 , 5 , 1 , 13 , 12 , 7 , 11 , 4 , 2 , 8 ,
        13 , 7 , 0 , 9 , 3 , 4 , 6 , 10 , 2 , 8 , 5 , 14 , 12 , 11 , 15 , 1 ,
        13 , 6 , 4 , 9 , 8 , 15 , 3 , 0 , 11 , 1 , 2 , 12 , 5 , 10 , 14 , 7 ,
        1 , 10 , 13 , 0 , 6 , 9 , 8 , 7 , 4 , 15 , 14 , 3 , 11 , 5 , 2 , 12
} ,
    {//S4 置换表
        7 , 13 , 14 , 3 , 0 , 6 , 9 , 10 , 1 , 2 , 8 , 5 , 11 , 12 , 4 , 15 ,
        13 , 8 , 11 , 5 , 6 , 15 , 0 , 3 , 4 , 7 , 2 , 12 , 1 , 10 , 14 , 9 ,
        10 , 6 , 9 , 0 , 12 , 11 , 7 , 13 , 15 , 1 , 3 , 14 , 5 , 2 , 8 , 4 ,
        3 , 15 , 0 , 6 , 10 , 1 , 13 , 8 , 9 , 4 , 5 , 11 , 12 , 7 , 2 , 14
} ,
        {//S5 置换表
    2 , 12 , 4 , 1 , 7 , 10 , 11 , 6 , 8 , 5 , 3 , 15 , 13 , 0 , 14 , 9 ,
        14 , 11 , 2 , 12 , 4 , 7 , 13 , 1 , 5 , 0 , 15 , 10 , 3 , 9 , 8 , 6 ,
        4 , 2 , 1 , 11 , 10 , 13 , 7 , 8 , 15 , 9 , 12 , 5 , 6 , 3 , 0 , 14 ,
        11 , 8 , 12 , 7 , 1 , 14 , 2 , 13 , 6 , 15 , 0 , 9 , 10 , 4 , 5 , 3
} ,
        {//S6 置换表
    12 , 1 , 10 , 15 , 9 , 2 , 6 , 8 , 0 , 13 , 3 , 4 , 14 , 7 , 5 , 11 ,
        10 , 15 , 4 , 2 , 7 , 12 , 9 , 5 , 6 , 1 , 13 , 14 , 0 , 11 , 3 , 8 ,
        9 , 14 , 15 , 5 , 2 , 8 , 12 , 3 , 7 , 0 , 4 , 10 , 1 , 13 , 11 , 6 ,
        4 , 3 , 2 , 12 , 9 , 5 , 15 , 10 , 11 , 14 , 1 , 7 , 6 , 0 , 8 , 13
} ,
    {//S7 置换表
        4 , 11 , 2 , 14 , 15 , 0 , 8 , 13 , 3 , 12 , 9 , 7 , 5 , 10 , 6 , 1 ,
        13 , 0 , 11 , 7 , 4 , 9 , 1 , 10 , 14 , 3 , 5 , 12 , 2 , 15 , 8 , 6 ,
        1 , 4 , 11 , 13 , 12 , 3 , 7 , 14 , 10 , 15 , 6 , 8 , 0 , 5 , 9 , 2 ,
        6 , 11 , 13 , 8 , 1 , 4 , 10 , 7 , 9 , 5 , 0 , 15 , 14 , 2 , 3 , 12
} ,
    {//S8 置换表
        13 , 2 , 8 , 4 , 6 , 15 , 11 , 1 , 10 , 9 , 3 , 14 , 5 , 0 , 12 , 7 ,
        1 , 15 , 13 , 8 , 10 , 3 , 7 , 4 , 12 , 5 , 6 , 11 , 0 , 14 , 9 , 2 ,
        7 , 11 , 4 , 1 , 9 , 12 , 14 , 2 , 0 , 6 , 10 , 13 , 15 , 3 , 5 , 8 ,
        2 , 1 , 14 , 7 , 4 , 10 , 8 , 13 , 15 , 12 , 9 , 0 , 3 , 5 , 6 , 11
}
};

//P盒置换表
const static unsigned char p_permute_table[32] = {
    16 , 7 , 20 , 21 , 29 , 12 , 28 , 17 ,
    1 , 15 , 23 , 26 , 5 , 18 , 31 , 10 ,
    2 , 8 , 24 , 14 , 32 , 27 , 3 , 9 ,
    19 , 13 , 30 , 6 , 22 , 11 , 4 , 25
};

//最后一次置换操作的置换表
const static unsigned char ip_reverse_table[64] = {
    40 , 8 , 48 , 16 , 56 , 24 , 64 , 32 , 39 , 7 , 47 , 15 , 55 , 23 , 63 , 31 ,
    38 , 6 , 46 , 14 , 54 , 22 , 62 , 30 , 37 , 5 , 45 , 13 , 53 , 21 , 61 , 29 ,
    36 , 4 , 44 , 12 , 52 , 20 , 60 , 28 , 35 , 3 , 43 , 11 , 51 , 19 , 59 , 27 ,
    34 , 2 , 42 , 10 , 50 , 18 , 58 , 26 , 33 , 1 , 41 , 9 , 49 , 17 , 57 , 25
};



//DES构造函数
DES::DES(bit64 key) : m_key(key) {
    make_subkeys(); //生成子密钥
}


void DES::make_subkeys() {
    bit56 key_56;
    for (int i = 0; i < 56; i++) {
        key_56[i] = m_key[key_permute_1[i] - 1]; //首先从64位bit到56位bit进行置换
    }
    bit28 key_28_split_l, key_28_split_r; //将56位bit分为左右两部分

    for (int i = 0; i < 28; i++) {
        key_28_split_l[i] = key_56[i];
    }

    for (int i = 28; i < 56; i++) {
        key_28_split_r[i - 28] = key_56[i];
    }

    //进行16个subkey的生成
    bit48 subkey_temp;
    for (int i = 0; i < 16; i++) {
        key_28_split_l = left_shift_bit<28>(key_28_split_l, shift_table[i]); //按照移位表进行左移
        key_28_split_r = left_shift_bit<28>(key_28_split_r, shift_table[i]); //按照移位表进行左移
        for (int j = 0; j < 48; j++) { //从56位到48位的置换
            if (key_permute_2[j] - 1 < 28) {
                subkey_temp[j] = key_28_split_l[key_permute_2[j] - 1];
            }
            else {
                subkey_temp[j] = key_28_split_r[key_permute_2[j] - 28 - 1];
            }
        }
        m_subkeys[i] = subkey_temp;
    }
}

//对一个block进行加密
DES::bit64 DES::encode(bit64 block) {
    return process(std::forward<bit64>(block), true);
}

//对一个block进行解密
DES::bit64 DES::decode(bit64 block) {
    return process(std::forward<bit64>(block), false);
}

//核心的处理函数，由于加解密过程只有子密钥的使用顺序不同，所以使用encode_flag表示加密和解密标识
DES::bit64 DES::process(bit64 block, bool encode_flag) {
    block = permute_block(block);  //block的初次置换
    bit32 block_32_split_l, block_32_split_r; //将block分为左右两部分
    for (int i = 0; i < 32; i++) {
        block_32_split_l[i] = block[i];
    }
    for (int i = 32; i < 64; i++) {
        block_32_split_r[i - 32] = block[i];
    }
    bit32 last_l_temp;   //记录上一次的左子block
    bit48 bit_select_temp; 
    bit32 box_temp;
    for (int i = 0; i < 16; i++) {
        last_l_temp = block_32_split_l;  //首先使用temp记录上一次的左子block
        block_32_split_l = block_32_split_r;  //将R_{n-1}赋值给L_{n}
        bit_select_temp = bit_select(block_32_split_l);  //32位bit到48位bit的置换

        if (encode_flag) bit_select_temp = (bit_select_temp ^ m_subkeys[i]); //加密时，顺序与子密钥进行异或操作
        else bit_select_temp = (bit_select_temp ^ m_subkeys[15 - i]); //解密时，逆序与子密钥进行异或操作

        box_temp = box_convert(bit_select_temp); //S BOX将每6个bit置换成4个bit， 48位bit转换为32位bit
        box_temp = p_permute(box_temp); //p盒置换
        block_32_split_r = (last_l_temp ^ box_temp);  //异或操作结束一轮迭代
    }
    bit64 res_block;  //储存最后的结果
    for (int i = 0; i < 64; i++) { //最后一次置换，从R_{16}L_{16}中置换出最后的结果
        if (ip_reverse_table[i] - 1 < 32) {
            res_block[i] = block_32_split_r[ip_reverse_table[i] - 1]; 
        }
        else {
            res_block[i] = block_32_split_l[ip_reverse_table[i] - 32 - 1];
        }
    }
    return res_block;
}


//返回DES中的子密钥
vector<DES::bit48> DES::get_subkeys() {
    return m_subkeys;  
}

//对于block的初始置换
DES::bit64 DES::permute_block(DES::bit64 block) {
    bit64 res_block;
    for (int i = 0; i < 64; i++) {
        res_block[i] = block[ip_table[i] - 1];
    }
    return res_block;
}

//从32bit到48bit的置换
DES::bit48 DES::bit_select(bit32 bits) {
    bit48 res_block;
    for (int i = 0; i < 48; i++) {
        res_block[i] = bits[bit_select_table[i] - 1];
    }
    return res_block;
}

//S BOX将每6个bit置换成4个bit， 48位bit转换为32位b
DES::bit32 DES::box_convert(DES::bit48 bits) {
    bit32 res_bits;
    for (int i = 0; i < 8; i++) {
        int row_index = bits[i * 6] * 2 + bits[i * 6 + 5];
        int col_index = bits[i * 6 + 1] * 8 + bits[i * 6 + 2] * 4 + bits[i * 6 + 3] * 2 + bits[i * 6 + 4];
        unsigned char substitute_num = sbox[i][row_index * 16 + col_index];
        res_bits[i * 4] = (substitute_num & (1 << 3));
        res_bits[i * 4 + 1] = (substitute_num & (1 << 2));
        res_bits[i * 4 + 2] = (substitute_num & (1 << 1));
        res_bits[i * 4 + 3] = (substitute_num & 1);
    }
    return res_bits;
}

//p盒子置换
DES::bit32 DES::p_permute(DES::bit32 bits) {
    bit32 res_bits;
    for (int i = 0; i < 32; i++) {
        res_bits[i] = bits[p_permute_table[i] - 1];
    }
    return res_bits;
}