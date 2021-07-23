#include "des.hpp"

//�Գ�ʼkey���û����û���
const static unsigned char key_permute_1[56] = {
    57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 ,
    58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 ,
    59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
    60 , 52 , 44 , 36 , 63 , 55 , 47 , 39 ,
    31 , 23 , 15 , 7 , 62 , 54 , 46 , 38 ,
    30 , 22 , 14 , 6 , 61 , 53 , 45 , 37 ,
    29 , 21 , 13 , 5 , 28 , 20 , 12 , 4
};

//56λbit��48λbit���û���
const static unsigned char key_permute_2[48] = {
    14 , 17 , 11 , 24 , 1 , 5 , 3 , 28 ,
    15 , 6 , 21 , 10 , 23 , 19 , 12 , 4 ,
    26 , 8 , 16 , 7 , 27 , 20 , 13 , 2 ,
    41 , 52 , 31 , 37 , 47 , 55 , 30 , 40 ,
    51 , 45 , 33 , 48 , 44 , 49 , 39 , 56 ,
    34 , 53 , 46 , 42 , 50 , 36 , 29 , 32
};

//����Կ������bit��
const static unsigned char shift_table[16] = {
    1 , 1 , 2 , 2 , 2 , 2 , 2 , 2 ,
    1 , 2 , 2 , 2 , 2 , 2 , 2 , 1
};

//������Ĵ�����block���û���
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

//��չ�û��������ݴ�32λ��չΪ48λ
static const unsigned char bit_select_table[48] = {
    32 , 1 , 2 , 3 , 4 , 5 , 4 , 5 ,
    6 , 7 , 8 , 9 , 8 , 9 , 10 , 11 ,
    12 , 13 , 12 , 13 , 14 , 15 , 16 , 17 ,
    16 , 17 , 18 , 19 , 20 , 21 , 20 , 21 ,
    22 , 23 , 24 , 25 , 24 , 25 , 26 , 27 ,
    28 , 29 , 28 , 29 , 30 , 31 , 32 , 1
};

//S Box�û����û���
const static unsigned char sbox[8][64] = {
        {//S1 �û���
    14 , 4 , 13 , 1 , 2 , 15 , 11 , 8 , 3 , 10 , 6 , 12 , 5 , 9 , 0 , 7 ,
        0 , 15 , 7 , 4 , 14 , 2 , 13 , 1 , 10 , 6 , 12 , 11 , 9 , 5 , 3 , 8 ,
        4 , 1 , 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5 , 0 ,
        15 , 12 , 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11 , 3 , 14 , 10 , 0 , 6 , 13
} ,
    {//S2 �û���
        15 , 1 , 8 , 14 , 6 , 11 , 3 , 4 , 9 , 7 , 2 , 13 , 12 , 0 , 5 , 10 ,
        3 , 13 , 4 , 7 , 15 , 2 , 8 , 14 , 12 , 0 , 1 , 10 , 6 , 9 , 11 , 5 ,
        0 , 14 , 7 , 11 , 10 , 4 , 13 , 1 , 5 , 8 , 12 , 6 , 9 , 3 , 2 , 15 ,
        13 , 8 , 10 , 1 , 3 , 15 , 4 , 2 , 11 , 6 , 7 , 12 , 0 , 5 , 14 , 9
} ,
    {//S3 �û���
        10 , 0 , 9 , 14 , 6 , 3 , 15 , 5 , 1 , 13 , 12 , 7 , 11 , 4 , 2 , 8 ,
        13 , 7 , 0 , 9 , 3 , 4 , 6 , 10 , 2 , 8 , 5 , 14 , 12 , 11 , 15 , 1 ,
        13 , 6 , 4 , 9 , 8 , 15 , 3 , 0 , 11 , 1 , 2 , 12 , 5 , 10 , 14 , 7 ,
        1 , 10 , 13 , 0 , 6 , 9 , 8 , 7 , 4 , 15 , 14 , 3 , 11 , 5 , 2 , 12
} ,
    {//S4 �û���
        7 , 13 , 14 , 3 , 0 , 6 , 9 , 10 , 1 , 2 , 8 , 5 , 11 , 12 , 4 , 15 ,
        13 , 8 , 11 , 5 , 6 , 15 , 0 , 3 , 4 , 7 , 2 , 12 , 1 , 10 , 14 , 9 ,
        10 , 6 , 9 , 0 , 12 , 11 , 7 , 13 , 15 , 1 , 3 , 14 , 5 , 2 , 8 , 4 ,
        3 , 15 , 0 , 6 , 10 , 1 , 13 , 8 , 9 , 4 , 5 , 11 , 12 , 7 , 2 , 14
} ,
        {//S5 �û���
    2 , 12 , 4 , 1 , 7 , 10 , 11 , 6 , 8 , 5 , 3 , 15 , 13 , 0 , 14 , 9 ,
        14 , 11 , 2 , 12 , 4 , 7 , 13 , 1 , 5 , 0 , 15 , 10 , 3 , 9 , 8 , 6 ,
        4 , 2 , 1 , 11 , 10 , 13 , 7 , 8 , 15 , 9 , 12 , 5 , 6 , 3 , 0 , 14 ,
        11 , 8 , 12 , 7 , 1 , 14 , 2 , 13 , 6 , 15 , 0 , 9 , 10 , 4 , 5 , 3
} ,
        {//S6 �û���
    12 , 1 , 10 , 15 , 9 , 2 , 6 , 8 , 0 , 13 , 3 , 4 , 14 , 7 , 5 , 11 ,
        10 , 15 , 4 , 2 , 7 , 12 , 9 , 5 , 6 , 1 , 13 , 14 , 0 , 11 , 3 , 8 ,
        9 , 14 , 15 , 5 , 2 , 8 , 12 , 3 , 7 , 0 , 4 , 10 , 1 , 13 , 11 , 6 ,
        4 , 3 , 2 , 12 , 9 , 5 , 15 , 10 , 11 , 14 , 1 , 7 , 6 , 0 , 8 , 13
} ,
    {//S7 �û���
        4 , 11 , 2 , 14 , 15 , 0 , 8 , 13 , 3 , 12 , 9 , 7 , 5 , 10 , 6 , 1 ,
        13 , 0 , 11 , 7 , 4 , 9 , 1 , 10 , 14 , 3 , 5 , 12 , 2 , 15 , 8 , 6 ,
        1 , 4 , 11 , 13 , 12 , 3 , 7 , 14 , 10 , 15 , 6 , 8 , 0 , 5 , 9 , 2 ,
        6 , 11 , 13 , 8 , 1 , 4 , 10 , 7 , 9 , 5 , 0 , 15 , 14 , 2 , 3 , 12
} ,
    {//S8 �û���
        13 , 2 , 8 , 4 , 6 , 15 , 11 , 1 , 10 , 9 , 3 , 14 , 5 , 0 , 12 , 7 ,
        1 , 15 , 13 , 8 , 10 , 3 , 7 , 4 , 12 , 5 , 6 , 11 , 0 , 14 , 9 , 2 ,
        7 , 11 , 4 , 1 , 9 , 12 , 14 , 2 , 0 , 6 , 10 , 13 , 15 , 3 , 5 , 8 ,
        2 , 1 , 14 , 7 , 4 , 10 , 8 , 13 , 15 , 12 , 9 , 0 , 3 , 5 , 6 , 11
}
};

//P���û���
const static unsigned char p_permute_table[32] = {
    16 , 7 , 20 , 21 , 29 , 12 , 28 , 17 ,
    1 , 15 , 23 , 26 , 5 , 18 , 31 , 10 ,
    2 , 8 , 24 , 14 , 32 , 27 , 3 , 9 ,
    19 , 13 , 30 , 6 , 22 , 11 , 4 , 25
};

//���һ���û��������û���
const static unsigned char ip_reverse_table[64] = {
    40 , 8 , 48 , 16 , 56 , 24 , 64 , 32 , 39 , 7 , 47 , 15 , 55 , 23 , 63 , 31 ,
    38 , 6 , 46 , 14 , 54 , 22 , 62 , 30 , 37 , 5 , 45 , 13 , 53 , 21 , 61 , 29 ,
    36 , 4 , 44 , 12 , 52 , 20 , 60 , 28 , 35 , 3 , 43 , 11 , 51 , 19 , 59 , 27 ,
    34 , 2 , 42 , 10 , 50 , 18 , 58 , 26 , 33 , 1 , 41 , 9 , 49 , 17 , 57 , 25
};



//DES���캯��
DES::DES(bit64 key) : m_key(key) {
    make_subkeys(); //��������Կ
}


void DES::make_subkeys() {
    bit56 key_56;
    for (int i = 0; i < 56; i++) {
        key_56[i] = m_key[key_permute_1[i] - 1]; //���ȴ�64λbit��56λbit�����û�
    }
    bit28 key_28_split_l, key_28_split_r; //��56λbit��Ϊ����������

    for (int i = 0; i < 28; i++) {
        key_28_split_l[i] = key_56[i];
    }

    for (int i = 28; i < 56; i++) {
        key_28_split_r[i - 28] = key_56[i];
    }

    //����16��subkey������
    bit48 subkey_temp;
    for (int i = 0; i < 16; i++) {
        key_28_split_l = left_shift_bit<28>(key_28_split_l, shift_table[i]); //������λ���������
        key_28_split_r = left_shift_bit<28>(key_28_split_r, shift_table[i]); //������λ���������
        for (int j = 0; j < 48; j++) { //��56λ��48λ���û�
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

//��һ��block���м���
DES::bit64 DES::encode(bit64 block) {
    return process(std::forward<bit64>(block), true);
}

//��һ��block���н���
DES::bit64 DES::decode(bit64 block) {
    return process(std::forward<bit64>(block), false);
}

//���ĵĴ����������ڼӽ��ܹ���ֻ������Կ��ʹ��˳��ͬ������ʹ��encode_flag��ʾ���ܺͽ��ܱ�ʶ
DES::bit64 DES::process(bit64 block, bool encode_flag) {
    block = permute_block(block);  //block�ĳ����û�
    bit32 block_32_split_l, block_32_split_r; //��block��Ϊ����������
    for (int i = 0; i < 32; i++) {
        block_32_split_l[i] = block[i];
    }
    for (int i = 32; i < 64; i++) {
        block_32_split_r[i - 32] = block[i];
    }
    bit32 last_l_temp;   //��¼��һ�ε�����block
    bit48 bit_select_temp; 
    bit32 box_temp;
    for (int i = 0; i < 16; i++) {
        last_l_temp = block_32_split_l;  //����ʹ��temp��¼��һ�ε�����block
        block_32_split_l = block_32_split_r;  //��R_{n-1}��ֵ��L_{n}
        bit_select_temp = bit_select(block_32_split_l);  //32λbit��48λbit���û�

        if (encode_flag) bit_select_temp = (bit_select_temp ^ m_subkeys[i]); //����ʱ��˳��������Կ����������
        else bit_select_temp = (bit_select_temp ^ m_subkeys[15 - i]); //����ʱ������������Կ����������

        box_temp = box_convert(bit_select_temp); //S BOX��ÿ6��bit�û���4��bit�� 48λbitת��Ϊ32λbit
        box_temp = p_permute(box_temp); //p���û�
        block_32_split_r = (last_l_temp ^ box_temp);  //����������һ�ֵ���
    }
    bit64 res_block;  //�������Ľ��
    for (int i = 0; i < 64; i++) { //���һ���û�����R_{16}L_{16}���û������Ľ��
        if (ip_reverse_table[i] - 1 < 32) {
            res_block[i] = block_32_split_r[ip_reverse_table[i] - 1]; 
        }
        else {
            res_block[i] = block_32_split_l[ip_reverse_table[i] - 32 - 1];
        }
    }
    return res_block;
}


//����DES�е�����Կ
vector<DES::bit48> DES::get_subkeys() {
    return m_subkeys;  
}

//����block�ĳ�ʼ�û�
DES::bit64 DES::permute_block(DES::bit64 block) {
    bit64 res_block;
    for (int i = 0; i < 64; i++) {
        res_block[i] = block[ip_table[i] - 1];
    }
    return res_block;
}

//��32bit��48bit���û�
DES::bit48 DES::bit_select(bit32 bits) {
    bit48 res_block;
    for (int i = 0; i < 48; i++) {
        res_block[i] = bits[bit_select_table[i] - 1];
    }
    return res_block;
}

//S BOX��ÿ6��bit�û���4��bit�� 48λbitת��Ϊ32λb
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

//p�����û�
DES::bit32 DES::p_permute(DES::bit32 bits) {
    bit32 res_bits;
    for (int i = 0; i < 32; i++) {
        res_bits[i] = bits[p_permute_table[i] - 1];
    }
    return res_bits;
}