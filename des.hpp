#ifndef DES_H
#define DES_H

#include <bitset>
#include <vector>
#include <iostream>
using namespace std;


class DES {
public:
    using bit64 = bitset<64>;
    using bit56 = bitset<56>;
    using bit48 = bitset<48>;
    using bit32 = bitset<32>;
    using bit28 = bitset<28>;


 
    DES(bit64 key); //��key�й���DES

    vector<bit48> get_subkeys();  //���16������Կ
    bit64 encode(bit64 block); //���ܺ���
    bit64 decode(bit64 block); //���ܺ���


    template<int N>
    static bitset<N> left_shift_bit(bitset<N> bits, int shift); //��N��bit��bitset��������

    template<int N>
    static void print_bits(bitset<N> bits);  //��˳��,�ӵ�λ����λ��ӡbitset��Ԫ��

    static bit64 permute_block(bit64 block); //������Ĵ�����block�����û�
    static bit48 bit_select(bit32 bits); //��32Ϊbit�û�Ϊ48Ϊbit
    static bit32 box_convert(bit48 bits); //S box �û�
    static bit32 p_permute(bit32 bits); // P���û�

private:
    void make_subkeys(); //��������Կ
    bit64 process(bit64 block, bool encode_flag = true); //���ܻ��߽��ܴ���ӿ�
    bit64 m_key; //��ʼ������Կ
    vector<bit48> m_subkeys = vector<bit48>(16); //����Կ
};


template<int N>
bitset<N> DES::left_shift_bit(bitset<N> bits, int shift) {  // bitset���ƺ���
    vector<unsigned char> temp(shift, 0);   //���ڴ洢��ʼ��shiftλ�õ�bit
    for (int i = 0; i < shift; i++) {
        if (bits[i]) temp[i] = 1;
    }
    bits >>= shift;   //���ƣ�ע��bitset�е�bit���ӵ�λ����λ����������������Ҫ��>>����
    for (int i = 0; i < shift; i++) {  //����ʼ��shiftλ�õ�bit���ǵ����ƺ��bits��ĩβ�����ѭ����λ
        bits[N - shift + i] = (temp[i] == 1);
    }
    return bits;
}

//�ӵ�λ����λ��ӡbits��������ʹ��
template<int N>
void DES::print_bits(bitset<N> bits) {
    for (int i = 0; i < N; i++) {
        cout << bits[i];
    }
    cout << endl;
}

#endif
