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


 
    DES(bit64 key); //从key中构造DES

    vector<bit48> get_subkeys();  //获得16个子密钥
    bit64 encode(bit64 block); //加密函数
    bit64 decode(bit64 block); //解密函数


    template<int N>
    static bitset<N> left_shift_bit(bitset<N> bits, int shift); //对N个bit的bitset进行左移

    template<int N>
    static void print_bits(bitset<N> bits);  //按顺序,从低位到高位打印bitset的元素

    static bit64 permute_block(bit64 block); //对输入的待加密block进行置换
    static bit48 bit_select(bit32 bits); //将32为bit置换为48为bit
    static bit32 box_convert(bit48 bits); //S box 置换
    static bit32 p_permute(bit32 bits); // P盒置换

private:
    void make_subkeys(); //生成子密钥
    bit64 process(bit64 block, bool encode_flag = true); //加密或者解密处理接口
    bit64 m_key; //初始输入密钥
    vector<bit48> m_subkeys = vector<bit48>(16); //子密钥
};


template<int N>
bitset<N> DES::left_shift_bit(bitset<N> bits, int shift) {  // bitset左移函数
    vector<unsigned char> temp(shift, 0);   //用于存储开始的shift位置的bit
    for (int i = 0; i < shift; i++) {
        if (bits[i]) temp[i] = 1;
    }
    bits >>= shift;   //左移，注意bitset中的bit按从低位到高位进行索引，所以需要用>>左移
    for (int i = 0; i < shift; i++) {  //将初始的shift位置的bit覆盖到左移后的bits的末尾，完成循环移位
        bits[N - shift + i] = (temp[i] == 1);
    }
    return bits;
}

//从低位到高位打印bits，供调试使用
template<int N>
void DES::print_bits(bitset<N> bits) {
    for (int i = 0; i < N; i++) {
        cout << bits[i];
    }
    cout << endl;
}

#endif
