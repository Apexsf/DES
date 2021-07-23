#include <string.h>
#include <bitset>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include "des.hpp"

#define IO_READ_SIZE 4096  //每次进行io时读取的字节数量
using namespace std;


//使用stat函数判断该路径是否存在
bool file_exists(const char* path) 
{
    struct stat buf;
    if (stat(path, &buf) != -1)
    {
        return true;
    }
    return false;
}

//打印报错和帮助信息
void help(const char* msg) {
    printf("%s\n", msg);
    printf("usage: des.exe -[ed] srcFile dstFile key\nfor example:\nencode a file : des.exe -e ori.txt encrypt.txt odpaklad\n"\
        "decode a file : des.exe -d encrypt.txt decrypt.txt odpaklad\n");
    exit(0);
}

//将长度为n的字符串转换为长度为N的bitsets, 其中N = 8*n, 
template<int N>
void str2bits(const char* str, bitset<N>& bits) {
    for (int i = 0; i < N; i++) { //逐位判断和赋值即可
        if (str[i / 8] & (1 << (7 - i % 8))) bits[i] = true;
        else bits[i] = false;
    }
}

//将长度为N的bitsets转换为长度为n的字符串，其中N=8*n.
template<int N>
void bits2str(char* buf, bitset<N>& bits) {
    int num_char = N / 8;
    memset(buf, 0, num_char);
    for (int i = 0; i < N; i++) { //逐位判断和赋值即可
        if (bits[i]) buf[i / 8] |= (1 << (7 - i % 8));
    }
}

//使用实例化的DES对象，来对src_fd指向文件的内容进行加密，并将其写入到dst_fd的指向文件中
void encode(DES& des, ifstream& src_fd, ostream& dst_fd) {
    bitset<64> block;  // 每次对64位bit，即8个byte进行处理
    int byte_read_cnt = 0; // 每次实际读取的字节数量
    char* io_buffer = new char[IO_READ_SIZE]; // 创建读取字节的存储buffer
    while (!src_fd.eof()) {
        src_fd.read(io_buffer, IO_READ_SIZE); //将文件内容读取到buffer中
        byte_read_cnt = src_fd.gcount();  // 实际的读取字节数量
        for (int i = 0; i < byte_read_cnt-7; i += 8) { //每次处理8个字节,末尾如果不足8个字节，则舍弃
            str2bits<64>(io_buffer + i, block); //先将字符串转换为bit表示，并存储到block中
            block = des.encode(block); //对block进行加密
            bits2str(io_buffer + i, block); //将加密结果转换为字符串
        }
        dst_fd.write(io_buffer, byte_read_cnt-byte_read_cnt%8); //写入加密后的字节，同时舍弃末尾不足8的字节
    }
    int tail = 0; //可虑到文件字节数可能不是8的倍数，所以需要另外处理
    if ((tail = (byte_read_cnt % 8)) != 0) {
        for (int i = 0; i < 8 - tail; i++) {
            io_buffer[byte_read_cnt + i] = '\0';  //将不足的部分用'\0'来填充，然后如上进行编码写入
        }
        str2bits<64>(io_buffer + byte_read_cnt - tail, block);
        block = des.encode(block);
        bits2str<64>(io_buffer + byte_read_cnt - tail, block);
        dst_fd.write(io_buffer +byte_read_cnt - tail, 8);
    }
    delete[] io_buffer; //释放堆上申请的内存。
}


//使用实例化的DES对象，来对src_fd指向文件的内容进行解密，并将其写入到dst_fd的指向文件中
void decode(DES& des, ifstream& src_fd, ostream& dst_fd) {
    bitset<64> block; // 每次对64位bit，即8个byte进行处理
    int byte_read_cnt = INT_MAX; // 每次实际读取的字节数量
    char* io_buffer = new char[IO_READ_SIZE]; // 创建读取字节的存储buffer
    while (!src_fd.eof()) {
        src_fd.read(io_buffer, IO_READ_SIZE);  //将文件内容读取到buffer中
        byte_read_cnt = src_fd.gcount();   // 实际的读取字节数量，由于加密时进行了填充，所以byte_read_cnt肯定是8的倍数
        if (byte_read_cnt == 0) break;
        for (int i = 0; i < byte_read_cnt-7; i += 8) { //每次处理8个字节
            str2bits<64>(io_buffer + i, block); //先将字符串转换为bit表示，并存储到block中
            block = des.decode(block);   //对block进行解密
            bits2str<64>(io_buffer + i, block); //将解密结果转换为字符串
        }
        //每次写入之前都对最后的8个字节进行检查，取出末尾'\0'的部分
        int write_byte_num = byte_read_cnt - 8;
        while ((*(io_buffer + write_byte_num) != '\0') && write_byte_num < byte_read_cnt) write_byte_num++;
        dst_fd.write(io_buffer, write_byte_num);
    }

    delete[] io_buffer;  //释放堆上申请的内存。
}




int main(int argc, char* argv[]) {
    if (argc != 5) help("The inputted argument was wrong!");
    const char* option = argv[1]; // 第一个输入参数 -e 表示 加密， -d表示解密
    const char* srcFilePath = argv[2]; //第二个输入参数，需要加密或者解密的文件路径
    const char* dstFilePath = argv[3]; //第三个输入参数，加密或者解密结果文件的存储路径
    const char* inputkey = argv[4]; //第四个输入参数，加密和解密用到的密钥,必须是8个byte

    //对输入参数是否符合要求进行判断，并打印错误信息
    if (strcmp(option, "-e") != 0 && strcmp(option, "-d") != 0) 
        help("The option should be -e to encode file or -d to decode file");
    if (!file_exists(srcFilePath))
        help("The srcFile is not existing, please check your entered path!");
    if (strlen(inputkey) != 8) {
        help("The lenght of the key must be 8 bytes!");
    }

    ifstream src_fd(srcFilePath,ios::binary); //输入文件流
    ofstream dst_fd(dstFilePath,ios::binary); //输出文件流

    bitset<64> key;  //用于存储key
    str2bits<64>(inputkey, key); //将输入的密钥字符串，转换为64位bit
    DES des(key); //构建DES对象
      
    if (strcmp(option, "-e") == 0) encode(des, src_fd, dst_fd); //加密
    else if(strcmp(option,"-d") == 0) decode(des, src_fd, dst_fd); //解密

    src_fd.close(); //关闭输入文件流
    dst_fd.close(); //关闭输出文件流
    return 0;
}