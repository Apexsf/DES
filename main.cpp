#include <string.h>
#include <bitset>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include "des.hpp"

#define IO_READ_SIZE 4096  //ÿ�ν���ioʱ��ȡ���ֽ�����
using namespace std;


//ʹ��stat�����жϸ�·���Ƿ����
bool file_exists(const char* path) 
{
    struct stat buf;
    if (stat(path, &buf) != -1)
    {
        return true;
    }
    return false;
}

//��ӡ����Ͱ�����Ϣ
void help(const char* msg) {
    printf("%s\n", msg);
    printf("usage: des.exe -[ed] srcFile dstFile key\nfor example:\nencode a file : des.exe -e ori.txt encrypt.txt odpaklad\n"\
        "decode a file : des.exe -d encrypt.txt decrypt.txt odpaklad\n");
    exit(0);
}

//������Ϊn���ַ���ת��Ϊ����ΪN��bitsets, ����N = 8*n, 
template<int N>
void str2bits(const char* str, bitset<N>& bits) {
    for (int i = 0; i < N; i++) { //��λ�жϺ͸�ֵ����
        if (str[i / 8] & (1 << (7 - i % 8))) bits[i] = true;
        else bits[i] = false;
    }
}

//������ΪN��bitsetsת��Ϊ����Ϊn���ַ���������N=8*n.
template<int N>
void bits2str(char* buf, bitset<N>& bits) {
    int num_char = N / 8;
    memset(buf, 0, num_char);
    for (int i = 0; i < N; i++) { //��λ�жϺ͸�ֵ����
        if (bits[i]) buf[i / 8] |= (1 << (7 - i % 8));
    }
}

//ʹ��ʵ������DES��������src_fdָ���ļ������ݽ��м��ܣ�������д�뵽dst_fd��ָ���ļ���
void encode(DES& des, ifstream& src_fd, ostream& dst_fd) {
    bitset<64> block;  // ÿ�ζ�64λbit����8��byte���д���
    int byte_read_cnt = 0; // ÿ��ʵ�ʶ�ȡ���ֽ�����
    char* io_buffer = new char[IO_READ_SIZE]; // ������ȡ�ֽڵĴ洢buffer
    while (!src_fd.eof()) {
        src_fd.read(io_buffer, IO_READ_SIZE); //���ļ����ݶ�ȡ��buffer��
        byte_read_cnt = src_fd.gcount();  // ʵ�ʵĶ�ȡ�ֽ�����
        for (int i = 0; i < byte_read_cnt-7; i += 8) { //ÿ�δ���8���ֽ�,ĩβ�������8���ֽڣ�������
            str2bits<64>(io_buffer + i, block); //�Ƚ��ַ���ת��Ϊbit��ʾ�����洢��block��
            block = des.encode(block); //��block���м���
            bits2str(io_buffer + i, block); //�����ܽ��ת��Ϊ�ַ���
        }
        dst_fd.write(io_buffer, byte_read_cnt-byte_read_cnt%8); //д����ܺ���ֽڣ�ͬʱ����ĩβ����8���ֽ�
    }
    int tail = 0; //���ǵ��ļ��ֽ������ܲ���8�ı�����������Ҫ���⴦��
    if ((tail = (byte_read_cnt % 8)) != 0) {
        for (int i = 0; i < 8 - tail; i++) {
            io_buffer[byte_read_cnt + i] = '\0';  //������Ĳ�����'\0'����䣬Ȼ�����Ͻ��б���д��
        }
        str2bits<64>(io_buffer + byte_read_cnt - tail, block);
        block = des.encode(block);
        bits2str<64>(io_buffer + byte_read_cnt - tail, block);
        dst_fd.write(io_buffer +byte_read_cnt - tail, 8);
    }
    delete[] io_buffer; //�ͷŶ���������ڴ档
}


//ʹ��ʵ������DES��������src_fdָ���ļ������ݽ��н��ܣ�������д�뵽dst_fd��ָ���ļ���
void decode(DES& des, ifstream& src_fd, ostream& dst_fd) {
    bitset<64> block; // ÿ�ζ�64λbit����8��byte���д���
    int byte_read_cnt = INT_MAX; // ÿ��ʵ�ʶ�ȡ���ֽ�����
    char* io_buffer = new char[IO_READ_SIZE]; // ������ȡ�ֽڵĴ洢buffer
    while (!src_fd.eof()) {
        src_fd.read(io_buffer, IO_READ_SIZE);  //���ļ����ݶ�ȡ��buffer��
        byte_read_cnt = src_fd.gcount();   // ʵ�ʵĶ�ȡ�ֽ����������ڼ���ʱ��������䣬����byte_read_cnt�϶���8�ı���
        if (byte_read_cnt == 0) break;
        for (int i = 0; i < byte_read_cnt-7; i += 8) { //ÿ�δ���8���ֽ�
            str2bits<64>(io_buffer + i, block); //�Ƚ��ַ���ת��Ϊbit��ʾ�����洢��block��
            block = des.decode(block);   //��block���н���
            bits2str<64>(io_buffer + i, block); //�����ܽ��ת��Ϊ�ַ���
        }
        //ÿ��д��֮ǰ��������8���ֽڽ��м�飬ȡ��ĩβ'\0'�Ĳ���
        int write_byte_num = byte_read_cnt - 8;
        while ((*(io_buffer + write_byte_num) != '\0') && write_byte_num < byte_read_cnt) write_byte_num++;
        dst_fd.write(io_buffer, write_byte_num);
    }

    delete[] io_buffer;  //�ͷŶ���������ڴ档
}




int main(int argc, char* argv[]) {
    if (argc != 5) help("The inputted argument was wrong!");
    const char* option = argv[1]; // ��һ��������� -e ��ʾ ���ܣ� -d��ʾ����
    const char* srcFilePath = argv[2]; //�ڶ��������������Ҫ���ܻ��߽��ܵ��ļ�·��
    const char* dstFilePath = argv[3]; //������������������ܻ��߽��ܽ���ļ��Ĵ洢·��
    const char* inputkey = argv[4]; //���ĸ�������������ܺͽ����õ�����Կ,������8��byte

    //����������Ƿ����Ҫ������жϣ�����ӡ������Ϣ
    if (strcmp(option, "-e") != 0 && strcmp(option, "-d") != 0) 
        help("The option should be -e to encode file or -d to decode file");
    if (!file_exists(srcFilePath))
        help("The srcFile is not existing, please check your entered path!");
    if (strlen(inputkey) != 8) {
        help("The lenght of the key must be 8 bytes!");
    }

    ifstream src_fd(srcFilePath,ios::binary); //�����ļ���
    ofstream dst_fd(dstFilePath,ios::binary); //����ļ���

    bitset<64> key;  //���ڴ洢key
    str2bits<64>(inputkey, key); //���������Կ�ַ�����ת��Ϊ64λbit
    DES des(key); //����DES����
      
    if (strcmp(option, "-e") == 0) encode(des, src_fd, dst_fd); //����
    else if(strcmp(option,"-d") == 0) decode(des, src_fd, dst_fd); //����

    src_fd.close(); //�ر������ļ���
    dst_fd.close(); //�ر�����ļ���
    return 0;
}