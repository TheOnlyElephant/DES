#include <stdint.h>
#include <stdio.h>

// 原始扩展置换表
static const int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// 查找表，每个子表有 256 个 48 位数值
static uint64_t E_TABLE[4][256];

// 生成查找表函数
void generate_E_table() {
    for (int block = 0; block < 4; block++) { // 遍历每个 block（4 个 8 位块）
        for (int value = 0; value < 256; value++) { // 遍历每个可能的 8 位值（0-255）
            uint64_t expanded = 0;

            for (int i = 0; i < 48; i++) { // 遍历 E 表的每一位
                int input_bit = E[i] - 1; // 输入位索引（0-31）

                if (input_bit / 8 == block) { // 判断该输入位是否属于当前的 block
                    int bit_in_block = input_bit % 8;

                    // 检查输入值的对应位是否为 1
                    if (value & (1 << (7 - bit_in_block))) {
                        // 在扩展后的输出中设置对应的位
                        expanded |= (1ULL << (47 - i)); // 47 - i，因为我们从高位到低位
                    }
                }
            }
            E_TABLE[block][value] = expanded; // 将结果存入表中
        }
    }
}

// 输出查找表到 C 文件
void output_E_table_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("无法打开文件");
        return;
    }

    fprintf(fp, "#include <stdint.h>\n\n");
    fprintf(fp, "uint64_t E_TABLE[4][256] = {\n");

    for (int block = 0; block < 4; block++) {
        fprintf(fp, "    {\n");
        for (int value = 0; value < 256; value++) {
            fprintf(fp, "        0x%012llxULL", E_TABLE[block][value]);
            if (value != 255) fprintf(fp, ",");
            if ((value + 1) % 4 == 0) fprintf(fp, "\n");
        }
        fprintf(fp, "    }%s\n", (block != 3) ? "," : "");
    }

    fprintf(fp, "};\n");
    fclose(fp);
}

int main() {
    generate_E_table();
    output_E_table_to_file("E_TABLE.c");
    return 0;
}
