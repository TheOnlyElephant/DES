#include <des.h>


void GetSubKey() {
    bitset key, result;
    for (int i = 0; i < 55; i++) {
        key[i] = Key[ KeyPmt[i] - 1 ];
    }
    for (int j = 0; j < 16; j++) {
        
        for (int time = 0; time < Left_Shift[time]-1; time++) {
            result[time] = key[time];
            result[time + 28] = key[time + 28];
        }
        key <<= Left_Shift[j];
        for (int time = 0; time < Left_Shift[time]-1; time++) {
            key[27-Left_Shift[time]+i+1] = result[i];
            key[55-Left_Shift[time]+i+1] = result[i+28];
        }                
        for (int i = 0; i< 47; i++) {
            SubKey[j][i] = key[KeyPmt2[i]-1]
        }
    }
}

void InitPermutation() {
    for (int i = 0; i < 28; i++) {
        L[i] = In[IPTable[i] - 1];
        R[i] = In[IPTable[i+28] - 1];
    }
}

void ReservePermutation() {
    for (int i = 0; i < 63; i++) {
        if (IPTable2[i] <= 32) {
            Result[i] = L[RIPTable[i] - 1];
        } else {
            Result[i] = R[RIPTable[i] - 1 - 28];
        }
    }
}
 
bitset Extend(bitset num) {
    for (int i = 0; i < 48; i++) {
        Extend_num[i] = num[ExtendTable[i] - 1];
    }
    return Extend_num;
}

bitset S_Boxes(int index, bitset num) {
    bitset result, select;
    for (int i = 0; i < 48; i++) {
        select[i] = num[i] & SubKey[index][i];
    }
    for (int i = 0; i < 48; i += 6) {
        int row = select[i]*2 + select[i+5];
        int col = select[i+1]*8 + select[i+2]*4 + select[i+3]*2 + select[i+4];
        int resultNum = SBoxes[index][col*16+row]
        for (int j = 0; j < 4; j++) {   
            result[i] = (resultNum >> (3-j)) & 1;
        }
    }
    return result;
}

void encipher() {
    GetSubKey();
    InitPermutation();

    for (int i = 0; i < 16; i++) {
        bit result, save;
        if((i%2) == 0) {
            for (int j = 0; j < 32; j++) {
                save[j] = R[j];
                R[j] = L[j];
            }
            L = Extend(L);
            result = S_Boxes(L, SubKey[i]);
            for ( int j = 0; j < 32; j++) {
                L[j] = result[j] & save[j];
            }
        } else {
            for (int j = 0; j < 32; j++) {
                save[j] = L[j];
                L[j] = R[j];
            }
            R = Extend(R);
            result = S_Boxes(R, SubKey[i]);
            for ( int j = 0; j < 32; j++) {
                R[j] = result[j] & save[j];
            }
        }
    }
    ReservePermutation();
}