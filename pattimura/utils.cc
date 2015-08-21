//=======================================================================
// Copyright abeinoe 2015.
// Distributed under the MIT License.
// (See accompanying file LICENSE or copy at
//  http://opensource.org/licenses/MIT)
//=======================================================================

#include <stdio.h>

void printCharArray(unsigned char *in, short len, char *label)
{
    short i;

    printf("\n%s\n", label);
    for(i=0; i < len; i++)
        printf("%.2x ", in[i]);
    printf("\n");
}

short checkBox(const unsigned char *box)
{
    short i, j, k, l;

    l = 0;
    for(i=0; i < 256; i++){
        k = 0;
        for(j=0; j < 256; j++){
            if(box[j] == (unsigned char) i)
                k++;
        }
        if(k > 1){
            l++;
            printf("\nterdapat %d sebanyak: %d", i, k);
        } else if(k < 1){
            l++;
            printf("\ntidak ditemukan %d", i);
        }
    }

    if(l == 0){
        //printf("\nBox siap pakai.");
        return 0;
    }

    printf("\n");
    return 1;
}
