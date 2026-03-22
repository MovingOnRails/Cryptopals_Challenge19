#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../../set2/Challenge12/base64.c"
#include "../../set2/Challenge10/aes.c"
//#include "../../set1/Challenge2/xorHelper.c"


unsigned char base64Strings[40][53] = {
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
};

int main() {


    // max length = 21
    unsigned char ciphertextStrings[40][22];
    int ciphertextLengths[40];

    for(int i=0;i<40;i++){
        unsigned char* rawBytesString = convertBase64ToRawBytes(base64Strings[i]);
        int encryptedLength = getRawByteLengthFromBase64String(base64Strings[i]);
        ciphertextLengths[i] = encryptedLength;
        unsigned char* ciphertextString = aes_ctr_transform(rawBytesString,encryptedLength,"THISISATESTKEY!!",0);
        memcpy(ciphertextStrings[i],ciphertextString,encryptedLength);
        free(rawBytesString);
        free(ciphertextString);

    }


    //--------------------DECRYPTION--------------------

    int num = -1;
    char* str = calloc(100,1);

    while(true){
        

        printf("Enter a number: ");
        if (scanf("%d", &num) != 1) {
            fprintf(stderr, "Invalid input for number.\n");
            exit(EXIT_FAILURE);
        }

        // 2. Clear the newline character from the buffer
        // This is crucial because scanf leaves the '\n' behind
        while (getchar() != '\n');

        printf("Enter a plaintext string: ");
        // 3. Read the string (fgets is safer than scanf for strings)
        if (fgets(str, 100, stdin) == NULL) {
            fprintf(stderr, "Error when reading plaintext");
            exit(EXIT_FAILURE);
        }
        int stringLength = strlen(str)-1;

        unsigned char* ciphertext = ciphertextStrings[num];
        unsigned char* plaintext = str;
        unsigned char* keystream = xorRawStrings(ciphertext,plaintext,stringLength);

        for(int j=0;j<40;j++){
            unsigned char* ciphertext_j = ciphertextStrings[j];
            int ciphertext_j_length = ciphertextLengths[j];
            int minLength = -1;
            if(ciphertext_j_length < stringLength){
                minLength = ciphertext_j_length;
            } else {
                minLength = stringLength;
            }
            unsigned char* plaintext_j = xorRawStrings(ciphertext_j,keystream,minLength);
            
            printf("%d ",j);
            for(int n=0;n<minLength;n++){
                printf("%c",plaintext_j[n]);
            }
            free(plaintext_j);
            int encryptedLength = ciphertextLengths[j];
            for(int n=0;n<encryptedLength-minLength;n++){
                printf("?");
            }
            printf("\n");
            
        }
        printf("-----------------------------------\n");
    }
    
    return 0;
}