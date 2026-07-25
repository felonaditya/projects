#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

// Convert Binary to Decimal
long long binaryToDecimal(const char* bin) {
    long long decimal = 0;
    int base = 1;
    int len = strlen(bin);
    for (int i = len - 1; i >= 0; i--) {
        if (bin[i] == '1') decimal += base;
        base *= 2;
    }
    return decimal;
}

// Convert Decimal to Binary (returns string)
void decimalToBinary(long long n, char* bin) {
    if (n == 0) {
        strcpy(bin, "0");
        return;
    }
    char temp[64];
    int i = 0;
    while (n > 0) {
        temp[i++] = (n % 2) + '0';
        n /= 2;
    }
    temp[i] = '\0';
    // Reverse
    int j = 0;
    for (int k = i - 1; k >= 0; k--) {
        bin[j++] = temp[k];
    }
    bin[j] = '\0';
}

// Convert Decimal to Octal
int decimalToOctal(long long n) {
    int octal = 0, base = 1;
    while (n > 0) {
        octal += (n % 8) * base;
        n /= 8;
        base *= 10;
    }
    return octal;
}

// Convert Decimal to Hexadecimal (prints)
void decimalToHex(long long n) {
    if (n == 0) {
        printf("0");
        return;
    }
    char hex[32];
    int i = 0;
    while (n > 0) {
        int rem = n % 16;
        hex[i++] = (rem < 10) ? (rem + '0') : (rem - 10 + 'A');
        n /= 16;
    }
    for (int j = i - 1; j >= 0; j--) {
        printf("%c", hex[j]);
    }
}

// Binary Addition
void binaryAdd(const char* a, const char* b) {
    char result[100];
    int i = strlen(a) - 1;
    int j = strlen(b) - 1;
    int carry = 0, k = 0;
    
    while (i >= 0 || j >= 0 || carry) {
        int sum = carry;
        if (i >= 0) sum += a[i--] - '0';
        if (j >= 0) sum += b[j--] - '0';
        result[k++] = (sum % 2) + '0';
        carry = sum / 2;
    }
    result[k] = '\0';
    
    // Reverse
    printf("Result: ");
    for (int m = k - 1; m >= 0; m--) {
        printf("%c", result[m]);
    }
    printf("\n");
}

int main() {
    int choice;
    char bin1[64], bin2[64];
    long long dec;
    
    printf("=== Binary Number System Calculator ===\n");
    
    while (1) {
        printf("\nMenu:\n");
        printf("1. Binary to Decimal\n");
        printf("2. Decimal to Binary\n");
        printf("3. Binary to Octal\n");
        printf("4. Binary to Hexadecimal\n");
        printf("5. Decimal to Octal\n");
        printf("6. Decimal to Hexadecimal\n");
        printf("7. Binary Addition\n");
        printf("8. Binary Subtraction (limited support)\n");
        printf("0. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        
        if (choice == 0) {
            printf("Exiting...\n");
            break;
        }
        
        switch (choice) {
            case 1: // Bin -> Dec
                printf("Enter binary number: ");
                scanf("%s", bin1);
                printf("Decimal: %lld\n", binaryToDecimal(bin1));
                break;
                
            case 2: // Dec -> Bin
                printf("Enter decimal number: ");
                scanf("%lld", &dec);
                decimalToBinary(dec, bin1);
                printf("Binary: %s\n", bin1);
                break;
                
            case 3: // Bin -> Octal
                printf("Enter binary: ");
                scanf("%s", bin1);
                dec = binaryToDecimal(bin1);
                printf("Octal: %d\n", decimalToOctal(dec));
                break;
                
            case 4: // Bin -> Hex
                printf("Enter binary: ");
                scanf("%s", bin1);
                dec = binaryToDecimal(bin1);
                printf("Hexadecimal: ");
                decimalToHex(dec);
                printf("\n");
                break;
                
            case 5: // Dec -> Octal
                printf("Enter decimal: ");
                scanf("%lld", &dec);
                printf("Octal: %d\n", decimalToOctal(dec));
                break;
                
            case 6: // Dec -> Hex
                printf("Enter decimal: ");
                scanf("%lld", &dec);
                printf("Hexadecimal: ");
                decimalToHex(dec);
                printf("\n");
                break;
                
            case 7: // Binary Addition
                printf("Enter first binary: ");
                scanf("%s", bin1);
                printf("Enter second binary: ");
                scanf("%s", bin2);
                binaryAdd(bin1, bin2);
                break;
                
            case 8: // Binary Subtraction (simple positive case)
                printf("Enter first binary: ");
                scanf("%s", bin1);
                printf("Enter second binary: ");
                scanf("%s", bin2);
                long long n1 = binaryToDecimal(bin1);
                long long n2 = binaryToDecimal(bin2);
                if (n1 >= n2) {
                    decimalToBinary(n1 - n2, bin1);
                    printf("Result: %s\n", bin1);
                } else {
                    printf("Negative result not supported in this simple version.\n");
                }
                break;
                
            default:
                printf("Invalid choice!\n");
        }
    }
    return 0;
}