#include <stdio.h>
#include <stdlib.h>

// Basic Logic Gates
int AND(int a, int b) {
    return (a && b) ? 1 : 0;
}

int OR(int a, int b) {
    return (a || b) ? 1 : 0;
}

int NOT(int a) {
    return (!a) ? 1 : 0;
}

int XOR(int a, int b) {
    return (a != b) ? 1 : 0;
}

int NAND(int a, int b) {
    return !(a && b) ? 1 : 0;
}

int NOR(int a, int b) {
    return !(a || b) ? 1 : 0;
}

// Half Adder: Returns sum and carry via pointers
void halfAdder(int a, int b, int* sum, int* carry) {
    *sum = XOR(a, b);
    *carry = AND(a, b);
}

// Full Adder: Returns sum and carry via pointers
void fullAdder(int a, int b, int cin, int* sum, int* carry) {
    int sum1, carry1, carry2;
    halfAdder(a, b, &sum1, &carry1);
    *sum = XOR(sum1, cin);
    carry2 = AND(sum1, cin);
    *carry = OR(carry1, carry2);
}

void printTruthTable(const char* gateName, int (*gate)(int, int)) {
    printf("\nTruth Table for %s:\n", gateName);
    printf("A B | Output\n");
    printf("---------\n");
    for (int a = 0; a <= 1; a++) {
        for (int b = 0; b <= 1; b++) {
            printf("%d %d | %d\n", a, b, gate(a, b));
        }
    }
}

int main() {
    int choice, a, b, cin, sum, carry;
    
    printf("=== Digital Logic Simulator ===\n");
    
    while (1) {
        printf("\nMenu:\n");
        printf("1. AND Gate\n");
        printf("2. OR Gate\n");
        printf("3. NOT Gate\n");
        printf("4. XOR Gate\n");
        printf("5. NAND Gate\n");
        printf("6. NOR Gate\n");
        printf("7. Half Adder\n");
        printf("8. Full Adder\n");
        printf("9. Show All Truth Tables\n");
        printf("0. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        
        if (choice == 0) {
            printf("Exiting simulator...\n");
            break;
        }
        
        switch (choice) {
            case 1: // AND
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("AND(%d, %d) = %d\n", a, b, AND(a, b));
                break;
                
            case 2: // OR
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("OR(%d, %d) = %d\n", a, b, OR(a, b));
                break;
                
            case 3: // NOT
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("NOT(%d) = %d\n", a, NOT(a));
                break;
                
            case 4: // XOR
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("XOR(%d, %d) = %d\n", a, b, XOR(a, b));
                break;
                
            case 5: // NAND
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("NAND(%d, %d) = %d\n", a, b, NAND(a, b));
                break;
                
            case 6: // NOR
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("NOR(%d, %d) = %d\n", a, b, NOR(a, b));
                break;
                
            case 7: // Half Adder
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                halfAdder(a, b, &sum, &carry);
                printf("Half Adder(A=%d, B=%d) -> Sum=%d, Carry=%d\n", a, b, sum, carry);
                break;
                
            case 8: // Full Adder
                printf("Enter A (0/1): ");
                scanf("%d", &a);
                printf("Enter B (0/1): ");
                scanf("%d", &b);
                printf("Enter Cin (0/1): ");
                scanf("%d", &cin);
                fullAdder(a, b, cin, &sum, &carry);
                printf("Full Adder(A=%d, B=%d, Cin=%d) -> Sum=%d, Carry=%d\n", a, b, cin, sum, carry);
                break;
                
            case 9: // Truth Tables
                printTruthTable("AND", AND);
                printTruthTable("OR", OR);
                printTruthTable("XOR", XOR);
                printTruthTable("NAND", NAND);
                printTruthTable("NOR", NOR);
                printf("\nNOT Truth Table:\n");
                printf("A | Output\n");
                printf("---------\n");
                printf("0 | %d\n", NOT(0));
                printf("1 | %d\n", NOT(1));
                break;
                
            default:
                printf("Invalid choice! Please try again.\n");
        }
    }
    
    return 0;
}