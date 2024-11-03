#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Right rotate function
uint32_t rightRotate(uint32_t value, int n)
{
    return ((value >> n) | (value << (32 - n))) & 0xFFFFFFFF;
}

// Choose function
uint32_t sha256Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

// Majority function
uint32_t sha256Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// Sigma_0 function
uint32_t sha256Sigma0(uint32_t x)
{
    return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
}

// Sigma_1 function
uint32_t sha256Sigma1(uint32_t x)
{
    return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
}

// Gamma_0 function
uint32_t sha256Gamma0(uint32_t x)
{
    return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >> 3);
}

// Gamma_1 function
uint32_t sha256Gamma1(uint32_t x)
{
    return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
}

// Function to convert a 32-bit integer to hexadecimal
void toHex(uint32_t value, char *output)
{
    for (int i = 0; i < 4; i++)
    {
        sprintf(output + (i * 2), "%02x", (value >> (24 - i * 8)) & 0xFF);
    }
}

// Function to trim leading and trailing whitespace
char *trim(char *str)
{
    char *end;
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
        str++; // Leading spaces
    if (*str == 0)
        return str;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        end--; // Trailing spaces
    *(end + 1) = 0;
    return str;
}

// SHA-256 function to compute the hash
void sha256(const char *message, char *output) {
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // SHA-256 constants
    const uint32_t K[] = { /* 64 constants here */ };

    // Message padding
    size_t original_len = strlen(message);
    size_t padded_len = original_len + 1;
    while (padded_len % 64 != 56)
        padded_len++;
    padded_len += 8;

    uint8_t *padded = (uint8_t *)calloc(padded_len, 1);
    memcpy(padded, message, original_len);
    padded[original_len] = 0x80;

    uint64_t original_bit_len = original_len * 8;
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 1 - i] = original_bit_len >> (i * 8);
    }

    // SHA-256 processing
    for (size_t i = 0; i < padded_len; i += 64) {
        uint32_t words[64];
        for (int j = 0; j < 16; j++) {
            words[j] = (padded[i + 4 * j] << 24) | (padded[i + 4 * j + 1] << 16) |
                       (padded[i + 4 * j + 2] << 8) | padded[i + 4 * j + 3];
        }

        for (int j = 16; j < 64; j++) {
            uint32_t s0 = sha256Gamma0(words[j - 15]);
            uint32_t s1 = sha256Gamma1(words[j - 2]);
            words[j] = words[j - 16] + s0 + words[j - 7] + s1;
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (int j = 0; j < 64; j++) {
            uint32_t S1 = sha256Sigma1(e);
            uint32_t ch = sha256Ch(e, f, g);
            uint32_t temp1 = h + S1 + ch + K[j] + words[j];
            uint32_t S0 = sha256Sigma0(a);
            uint32_t maj = sha256Maj(a, b, c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    free(padded);

    // Convert hash values to hex string
    toHex(h0, output);
    toHex(h1, output + 8);
    toHex(h2, output + 16);
    toHex(h3, output + 24);
    toHex(h4, output + 32);
    toHex(h5, output + 40);
    toHex(h6, output + 48);
    toHex(h7, output + 56);
    output[64] = '\0'; // Ensure output is null-terminated
}


// Function to calculate SHA-256 hash for a given string
void calculateSHA256(const char *str, char *outputBuffer)
{
    sha256(str, outputBuffer);
}

// Define a structure to hold the block information
struct Block
{
    int index;
    uint32_t timestamp;
    char previous_block_hash[65];
    char merkle_root[65];
    char block_hash[65];


    // 3D array to store diagnoses
    char ***diagnoses;   // Pointer to an array of diagnoses, each with [disease, description, treatment]
    int diagnosis_count; // Number of diagnoses in the array
};

// Define a structure to hold the blockchain information
struct Blockchain
{
    struct Block *chain; // Pointer to an array of blocks
    int block_count;     // Number of blocks in the chain
};

struct Patient
{
    int patient_idx;
    char patient_name[64];
    char unique_id[64];
    int patient_age;
    char ***diagnoses;
    int diagnosis_count;
};

void addPatientDiagnosis(struct Patient* patient,uint32_t timestamp, char *doctor_id, char *disease, char *description, char *treatment)
{
    patient->diagnoses = realloc(patient->diagnoses, (patient->diagnosis_count + 1) * sizeof(char **));

    patient->diagnoses[patient->diagnosis_count] = malloc(5 * sizeof(char *));
    char timestamp_str[11]; 
    sprintf(timestamp_str, "%u", timestamp);

    patient->diagnoses[patient->diagnosis_count][0] = strdup(timestamp_str);
    patient->diagnoses[patient->diagnosis_count][1] = strdup(doctor_id);
    patient->diagnoses[patient->diagnosis_count][2] = strdup(disease);
    patient->diagnoses[patient->diagnosis_count][3] = strdup(description);
    patient->diagnoses[patient->diagnosis_count][4] = strdup(treatment);

    patient->diagnosis_count++;
}
  
// Function to calculate the block hash
void calculateBlockHash(struct Block *block) {
    char data[2048];
    //clear the data buffer
    memset(data, 0, sizeof(data));
    snprintf(data, sizeof(data), "%d%u%s%s", block->index, block->timestamp, block->previous_block_hash, block->merkle_root);
    char new_hash[65];
    calculateSHA256(data, new_hash);
    strcpy(block->block_hash, new_hash);

    printf("Previous block hash after hashing: %s\n", block->previous_block_hash);
    printf("Computed block hash: %s\n", block->block_hash);
}


// Function to allocate memory and set a diagnosis with disease, description, and treatment
// Function to add a diagnosis to a block
void addDiagnosis(struct Block *block, const char *patient_id, const char *doctor_id, const char *disease, const char *description, const char *treatment) {
    block->diagnoses = realloc(block->diagnoses, (block->diagnosis_count + 1) * sizeof(char **));
    block->diagnoses[block->diagnosis_count] = malloc(5 * sizeof(char *));
    block->diagnoses[block->diagnosis_count][0] = strdup(patient_id);
    block->diagnoses[block->diagnosis_count][1] = strdup(doctor_id);
    block->diagnoses[block->diagnosis_count][2] = strdup(disease);
    block->diagnoses[block->diagnosis_count][3] = strdup(description);
    block->diagnoses[block->diagnosis_count][4] = strdup(treatment);
    block->diagnosis_count++;
}

// Function to free memory for the diagnoses array
void freeDiagnoses(struct Block *block)
{
    for (int i = 0; i < block->diagnosis_count; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            free(block->diagnoses[i][j]);
        }
        free(block->diagnoses[i]);
    }
    free(block->diagnoses);
    block->diagnoses = NULL;
    block->diagnosis_count = 0;
}

void calculateMerkleRoot(struct Block *block)
{
    if (block->diagnosis_count == 0) {
        strcpy(block->merkle_root, ""); // No diagnoses, empty Merkle root
        return;
    }


   // Allocate memory for the initial hashes
    char (*hashes)[65] = malloc(block->diagnosis_count * sizeof(*hashes));
    if (!hashes) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Hash each diagnosis
    for (int i = 0; i < block->diagnosis_count; i++) {
        char combined[2048];
        snprintf(combined, sizeof(combined), "%s%s%s%s%s", 
                 block->diagnoses[i][0], // patient_id
                 block->diagnoses[i][1], // doctor_id
                 block->diagnoses[i][2], // disease
                 block->diagnoses[i][3], // description
                 block->diagnoses[i][4]); // treatment
        calculateSHA256(combined, hashes[i]);
    }

    int count = block->diagnosis_count;

    // Repeat the process until we get a single hash
    while (count > 1) {
        int new_count = (count + 1) / 2;
        for (int i = 0; i < new_count; i++) {
            char combined[130]; // 2 * 64 + 1 for null terminator
            if (2 * i + 1 < count) {
                snprintf(combined, sizeof(combined), "%s%s", hashes[2 * i], hashes[2 * i + 1]);
            } else {
                snprintf(combined, sizeof(combined), "%s", hashes[2 * i]);
            }
            calculateSHA256(combined, hashes[i]);
        }
        count = new_count;
    }

    // The final hash is the Merkle root
    strcpy(block->merkle_root, hashes[0]);

    // Free allocated memory
    free(hashes);
}

// Function to initialize the blockchain with a genesis block
void initializeBlockchain(struct Blockchain *blockchain)
{
    blockchain->chain = malloc(sizeof(struct Block));
    if (blockchain->chain == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    blockchain->block_count = 1;
    struct Block genesisBlock;
    genesisBlock.index = 0;
    strcpy(genesisBlock.merkle_root, "");
    genesisBlock.timestamp = time(NULL);
    strcpy(genesisBlock.previous_block_hash, "0");
    genesisBlock.diagnoses = NULL;
    genesisBlock.diagnosis_count = 0;
    calculateBlockHash(&genesisBlock);
    blockchain->chain[0] = genesisBlock;
}

// Function to add a new block to the blockchain
void addBlock(struct Blockchain *blockchain, struct Block newBlock) {
    blockchain->chain = realloc(blockchain->chain, (blockchain->block_count + 1) * sizeof(struct Block));
    blockchain->chain[blockchain->block_count] = newBlock;
    blockchain->block_count++;
}


// Function to get and print the blockchain details
void getBlockchain(struct Blockchain *blockchain)
{
    for (int i = 0; i < blockchain->block_count; i++)
    {
        printf("Block %d:\n", blockchain->chain[i].index);
        printf("  Merkle Root: %s\n", blockchain->chain[i].merkle_root);
        printf("  Timestamp: %u\n", blockchain->chain[i].timestamp);
        printf("  Previous Block Hash: %s\n", blockchain->chain[i].previous_block_hash);
        printf("  Block Hash: %s\n", blockchain->chain[i].block_hash);
        printf("  Diagnoses:\n");
        for (int j = 0; j < blockchain->chain[i].diagnosis_count; j++)
        {
            printf("    Diagnosis %d:\n", j + 1);
            printf("      Patient ID: %s\n", blockchain->chain[i].diagnoses[j][0]);
            printf("      Doctor ID: %s\n", blockchain->chain[i].diagnoses[j][1]);
            printf("      Disease: %s\n", blockchain->chain[i].diagnoses[j][2]);
            printf("      Description: %s\n", blockchain->chain[i].diagnoses[j][3]);
            printf("      Treatment: %s\n", blockchain->chain[i].diagnoses[j][4]);
        }
    }
}

int main()
{
    struct Blockchain blockchain;
    initializeBlockchain(&blockchain);
    struct Patient patients[100];
    int patient_count = 0;

    while (1)
    {
        printf("\nBlockchain Electronic Health Record System:\n");
        printf("1) Register Patient\n");
        printf("2) View Patient Record\n");
        printf("3) Add Doctor's Diagnosis\n");
        printf("4) Patient Pharmacy\n");
        printf("5) BlockChain Details\n");
        printf("6) Exit\n\n");

        int choice;
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); 

        if(choice==1)
        {
            char patient_name[64];
            char unique_id[64];
            int patient_age;
            printf("Enter patient name: ");
            fgets(patient_name, sizeof(patient_name), stdin);
            patient_name[strcspn(patient_name, "\n")] = '\0'; 
            printf("Enter patient unique ID: ");
            scanf("%s", unique_id);
            printf("Enter patient age: ");
            scanf("%d", &patient_age);

            int found = 0;
            for (int i = 0; i < patient_count; i++)
            {
                if (strcmp(patients[i].unique_id, unique_id) == 0)
                {
                    found = 1;
                    break;
                }
            }

            if (found == 1)
            {
                printf("Patient already registered.\n");
            }
            else
            {
                struct Patient newPatient;
                newPatient.patient_idx = patient_count;
                strcpy(newPatient.patient_name, patient_name);
                strcpy(newPatient.unique_id, unique_id);
                newPatient.patient_age = patient_age;
                newPatient.diagnoses = NULL;
                newPatient.diagnosis_count = 0;
                patients[patient_count] = newPatient;
                patient_count++;
                printf("\nPatient registered successfully.\n");
            }

        }
        else if(choice==2)
        {
            char unique_id[64];
            printf("\nEnter patient unique ID: ");
            scanf("%s", unique_id);

            int patient_idx = -1;
            for (int i = 0; i < patient_count; i++)
            {
                if (strcmp(patients[i].unique_id, unique_id) == 0)
                {
                    patient_idx = i;
                    break;
                }
            }

            if (patient_idx == -1)
            {
                printf("Patient not found.\n");
            }
            else
            {
                struct Patient *patient = &patients[patient_idx];
                printf("Patient Name: %s\n", patient->patient_name);
                printf("Patient Unique ID: %s\n", patient->unique_id);
                printf("Patient Age: %d\n", patient->patient_age);
                printf("Diagnoses:\n");
                for (int i = 0; i < patient->diagnosis_count; i++)
                {
                    printf("  Diagnosis %d:\n", i + 1);
                    printf("    Time: %s\n", patient->diagnoses[i][0]);
                    printf("    Doctor ID: %s\n", patient->diagnoses[i][1]);
                    printf("    Disease: %s\n", patient->diagnoses[i][2]);
                    printf("    Description: %s\n", patient->diagnoses[i][3]);
                    printf("    Treatment: %s\n", patient->diagnoses[i][4]);
                }
            }
        }
        else if(choice==3)
        {
            char unique_id[64];
            printf("\nEnter patient unique ID: ");
            scanf("%s", unique_id);

            int patient_idx = -1;
            for (int i = 0; i < patient_count; i++)
            {
                if (strcmp(patients[i].unique_id, unique_id) == 0)
                {
                    patient_idx = i;
                    break;
                }
            }

            if (patient_idx == -1)
            {
                printf("Patient not found.\n");
            }
            else
            {
                struct Patient *patient = &patients[patient_idx];
                uint32_t timestamp = time(NULL);
                char doctor_id[64];
                char disease[64];
                char description[200];
                char treatment[200];
                printf("Enter doctor ID: ");
                scanf("%s", doctor_id);
                printf("Enter disease: ");
                scanf("%s", disease);
                printf("Enter description: ");
                getchar();
                fgets(description, sizeof(description), stdin);
                description[strcspn(description, "\n")] = '\0';
                printf("Enter treatment: ");
                fgets(treatment, sizeof(treatment), stdin);
                treatment[strcspn(treatment, "\n")] = '\0';
                addPatientDiagnosis(patient, timestamp, doctor_id, disease, description, treatment);

                struct Block newBlock;
                newBlock.index = blockchain.block_count;
                newBlock.timestamp = time(NULL);
                strcpy(newBlock.previous_block_hash, blockchain.chain[blockchain.block_count - 1].block_hash);
                newBlock.diagnoses = NULL;
                newBlock.diagnosis_count = 0;

                addDiagnosis(&newBlock, unique_id, doctor_id, disease, description, treatment);
                calculateMerkleRoot(&newBlock);
                calculateBlockHash(&newBlock);
                addBlock(&blockchain, newBlock);

                printf("\nDiagnosis added successfully.\n");
            }
        }
        else if(choice==4)
        {
            //Find the latest diagnosis in the patient record and print the treatment
            char unique_id[64];
            printf("\nEnter patient unique ID: ");
            scanf("%s", unique_id);

            int patient_idx = -1;
            for (int i = 0; i < patient_count; i++)
            {
                if (strcmp(patients[i].unique_id, unique_id) == 0)
                {
                    patient_idx = i;
                    break;
                }
            }

            if (patient_idx == -1)
            {
                printf("Patient not found.\n");
            }
            else
            {
                struct Patient *patient = &patients[patient_idx];
                if (patient->diagnosis_count == 0)
                {
                    printf("No diagnosis found for the patient.\n");
                }
                else
                {
                    printf("Latest treatment for the patient:\n");
                    printf("Treatment: %s\n", patient->diagnoses[patient->diagnosis_count - 1][4]);
                }
            }
        }
        else if (choice==5)
        {
            printf("\nBlockchain Details:\n");
            printf("1) View Full Blockchain\n");
            printf("2) View Single Block\n");
            printf("3) Demonstrate Blockchain Immmutability\n");
            printf("4) Exit\n\n");

            int choice;
            printf("Enter your choice: ");
            scanf("%d", &choice);
        
            if(choice==1)
            {
                getBlockchain(&blockchain);
            }
            else if(choice==2)
            {
                int blockIndex;
                printf("Enter the block index to access: ");
                scanf("%d", &blockIndex);

                if (blockIndex >= blockchain.block_count)
                {
                    printf("Block not found.\n");
                }
                else
                {
                    struct Block *block = &blockchain.chain[blockIndex];
                    printf("Block %d:\n", block->index);
                    printf("  Merkle Root: %s\n", block->merkle_root);
                    printf("  Timestamp: %u\n", block->timestamp);
                    printf("  Previous Block Hash: %s\n", block->previous_block_hash);
                    printf("  Block Hash: %s\n", block->block_hash);
                    printf("  Diagnoses:\n");
                    for (int i = 0; i < block->diagnosis_count; i++)
                    {
                        printf("    Diagnosis %d:\n", i + 1);
                        printf("      Patient ID: %s\n", block->diagnoses[i][0]);
                        printf("      Doctor ID: %s\n", block->diagnoses[i][1]);
                        printf("      Disease: %s\n", block->diagnoses[i][2]);
                        printf("      Description: %s\n", block->diagnoses[i][3]);
                        printf("      Treatment: %s\n", block->diagnoses[i][4]);
                    }
                }
            }
            else if(choice==3)
            {
                int blockIndex;
                printf("Enter the block index to tamper in the range 0 to %d-1: ", blockchain.block_count);
                scanf("%d", &blockIndex);

                if (blockIndex >= blockchain.block_count)
                {
                    printf("Block not found.\n");
                }
                else
                {
                    struct Block *block = &blockchain.chain[blockIndex];
                    struct Block *modifiedBlock = malloc(sizeof(struct Block));
                    modifiedBlock->index = block->index;
                    modifiedBlock->timestamp = block->timestamp;
                    strcpy(modifiedBlock->previous_block_hash, block->previous_block_hash);
                    modifiedBlock->diagnoses = malloc(block->diagnosis_count * sizeof(char **));
                    for (int i = 0; i < block->diagnosis_count; i++)
                    {
                        modifiedBlock->diagnoses[i] = malloc(5 * sizeof(char *));
                        for (int j = 0; j < 5; j++)
                        {
                            modifiedBlock->diagnoses[i][j] = strdup(block->diagnoses[i][j]);
                        }
                    }
                    modifiedBlock->diagnosis_count = block->diagnosis_count;
                    printf("Block %d:\n", block->index);
                    printf("  Merkle Root: %s\n", block->merkle_root);
                    printf("  Timestamp: %u\n", block->timestamp);
                    printf("  Previous Block Hash: %s\n", block->previous_block_hash);
                    printf("  Block Hash: %s\n", block->block_hash);
                    printf("  Diagnoses:\n");
                    for (int i = 0; i < block->diagnosis_count; i++)
                    {
                        printf("    Diagnosis %d:\n", i + 1);
                        printf("      Patient ID: %s\n", block->diagnoses[i][0]);
                        printf("      Doctor ID: %s\n", block->diagnoses[i][1]);
                        printf("      Disease: %s\n", block->diagnoses[i][2]);
                        printf("      Description: %s\n", block->diagnoses[i][3]);
                        printf("      Treatment: %s\n", block->diagnoses[i][4]);
                    }

                    printf("\n");
                    printf("Enter the diagnosis index to tamper in the range 0 to %d-1: ", block->diagnosis_count);
                    int diagnosisNum;
                    scanf("%d", &diagnosisNum);

                    if (diagnosisNum >= block->diagnosis_count)
                    {
                        printf("Diagnosis not found.\n");
                    }
                    else
                    {
                        printf("Enter the Doctor ID: ");
                        char doctor_id[64];
                        scanf("%s", doctor_id);
                        printf("Enter the Disease: ");
                        char disease[64];
                        scanf("%s", disease);
                        printf("Enter the Description: ");
                        char description[200];
                        getchar();
                        fgets(description, sizeof(description), stdin);
                        description[strcspn(description, "\n")] = '\0';
                        printf("Enter the Treatment: ");
                        char treatment[200];
                        fgets(treatment, sizeof(treatment), stdin);
                        treatment[strcspn(treatment, "\n")] = '\0';

                        free(modifiedBlock->diagnoses[diagnosisNum][1]);
                        free(modifiedBlock->diagnoses[diagnosisNum][2]);
                        free(modifiedBlock->diagnoses[diagnosisNum][3]);
                        free(modifiedBlock->diagnoses[diagnosisNum][4]);
                        modifiedBlock->diagnoses[diagnosisNum][1] = strdup(doctor_id);
                        modifiedBlock->diagnoses[diagnosisNum][2] = strdup(disease);
                        modifiedBlock->diagnoses[diagnosisNum][3] = strdup(description);
                        modifiedBlock->diagnoses[diagnosisNum][4] = strdup(treatment);

                        calculateMerkleRoot(modifiedBlock);

                        printf("\nBlock %d:\n", block->index);
                        //print the merkle roots before and after modicfication
                        printf("  Merkle Root before modification: %s\n", block->merkle_root);
                        printf("  Merkle Root after modification: %s\n", modifiedBlock->merkle_root);

                        if(strcmp(block->merkle_root, modifiedBlock->merkle_root) != 0)
                        {
                            printf("\nMerkle Roots Differ, Tampering failed and thus Blockchain is immutable.\n");
                        }
                        else
                        {
                            printf("\nBlock is tampered, thus blockchain is insecure.\n");
                        }
                    }
                }
            }
            else if(choice==4)
            {
                break;
            }
        }
        else
        {
            break;
        }
        printf("\n");
    }

    return 0;
}
