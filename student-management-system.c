#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>

#define INITIAL_CAPACITY 20
#define MAX_NAME_LEN     120
#define MAX_SUBJECTS     5
#define DATA_FILE        "students.dat"
#define FILE_VERSION     4
#define MAX_MARKS        100.0f

const char *subject_names[MAX_SUBJECTS] = {
    "Mathematics",
    "Physics",
    "Chemistry",
    "English",
    "Computer Science"
};

typedef struct {
    int roll;
    char name[MAX_NAME_LEN];
    float marks[MAX_SUBJECTS];
} Student;

typedef struct {
    Student *students;
    size_t count;
    size_t capacity;
} StudentDatabase;

/* ====================== Utility ====================== */

static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

static void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len-1] == '\n') str[len-1] = '\0';
    while (len > 0 && isspace((unsigned char)str[len-1])) str[--len] = '\0';
}

static bool is_valid_name(const char *name) {
    if (!name || strlen(name) == 0) return false;
    for (const char *p = name; *p; ++p) {
        if (!isalnum((unsigned char)*p) && !isspace((unsigned char)*p) &&
            *p != '.' && *p != '-' && *p != ',' && *p != '\'')
            return false;
    }
    return true;
}

static void print_header(const char *title) {
    printf("\n=== %s ===\n", title);
}

/* ====================== Database Core ====================== */

StudentDatabase* db_create(void) {
    StudentDatabase *db = calloc(1, sizeof(StudentDatabase));
    if (!db) {
        perror("Failed to allocate database");
        exit(EXIT_FAILURE);
    }
    db->capacity = INITIAL_CAPACITY;
    db->students = calloc(INITIAL_CAPACITY, sizeof(Student));
    if (!db->students) {
        free(db);
        perror("Failed to allocate student array");
        exit(EXIT_FAILURE);
    }
    return db;
}

void db_destroy(StudentDatabase *db) {
    if (db) {
        free(db->students);
        free(db);
    }
}

static void db_ensure_capacity(StudentDatabase *db) {
    if (db->count >= db->capacity) {
        size_t new_cap = db->capacity * 2;
        Student *new_arr = realloc(db->students, new_cap * sizeof(Student));
        if (!new_arr) {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(EXIT_FAILURE);
        }
        db->students = new_arr;
        db->capacity = new_cap;
    }
}

/* ====================== CRUD ====================== */

bool db_add_student(StudentDatabase *db, int roll, const char *name, const float subject_marks[]) {
    if (!db || roll <= 0 || !is_valid_name(name))
        return false;

    for (size_t i = 0; i < db->count; ++i) {
        if (db->students[i].roll == roll)
            return false; // duplicate roll
    }

    db_ensure_capacity(db);

    Student *s = &db->students[db->count++];
    s->roll = roll;
    strncpy(s->name, name, MAX_NAME_LEN - 1);
    s->name[MAX_NAME_LEN - 1] = '\0';

    for (int i = 0; i < MAX_SUBJECTS; ++i) {
        s->marks[i] = (subject_marks[i] >= 0.0f && subject_marks[i] <= MAX_MARKS) ? subject_marks[i] : 0.0f;
    }

    return true;
}

bool db_delete_student(StudentDatabase *db, int roll) {
    for (size_t i = 0; i < db->count; ++i) {
        if (db->students[i].roll == roll) {
            memmove(&db->students[i], &db->students[i + 1],
                    (db->count - i - 1) * sizeof(Student));
            db->count--;
            return true;
        }
    }
    return false;
}

bool db_update_student(StudentDatabase *db, int roll, const char *new_name, const float new_marks[]) {
    for (size_t i = 0; i < db->count; ++i) {
        if (db->students[i].roll == roll) {
            if (new_name && is_valid_name(new_name)) {
                strncpy(db->students[i].name, new_name, MAX_NAME_LEN - 1);
                db->students[i].name[MAX_NAME_LEN - 1] = '\0';
            }
            if (new_marks) {
                for (int j = 0; j < MAX_SUBJECTS; ++j) {
                    if (new_marks[j] >= 0.0f && new_marks[j] <= MAX_MARKS) {
                        db->students[i].marks[j] = new_marks[j];
                    }
                }
            }
            return true;
        }
    }
    return false;
}

const Student* db_find_by_roll(const StudentDatabase *db, int roll) {
    for (size_t i = 0; i < db->count; ++i) {
        if (db->students[i].roll == roll)
            return &db->students[i];
    }
    return NULL;
}

/* ====================== Display ====================== */

void db_display_all(const StudentDatabase *db) {
    if (db->count == 0) {
        printf("No student records found.\n");
        return;
    }

    printf("\n%-8s %-30s ", "Roll", "Name");
    for (int i = 0; i < MAX_SUBJECTS; ++i) {
        printf("%-12s ", subject_names[i]);
    }
    printf(" Total   Avg   Grade\n");
    printf("-----------------------------------------------------------------------------------------------\n");

    for (size_t i = 0; i < db->count; ++i) {
        const Student *s = &db->students[i];
        float total = 0.0f;
        for (int j = 0; j < MAX_SUBJECTS; ++j) {
            total += s->marks[j];
        }
        float avg = total / MAX_SUBJECTS;
        char grade = (avg >= 90) ? 'A' : (avg >= 80) ? 'B' :
                     (avg >= 70) ? 'C' : (avg >= 60) ? 'D' : 'F';

        printf("%-8d %-30s ", s->roll, s->name);
        for (int j = 0; j < MAX_SUBJECTS; ++j) {
            printf("%-12.2f ", s->marks[j]);
        }
        printf("%-8.2f %-5.2f %c\n", total, avg, grade);
    }
}

void db_export_csv(const StudentDatabase *db) {
    FILE *fp = fopen("students_export.csv", "w");
    if (!fp) {
        perror("Failed to create CSV");
        return;
    }

    fprintf(fp, "Roll,Name");
    for (int i = 0; i < MAX_SUBJECTS; ++i) {
        fprintf(fp, ",%s", subject_names[i]);
    }
    fprintf(fp, ",Total,Avg,Grade\n");

    for (size_t i = 0; i < db->count; ++i) {
        const Student *s = &db->students[i];
        float total = 0.0f;
        for (int j = 0; j < MAX_SUBJECTS; ++j) total += s->marks[j];
        float avg = total / MAX_SUBJECTS;
        char grade = (avg >= 90) ? 'A' : (avg >= 80) ? 'B' :
                     (avg >= 70) ? 'C' : (avg >= 60) ? 'D' : 'F';

        fprintf(fp, "%d,\"%s\"", s->roll, s->name);
        for (int j = 0; j < MAX_SUBJECTS; ++j) {
            fprintf(fp, ",%.2f", s->marks[j]);
        }
        fprintf(fp, ",%.2f,%.2f,%c\n", total, avg, grade);
    }
    fclose(fp);
    printf("[SUCCESS] Exported to students_export.csv\n");
}

/* ====================== Statistics ====================== */

void db_show_statistics(const StudentDatabase *db) {
    if (db->count == 0) return;

    float total_all = 0.0f;
    float max_avg = 0.0f, min_avg = MAX_MARKS;
    int passed = 0;

    for (size_t i = 0; i < db->count; ++i) {
        float total = 0.0f;
        for (int j = 0; j < MAX_SUBJECTS; ++j) {
            total += db->students[i].marks[j];
        }
        float avg = total / MAX_SUBJECTS;
        total_all += avg;

        if (avg > max_avg) max_avg = avg;
        if (avg < min_avg) min_avg = avg;
        if (avg >= 60.0f) passed++;
    }

    printf("\n=== STATISTICS ===\n");
    printf("Total Students     : %zu\n", db->count);
    printf("Overall Average    : %.2f\n", total_all / db->count);
    printf("Highest Average    : %.2f\n", max_avg);
    printf("Lowest Average     : %.2f\n", min_avg);
    printf("Pass Percentage    : %.2f%%\n", (passed * 100.0f) / db->count);
}

/* ====================== Sorting ====================== */

typedef int (*CompareFunc)(const void *, const void *);

static int cmp_roll_asc(const void *a, const void *b) {
    return ((const Student*)a)->roll - ((const Student*)b)->roll;
}

static int cmp_avg_desc(const void *a, const void *b) {
    float total_a = 0.0f, total_b = 0.0f;
    for (int i = 0; i < MAX_SUBJECTS; ++i) {
        total_a += ((const Student*)a)->marks[i];
        total_b += ((const Student*)b)->marks[i];
    }
    float avg_a = total_a / MAX_SUBJECTS;
    float avg_b = total_b / MAX_SUBJECTS;
    return (avg_b > avg_a) - (avg_b < avg_a);
}

static int cmp_name_asc(const void *a, const void *b) {
    return strcasecmp(((const Student*)a)->name, ((const Student*)b)->name);
}

void db_sort(StudentDatabase *db, int option) {
    if (db->count <= 1) return;
    CompareFunc cmp = (option == 1) ? cmp_roll_asc :
                      (option == 2) ? cmp_avg_desc : cmp_name_asc;
    qsort(db->students, db->count, sizeof(Student), cmp);
}

/* ====================== File I/O ====================== */

bool db_save(const StudentDatabase *db) {
    FILE *fp = fopen(DATA_FILE, "wb");
    if (!fp) return false;

    int version = FILE_VERSION;
    size_t count = db->count;
    fwrite(&version, sizeof(int), 1, fp);
    fwrite(&count, sizeof(size_t), 1, fp);
    fwrite(db->students, sizeof(Student), count, fp);
    fclose(fp);
    return true;
}

bool db_load(StudentDatabase *db) {
    FILE *fp = fopen(DATA_FILE, "rb");
    if (!fp) return false;

    int version;
    size_t count;
    if (fread(&version, sizeof(int), 1, fp) != 1 || version != FILE_VERSION ||
        fread(&count, sizeof(size_t), 1, fp) != 1) {
        fclose(fp);
        return false;
    }

    if (count > db->capacity) {
        size_t new_cap = count * 2 > INITIAL_CAPACITY ? count * 2 : INITIAL_CAPACITY;
        Student *new_arr = realloc(db->students, new_cap * sizeof(Student));
        if (new_arr) {
            db->students = new_arr;
            db->capacity = new_cap;
        }
    }

    if (fread(db->students, sizeof(Student), count, fp) == count) {
        db->count = count;
    }
    fclose(fp);
    return true;
}

/* ====================== Input ====================== */

static int get_int(const char *prompt, int minv, int maxv) {
    int val;
    while (1) {
        printf("%s", prompt);
        if (scanf("%d", &val) == 1 && val >= minv && (maxv < 0 || val <= maxv)) {
            clear_input_buffer();
            return val;
        }
        printf("Invalid input!\n");
        clear_input_buffer();
    }
}

static float get_float(const char *prompt) {
    float val;
    while (1) {
        printf("%s", prompt);
        if (scanf("%f", &val) == 1 && val >= 0.0f && val <= MAX_MARKS) {
            clear_input_buffer();
            return val;
        }
        printf("Marks must be between 0 and %.0f\n", MAX_MARKS);
        clear_input_buffer();
    }
}

static void get_name(char *buf, size_t size) {
    while (1) {
        printf("Enter Name: ");
        fgets(buf, size, stdin);
        trim_newline(buf);
        if (is_valid_name(buf)) return;
        printf("Invalid name format.\n");
    }
}

static void input_subject_marks(float marks_out[]) {
    printf("Enter marks for each subject (0-100):\n");
    for (int i = 0; i < MAX_SUBJECTS; ++i) {
        char prompt[100];
        snprintf(prompt, sizeof(prompt), "  %s: ", subject_names[i]);
        marks_out[i] = get_float(prompt);
    }
}

/* ====================== Main ====================== */

int main(void) {
    StudentDatabase *db = db_create();
    db_load(db);

    print_header("STUDENT MANAGEMENT SYSTEM");

    int choice;
    while (1) {
        printf("\n");
        printf("1. Add Student\n");
        printf("2. Display All\n");
        printf("3. Search by Roll\n");
        printf("4. Update Student\n");
        printf("5. Delete Student\n");
        printf("6. Statistics & Reports\n");
        printf("7. Sort Students\n");
        printf("8. Export to CSV\n");
        printf("9. Exit & Save\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1: {
                int roll = get_int("Enter Roll Number: ", 1, -1);
                char name[MAX_NAME_LEN];
                get_name(name, sizeof(name));

                float subject_marks[MAX_SUBJECTS];
                input_subject_marks(subject_marks);

                if (db_add_student(db, roll, name, subject_marks))
                    printf("[SUCCESS] Student added successfully.\n");
                else
                    printf("[ERROR] Failed (duplicate roll or invalid data).\n");
                break;
            }

            case 2:
                db_display_all(db);
                break;

            case 3: {
                int roll = get_int("Enter Roll Number: ", 1, -1);
                const Student *s = db_find_by_roll(db, roll);
                if (s) {
                    printf("\nStudent Found:\n");
                    printf("  Roll : %d\n", s->roll);
                    printf("  Name : %s\n", s->name);
                    printf("  Marks:\n");
                    float total = 0.0f;
                    for (int i = 0; i < MAX_SUBJECTS; ++i) {
                        printf("    %-20s : %.2f\n", subject_names[i], s->marks[i]);
                        total += s->marks[i];
                    }
                    printf("  Total: %.2f | Average: %.2f\n", total, total / MAX_SUBJECTS);
                } else {
                    printf("Student not found.\n");
                }
                break;
            }

            case 4: {
                int roll = get_int("Enter Roll to update: ", 1, -1);
                if (!db_find_by_roll(db, roll)) {
                    printf("Student not found.\n");
                    break;
                }

                printf("1. Update Name only\n2. Update Marks only\n3. Update Both\n");
                int opt = get_int("Choice: ", 1, 3);

                char name[MAX_NAME_LEN] = {0};
                float new_marks[MAX_SUBJECTS] = {0};

                if (opt == 1 || opt == 3) get_name(name, sizeof(name));
                if (opt == 2 || opt == 3) input_subject_marks(new_marks);

                db_update_student(db, roll, (opt==1||opt==3)?name:NULL, (opt==2||opt==3)?new_marks:NULL);
                printf("[SUCCESS] Student updated.\n");
                break;
            }

            case 5: {
                int roll = get_int("Enter Roll to delete: ", 1, -1);
                if (db_delete_student(db, roll))
                    printf("[SUCCESS] Student deleted.\n");
                else
                    printf("Student not found.\n");
                break;
            }

            case 6:
                db_display_all(db);
                db_show_statistics(db);
                break;

            case 7: {
                printf("1. By Roll Number\n2. By Average Marks (High to Low)\n3. By Name\n");
                int opt = get_int("Choice: ", 1, 3);
                db_sort(db, opt);
                printf("[SUCCESS] Students sorted.\n");
                db_display_all(db);
                break;
            }

            case 8:
                db_export_csv(db);
                break;

            case 9:
                if (db_save(db))
                    printf("Data saved successfully.\n");
                else
                    printf("Warning: Failed to save data.\n");
                db_destroy(db);
                return 0;

            default:
                printf("Invalid choice.\n");
        }
    }
}