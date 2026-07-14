#include <iostream>  // Username - admin
#include <vector>    // Password - admin123
#include <string>
#include <map>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <limits>
#include <memory>

// ==========================================
// 1. UTILITY & UTILITY ERROR HANDLING CLASS
// ==========================================
class InputValidator {
public:
    static std::string getLine() {
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    static int getInteger(const std::string& prompt, int minVal = 0, int maxVal = std::numeric_limits<int>::max()) {
        while (true) {
            std::cout << prompt;
            std::string input = getLine();
            std::stringstream ss(input);
            int value;
            if (ss >> value && ss.eof()) {
                if (value >= minVal && value <= maxVal) {
                    return value;
                }
            }
            std::cout << "Invalid input! Please enter a number between " << minVal << " and " << maxVal << ".\n";
        }
    }

    static double getDouble(const std::string& prompt, double minVal = 0.0, double maxVal = 100.0) {
        while (true) {
            std::cout << prompt;
            std::string input = getLine();
            std::stringstream ss(input);
            double value;
            if (ss >> value && ss.eof()) {
                if (value >= minVal && value <= maxVal) {
                    return value;
                }
            }
            std::cout << "Invalid input! Please enter a decimal value between " << minVal << " and " << maxVal << ".\n";
        }
    }

    static std::string getNonEmptyString(const std::string& prompt) {
        while (true) {
            std::cout << prompt;
            std::string input = getLine();
            if (!input.empty() && input.find_first_not_of(" \t\n\v\f\r") != std::string::npos) {
                return input;
            }
            std::cout << "Input cannot be empty!\n";
        }
    }
};

// ==========================================
// 2. CORE DOMAIN MODEL: STUDENT
// ==========================================
class Student {
private:
    int id;
    std::string name;
    int age;
    std::string course;
    std::map<std::string, double> marks; // Subject -> Marks Mapping

public:
    Student(int id, std::string name, int age, std::string course)
        : id(id), name(name), age(age), course(course) {}

    // Getters
    int getId() const { return id; }
    std::string getName() const { return name; }
    int getAge() const { return age; }
    std::string getCourse() const { return course; }
    const std::map<std::string, double>& getMarks() const { return marks; }

    // Setters
    void setName(const std::string& n) { name = n; }
    void setAge(int a) { age = a; }
    void setCourse(const std::string& c) { course = c; }
    
    void addOrUpdateMark(const std::string& subject, double mark) {
        marks[subject] = mark;
    }

    void removeSubject(const std::string& subject) {
        marks.erase(subject);
    }

    double calculateGPA() const {
        if (marks.empty()) return 0.0;
        double sum = 0;
        for (const auto& pair : marks) {
            sum += pair.second;
        }
        return sum / marks.size();
    }

    void displaySummary() const {
        std::cout << std::left << std::setw(8) << id 
                  << std::setw(20) << name 
                  << std::setw(8) << age 
                  << std::setw(15) << course 
                  << std::fixed << std::setprecision(2) << std::setw(10) << calculateGPA() << "\n";
    }

    void displayDetailed() const {
        std::cout << "\n----------------------------------------\n";
        std::cout << " Student Profile (ID: " << id << ")\n";
        std::cout << "----------------------------------------\n";
        std::cout << " Name:    " << name << "\n";
        std::cout << " Age:     " << age << "\n";
        std::cout << " Course:  " << course << "\n";
        std::cout << " Marksheet:\n";
        if (marks.empty()) {
            std::cout << "   No grades recorded yet.\n";
        } else {
            for (const auto& pair : marks) {
                std::cout << "   - " << std::left << std::setw(15) << pair.first << ": " << pair.second << "/100\n";
            }
            std::cout << " Average Grade: " << std::fixed << std::setprecision(2) << calculateGPA() << "%\n";
        }
        std::cout << "----------------------------------------\n";
    }
};

// ==========================================
// 3. REGISTRY ENGINE (MANAGEMENT OPERATIONS)
// ==========================================
class StudentRegistry {
private:
    std::vector<Student> students;

    // Helper to find index by ID
    int findIndexById(int id) const {
        for (size_t i = 0; i < students.size(); ++i) {
            if (students[i].getId() == id) return i;
        }
        return -1;
    }

public:
    // Create
    bool addStudent(const Student& s) {
        if (findIndexById(s.getId()) != -1) {
            return false; // ID already exists
        }
        students.push_back(s);
        return true;
    }

    // Read
    const Student* getStudent(int id) const {
        int index = findIndexById(id);
        if (index != -1) return &students[index];
        return nullptr;
    }

    Student* getStudentMutable(int id) {
        int index = findIndexById(id);
        if (index != -1) return &students[index];
        return nullptr;
    }

    // Update
    bool updateStudent(int id, const std::string& newName, int newAge, const std::string& newCourse) {
        Student* s = getStudentMutable(id);
        if (s) {
            s->setName(newName);
            s->setAge(newAge);
            s->setCourse(newCourse);
            return true;
        }
        return false;
    }

    // Delete
    bool deleteStudent(int id) {
        int index = findIndexById(id);
        if (index != -1) {
            students.erase(students.begin() + index);
            return true;
        }
        return false;
    }

    // Advanced Searches
    std::vector<Student> searchByName(const std::string& query) const {
        std::vector<Student> results;
        std::string lowerQuery = query;
        std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

        for (const auto& s : students) {
            std::string nameLower = s.getName();
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
            if (nameLower.find(lowerQuery) != std::string::npos) {
                results.push_back(s);
            }
        }
        return results;
    }

    std::vector<Student> searchByCourse(const std::string& course) const {
        std::vector<Student> results;
        for (const auto& s : students) {
            if (s.getCourse() == course) results.push_back(s);
        }
        return results;
    }

    // Sorting Engine
    void displayAll(std::vector<Student> listToPrint) const {
        if (listToPrint.empty()) {
            std::cout << "No student records found.\n";
            return;
        }
        std::cout << "\n" << std::left << std::setw(8) << "ID" 
                  << std::setw(20) << "Name" 
                  << std::setw(8) << "Age" 
                  << std::setw(15) << "Course" 
                  << std::setw(10) << "GPA (%)" << "\n";
        std::cout << std::string(61, '-') << "\n";
        for (const auto& s : listToPrint) {
            s.displaySummary();
        }
    }

    void viewSorted(int criterion) {
        // 1: ID, 2: Name, 3: GPA
        std::vector<Student> sortedList = students;
        if (criterion == 1) {
            std::sort(sortedList.begin(), sortedList.end(), [](const Student& a, const Student& b) {
                return a.getId() < b.getId();
            });
        } else if (criterion == 2) {
            std::sort(sortedList.begin(), sortedList.end(), [](const Student& a, const Student& b) {
                return a.getName() < b.getName();
            });
        } else if (criterion == 3) {
            std::sort(sortedList.begin(), sortedList.end(), [](const Student& a, const Student& b) {
                return a.calculateGPA() > b.calculateGPA(); // Descending order for top marks
            });
        }
        displayAll(sortedList);
    }

    // Statistical Engine
    void generateStatistics() const {
        if (students.empty()) {
            std::cout << "Analytics unavailable: Registry database is empty.\n";
            return;
        }

        double absoluteSum = 0;
        const Student* topStudent = &students[0];
        const Student* lowestStudent = &students[0];

        for (const auto& s : students) {
            double currentGPA = s.calculateGPA();
            absoluteSum += currentGPA;
            if (currentGPA > topStudent->calculateGPA()) topStudent = &s;
            if (currentGPA < lowestStudent->calculateGPA()) lowestStudent = &s;
        }

        std::cout << "\n========================================\n";
        std::cout << "       SYSTEM ANALYTICS & STATS         \n";
        std::cout << "========================================\n";
        std::cout << " Total Registered Students: " << students.size() << "\n";
        std::cout << " Batch Class Average Grade: " << (absoluteSum / students.size()) << "%\n";
        std::cout << " Top Academic Achiever:     " << topStudent->getName() << " (" << topStudent->calculateGPA() << "%)\n";
        std::cout << " Lowest Academic Stand:     " << lowestStudent->getName() << " (" << lowestStudent->calculateGPA() << "%)\n";
        std::cout << "========================================\n";
    }

    const std::vector<Student>& getAllRaw() const { return students; }
};

// ==========================================
// 4. SECURITY (AUTHENTICATION LAYER)
// ==========================================
class AuthenticationSystem {
public:
    static bool login() {
        std::cout << "\n========================================\n";
        std::cout << "   STUDENT MANAGEMENT SYSTEM PORTAL     \n";
        std::cout << "========================================\n";
        
        int attempts = 3;
        const std::string defaultUser = "admin";
        const std::string defaultPass = "admin123";

        while (attempts > 0) {
            std::string user = InputValidator::getNonEmptyString("Enter Admin Username: ");
            std::cout << "Enter Admin Password: ";
            std::string pass = InputValidator::getLine(); // allows tracking blank input securely

            if (user == defaultUser && pass == defaultPass) {
                std::cout << "\nAccess Granted. Welcome, Administrator.\n";
                return true;
            } else {
                attempts--;
                std::cout << "Access Denied! Credentials mismatch. (" << attempts << " attempts remaining)\n";
            }
        }
        return false;
    }
};

// ==========================================
// 5. INTERFACE LAYER (MAIN CONSOLE)
// ==========================================
int main() {
    // Authenticate First
    if (!AuthenticationSystem::login()) {
        std::cout << "\nCRITICAL ERROR: Maximum authentication attempts exceeded. Terminating thread.\n";
        return 0;
    }

    StudentRegistry registry;
    
    // Seed sample system data to prevent bootstrapping overhead
    Student s1(1, "Aditya", 20, "Engineering");
    s1.addOrUpdateMark("Mathematics", 100.0);
    s1.addOrUpdateMark("Physics", 100.0);
    
    Student s2(2, "Anonymous", 21, "Management");
    s2.addOrUpdateMark("Mathematics", 78.2);
    s2.addOrUpdateMark("Statistics", 77.9);

    registry.addStudent(s1);
    registry.addStudent(s2);

    while (true) {
        std::cout << "\n========================================\n";
        std::cout << "             MAIN CONTROLS              \n";
        std::cout << "========================================\n";
        std::cout << "1. Add New Student Profile\n";
        std::cout << "2. View All Student Directories\n";
        std::cout << "3. Fetch Individual Detail Record (By ID)\n";
        std::cout << "4. Update Existing Student Info\n";
        std::cout << "5. Remove Student Records (Delete)\n";
        std::cout << "6. Record/Manage Multi-Subject Grades\n";
        std::cout << "7. Advanced Query Search Engines\n";
        std::cout << "8. Sort Directory View Matrix\n";
        std::cout << "9. Compute Diagnostic Dashboard Stats\n";
        std::cout << "10. Log Out & Terminate Session\n";
        std::cout << "----------------------------------------\n";
        
        int choice = InputValidator::getInteger("Select target operation (1-10): ", 1, 10);

        if (choice == 1) { // CREATE
            int id = InputValidator::getInteger("Enter Unique Student ID: ", 1);
            if (registry.getStudent(id) != nullptr) {
                std::cout << "Operation Aborted: Student ID already mapping another record.\n";
                continue;
            }
            std::string name = InputValidator::getNonEmptyString("Enter Full Name: ");
            int age = InputValidator::getInteger("Enter Age: ", 16, 100);
            std::string course = InputValidator::getNonEmptyString("Enter Department Course Track: ");

            registry.addStudent(Student(id, name, age, course));
            std::cout << "Student Record Committed Successfully.\n";

        } else if (choice == 2) { // READ ALL
            registry.displayAll(registry.getAllRaw());

        } else if (choice == 3) { // READ INDIVIDUAL
            int id = InputValidator::getInteger("Enter Search Target Student ID: ", 1);
            const Student* s = registry.getStudent(id);
            if (s) s->displayDetailed();
            else std::cout << "Error: Target ID element not found in local table arrays.\n";

        } else if (choice == 4) { // UPDATE
            int id = InputValidator::getInteger("Enter Record Target ID to Update: ", 1);
            if (!registry.getStudent(id)) {
                std::cout << "Error: Target reference missing.\n";
                continue;
            }
            std::string name = InputValidator::getNonEmptyString("Enter Corrected Full Name: ");
            int age = InputValidator::getInteger("Enter Corrected Age: ", 16, 100);
            std::string course = InputValidator::getNonEmptyString("Enter Corrected Department Course Track: ");
            
            registry.updateStudent(id, name, age, course);
            std::cout << "Local record tracking maps updated successfully.\n";

        } else if (choice == 5) { // DELETE
            int id = InputValidator::getInteger("Enter Record ID targeted for deletion: ", 1);
            if (registry.deleteStudent(id)) {
                std::cout << "Target element successfully purged from vector runtime stacks.\n";
            } else {
                std::cout << "Error: Purge target identifier unresolved.\n";
            }

        } else if (choice == 6) { // MARKS MANAGEMENT
            int id = InputValidator::getInteger("Enter target student ID for Grade Evaluation: ", 1);
            Student* s = registry.getStudentMutable(id);
            if (!s) {
                std::cout << "Error: Reference mismatch. Profile unfound.\n";
                continue;
            }
            std::cout << "1. Add/Modify Subject Score\n2. Delete Subject Score\n";
            int subChoice = InputValidator::getInteger("Select operation choice: ", 1, 2);
            std::string subject = InputValidator::getNonEmptyString("Enter Targeted Subject Title: ");
            
            if (subChoice == 1) {
                double score = InputValidator::getDouble("Enter Score Numerical Matrix Value (0.0 - 100.0): ", 0.0, 100.0);
                s->addOrUpdateMark(subject, score);
                std::cout << "Assessment data mapped cleanly.\n";
            } else {
                s->removeSubject(subject);
                std::cout << "Assessment parameter stripped clean.\n";
            }

        } else if (choice == 7) { // ADVANCED SEARCH
            std::cout << "Query Metrics: 1. By Partial String Name  2. By Department Course Track\n";
            int searchType = InputValidator::getInteger("Select mode filter choice: ", 1, 2);
            if (searchType == 1) {
                std::string q = InputValidator::getNonEmptyString("Enter Search String Query: ");
                registry.displayAll(registry.searchByName(q));
            } else {
                std::string q = InputValidator::getNonEmptyString("Enter Exact Track Program Query: ");
                registry.displayAll(registry.searchByCourse(q));
            }

        } else if (choice == 8) { // SORTING ENGINE
            std::cout << "Sort Matrix Framework: 1. Sort ascending by ID  2. Sort Alphabetical  3. Sort Descending by GPA\n";
            int sortType = InputValidator::getInteger("Select priority view order: ", 1, 3);
            registry.viewSorted(sortType);

        } else if (choice == 9) { // ANALYTICS
            registry.generateStatistics();

        } else if (choice == 10) { // EXIT
            std::cout << "\nSafely flushing structures... Session context destroyed.\n";
            break;
        }
    }
    return 0;
}