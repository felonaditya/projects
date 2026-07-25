# Student Management System
# Username: admin    Password: admin123

import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
import sqlite3
import csv
import hashlib
import os
import logging

# Constants
DB_NAME = "students.db"
SALT = b"student_app_scrypt_2024"
MIN_AGE = 5
MAX_AGE = 100
APP_TITLE = "🏫 Student Management System"

# Setup logging
logging.basicConfig(level=logging.ERROR, filename='student_app.log', 
                   format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------- PASSWORD HASHING ----------------
def hash_password(password):
    """Hash password using scrypt with fixed salt"""
    return hashlib.scrypt(password.encode('utf-8'), salt=SALT, n=16384, r=8, p=1).hex()

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    return hash_password(password) == stored_hash

# ---------------- DATABASE FUNCTIONS ----------------
def init_db():
    """Initialize database with users and students tables"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    grade TEXT NOT NULL
                )
            """)
            admin_hash = hash_password('admin123')
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin', admin_hash, 'admin')
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database init error: {e}")
        raise

def login(username, password):
    """Authenticate user and return role"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT role, password FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            if result and verify_password(password, result[1]):
                return result[0]
            return None
    except sqlite3.Error:
        return None

def get_students(search_term=""):
    """Get students with optional search filter"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            if search_term.strip():
                search = f"%{search_term.strip()}%"
                cursor.execute(
                    "SELECT id, name, age, grade FROM students "
                    "WHERE name LIKE ? OR grade LIKE ? OR CAST(id AS TEXT) LIKE ? "
                    "ORDER BY id",
                    (search, search, search)
                )
            else:
                cursor.execute("SELECT id, name, age, grade FROM students ORDER BY id")
            return cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Get students error: {e}")
        return []

def get_student_by_id(student_id):
    """Get single student by ID"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, age, grade FROM students WHERE id = ?",
                (student_id,)
            )
            return cursor.fetchone()
    except (sqlite3.Error, ValueError) as e:
        logging.error(f"Get student by ID error: {e}")
        return None

def validate_student_data(name, age_str, grade):
    """Validate student data before DB operations"""
    if not all([name.strip(), age_str.strip(), grade.strip()]):
        raise ValueError("All fields are required")
    try:
        age = int(age_str.strip())
        if not (MIN_AGE <= age <= MAX_AGE):
            raise ValueError(f"Age must be between {MIN_AGE} and {MAX_AGE}")
        return name.strip(), age, grade.strip()
    except ValueError as e:
        if "between" not in str(e):
            raise ValueError("Age must be a valid number")

def add_student(name, age, grade):
    """Add new student to database"""
    validated_name, validated_age, validated_grade = validate_student_data(name, str(age), grade)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO students (name, age, grade) VALUES (?, ?, ?)",
                (validated_name, validated_age, validated_grade)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Add student error: {e}")
        raise ValueError("Failed to add student")

def update_student(student_id, name, age, grade):
    """Update existing student"""
    validated_name, validated_age, validated_grade = validate_student_data(name, str(age), grade)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE students SET name=?, age=?, grade=? WHERE id=?",
                (validated_name, validated_age, validated_grade, student_id)
            )
            if cursor.rowcount == 0:
                raise ValueError("Student not found")
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Update student error: {e}")
        raise ValueError("Failed to update student")

def delete_student(student_id):
    """Delete student by ID"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM students WHERE id=?", (student_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Delete student error: {e}")
        raise ValueError("Failed to delete student")

def export_csv(filename):
    """Export students to CSV file"""
    try:
        students = get_students()
        with open(filename, "w", newline="", encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Name", "Age", "Grade"])
            writer.writerows(students)
    except IOError as e:
        logging.error(f"CSV export error: {e}")
        raise IOError("Cannot export CSV file")

# ---------------- MAIN GUI APPLICATION ----------------
class StudentApp:
    def __init__(self, root, role):
        self.root = root
        self.role = role
        self.root.title(APP_TITLE)
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Global exception handler
        self.root.report_callback_exception = self._handle_callback_exception

        self.setup_ui()
        self.setup_treeview()
        self.refresh()

    def setup_ui(self):
        """Setup main UI components"""
        # Title
        tk.Label(self.root, text=APP_TITLE, font=("Arial", 20, "bold")).pack(pady=20)
        
        # User info
        tk.Label(self.root, text=f"🔐 Logged in as: {self.role}", 
                font=("Arial", 12)).pack(pady=10)

        # Search frame
        search_frame = tk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30, font=("Arial", 11))
        search_entry.pack(side=tk.LEFT, padx=10)
        search_entry.bind('<KeyRelease>', lambda e: self.refresh())
        
        tk.Button(search_frame, text="🔄 Refresh", command=self.refresh,
                 bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=10)
        tk.Button(search_frame, text="📤 Export CSV", command=self.export_csv,
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=10)

        # Admin buttons
        if self.role == "admin":
            btn_frame = tk.Frame(self.root)
            btn_frame.pack(pady=10)
            tk.Button(btn_frame, text="➕ Add Student", command=self.add_student_ui,
                     bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)
            tk.Button(btn_frame, text="✏️ Edit Selected", command=self._edit_selected,
                     bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)
            tk.Button(btn_frame, text="🗑️ Delete Selected", command=self.delete_student_ui,
                     bg="#f44336", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)

        # Exit button
        tk.Button(self.root, text="❌ Exit", command=self.root.quit,
                 bg="#757575", fg="white", font=("Arial", 12, "bold")).pack(pady=20)

    def setup_treeview(self):
        """Setup treeview table with scrollbars"""
        # Main content frame
        content_frame = tk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Table columns
        columns = ("ID", "Name", "Age", "Grade")
        self.tree = ttk.Treeview(content_frame, columns=columns, show="headings", height=18)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120 if col == "Name" else 90, anchor=tk.CENTER)

        # Scrollbars
        v_scroll = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(content_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Pack treeview and scrollbars
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.bind("<Double-1>", self.on_double_click)

    def _handle_callback_exception(self, exc_type, exc_value, exc_traceback):
        """Global exception handler"""
        error_msg = f"Unexpected error: {str(exc_value)}"
        messagebox.showerror("Error", error_msg)
        logging.error(f"Tkinter callback error: {exc_type.__name__}: {exc_value}", exc_info=True)

    def refresh(self):
        """Refresh student table"""
        try:
            for item in self.tree.get_children():
                self.tree.delete(item)
            students = get_students(self.search_var.get())
            for student in students:
                self.tree.insert("", "end", values=student)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh: {str(e)}")
            logging.error(f"Refresh error: {e}")

    def _edit_selected(self):
        """Handle edit button click"""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a student to edit")
                return
            student_id = self.tree.item(selection[0])['values'][0]
            self.edit_student_ui(student_id)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot edit: {str(e)}")
            logging.error(f"Edit selected error: {e}")

    def on_double_click(self, event):
        """Handle double-click on table row (admin only)"""
        if self.role != "admin":
            return
        try:
            selection = self.tree.selection()
            if selection:
                student_id = self.tree.item(selection[0])['values'][0]
                self.edit_student_ui(student_id)
        except Exception as e:
            logging.error(f"Double-click error: {e}")

    def student_dialog(self, title, student_id=None):
        """Create student edit/add dialog - FIXED VERSION"""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("400x350")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        # ID label for edit
        if student_id:
            tk.Label(win, text=f"🆔 ID: {student_id}", 
                    font=("Arial", 11, "bold"), fg="blue").pack(pady=15)

        # Name field
        tk.Label(win, text="👤 Name:", font=("Arial", 11)).pack(pady=(20,5))
        name_entry = tk.Entry(win, width=35, font=("Arial", 11))
        name_entry.pack(pady=5)
        name_entry.focus()

        # Age field
        tk.Label(win, text="📅 Age:", font=("Arial", 11)).pack(pady=(15,5))
        age_entry = tk.Entry(win, width=35, font=("Arial", 11))
        age_entry.pack(pady=5)

        # Grade field
        tk.Label(win, text="🎓 Grade:", font=("Arial", 11)).pack(pady=(15,5))
        grade_entry = tk.Entry(win, width=35, font=("Arial", 11))
        grade_entry.pack(pady=5)

        # Load existing data for edit
        if student_id:
            student = get_student_by_id(student_id)
            if student:
                name_entry.insert(0, student[1])
                age_entry.insert(0, student[2])
                grade_entry.insert(0, student[3])

        def save():
            try:
                name = name_entry.get()
                age_str = age_entry.get()
                grade = grade_entry.get()
                
                # ✅ VALIDATION NOW WORKS PROPERLY
                if student_id:
                    update_student(student_id, name, age_str, grade)
                    msg = f"✅ Student '{name.strip()}' updated successfully!"
                else:
                    add_student(name, age_str, grade)
                    msg = f"✅ Student '{name.strip()}' added successfully!"
                
                self.refresh()
                messagebox.showinfo("Success", msg)
                win.destroy()
            except ValueError as e:
                messagebox.showerror("❌ Validation Error", str(e))
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to save: {str(e)}")
                logging.error(f"Save student error: {e}")

        # ✅ FIXED: Prominent SAVE button + Enter key support
        button_frame = tk.Frame(win)
        button_frame.pack(pady=25)
        
        tk.Button(button_frame, text="💾 SAVE CHANGES", command=save, 
                 bg="#4CAF50", fg="white", font=("Arial", 13, "bold"), 
                 width=16, height=2).pack(pady=5)
        
        tk.Button(button_frame, text="❌ Cancel", command=win.destroy,
                 bg="#757575", fg="white", font=("Arial", 11), width=12).pack()

        # Enter key to save, Escape to cancel
        name_entry.bind('<Return>', lambda e: save())
        win.bind('<Escape>', lambda e: win.destroy())
        win.bind('<Return>', lambda e: save())

    def add_student_ui(self):
        """Show add student dialog"""
        self.student_dialog("➕ Add New Student")

    def edit_student_ui(self, student_id):
        """Show edit student dialog"""
        self.student_dialog("✏️ Edit Student", student_id)

    def delete_student_ui(self):
        """Show delete confirmation dialog"""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning("⚠️ No Selection", "Please select a student to delete")
                return
            
            values = self.tree.item(selection[0])['values']
            student_id, name = values[0], values[1]
            
            if messagebox.askyesno("🗑️ Confirm Delete", 
                                 f"Delete student:\nID: {student_id}\nName: {name}?\n\nThis cannot be undone."):
                delete_student(student_id)
                self.refresh()
                messagebox.showinfo("✅ Success", f"Student '{name}' deleted successfully")
        except Exception as e:
            messagebox.showerror("❌ Error", f"Delete failed: {str(e)}")
            logging.error(f"Delete student UI error: {e}")

    def export_csv(self):
        """Export data to CSV file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Save students as CSV"
            )
            if filename:
                export_csv(filename)
                messagebox.showinfo("✅ Export Success", f"Data exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("❌ Export Error", f"Failed to export: {str(e)}")

# ---------------- LOGIN UI ----------------
def login_ui():
    """Show login dialog and start main app"""
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    try:
        username = simpledialog.askstring("🔐 Login", "👤 Username:", parent=root)
        if username is None:  # User cancelled
            root.destroy()
            return
            
        password = simpledialog.askstring("🔐 Login", "🔑 Password:", show="*", parent=root)
        if password is None:  # User cancelled
            root.destroy()
            return
            
        role = login(username.strip(), password)
        root.destroy()
        
        if role:
            main_root = tk.Tk()
            app = StudentApp(main_root, role)
            main_root.mainloop()
        else:
            messagebox.showerror("❌ Login Failed", 
                "Invalid username or password!\n\nDefault credentials:\n👤 Username: admin\n🔑 Password: admin123")
            
    except Exception as e:
        root.destroy()
        messagebox.showerror("Startup Error", f"Application failed to start: {str(e)}")
        logging.error(f"Login UI error: {e}")

# ---------------- MAIN ENTRY POINT ----------------
if __name__ == "__main__":
    try:
        init_db()
        login_ui()
    except Exception as e:
        error_msg = f"Fatal startup error: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        input("Press Enter to exit...")