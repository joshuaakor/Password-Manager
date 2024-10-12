import customtkinter
import sqlite3
import secrets
import bcrypt
import pyperclip
from CTkMessagebox import CTkMessagebox
from customtkinter import CTkToplevel
from customtkinter import CTkScrollableFrame

database = sqlite3.connect('database.db')
cursor = database.cursor()


cursor.execute('''

        CREATE TABLE IF NOT EXISTS users ( 
              id INTEGER PRIMARY KEY AUTOINCREMENT, 
              username TEXT NOT NULL,
              password TEXT NOT NULL)''')


cursor.execute('''
               
        CREATE TABLE IF NOT EXISTS generated_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_name TEXT NOT NULL,
                password_text TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id))''')


database.close()
#cursor.execute('''ALTER TABLE generated_passwords 
 #                 ADD COLUMN user_id INTEGER''')

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))


font1 = ('Arial', 13, 'bold', 'underline')

## Save Generated Passwords ##


def signup_window():
    global window_open, register_window
    if not window_open:
        register_window = customtkinter.CTkToplevel(root)
        register_window.title("Sign Up")
        register_window.geometry("500x350")
        register_window.protocol("WM_DELETE_WINDOW", on_close)
        register_window.grab_set()
        window_open = True
        noaccount_button.configure(state=customtkinter.DISABLED)
   


    signup_label = customtkinter.CTkLabel(master=register_window, text="Sign up")
    signup_label.pack(pady=12, padx=10)

    global username_entry
    username_entry = customtkinter.CTkEntry(master=register_window, placeholder_text="Username")
    username_entry.pack(pady=12, padx=10)

    global password_entry
    password_entry = customtkinter.CTkEntry(master=register_window, placeholder_text="Password", show="*")
    password_entry.pack(pady=12, padx=10)

    global retype_password
    retype_password = customtkinter.CTkEntry(master=register_window, placeholder_text="Retype password", show="*")
    retype_password.pack(pady=12, padx=10)

    signup_button = customtkinter.CTkButton(master=register_window, text="Sign Up", command=signup)
    signup_button.pack(pady=12, padx=10)

    
    #Signup Function

def signup():

    database = sqlite3.connect('database.db')
    cursor = database.cursor()
    
    username = username_entry.get()
    password = password_entry.get()
    password2 = retype_password.get()
    
        
    if username != '' and password != '' and password2 != '':
        if password != password2:
            pass
            CTkMessagebox(title="Alert", message="Passwords do not match")
        else:
            cursor.execute('SELECT username FROM users WHERE username=?', (username,))
            
            if cursor.fetchone() is not None:
                CTkMessagebox(title="Alert", message="Username already exists")
                database.close()
            else:
                encoded_password = password.encode('utf-8')
                hashed_passwords = bcrypt.hashpw(encoded_password, bcrypt.gensalt())
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_passwords))
                database.commit()
                CTkMessagebox(title="Alert", message="Account created successfully!")
                on_close()
             
                    
    else:
        CTkMessagebox(title="Alert", message="Enter all Data")
    database.close()
    




def login_success(show_message=True):

    
    if show_message:
        CTkMessagebox(title="Alert", message="Login Successful!")
    
    login_frame = customtkinter.CTkFrame(master=root)
    login_frame.pack(pady=70, padx=60, fill="both", expand=True)

    login_label = customtkinter.CTkLabel(master=login_frame, text="Options", font=("Times New Roman",22), text_color="red")
    login_label.pack(pady=12, padx=10)

    def sign_out():
        login_frame.pack_forget()
        CTkMessagebox(title="Alert", message="You have signed out")

        default_page()

    
# View passwords after they have been saved
    
    def view_saved_passwords():

        login_frame.pack_forget()

        saved_password_frame = customtkinter.CTkFrame(master=root)
        saved_password_frame.pack(pady=20, padx=60, fill="both", expand=True)

        def back_button2():
            saved_password_frame.pack_forget()
            login_success(show_message=False)


        label = customtkinter.CTkLabel(master=saved_password_frame, text="Saved Passwords")
        label.pack(pady=12, padx=10)

        back_button = customtkinter.CTkButton(master=saved_password_frame, text="\u2190 Back", width=50, command=back_button2)
        back_button.place(x=50, y=20)

        scroll_frame = customtkinter.CTkScrollableFrame(master=saved_password_frame, width=900, height=350)
        scroll_frame.pack(pady=20, padx=60,  fill="both", expand=True)


        database = sqlite3.connect('database.db')
        cursor = database.cursor()

        cursor.execute("SELECT id FROM users WHERE username=?", (valid_username,))
        loginn = cursor.fetchone()
        logged_in_user_id = loginn[0]
   

        cursor.execute('SELECT id, password_name, password_text FROM generated_passwords WHERE user_id=?', (logged_in_user_id,))
        view_saved = cursor.fetchall()
        

        def copy_to_clipboard(password_id):
            connection = sqlite3.connect('database.db')
            cursor = connection.cursor()
            cursor.execute("SELECT password_text FROM generated_passwords WHERE id=?", (password_id,))
            copy_password = cursor.fetchone()
            if copy_password:
                copied_password = copy_password[0]
            pyperclip.copy(str(copied_password))
            print("Password copied to clipboard")

            connection.close()

        def delete_password(password_id, widgets_to_destroy):
            connection = sqlite3.connect('database.db')
            cursor = connection.cursor()
            cursor.execute("DELETE FROM generated_passwords WHERE id=?", (password_id,))
            connection.commit()
            connection.close()

            for widget in widgets_to_destroy:
                widget.destroy()


            
        headers = ["ID","Password Name", "Password Text", "Copy Password", "Delete Password"]

        bold_font = customtkinter.CTkFont(family="Arial", size=12, weight="bold")

        for col, header in enumerate(headers):
            header_label = customtkinter.CTkLabel(scroll_frame, text=header, font=bold_font, width=100)
            header_label.grid(row=0, column=col, padx=5, pady=5)

        for row, entry in enumerate(view_saved, start=1):
            
            row_widgets = []
            
            for col, value in enumerate(entry):
                cell_label = customtkinter.CTkLabel(scroll_frame, text=str(value), width=100)
                cell_label.grid(row=row, column=col, padx=5, pady=5)
                row_widgets.append(cell_label)

            copy_button = customtkinter.CTkButton(scroll_frame, text="Copy", width=80, command=lambda password_id=entry[0]: copy_to_clipboard(password_id))
            copy_button.grid(row=row, column=len(headers)-2, padx=5, pady=5)
            row_widgets.append(copy_button) 

            delete_button = customtkinter.CTkButton(scroll_frame, text="Delete", width=80, command=lambda password_id=entry[0], widgets=row_widgets: delete_password(password_id, widgets))
            delete_button.grid(row=row, column=len(headers)-1, padx=5, pady=5)
            row_widgets.append(delete_button)
        
        database.close()


    
    
    
    
    def create_pass():
        login_frame.pack_forget()
        
        crtpass_frame = customtkinter.CTkFrame(master=root)
        crtpass_frame.pack(pady=20, padx=60, fill="both", expand=True)

        label = customtkinter.CTkLabel(master=crtpass_frame, text="Create Password")
        label.pack(pady=12, padx=10)

        global password_name
        password_name = customtkinter.CTkEntry(master=crtpass_frame, placeholder_text="Enter Password Name", width=250)
        password_name.pack(pady=12, padx=10)

        
        #password_name_value = password_name.get()


        def save_generated_password():
            global password_name_value
            password_name_value = password_name.get()
            global logged_in_user_id
            database = sqlite3.connect('database.db')
            cursor = database.cursor()
            try:
                cursor.execute("SELECT id FROM users WHERE username=?", (valid_username,))
                global userss
                userss = cursor.fetchone()
                print(userss)

                if userss:
                    
                    logged_in_user_id = userss[0]
                    cursor.execute("INSERT INTO generated_passwords (password_name, password_text, user_id) VALUES (?, ?, ?)", (password_name_value, generated_pass, logged_in_user_id))
                    database.commit()
                    CTkMessagebox(title="Alert", message="Password Saved!")
                    save_password.configure(state=customtkinter.DISABLED)
                else:
                    CTkMessagebox(title="Alert", message="Error. User Not Found")
            except Exception as e:
                print(str(e))
            database.close()

        
        
        char_num = customtkinter.CTkEntry(master=crtpass_frame, placeholder_text="Enter number of password characters", width=250)
        char_num.pack(pady=12, padx=10)


        def password_generate():
            if password_name.get() == "" and char_num.get() == "":
                CTkMessagebox(title="Alert", message="Feilds cannot be empty")
            elif char_num.get() == "" and password_name.get().strip():

                CTkMessagebox(title="Alert", message="Type in number of password characters")
            elif password_name.get() == "" and char_num.get().strip():
                CTkMessagebox(title="Alert", message="Passwords must have names")
            else:
                try:
                    int(char_num.get())
                except:
                    CTkMessagebox(title="Alert", message="Input must be digit")

            capital_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            small_letters = "abcdefghijklmnopqrstuvwxyz"
            number_list = "0123456789"
            special_char = "!£$%^&*()_-+=#~[]{'}@:;/?.><,|`"""

            password_length = int(char_num.get())
            characters = capital_letters + small_letters + number_list + special_char
            global generated_pass
            generated_pass = ''.join(secrets.choice(characters) for _ in range(password_length))
          
            
            ## password will not be generated if password name is empty ##
            def dont_generate():
                if password_name.get() == "":
                    pass
                else:
                    password_label.configure(text="Generated Password: " + generated_pass, font=("Times New Roman", 22))
            dont_generate()
            save_password.configure(state=customtkinter.NORMAL)

        
        generate_pass = customtkinter.CTkButton(master=crtpass_frame, text="Generate Password", command=password_generate)
        generate_pass.pack(pady=12, padx=10)
            
        password_label = customtkinter.CTkLabel(master=crtpass_frame, text="")
        password_label.pack(pady=12, padx=10)

        global save_password
        save_password = customtkinter.CTkButton(master=crtpass_frame, text="Save Password", command=save_generated_password)
        save_password.pack(pady=12, padx=10)
        save_password.configure(state=customtkinter.DISABLED)



##  Function for the back button 
        def back_function():
            crtpass_frame.pack_forget()

            login_success(show_message=False)



        
        back_button = customtkinter.CTkButton(master=crtpass_frame, text="\u2190 Back", width=50, command=back_function)
        back_button.place(x=50, y=20)

    #def back_function2():
        #   view_pass_frame.pack_forget()
        
    
    
    signout_button = customtkinter.CTkButton(master=login_frame, text="Sign Out", command=sign_out, width=50)
    signout_button.place(x=1050, y=20,)

    create_password = customtkinter.CTkButton(master=login_frame, text="Create New Password", width=200, command=create_pass)
    create_password.place(x=480, y=150)

    saved_passwords = customtkinter.CTkButton(master=login_frame, text="View Saved Passwords", width=200, command=view_saved_passwords)
    saved_passwords.place(x=480, y=200)


    







#def login_fail():
 #   CTkMessagebox(title="Alert", message="Login Failed\n Username or Password incorrect")

def default_page():

    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    label = customtkinter.CTkLabel(master=frame, text="Login System")
    label.pack(pady=12, padx=10)


    global username5
    username5 = customtkinter.CTkEntry(master=frame, placeholder_text="Username")
    username5.pack(pady=12, padx=10)

    global password5
    password5 = customtkinter.CTkEntry(master=frame, placeholder_text="\U0001F511 Password", show="*")
    password5.pack(pady=12, padx=10)



   ## Login Authentication ## 
    def authentication():
        database = sqlite3.connect('database.db')
        cursor = database.cursor()
        
        global valid_username
        global valid_password
        valid_username = username5.get()
        valid_password = password5.get()

        if valid_username != '' and valid_password != '':
            cursor.execute("SELECT password FROM users WHERE username=?", (valid_username,))
            result = cursor.fetchone()

            if result:
                if bcrypt.checkpw(valid_password.encode('utf-8'), result[0]):
                    frame.pack_forget()
                    login_success() 
                else:
                    CTkMessagebox(title="Alert", message="Invalid Password")
            else:
                CTkMessagebox(title="Alert", message="Invalid Username")
            
        else:
            CTkMessagebox(title="Alert", message="Enter all Data")
        
        database.close()

            
    
    checkbox = customtkinter.CTkCheckBox(master=frame, text="Remember Me")
    checkbox.pack(pady=12, padx=10)

    button1 = customtkinter.CTkButton(master=frame, text="Login", command=authentication)
    button1.pack(pady=12, padx=10)
                                                        


    noaccount_label = customtkinter.CTkLabel(master=frame, text="Don't have an account ? ")
    noaccount_label.place(x=490, y=350)



    global noaccount_button
    noaccount_button = customtkinter.CTkButton(master=frame, text="Sign Up", font=font1, fg_color=None, width=20, height=20, hover_color="white", command=signup_window)
    noaccount_button.place(x=640, y=350)


def on_close():
    global window_open
    window_open = False
    register_window.destroy()
    noaccount_button.configure(state=customtkinter.NORMAL)




window_open = False
register_window = None

default_page()

    

root.mainloop()