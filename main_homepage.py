# using library
from tkinter import *
# from pygame import mixer
# import speech_recognition
from email.message import EmailMessage
import smtplib
import imghdr
import pandas
from tkinter import ttk
from tkinter import messagebox
from functools import partial
from PIL import Image, ImageTk
from stegano import lsb
from tkinter import filedialog
from PyPDF2 import PdfWriter, PdfReader
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from google.oauth2 import service_account
# from googleapiclient.discovery import build
# from googleapiclient.http import MediaFileUpload
import os
import csv
import time
import pyperclip



# key for permanent login
key_of_login = None  # Define key_of_login as a global variable outside any function
private_key_pem = None
public_key_pem = None

# Open the file in read mode and retrieve the user name
if os.path.exists('username.txt') and os.path.exists('userPrivate_key.txt') and os.path.exists('userPublic_key.txt'):
    with open("username.txt", "r") as file:
        key_of_login = file.read()
    with open("userPrivate_key.txt", "r") as file:
        private_key_pem = file.read()
    with open("userPublic_key.txt", "r") as file:
        public_key_pem = file.read()

# create a class
class en_Dec_rypt:

    def __init__(self, root):
        # Setting the Tkinter main window
        self.window = root
        self.window.geometry("700x500+150+180")
        self.window.title('SecureInfoSoftware')
        self.window.resizable(False,False)
        self.window.configure(bg="#2f4155")
        # icon
        self.image_icon=PhotoImage(file="images\logo_200x200.png")
        self.window.iconphoto(False,self.image_icon)
        # Calling the Home_Page() function
        self.home_page()

    # home page (First open page)
    def home_page(self):
        # call the clear screen Function
        self.ClearScreen()
        self.window.configure(bg="#2f4155")
        # global key of login
        global key_of_login
        # manu show function (only login user access)
        def show_menu():
            # global key of login
            global key_of_login
            # if else condition for login user and logout user
            if key_of_login == "" or key_of_login == None:  # for without login user
                Button(title_lable, text="Login/Reg.", height=2, width=10, bg="white", fg="blue", font="arial 12 bold",
                       bd=0, command=partial(self.register_page)).place(x=600, y=4)
            else:  # for login user
                def toggel_menu():
                    # global key of login
                    global key_of_login
                    def log_out(): # logout funtion
                        global key_of_login
                        key_of_login = None
                        # Remove the file data
                        with open("username.txt", "w") as file:
                            file.write("")

                        # Delete the file
                        os.remove("username.txt")

                        taggle_menu_fm.destroy()
                        self.home_page()
                        messagebox.showinfo("Success", "Logout successful!")

                    def coleb_menu(): # destroy taggle bar
                        taggle_menu_fm.destroy()
                        self.home_page()

                    def root_destroy():
                        root.destroy()

                    taggle_menu_fm = Frame(self.window, bg='#158aff', width=200, height=500)
                    taggle_menu_fm.place(x=500, y=0)

                    b11 = Button(taggle_menu_fm, text='X', bg='#158aff', fg='white', font=('Bold', 20), bd=0,activebackground='#158aff', activeforeground='black', command=coleb_menu)
                    b11.place(x=2, y=2)
                    Label(taggle_menu_fm,text="Welcome",font="arial 18 bold", bg="#158aff", fg="white").place(x=5, y=60)
                    Label(taggle_menu_fm,text=key_of_login,font="arial 20 bold", bg="#158aff", fg="white").place(x=5, y=100)
                    # toggel menu button
                    t_btn4 = Button(taggle_menu_fm, text="Public Keys", font=('bold', 18), bd=0, bg='#158aff',fg='white', activebackground='#158aff', activeforeground='black',command=partial(self.public_page))
                    t_btn4.place(x=20, y=300)
                    t_btn1=Button(taggle_menu_fm,text="About",font=('bold',18),bd=0,bg='#158aff', fg='white',activebackground='#158aff', activeforeground='black',command=partial(self.about_page))
                    t_btn1.place(x=20,y=340)
                    t_btn2 = Button(taggle_menu_fm, text="Logout", font=('bold', 18), bd=0, bg='#158aff', fg='white',activebackground='#158aff', activeforeground='black',command=log_out)
                    t_btn2.place(x=20, y=380)
                    t_btn3 = Button(taggle_menu_fm, text="Exit", font=('bold', 18), bd=0, bg='#158aff', fg='white',activebackground='#158aff', activeforeground='black',command=root_destroy)
                    t_btn3.place(x=20, y=450)





                # all button to use softwarw
                a = Menubutton(title_lable, text="Information >", height=2, width=10, bg="white", fg="blue",font="arial 12 bold")
                a.place(x=550, y=4)
                info = Menu(a, tearoff=0)
                info.add_command(label="Text secure", command=partial(self.text_incrupt_decrypt))
                info.add_command(label="Image secure", command=partial(self.image_proccess))
                info.add_command(label="Audio secure", command=partial(self.audio_file))
                info.add_command(label="Video secure", command=partial(self.video_file))
                info.add_command(label="TextHide Ima.", command=partial(self.image_text_hide))
                info.add_command(label="PDF protect", command=partial(self.pdf_password))
                a['menu'] = info
                # toggle bar Button
                b2=Button(title_lable, text='☰', bg='white', fg='blue',font=('Bold', 20), bd=0,activebackground='white', activeforeground='black',command=toggel_menu)
                b2.place(x=650,y=1)




        #Encrupt Button
        title_lable = Label(self.window,bg="white", height=3, relief=SUNKEN)
        title_lable.pack(side=TOP,fill=X)
        # logo
        image1 = Image.open("images//ramew.png")
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(title_lable, image=photo1,bg="white")
        label1.image = photo1
        label1.place(x=30, y=0)

        image=Image.open("images/Cryptography.jpg")
        photo=ImageTk.PhotoImage(image)
        label=Label(self.window,image=photo)
        label.image=photo
        label.place(x=0,y=60)

        Button(text="Send Message", height=1, width=40, bg="green", fg="white", font="arial 13 bold", bd=3, command=partial(self.send_message)).place(x=140,
                                                                                                                  y=325)
        # about the app
        frame1 = Frame(self.window, bd=6, bg="#454545", width=680, height=105, relief=GROOVE)
        frame1.place(x=10, y=390)

        Label(frame1,text="""Encryption and decryption Software can be used by anyone who wants to protect \ntheir sensitive data from unauthorized access. These applications are used by individ-\nuals, businesses, Government agencies and organizations to secure their emails, \nmessages, files, and other private data.""",
                    font="arial 12 bold", bg="#454545", fg="white").place(x=5, y=5)

        show_menu()

    # Remove all widgets from the Home Page(self.frame)
    def ClearScreen(self):
        for widget in self.window.winfo_children():
            widget.destroy()

    def text_incrupt_decrypt(self):
        self.ClearScreen()
        color="#C5D4EC"
        self.window.configure(bg=color)
        global private_key_pem, public_key_pem
        def load_keys(public_key_pem):
            global private_key_pem
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            return private_key, public_key

        def decrypt():  # this function of decryption text
            key = code.get()
            if key != "":
                loaded_private_key, loaded_public_key = load_keys(key)

                def decryptin(cipher_text, private_key, public_key):
                    cipher_text = bytes.fromhex(cipher_text)

                    shared_key = private_key.exchange(ec.ECDH(), public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'',
                    ).derive(shared_key)

                    aesgcm = AESGCM(derived_key)
                    nonce = b'\x00' * 12
                    plain_text = aesgcm.decrypt(nonce, cipher_text, None)
                    return plain_text.decode('utf-8')

                screen2 = Toplevel(self.window)
                screen2.geometry("400x200")
                screen2.configure(bg="#00bd56")
                screen2.resizable(False, False)
                # icon
                image_icon1 = PhotoImage(file="images\logo_200x200.png")
                screen2.iconphoto(False, image_icon1)
                screen2.title('SecureInfo')

                message = text1.get(1.0, END)
                decrypt = decryptin(message, loaded_private_key, loaded_public_key)

                Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=10)
                texe2 = Text(screen2, font="Rpbots 15", fg="green", bg="black", relief=GROOVE, wrap=WORD, bd=3)
                texe2.place(x=10, y=40, width=380, height=150)
                texe2.insert(END, decrypt)
                code.set("")
                text1.delete(1.0, END)
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")


        def encrypt():  # this function of encryption text
            key = code.get()
            if key!="":
                loaded_private_key, loaded_public_key = load_keys(key)

                def encryptin(plain_text, private_key, public_key):
                    plain_text = plain_text.encode('utf-8')

                    shared_key = private_key.exchange(ec.ECDH(), public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'',
                    ).derive(shared_key)

                    aesgcm = AESGCM(derived_key)
                    nonce = b'\x00' * 12
                    cipher_text = aesgcm.encrypt(nonce, plain_text, None)
                    return cipher_text.hex()

                screen1 = Toplevel(self.window)
                screen1.geometry("400x200")
                screen1.configure(bg="#ed3833")
                screen1.resizable(False, False)
                # icon
                image_icon1 = PhotoImage(file="images\logo_200x200.png")
                screen1.iconphoto(False, image_icon1)
                screen1.title("SecureInfo")

                message = text1.get(1.0, END)
                encrypt = encryptin(message, loaded_private_key, loaded_public_key)
                # cipher_text = encrypt(message, loaded_private_key, loaded_public_key)
                Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=10)
                texe2 = Text(screen1, font="Rpbots 15", fg="green", bg="black", relief=GROOVE, wrap=WORD, bd=3)
                texe2.place(x=10, y=40, width=380, height=150)
                texe2.insert(END, encrypt)
                code.set("")
                text1.delete(1.0, END)
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")


        # add home button
        ba1 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                     command=self.home_page)
        ba1.place(x=10, y=10)

        image1 = Image.open('images\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg="#C5D4EC")
        label1.image = photo1
        label1.place(x=70, y=10)
        # loga = ImageTk.PhotoImage(Image.open('images\logo-S.png'))
        # Label(self.window, image=loga, bg="#2f4155").place(x=40, y=10)

        def reset():  # use to reset all text box blank
            code.set("")
            text1.delete(1.0, END)

        Label(text="Text encryption and decryption", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=160, y=20)
        text1 = Text( font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=5)
        text1.place(x=25, y=80, width=650, height=180)

        Label(text="Enter sender Public key", fg="black", bg=color, font="calibri 13 bold").place(x=25,y=270)

        code = StringVar()
        kkkkeeey=Entry(textvariable=code, bg="black", fg="red", width=20, bd=5, font="arial 25")
        kkkkeeey.place(x=25, y=305)

        Button(text="ENCRYRT", height=3, width=30, bg="red", fg="white", bd=3, command=encrypt).place(x=70, y=365)
        Button(text="DECRYPT", height=3, width=30, bg="green", fg="white", bd=3, command=decrypt).place(x=410, y=365)
        Button(text="RESAT", height=2, width=60, bg="blue", fg="white", bd=3, command=reset).place(x=135, y=435)

    def image_text_hide(self):
        self.ClearScreen()
        color="#C5D4EC"
        self.window.configure(bg=color)
        global private_key_pem, public_key_pem

        def load_keys(public_key_pem):
            global private_key_pem
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            return private_key, public_key

        def showImage():  # here image is put in the divece
            global filename
            filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                                  title="Select Image file",
                                                  filetypes=(("All image files", "*.png *.jpg *.jpeg"),))
            img = Image.open(filename)
            img = ImageTk.PhotoImage(img)
            lbl.configure(image=img, width=310, height=250)
            lbl.image = img

        def encryptin(plain_text, private_key, public_key):
            plain_text = plain_text.encode('utf-8')

            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            cipher_text = aesgcm.encrypt(nonce, plain_text, None)
            return cipher_text.hex()

        def decryptin(cipher_text, private_key, public_key):
            cipher_text = bytes.fromhex(cipher_text)

            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            plain_text = aesgcm.decrypt(nonce, cipher_text, None)
            return plain_text.decode('utf-8')


        def hideData():  # this funtion is use to hide data in the image
            global secret
            key = code.get()
            if key != "":
                loaded_private_key, loaded_public_key = load_keys(key)
                message = text1.get(1.0, END)
                encrypt = encryptin(message, loaded_private_key, loaded_public_key)
                secret = lsb.hide(str(filename), encrypt)
                scrollbarl.set("")
                code.set("")
                messagebox.showinfo("Success", "Hide message successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")


        def showData():
            key = code.get()
            if key != "":
                loaded_private_key, loaded_public_key = load_keys(key)
                clear_message = lsb.reveal(filename)
                decrypt = decryptin(clear_message, loaded_private_key, loaded_public_key)
                text1.delete(1.0, END)
                text1.insert(END, decrypt)
                scrollbarl.set("")
                code.set("")
                messagebox.showinfo("Success", "Show message successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")

        def saveImage():  # message is saving image in the mamory
            save_path = filedialog.asksaveasfilename(defaultextension=".png .jpg .jpeg", title="Save Image file",
                                                     filetypes=(("All image files", "*.png *.jpg *.jpeg"),))
            if save_path:
                secret.save(save_path)

        #home button
        ba=Button(self.window,text="<-Back",bg="#2f4155",fg="white",font=("Helvetica", 8, 'bold'),command=self.home_page)
        ba.place(x=10,y=10)
        # logo
        image1 = Image.open('images\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg="#C5D4EC")
        label1.image = photo1
        label1.place(x=70, y=10)
        Label(self.window, text="Message hide in Image", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=160, y=15)

        # first frame
        frame1 = Frame(self.window, bd=3, bg="black", width=340, height=280, relief=GROOVE)
        frame1.place(x=10, y=60)

        lbl = Label(frame1, bg="black")
        lbl.place(x=10, y=10)

        # second frame
        frame2 = Frame(self.window, bd=3, width=340, height=280, bg="white", relief=GROOVE)
        frame2.place(x=350, y=60)

        text1 = Text(frame2, font="Robote 20", bg="white", fg="black", relief=GROOVE)
        text1.place(x=0, y=0, width=320, height=295)

        scrollbarl = Scrollbar(frame2)
        scrollbarl.place(x=320, y=0, height=300)

        scrollbarl.configure(command=text1.yview)
        text1.configure(yscrollcommand=scrollbarl.set)

        Label(text="Enter Public key", fg="black", bg=color, font="calibri 20 bold").place(x=20, y=345)
        code = StringVar()
        entry_box = Entry(textvariable=code, bg="black", fg="red", width=20, bd=5, font="arial 25")
        entry_box.place(x=300, y=345)

        # tradeframe
        frame3 = Frame(self.window, bd=6, bg="#2f4155", width=330, height=100, relief=GROOVE)
        frame3.place(x=10, y=400)

        Button(frame3, text="Open Image", width=10, height=2, font="arial 14 bold", command=showImage).place(x=20, y=30)
        Button(frame3, text="Save Image", width=10, height=2, font="arial 14 bold", command=saveImage).place(x=180,
                                                                                                             y=30)
        Label(frame3, text="Picture, Image, Photo File", bg="#2f4155", fg="yellow").place(x=90, y=5)

        # forth frame
        frame4 = Frame(self.window, bd=6, bg="#2f4155", width=330, height=100, relief=GROOVE)
        frame4.place(x=360, y=400)

        Button(frame4, text="Hide Data", width=10, height=2, font="arial 14 bold", command=hideData).place(x=20, y=30)
        Button(frame4, text="Show Data", width=10, height=2, font="arial 14 bold", command=showData).place(x=180, y=30)
        Label(frame4, text="Data proccessing (Show & Hide)", bg="#2f4155", fg="yellow").place(x=70, y=5)

    def image_proccess(self):
        self.ClearScreen()
        color="#C5D4EC" # lite blue
        color2 = "#2f4155" # dark blue
        self.window.configure(bg=color)

        global private_key_pem, public_key_pem

        def load_keys(public_key_pem):
            global private_key_pem
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            return private_key, public_key

        def showImage():  # here image is put in the divece
            global filename
            filename = filedialog.askopenfile(mode='r',
                                              title="Select Image file",
                                              filetypes=(("All image files", "*.png *.jpg *.jpeg"),))
            entry1.insert(END, filename.name)

        def encrypt(plain_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            cipher_text = aesgcm.encrypt(nonce, plain_text, None)
            return cipher_text

        def decrypt(cipher_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            plain_text = aesgcm.decrypt(nonce, cipher_text, None)
            return plain_text

        def encryption_image():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name=filename.name
                with open(file_name, 'rb') as binary_file:
                    image = binary_file.read()

                cipher_text = encrypt(image, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(cipher_text)
                source.set("")
                p_key.set("")
                messagebox.showinfo("Success", "Encryption successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption\nand chacke path of image!")

        def decryption_image():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name = filename.name
                with open(file_name, 'rb') as binary_file:
                    cipher_text = binary_file.read()

                decrypted_text = decrypt(cipher_text, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(decrypted_text)
                source.set("")
                p_key.set("")
                messagebox.showinfo("Success", "Decryption successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")

        def reset():  # use to reset all text box blank
            p_key.set("")
            source.set("")


        #add home button
        ba1 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                    command=self.home_page)
        ba1.place(x=10, y=10)

        image1 = Image.open('images\\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg=color)
        label1.image = photo1
        label1.place(x=50, y=45)
        Label(text="Image encryption and decryption", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=150, y=50)
        # frame

        frame = Frame(self.window, bg=color2, width=680, height=350, bd=5, relief=GROOVE)
        frame.place(x=10, y=140)

        # ======code======
        source = StringVar()
        p_key = StringVar()
        Label(frame, text="Open image File:", bg=color2, font="arial 15 bold", fg="white").place(x=30, y=50)
        entry1 = Entry(frame, width=30, textvariable=source, font="arial 15", bd=1)
        entry1.place(x=200, y=50)
        Label(frame,text="Enter public key for Encryption and Decryption",font="abail 14 bold",bg=color2,fg="yellow").place(x=30,y=120)
        entry2=Entry(frame,textvariable=p_key, bg="black", fg="red", width=20, bd=5, font="arial 20")
        entry2.place(x=30, y=150)
        image1 = Image.open("images/upload-icon.png")
        photo1 = ImageTk.PhotoImage(image1)
        btn101=Button(frame,image=photo1,fg="black",width=25,height=24,bg=color2, command=showImage)
        btn101.image = photo1
        btn101.place(x=550,y=50)
        btn102=Button(frame, text='Encrypt', font="abial 14 bold", bg="red", fg="black", bd=3,height=2, width=15,command=encryption_image)
        btn102.place(x=70, y=210)
        btn103=Button(frame, text='Decrypt', font="abail 14 bold", bg="green", fg="white", bd=3,height=2,width=15,command=decryption_image)
        btn103.place(x=410, y=210)
        btn104=Button(text="RESAT", height=2, width=60, bg="blue", fg="white", bd=3, command=reset)
        btn104.place(x=135, y=430)


    def audio_file(self):
        self.ClearScreen()
        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue
        self.window.configure(bg=color)

        global private_key_pem, public_key_pem

        def load_keys(public_key_pem):
            global private_key_pem
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            return private_key, public_key

        def showaAudio():  # here image is put in the divece
            global filename
            filename = filedialog.askopenfile(mode='r',
                                              title="Select Image file",
                                              filetypes=(("Audio files", "*.mp3 *.m4a *.wav *.flac *.wma *.aac"),))
            entry1.insert(END, filename.name)

        def encrypt(plain_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            cipher_text = aesgcm.encrypt(nonce, plain_text, None)
            return cipher_text

        def decrypt(cipher_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            plain_text = aesgcm.decrypt(nonce, cipher_text, None)
            return plain_text

        def encryption_audio():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name = filename.name
                with open(file_name, 'rb') as binary_file:
                    audio = binary_file.read()

                cipher_text = encrypt(audio, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(cipher_text)
                    source.set("")
                    p_key.set("")
                messagebox.showinfo("Success", "Encryption audio successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption\nand chacke path of image!")

        def decryption_audio():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name = filename.name
                with open(file_name, 'rb') as binary_file:
                    cipher_text = binary_file.read()

                decrypted_text = decrypt(cipher_text, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(decrypted_text)
                source.set("")
                messagebox.showinfo("Success", "Decryption audio successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")

        def reset():  # use to reset all text box blank
            p_key.set("")
            source.set("")

        # add home button
        ba10 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                     command=self.home_page)
        ba10.place(x=10, y=10)

        image1 = Image.open('images\\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg=color)
        label1.image = photo1
        label1.place(x=50, y=45)
        Label(text="Audio encryption and decryption", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=150, y=50)
        # frame
        frame = Frame(self.window, bg=color2, width=680, height=350, bd=5, relief=GROOVE)
        frame.place(x=10, y=140)

        # ======code======
        source = StringVar()
        p_key = StringVar()
        Label(frame, text="Open image File:", bg=color2, font="arial 15 bold", fg="white").place(x=30, y=50)
        entry1 = Entry(frame, width=30, textvariable=source, font="arial 15", bd=1)
        entry1.place(x=200, y=50)
        Label(frame, text="Enter public key for Encryption and Decryption", font="abail 14 bold", bg=color2, fg="yellow").place(x=30, y=120)
        entry2 = Entry(frame, textvariable=p_key, bg="black", fg="red", width=20, bd=5, font="arial 20")
        entry2.place(x=30, y=150)

        image1 = Image.open("images/upload-icon.png")
        photo1 = ImageTk.PhotoImage(image1)
        btn201 = Button(frame, image=photo1, fg="black", width=25, height=24, bg=color2, command=showaAudio)
        btn201.image = photo1
        btn201.place(x=550, y=50)
        btn202 = Button(frame, text='Encrypt', font="abial 14 bold", bg="red", fg="black", bd=3, height=2, width=15,command = encryption_audio)
        btn202.place(x=70, y=210)
        btn203 = Button(frame, text='Decrypt', font="abail 14 bold", bg="blue", fg="white", bd=3, height=2, width=15,command = decryption_audio)
        btn203.place(x=410, y=210)
        btn204 = Button(text="RESAT", height=2, width=60, bg="blue", fg="white", bd=3, command=reset)
        btn204.place(x=135, y=430)


    def video_file(self):
        self.ClearScreen()
        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue
        self.window.configure(bg=color)

        global private_key_pem, public_key_pem

        def load_keys(public_key_pem):
            global private_key_pem
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            return private_key, public_key

        def showVideo():  # here image is put in the divece
            global filename
            filename = filedialog.askopenfile(mode='r',
                                              title="Select Video file",
                                              filetypes=(("Video files", "*.mp4 *.mkv *.webm *.mov *.wmv *.flv *.avi *.mts *.m2ts *.ts *.qt"),))
            entry1.insert(END, filename.name)

        def encrypt(plain_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            cipher_text = aesgcm.encrypt(nonce, plain_text, None)
            return cipher_text

        def decrypt(cipher_text, private_key, public_key):
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'',
            ).derive(shared_key)

            aesgcm = AESGCM(derived_key)
            nonce = b'\x00' * 12
            plain_text = aesgcm.decrypt(nonce, cipher_text, None)
            return plain_text

        def encryption_Video():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name = filename.name
                with open(file_name, 'rb') as binary_file:
                    video = binary_file.read()

                cipher_text = encrypt(video, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(cipher_text)
                source.set("")
                p_key.set("")
                messagebox.showinfo("Success", "Encryption Video successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption\nand chacke path of video!")

        def decryption_Video():
            key = p_key.get()
            if key != "" and filename is not None:
                loaded_private_key, loaded_public_key = load_keys(key)
                file_name = filename.name
                with open(file_name, 'rb') as binary_file:
                    cipher_text = binary_file.read()

                decrypted_text = decrypt(cipher_text, loaded_private_key, loaded_public_key)
                with open(file_name, 'wb') as binary_file:
                    binary_file.write(decrypted_text)
                source.set("")
                messagebox.showinfo("Success", "Decryption video successful!")
            else:
                messagebox.showerror("Invalid", "Please Enter Public key for Encryption!")


        def reset():  # use to reset all text box blank
            p_key.set("")
            source.set("")

        # add home button
        ba10 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                      command=self.home_page)
        ba10.place(x=10, y=10)

        image1 = Image.open('images\\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg=color)
        label1.image = photo1
        label1.place(x=50, y=45)
        Label(text="Video encryption and decryption", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=150, y=50)
        # frame
        frame = Frame(self.window, bg=color2, width=680, height=350, bd=5, relief=GROOVE)
        frame.place(x=10, y=140)

        # ======code======
        source = StringVar()
        p_key = StringVar()
        Label(frame, text="Open Video File:", bg=color2, font="arial 15 bold", fg="white").place(x=30, y=50)
        entry1 = Entry(frame, width=30, textvariable=source, font="arial 15", bd=1)
        entry1.place(x=200, y=50)
        Label(frame, text="Enter public key for Encryption and Decryption", font="abail 14 bold", bg=color2, fg="yellow").place(
            x=30, y=120)
        entry2 = Entry(frame, textvariable=p_key, bg="black", fg="red", width=20, bd=5, font="arial 20")
        entry2.place(x=30, y=150)

        image1 = Image.open("images/upload-icon.png")
        photo1 = ImageTk.PhotoImage(image1)
        btn301 = Button(frame, image=photo1, fg="black", width=25, height=24, bg=color2, command=showVideo)
        btn301.image = photo1
        btn301.place(x=550, y=50)
        btn302 = Button(frame, text='Encrypt', font="abial 14 bold", bg="red", fg="black", bd=3, height=2, width=15,
                        command=encryption_Video)
        btn302.place(x=70, y=210)
        btn303 = Button(frame, text='Decrypt', font="abail 14 bold", bg="green", fg="white", bd=3, height=2, width=15,
                        command=decryption_Video)
        btn303.place(x=410, y=210)
        btn304 = Button(text="RESAT", height=2, width=60, bg="blue", fg="white", bd=3, command=reset)
        btn304.place(x=135, y=430)

    def pdf_password(self):
        self.ClearScreen()
        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue
        self.window.configure(bg=color)

        def browse():
            global filename
            filename = filedialog.askopenfilename(defaultextension=".pdf",
                                                  title="Save PDF file",
                                                  filetypes=(('PDF file', '*.pdf'),))
            entry1.insert(END, filename)

        def savebrowse():
            filename1=filedialog.asksaveasfilename(defaultextension=".pdf",
                                                title="Select PDF file",
                                                filetypes=(('PDF file', '*.pdf'),))
            entry2.insert(END, filename1)

        def Protect():
            mainfile = source.get()
            protectfile = target.get()
            code = password.get()

            if mainfile == "" and protectfile == "" and password.get() == "":
                messagebox.showerror("Invalid", "All entries are empty!")
            elif mainfile == "":
                messagebox.showerror("Invalid", "Please type source PDF Filename")
            elif protectfile == "":
                messagebox.showerror("Invalid", "Please Type target PDF Filename!")
            elif password.get() == "":
                messagebox.showerror("Invalid", "Please Type Password")

            else:
                try:
                    out = PdfWriter()
                    file = PdfReader(filename)
                    num = len(file.pages)

                    for idx in range(num):
                        page = file.pages[idx]
                        out.add_page(page)

                    # password
                    out.encrypt(code)

                    with open(protectfile, "wb") as f:
                        out.write(f)

                    source.set("")
                    target.set("")
                    password.set("")

                    messagebox.showinfo("Info", "Successfully Done!")

                except Exception as e:
                    messagebox.showerror("Invalid Error", f"An error occurred: {str(e)}")

        def deProtect():
            filename = source.get()
            deprotectfile = target.get()
            code = password.get()
            if code == "":
                messagebox.showwarning('Warning', "Please set the password")
            else:
                try:
                    file = PdfReader(filename)
                    file.decrypt(code)

                    out = PdfWriter()
                    for idx in range(len(file.pages)):
                        out.add_page(file.pages[idx])

                    with open(deprotectfile, "wb") as f:
                        out.write(f)

                    source.set("")
                    target.set("")
                    password.set("")
                    messagebox.showinfo("Info", "Successfully Done!")

                except Exception as e:
                    messagebox.showerror("Invalid Error", f"An error occurred: {str(e)}")

        # add home button
        ba2 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                     command=self.home_page)
        ba2.place(x=10, y=10)

        # logo
        image1 = Image.open('images\\logo-S.png')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(self.window, image=photo1, bg=color)
        label1.image = photo1
        label1.place(x=50, y=45)
        Label(self.window, text="PDF Password Protector", bg=color, fg="red", font=("Game Of Squids", 16, "bold")).place(x=220, y=50)

        # frame
        frame = Frame(self.window, bg=color2, width=680, height=350, bd=5, relief=GROOVE)
        frame.place(x=10, y=140)

        # ======code====
        source = StringVar()
        Label(frame, text="Source PDF File:", bg=color2, font="arial 15 bold", fg="white").place(x=30, y=50)
        entry1 = Entry(frame, width=30, textvariable=source, font="arial 15", bd=1)
        entry1.place(x=200, y=50)
        image1 = Image.open("images/upload-icon.png")
        photo1 = ImageTk.PhotoImage(image1)
        btn101 = Button(frame, image=photo1, fg="black", width=25, height=24, bg=color2, command=browse)
        btn101.image = photo1
        btn101.place(x=550, y=50)

        # ======code====
        target = StringVar()
        Label(frame, text="Save PDF File:", bg=color2, font="arial 15 bold", fg="white").place(x=50, y=100)
        entry2 = Entry(frame, width=30, textvariable=target, font="arial 15", bd=1)
        entry2.place(x=200, y=100)
        image2 = Image.open("images/button image.png")
        photo2 = ImageTk.PhotoImage(image2)
        btn201 = Button(frame, image=photo2, fg="black", width=25, height=24, bg=color2, command=savebrowse)
        btn201.image = photo2
        btn201.place(x=550, y=100)

        # ======code====
        password = StringVar()
        Label(frame, text="Set Password:", bg=color2, font="arial 15 bold", fg="white").place(x=50, y=150)
        entry3 = Entry(frame, width=30, textvariable=password, font="arial 15", bd=1)
        entry3.place(x=200, y=150)

        # button_icon = PhotoImage(file="pdf_encrypt.png")
        protect = Button(frame, text="Protect PDF file", fg="black", width=15, height=2,bg="#bfb9b9", font="arial 14 bold", command=Protect)#compound=LEFT, image=button_icon
        protect.place(x=100, y=250)
        protect = Button(frame, text="Remove PDF Pass",fg="black", width=15, height=2,bg="#bfb9b9", font="arial 14 bold", command=deProtect)#compound=LEFT, image=button_icon
        protect.place(x=400, y=250)


    def logian_page(self):
        self.ClearScreen()

        global key_of_login,private_key_pem,public_key_pem
        # Background image
        image = Image.open("images/aa.jpg")
        photo = ImageTk.PhotoImage(image)
        pra_label = Label(self.window, image=photo)
        pra_label.image = photo
        pra_label.place(x=-2, y=0)

        def toggle_password_visibility():
            if loginvalue.get():
                passWord.config(show="")
            else:
                passWord.config(show="*")

        # login
        def login_page():
            global key_of_login,private_key_pem,public_key_pem
            username = mailId.get()
            password = passId.get()

            # Check if the username and password match
            if os.path.exists('users_make.csv'):
                with open('users_make.csv', 'r') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if row[0] == username and row[1] == password:
                            messagebox.showinfo("Success", "Login successful!")
                            key_of_login=username
                            private_key_pem=row[4]
                            public_key_pem=row[5]
                            # Open the file in write mode and save the user name
                            with open("userPrivate_key.txt", "w") as file:
                                file.write(private_key_pem)
                            with open("userPublic_key.txt", "w") as file:
                                file.write(public_key_pem)
                            with open("username.txt", "w") as file:
                                file.write(key_of_login)
                            self.home_page()
                            return

            messagebox.showerror("Error", "Invalid username or password!\n And If you not Register so please first do it!")

        # add home button
        ba4 = Button(pra_label, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                     command=self.home_page)
        ba4.place(x=10, y=10)

        # Creating the login form elements
        fream1 = Frame(pra_label, width=500, height=280, bg="white", bd=2)
        fream1.place(x=100, y=90)

        # Login button
        b1 = Button(pra_label, fg="white", bg="#454545", font="Helvetica 13 bold", text="Login", width=20, height=2,command=login_page)
        b1.place(x=250, y=345)

        # Labels
        l = Label(fream1, text="Login Here", fg="black", font=("Game Of Squids", 20, "bold"), bg="white")
        l.place(x=140, y=5)
        l1 = Label(fream1, text="Welcome to SecureInfo Login page for Old user", fg="black", font="Helvetica 12 bold",
                   bg="white")
        l1.place(x=70, y=40)
        l2 = Label(fream1, text="Username", fg="black", font="Helvetica 15 bold", bg="white")
        l2.place(x=100, y=70)
        l3 = Label(fream1, text="Password", fg="black", font="Helvetica 15 bold", bg="white")
        l3.place(x=100, y=130)

        # Entry fields
        mailId = StringVar()
        passId = StringVar()
        emailId = Entry(fream1, textvariable=mailId, width=32, bd=2, font="12", bg="#E5E8E8")
        passWord = Entry(fream1, textvariable=passId, show="*" , width=32, bd=2, font="12", bg="#E5E8E8")
        emailId.place(x=100, y=100)
        passWord.place(x=100, y=160)

        # "New User, Register Here" button
        b2 = Button(fream1, fg="blue", bg="white", font="10", bd=0, text="New User, Register Here", width=20, height=1,command=partial(self.register_page))
        b2.place(x=160, y=222)

        # "Forget Password?" button
        b3 = Button(fream1, fg="blue", bg="white", font="10", bd=0, text="Forget Password?", width=15, height=1)
        b3.place(x=95, y=190)

        # Checkbox to show/hide password
        loginvalue = IntVar()
        loginpage = Checkbutton(fream1, text="Show Password", bg="white", variable=loginvalue, command=toggle_password_visibility)
        loginpage.place(x=290, y=190)

    def register_page(self):
        self.ClearScreen()

        # Background image
        image = Image.open("images/aa.jpg")
        photo = ImageTk.PhotoImage(image)
        pra_label = Label(self.window, image=photo)
        pra_label.image = photo
        pra_label.place(x=-2, y=0)


        def toggle_password_visibility():
            if loginvalue.get():
                passWord1.config(show="")
                passWord2.config(show="")
            else:
                passWord1.config(show="*")
                passWord2.config(show="*")


        # add home button
        ba4 = Button(pra_label, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),
                     command=self.home_page)
        ba4.place(x=10, y=10)

        # Function to handle the registration process
        def registration_system():
            # Checking if all the fields are filled
            if new_user.get() == "" or name_full.get() == "" or mobile_num.get() == "" or passWord1.get() == "" or passWord2.get() == "":
                messagebox.showerror("Invalid Error", "Please Enter All Details!")
            # Checking if the passwords match
            elif passWord1.get() == passWord2.get():

                

                # Check if the username is already taken
                if os.path.exists('users_make.csv'):
                    with open('users_make.csv', 'r') as file:
                        reader = csv.reader(file)
                        for row in reader:
                            if row[0] == new_user.get():
                                messagebox.showerror("Error", "Username already taken!")
                                return

                # Check if the password and confirm password match
                if passId.get() != c_passId.get():
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                #genrate keys
                def generate_keys():
                    private_key = ec.generate_private_key(ec.SECP256R1())
                    public_key = private_key.public_key()
                    return private_key, public_key

                def save_keys(private_key, public_key):
                    global private_key_pem, public_key_pem

                    private_key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode()

                    public_key_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()


                # Example use
                private_key, public_key = generate_keys()
                save_keys(private_key, public_key)

                # Register the user
                with open('users_make.csv', 'a', newline='') as file:
                    writer = csv.writer(file)

                    # Check if the file is empty (to add the header row)
                    if os.stat('users_make.csv').st_size == 0:
                        writer.writerow(["Username", "Password", "Full Name", "Mobile No.","Private Key","Public key"])  # Attribute names
                    writer.writerow([new_user.get(), passId.get(), full_name.get(), mobile_No.get(), private_key_pem, public_key_pem])

                    # Register the user
                    with open('users_public.csv', 'a', newline='') as file:
                        writer = csv.writer(file)

                        if os.stat('users_make.csv').st_size == 0:
                            writer.writerow(["Username","Public key"])  # Attribute names
                        writer.writerow([new_user.get(), public_key_pem])

                # def savedata(nameoffile,datatosave):
                #     # Load the credentials from the JSON key file
                #     credentials = service_account.Credentials.from_service_account_file('file.json')
                #
                #     # Authorize the client
                #     drive_service = build('drive', 'v3', credentials=credentials)
                #
                #     # Search for the folder ID based on the folder title
                #     folder_title = 'CSVFilesSecureInfo'
                #     folder_id = None
                #
                #     results = drive_service.files().list(
                #         q="mimeType='application/vnd.google-apps.folder' and name='" + folder_title + "'",
                #         fields="files(id)").execute()
                #
                #     items = results.get('files', [])
                #     if items:
                #         folder_id = items[0]['id']
                #
                #     if folder_id:
                #         # Open the Google Sheets document
                #         spreadsheets = drive_service.files().list(
                #             q="mimeType='application/vnd.google-apps.spreadsheet' and '" + folder_id + "' in parents",
                #             fields="files(id, name)").execute()
                #
                #         spreadsheets_items = spreadsheets.get('files', [])
                #         for spreadsheet in spreadsheets_items:
                #             # Update with the actual title of the Google Sheets document
                #             sheet_title = nameoffile
                #             if spreadsheet['name'] == sheet_title:
                #                 spreadsheet_id = spreadsheet['id']
                #                 csv_filename = sheet_title + '.csv'
                #                 # print(csv_filename)
                #
                #                 # Read the existing CSV file
                #                 request = drive_service.files().export_media(fileId=spreadsheet_id, mimeType='text/csv')
                #                 response = request.execute()
                #                 content = response.decode("utf-8").splitlines()
                #                 existing_data = list(csv.reader(content))
                #                 # print(existing_data)
                #
                #                 # Append data to the existing CSV file
                #                 new_data = datatosave
                #                 existing_data.append(new_data)
                #
                #                 # Write the updated data to a new CSV file
                #                 with open(csv_filename, 'w', newline='') as file:
                #                     writer = csv.writer(file)
                #                     writer.writerows(existing_data)
                #
                #                 # Upload the updated CSV file to Google Drive
                #                 media_body = MediaFileUpload(csv_filename, mimetype='text/csv')
                #                 request = drive_service.files().update(fileId=spreadsheet_id, media_body=media_body)
                #                 response = request.execute()
                #
                #                 messagebox.showinfo("Success", "Data appended and updated successfully on Google Drive.")
                #     else:
                #         messagebox.showerror("Invalid Error", f"Folder '{folder_title}' not found in Google Drive.")

                # savedata('users_make1',[new_user.get(), passId.get(), full_name.get(), mobile_No.get(),private_key_pem, public_key_pem])
                # savedata('users_public1', [new_user.get(),public_key_pem])

                messagebox.showinfo("Success", "Registration successful!")
                self.logian_page()

            else:
                messagebox.showerror("Invalid Error", "Please Enter Same and Valid Password!")

        # Creating the registration form elements
        fream1 = Frame(pra_label, width=600, height=400, bg="white", bd=3)
        fream1.place(x=50, y=50)

        # Registration button
        b1 = Button(pra_label, fg="white", bg="#454545", font="Helvetica 13 bold", text="Registration",command=registration_system, width=20, height=2)
        b1.place(x=245, y=425)

        # Labels
        l = Label(fream1, text="Registration Here", fg="black", font=("Game Of Squids", 20, "bold"), bg="white")
        l.place(x=120, y=5)
        l1 = Label(fream1, text="Welcome to SecureInfo Registration page for new user", fg="black",font="Helvetica 12 bold", bg="white")
        l1.place(x=50, y=50)
        l2 = Label(fream1, text="Username:", fg="black", font="Helvetica 15 bold", bg="white")
        l2.place(x=50, y=90)
        l4 = Label(fream1, text="Full name:", fg="black", font="Helvetica 15 bold", bg="white")
        l4.place(x=50, y=130)
        l6 = Label(fream1, text="Mobile NO.:", fg="black", font="Helvetica 15 bold", bg="white")
        l6.place(x=50, y=170)
        l3 = Label(fream1, text="Password:", fg="black", font="Helvetica 15 bold", bg="white",)
        l3.place(x=50, y=210)
        l5 = Label(fream1, text="Confirm Password:", fg="black", font="Helvetica 15 bold", bg="white")
        l5.place(x=50, y=250)

        # Entry fields
        new_user = StringVar()
        full_name = StringVar()
        mobile_No = StringVar()
        passId = StringVar()
        c_passId = StringVar()
        emailId = Entry(fream1, textvariable=new_user, width=32, bd=2, font="12", bg="#E5E8E8")
        name_full = Entry(fream1, textvariable=full_name, width=32, bd=2, font="12", bg="#E5E8E8")
        mobile_num = Entry(fream1, textvariable=mobile_No, width=32, bd=2, font="12", bg="#E5E8E8")
        passWord1 = Entry(fream1, textvariable=passId, width=32, bd=2, font="12", bg="#E5E8E8",show="*")
        passWord2 = Entry(fream1, textvariable=c_passId, width=32, bd=2, font="12", bg="#E5E8E8",show="*")
        emailId.place(x=250, y=90)
        name_full.place(x=250, y=130)
        mobile_num.place(x=250, y=170)
        passWord1.place(x=250, y=210)
        passWord2.place(x=250, y=250)

        # "Old User, Login Here" button
        b2 = Button(fream1, fg="blue", bg="white", font="10", bd=0, text="Old User, Login Here", width=20, height=1,command=partial(self.logian_page))
        b2.place(x=100, y=325)

        # Checkbox to show/hide password
        loginvalue = IntVar()
        loginpage = Checkbutton(fream1, text="Show Password", bg="white", variable=loginvalue, command=toggle_password_visibility)
        loginpage.place(x=300, y=325)


    def public_page(self):
        self.ClearScreen()

        def read_csv_data(file_path):
            for child in tree.get_children():
                tree.delete(child)

            with open(file_path, 'r') as file:
                reader = csv.reader(file)
                for i, row in enumerate(reader, start=0):
                    tree.insert('', 'end', text=str(i), values=row)

        # def open_file():
        #     global file_path
        #     file_path = filedialog.askopenfilename(filetypes=[('CSV Files', '*.csv')])
        #     if file_path:
        #         read_csv_data(file_path)

        def search_user():
            file_path='users_public.csv'
            search_text = search_entry.get()

            for child in tree.get_children():
                tree.delete(child)

            with open(file_path, 'r') as file:
                reader = csv.reader(file)
                for i, row in enumerate(reader, start=1):
                    if search_text.lower() in row[0].lower():
                        tree.insert('', 'end', text=str(i), values=row)

        def copy_data(event):
            selected_item = tree.focus()
            if selected_item:
                values = tree.item(selected_item)['values']
                if len(values) > 1:
                    data = values[1]
                    pyperclip.copy(data)
                    messagebox.showinfo("Copy Successful", "Data copied to clipboard!")

        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue
        self.window.configure(bg=color)
        # add home button
        ba10 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),command=self.home_page)
        ba10.place(x=10, y=10)

        Label(self.window, text="Public key of all User", bg=color, fg="red", font=("Game Of Squids", 20, "bold")).place(
            x=150, y=10)
        Label(self.window, text="--", bg=color, fg="blue", font=("Game Of Squids", 20, "bold")).place(x=10, y=40)
        Label(self.window, text="--", bg=color, fg="orange", font=("Game Of Squids", 20, "bold")).place(x=60, y=40)
        Label(self.window, text="--", bg=color, fg="green", font=("Game Of Squids", 20, "bold")).place(x=110, y=40)
        Label(self.window, text="--", bg=color, fg="red", font=("Game Of Squids", 20, "bold")).place(x=160, y=40)

        frame=Frame(self.window,bg="white",bd=2,width=690,height=420)
        frame.place(x=5,y=100)

        tree = ttk.Treeview(frame)
        tree['columns'] = ('column1', 'column2')
        tree.heading('#0', text='Row')
        tree.column('#0', width=85)
        tree.column('#1', width=150)
        tree.column('#2', width=450)
        tree.heading('column1', text='User Name')
        tree.heading('column2', text='Public key')
        tree.pack()

        tree.bind('<Double-1>', copy_data)

        search_frame = Frame(frame)
        search_frame.pack()

        search_label = Label(search_frame, text="Search Username:")
        search_label.pack(side=LEFT)

        search_entry = Entry(search_frame)
        search_entry.pack(side=LEFT)

        search_button = Button(search_frame, text="Search", command=search_user)
        search_button.pack(side=LEFT)
        read_csv_data('users_public.csv')
        # open_button = Button(frame, text="Open CSV", command=open_file)
        # open_button.pack()



    def about_page(self):
        self.ClearScreen()
        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue
        self.window.configure(bg=color)
        # add home button

        ba10 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),command=self.home_page)
        ba10.place(x=10, y=10)

        Label(self.window,text="About The Software",bg=color,fg="red",font=("Game Of Squids", 20, "bold")).place(x=150,y=10)
        Label(self.window, text="--", bg=color, fg="blue",font=("Game Of Squids", 20, "bold")).place(x=10, y=40)
        Label(self.window, text="--", bg=color, fg="orange", font=("Game Of Squids", 20, "bold")).place(x=60, y=40)
        Label(self.window, text="--", bg=color, fg="green", font=("Game Of Squids", 20, "bold")).place(x=110, y=40)
        Label(self.window, text="--", bg=color, fg="red", font=("Game Of Squids", 20, "bold")).place(x=160, y=40)

        frame = Frame(self.window, bg=color2, bd=0, width=700, height=420)
        frame.place(x=0, y=80)

        # Create a canvas with scrollbar
        canvas = Canvas(frame, bg=color2, bd=0, width=680, height=420)
        canvas.pack(side="left", fill="both", expand=True)

        scrollbar = Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Add content to the canvas
        content_frame = Frame(canvas, bg=color2)
        canvas.create_window((0, 0), window=content_frame, anchor="nw")

        # Configure the scrollbar to work with the canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        content_frame.bind("<MouseWheel>", _on_mousewheel)

        self.window.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
        # scrollbar = Scrollbar(frame)
        # scrollbar.pack(side='left', fill='y')

        # frame.configure()
        # scrollbar.configure(command=frame.yview)

        # Label(frame, text="\n->\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n->\n\n\n\n\n->", bg=color2, fg="red").place(x=0, y=5)
        Label(frame,text="1. Text Information",bg=color2,fg="white",font=("Game Of Squids", 16, "bold")).place(x=200,y=5)
        Label(frame,text="-The text encryption and Decryption We can use\n"
                         "this proccess easilystep-by-step according to\n"
                         "my instractions after open softwate click in-\n"
                         "formation button then ckicl text secure button\n"
                         "after click button open text encryption and \n"
                         "decryption page is opened then Enter the Mes-\n"
                         "sage to send in the message box after enter \n"
                         "public public of sender from public keys opst-\n"
                         "ion near by about page then click Encrypt button\n"
                         "then copy encrypted message and send by any way\n"
                         "like Whatsapp, G-mail etc....                 \n"
                         "Here is started decryption process this proccess\n"
                         "are same to encryption but in this message box \n"
                         "enter encryptiod message by resiving and enter \n"
                         "self public key then click Decrypt button, Thanks.",font=("times new roman", 14),bd=2,bg=color).place(x=20,y=50)

        image1 = Image.open('images\\process-of.jpg')
        photo1 = ImageTk.PhotoImage(image1)
        label1 = Label(frame, image=photo1, bg=color)
        label1.image = photo1
        label1.place(x=420, y=100)

        Label(frame, text="2. Image Information", bg=color2, fg="white", font=("Game Of Squids", 16, "bold")).place(x=200, y=370)
        Label(frame,text="The text encryption and Decryption We can use\n"
                         "this proccess easilystep-by-step according to\n"
                         "my instractions after open softwate click in-\n"
                         "formation button then ckicl text secure button\n"
                         "after click button open text encryption and \n"
                         "decryption page is opened then Enter the Mes-\n"
                         "sage to send in the message box after enter \n"
                         "public public of sender from public keys opst-\n"
                         "ion near by about page then click Encrypt button\n"
                         "then copy encrypted message and send by any way\n"
                         "like Whatsapp, G-mail etc....                 \n"
                         "Here is started decryption process this proccess\n"
                         "are same to encryption but in this message box \n"
                         "enter encryptiod message by resiving and enter \n"
                         "self public key then click Decrypt button, Thanks.",font=("times new roman", 14), bd=2, bg=color).place(x=270, y=410)

        image2 = Image.open('images\\image.png')
        photo2 = ImageTk.PhotoImage(image2)
        label2 = Label(frame, image=photo2, bg=color)
        label2.image = photo2
        label2.place(x=10, y=440)

        Label(frame, text="3. Audio Information", bg=color2, fg="white", font=("Game Of Squids", 16, "bold")).place(x=200, y=720)
        Label(frame,text="The Image encryption and Decryption", bd=2, bg=color).place(x=10, y=750)

        image3 = Image.open('images\\logo-S.png')
        photo3 = ImageTk.PhotoImage(image3)
        label3 = Label(frame, image=photo3, bg=color)
        label3.image = photo2
        label3.place(x=440, y=770)

    def send_message(self):
        self.ClearScreen()
        color = "#C5D4EC"  # lite blue
        color2 = "#2f4155"  # dark blue

        check = False

        def browse():
            global final_emails
            path = filedialog.askopenfilename(initialdir='c:/', title='Select Excel File')
            if path == '':
                messagebox.showerror('Error', 'Please select an Excel File')

            else:
                data = pandas.read_excel(path)
                if 'Email' in data.columns:
                    emails = list(data['Email'])
                    final_emails = []
                    for i in emails:
                        if pandas.isnull(i) == False:
                            final_emails.append(i)

                    if len(final_emails) == 0:
                        messagebox.showerror('Error', 'File does not contain any email addresses')

                    else:
                        toEntryField.config(state=NORMAL)
                        toEntryField.insert(0, os.path.basename(path))
                        toEntryField.config(state='readonly')
                        totalLabel.config(text='Total: ' + str(len(final_emails)))
                        sentLabel.config(text='Sent:')
                        leftLabel.config(text='Left:')
                        failedLabel.config(text='Failed:')

        def button_check():
            if choice.get() == 'multiple':
                browseButton.config(state=NORMAL)
                toEntryField.config(state='readonly')

            if choice.get() == 'single':
                browseButton.config(state=DISABLED)
                toEntryField.config(state=NORMAL)

        def attachment():
            global filename, filetype, filepath, check
            check = True

            filepath = filedialog.askopenfilename(initialdir='c:/', title='Select File')
            filetype = filepath.split('.')
            filetype = filetype[1]
            filename = os.path.basename(filepath)
            textarea.insert(END, f'\n{filename}\n')

        def sendingEmail(toAddress, subject, body):
            f = open('images/credentials.txt', 'r')
            for i in f:
                credentials = i.split(',')

            message = EmailMessage()
            message['subject'] = subject
            message['to'] = toAddress
            message['from'] = credentials[0]
            message.set_content(body)
            if check:
                if filetype == 'png' or filetype == 'jpg' or filetype == 'jpeg':
                    f = open(filepath, 'rb')
                    file_data = f.read()
                    subtype = imghdr.what(filepath)

                    message.add_attachment(file_data, maintype='image', subtype=subtype, filename=filename)

                else:
                    f = open(filepath, 'rb')
                    file_data = f.read()
                    message.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=filename)

            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login(credentials[0], credentials[1])
            s.send_message(message)
            x = s.ehlo()
            if x[0] == 250:
                return 'sent'
            else:
                return 'failed'

        def send_email():
            if toEntryField.get() == '' or subjectEntryField.get() == '' or textarea.get(1.0, END) == '\n':
                messagebox.showerror('Error', 'All Fields Are Required', parent=self.window)

            else:
                if choice.get() == 'single':
                    result = sendingEmail(toEntryField.get(), subjectEntryField.get(), textarea.get(1.0, END))
                    if result == 'sent':
                        messagebox.showinfo('Success', 'Email is sent successfulyy')

                    if result == 'failed':
                        messagebox.showerror('Error', 'Email is not sent.')

                if choice.get() == 'multiple':
                    sent = 0
                    failed = 0
                    for x in final_emails:
                        result = sendingEmail(x, subjectEntryField.get(), textarea.get(1.0, END))
                        if result == 'sent':
                            sent += 1
                        if result == 'failed':
                            failed += 1

                        totalLabel.config(text='')
                        sentLabel.config(text='Sent:' + str(sent))
                        leftLabel.config(text='Left:' + str(len(final_emails) - (sent + failed)))
                        failedLabel.config(text='Failed:' + str(failed))

                        totalLabel.update()
                        sentLabel.update()
                        leftLabel.update()
                        failedLabel.update()

                    messagebox.showinfo('Success', 'Emails are sent successfully')

        def settings():
            def clear1():
                fromEntryField.delete(0, END)
                passwordEntryField.delete(0, END)

            def save():
                if fromEntryField.get() == '' or passwordEntryField.get() == '':
                    messagebox.showerror('Error', 'All Fields Are Required', parent=root1)

                else:
                    f = open('images/credentials.txt', 'w')
                    f.write(fromEntryField.get() + ',' + passwordEntryField.get())
                    f.close()
                    messagebox.showinfo('Information', 'CREDENTIALS SAVED SUCCESSFULLY', parent=root1)

            root1 = Toplevel()
            root1.title('Setting')
            root1.geometry('650x340+350+90')

            root1.config(bg='dodger blue2')

            Label(root1, text='Credential Settings', image=logoImage, compound=LEFT,
                  font=('goudy old style', 40, 'bold'),
                  fg='white', bg='gray20').grid(padx=60)

            fromLabelFrame = LabelFrame(root1, text='From (Email Address)', font=('times new roman', 16, 'bold'), bd=5,
                                        fg='white',
                                        bg='dodger blue2')
            fromLabelFrame.grid(row=1, column=0, pady=20)

            fromEntryField = Entry(fromLabelFrame, font=('times new roman', 18, 'bold'), width=30)
            fromEntryField.grid(row=0, column=0)

            passwordLabelFrame = LabelFrame(root1, text='Password', font=('times new roman', 16, 'bold'), bd=5,
                                            fg='white',
                                            bg='dodger blue2')
            passwordLabelFrame.grid(row=2, column=0, pady=20)

            passwordEntryField = Entry(passwordLabelFrame, font=('times new roman', 18, 'bold'), width=30, show='*')
            passwordEntryField.grid(row=0, column=0)

            Button(root1, text='SAVE', font=('times new roman', 18, 'bold'), cursor='hand2', bg='gold2', fg='black'
                   , command=save).place(x=210, y=280)
            Button(root1, text='CLEAR', font=('times new roman', 18, 'bold'), cursor='hand2', bg='gold2', fg='black'
                   , command=clear1).place(x=340, y=280)

            f = open('images/credentials.txt', 'r')
            for i in f:
                credentials = i.split(',')

            fromEntryField.insert(0, credentials[0])
            passwordEntryField.insert(0, credentials[1])

            root1.mainloop()

        # def speak():
        #     mixer.init()
        #     mixer.music.load('images/music1.mp3')
        #     mixer.music.play()
        #     sr = speech_recognition.Recognizer()
        #     with speech_recognition.Microphone() as m:
        #         try:
        #             sr.adjust_for_ambient_noise(m, duration=0.2)
        #             audio = sr.listen(m)
        #             text = sr.recognize_google(audio)
        #             textarea.insert(END, text + '.')
        #
        #         except:
        #             pass
        #
        # def iexit():
        #     result = messagebox.askyesno('Notification', 'Do you want to exit?')
        #     if result:
        #         self.window.destroy()
        #     else:
        #         pass

        def clear():
            toEntryField.delete(0, END)
            subjectEntryField.delete(0, END)
            textarea.delete(1.0, END)

        ba10 = Button(self.window, text="<-Back", bg="#2f4155", fg="white", font=("Helvetica", 8, 'bold'),command=self.home_page)
        ba10.place(x=1, y=1)

        titleFrame = Frame(self.window, bg=color)
        titleFrame.grid(row=0, column=0)

        image311 = Image.open('images/email.png')
        logoImage =ImageTk.PhotoImage(image311)
        titleLabel = Label(titleFrame, text='  Email Sender', image=logoImage, compound=LEFT,font=('Goudy Old Style', 18, 'bold'),bg=color, fg='dodger blue2')
        titleLabel.image=logoImage
        titleLabel.grid(row=0, column=0)
        # settingImage = PhotoImage(file='images/setting.png')
        image104 = Image.open("images/setting.png")
        settingImage = ImageTk.PhotoImage(image104)
        setbtn=Button(titleFrame, image=settingImage, bd=0, bg=color, cursor='hand2', activebackground='white', command=settings)
        setbtn.image=settingImage
        setbtn.grid(row=0, column=1, padx=20)
        chooseFrame = Frame(self.window, bg=color2)
        chooseFrame.grid(row=1, column=0, pady=10)
        choice = StringVar()

        singleRadioButton = Radiobutton(chooseFrame, text='Single', font=('times new roman', 15, 'bold')
                                        , variable=choice, value='single', bg=color2,
                                        activebackground='dodger blue2',
                                        command=button_check)
        singleRadioButton.grid(row=0, column=0, padx=20)

        multipleRadioButton = Radiobutton(chooseFrame, text='Multiple', font=('times new roman', 15, 'bold')
                                          , variable=choice, value='multiple', bg=color2,
                                          activebackground='dodger blue2',
                                          command=button_check)
        multipleRadioButton.grid(row=0, column=1, padx=20)

        choice.set('single')

        toLabelFrame = LabelFrame(self.window, text='To (Email Address)', font=('times new roman', 12, 'bold'), bd=5,
                                  fg='white', bg=color2)
        toLabelFrame.grid(row=2, column=0, padx=100)

        toEntryField = Entry(toLabelFrame, font=('times new roman', 14, 'bold'), width=30)
        toEntryField.grid(row=0, column=0)

        # browseImage = PhotoImage(file='images/browse.png')
        image103 = Image.open("images/browse.png")
        browseImage = ImageTk.PhotoImage(image103)
        browseButton = Button(toLabelFrame, text=' Browse', image=browseImage, compound=LEFT,font=('arial', 10, 'bold'),cursor='hand2', bd=0, bg=color2, activebackground='dodger blue2', state=DISABLED,command=browse)
        browseButton.image=browseImage
        browseButton.grid(row=0, column=1, padx=20)

        subjectLabelFrame = LabelFrame(self.window, text='Subject', font=('times new roman', 12, 'bold'), bd=5, fg='white',
                                       bg=color2)
        subjectLabelFrame.grid(row=3, column=0, pady=10)

        subjectEntryField = Entry(subjectLabelFrame, font=('times new roman', 14, 'bold'), width=30)
        subjectEntryField.grid(row=0, column=0)

        emailLabelFrame = LabelFrame(self.window, text='Compose Email', font=('times new roman', 12, 'bold'), bd=5, fg='white',
                                     bg=color2)
        emailLabelFrame.grid(row=4, column=0, padx=20)
        # micImage = PhotoImage(file='images/mic.png')
        image101 = Image.open("images/mic.png")
        micImage = ImageTk.PhotoImage(image101)
        micbtn=Button(emailLabelFrame, text=' Speak', image=micImage, compound=LEFT, font=('arial', 10, 'bold'),cursor='hand2', bd=0, bg=color2, activebackground='dodger blue2')#, command=speak
        micbtn.image=micImage
        micbtn.grid(row=0,column=0)
        # attachImage = PhotoImage(file='images/attachments.png')
        image10 = Image.open("images/attachments.png")
        attachImage = ImageTk.PhotoImage(image10)
        attdtn=Button(emailLabelFrame, text=' Attachment', image=attachImage, compound=LEFT, font=('arial', 10, 'bold'),cursor='hand2', bd=0, bg=color2, activebackground='dodger blue2', command=attachment)
        attdtn.image=attachImage
        attdtn.grid(row=0,column=1)

        textarea = Text(emailLabelFrame, font=('times new roman', 12,), height=8)
        textarea.grid(row=1, column=0, columnspan=2)

        image1 = Image.open("images/send.png")
        sendImage = ImageTk.PhotoImage(image1)
        email1=Button(self.window, image=sendImage, bd=0, bg=color2, cursor='hand2', activebackground='dodger blue2', command=send_email)
        email1.image=sendImage
        email1.place(x=400, y=460)

        image2 = Image.open("images/clear.png")
        clearImage = ImageTk.PhotoImage(image2)
        email2=Button(self.window, image=clearImage, bd=0, bg=color2, cursor='hand2', activebackground='dodger blue2', command=clear)
        email2.image=clearImage
        email2.place(x=500, y=460)

        image3 = Image.open("images/exit.png")
        exitImage = ImageTk.PhotoImage(image3)
        email3=Button(self.window, image=exitImage, bd=0, bg='dodger blue2', cursor='hand2', activebackground='dodger blue2')#, command=iexit
        email3.image=exitImage
        email3.place(x=600, y=460)

        totalLabel = Label(self.window, font=('times new roman', 14, 'bold'), bg=color2, fg='black')
        totalLabel.place(x=10, y=560)

        sentLabel = Label(self.window, font=('times new roman', 14, 'bold'), bg=color2, fg='black')
        sentLabel.place(x=100, y=560)

        leftLabel = Label(self.window, font=('times new roman', 14, 'bold'), bg=color2, fg='black')
        leftLabel.place(x=190, y=560)

        failedLabel = Label(self.window, font=('times new roman', 14, 'bold'), bg=color2, fg='black')
        failedLabel.place(x=280, y=560)




# The main function
if __name__ == "__main__":

    loding_root = Tk()

    # Using piece of code from old splash screen
    width_of_window = 427
    height_of_window = 250
    screen_width = loding_root.winfo_screenwidth()
    screen_height = loding_root.winfo_screenheight()
    x_coordinate = (screen_width / 2) - (width_of_window / 2)
    y_coordinate = (screen_height / 2) - (height_of_window / 2)
    loding_root.geometry("%dx%d+%d+%d" % (width_of_window, height_of_window, x_coordinate, y_coordinate))
    # loding_root.configure(bg='#ED1B76')
    loding_root.overrideredirect(1)  # for hiding titlebar

    Frame(loding_root, width=427, height=250, bg='#272727').place(x=0, y=0)

    if key_of_login == "" or key_of_login == None:  # for without login user
        label1 = Label(loding_root, text='Welcome   To', fg='white', bg='#272727',font=("Game Of Squids", 20, "bold"))  # decorate it
        label1.place(x=80, y=50)
        label2 = Label(loding_root, text='SecureInfo', fg='yellow', bg='#272727',font=("Game Of Squids", 20, "bold"))  # decorate it
        label2.place(x=100, y=100)
        label2 = Label(loding_root, text='You Should Login..', fg='white', bg='#272727',font=("Calibri", 11))  # decorate it
        label2.place(x=300, y=215)

    else:
        label1 = Label(loding_root, text='Welcome To', fg='white', bg='#272727',font=("Game Of Squids", 17, "bold"))  # decorate it
        label1.place(x=5, y=40)
        label2 = Label(loding_root, text='SecureInfo', fg='red', bg='#272727',font=("Game Of Squids", 17, "bold"))  # decorate it
        label2.place(x=217, y=40)
        label3 = Label(loding_root, text='User name - ', fg='white', bg='#272727',font=("Game Of Squids", 12, "bold"))  # decorate it
        label3.place(x=55, y=100)
        label4 = Label(loding_root, text=key_of_login, fg='yellow', bg='#272727',font=("Game Of Squids", 12, "bold"))  # decorate it
        label4.place(x=235, y=100)
        label2 = Label(loding_root, text='You Already Login.', fg='white', bg='#272727', font=("Calibri", 11))  # decorate it
        label2.place(x=300, y=215)


    label2 = Label(loding_root, text='Loading...', fg='white', bg='#272727',font=("Calibri", 11))  # decorate it
    label2.place(x=10, y=215)

    # making animation


    image_a = ImageTk.PhotoImage(Image.open('images/c2.png'))
    image_b = ImageTk.PhotoImage(Image.open('images/c1.png'))

    for i in range(8):  # 5loops
        dote_a = Label(loding_root, image=image_a, border=0, relief=SUNKEN)
        dote_a.image = image_a
        dote_a.place(x=180, y=160)

        dote_b = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_b.image = image_b
        dote_b.place(x=200, y=160)
        dote_c = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_c.image = image_b
        dote_c.place(x=220, y=160)
        dote_d = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_d.image = image_b
        dote_d.place(x=240, y=160)
        loding_root.update_idletasks()
        time.sleep(0.1)

        dote_a = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_a.image = image_b
        dote_a.place(x=180, y=160)

        dote_b = Label(loding_root, image=image_a, border=0, relief=SUNKEN)
        dote_b.image = image_a
        dote_b.place(x=200, y=160)
        dote_c = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_c.image = image_b
        dote_c.place(x=220, y=160)
        dote_d = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_d.image = image_b
        dote_d.place(x=240, y=160)
        loding_root.update_idletasks()
        time.sleep(0.1)

        dote_a = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_a.image = image_b
        dote_a.place(x=180, y=160)

        dote_b = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_b.image = image_b
        dote_b.place(x=200, y=160)
        dote_c = Label(loding_root, image=image_a, border=0, relief=SUNKEN)
        dote_c.image = image_a
        dote_c.place(x=220, y=160)
        dote_d = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_d.image = image_b
        dote_d.place(x=240, y=160)
        loding_root.update_idletasks()
        time.sleep(0.1)

        dote_a = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_a.image = image_b
        dote_a.place(x=180, y=160)

        dote_b = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_b.image = image_b
        dote_b.place(x=200, y=160)
        dote_c = Label(loding_root, image=image_b, border=0, relief=SUNKEN)
        dote_c.image = image_b
        dote_c.place(x=220, y=160)
        dote_d = Label(loding_root, image=image_a, border=0, relief=SUNKEN)
        dote_d.image = image_a
        dote_d.place(x=240, y=160)
        loding_root.update_idletasks()
        time.sleep(0.1)

    loding_root.destroy()
    loding_root.mainloop()

    root = Tk()
    # Creating a 'En_Dec_rypt' class object
    obj = en_Dec_rypt(root)
    root.mainloop()