import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from cryptography.fernet import Fernet
import os

# Generate encryption key if not exists
key_path = "secret.key"
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
else:
    with open(key_path, "rb") as key_file:
        key = key_file.read()

decryptor = Fernet(key)

# Function to hide message
def hide_message():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    message = text_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Please enter a message to encrypt.")
        return
    
    encrypted_message = decryptor.encrypt(message.encode()).decode()
    binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message) + '1111111111111110'
    
    img = Image.open(file_path)
    img_array = np.array(img)
    
    data_index = 0
    for row in img_array:
        for pixel in row:
            for channel in range(3):
                if data_index < len(binary_message):
                    pixel[channel] = (pixel[channel] & ~1) | int(binary_message[data_index])
                    data_index += 1
    
    stego_img = Image.fromarray(img_array)
    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        stego_img.save(save_path)
        messagebox.showinfo("Success", "Image saved with hidden message.")

# Function to extract message
def extract_message():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    img = Image.open(file_path)
    img_array = np.array(img)
    binary_message = ""
    
    for row in img_array:
        for pixel in row:
            for channel in range(3):
                binary_message += str(pixel[channel] & 1)
                if binary_message[-16:] == "1111111111111110":
                    binary_message = binary_message[:-16]
                    decrypted_text = decryptor.decrypt(''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)).encode()).decode()
                    messagebox.showinfo("Hidden Message", decrypted_text)
                    return
    
    messagebox.showerror("Error", "No hidden message found.")

# Create GUI window
root = tk.Tk()
root.title("Image Steganography")
root.geometry("500x400")

# Text Entry
text_label = tk.Label(root, text="Text to Encrypt:")
text_label.pack()
text_entry = tk.Text(root, height=3, width=50)
text_entry.pack()

# Buttons
save_button = tk.Button(root, text="Save Image with Data", bg="green", fg="white", command=hide_message)
save_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt Image", bg="blue", fg="white", command=extract_message)
decrypt_button.pack()

root.mainloop()
