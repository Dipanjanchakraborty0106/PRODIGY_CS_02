import hashlib
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
def generate_keystream(password, length):
    hash_bytes = hashlib.sha256(password.encode()).digest()
    keystream = bytearray()
    while len(keystream) < length:
        hash_bytes = hashlib.sha256(hash_bytes).digest()
        keystream.extend(hash_bytes)
    return keystream[:length]
def encrypt_decrypt_image(file_path, password, mode):
    MAGIC = b"IMGSAFE"  
    HEADER_LEN = len(MAGIC)
    try:
        with Image.open(file_path) as img:
            img = img.convert("RGB")
            width, height = img.size
            pixels = list(img.getdata())
            total_bytes = width * height * 3
            flat_pixels = bytearray()
            for r, g, b in pixels:
                flat_pixels.extend([r, g, b])
            keystream = generate_keystream(password, total_bytes)
            if mode == "encrypt":
                for i in range(HEADER_LEN):
                    flat_pixels[i] = MAGIC[i] ^ keystream[i]
                for i in range(HEADER_LEN, total_bytes):
                    flat_pixels[i] ^= keystream[i]
            elif mode == "decrypt":
                extracted = bytearray()
                for i in range(HEADER_LEN):
                    extracted.append(flat_pixels[i] ^ keystream[i])
                if extracted != MAGIC:
                    raise ValueError("Incorrect password. Magic header mismatch.")
                for i in range(HEADER_LEN, total_bytes):
                    flat_pixels[i] ^= keystream[i]
            new_pixels = [
                (flat_pixels[i], flat_pixels[i+1], flat_pixels[i+2])
                for i in range(0, total_bytes, 3)
            ]
            new_img = Image.new("RGB", (width, height))
            new_img.putdata(new_pixels)
            suffix = "_encrypt" if mode == "encrypt" else "_decrypt"
            output_path = Path(file_path).with_name(Path(file_path).stem + suffix + ".png")
            new_img.save(output_path)
            return new_img, output_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to process image:\n{e}")
        return None, None
def browse_file(entry_file):
    file_path = filedialog.askopenfilename(
        title="Select an image",
        filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.tiff *.webp")]
    )
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)
def show_image(img_path, canvas):
    try:
        img = Image.open(img_path)
        img.thumbnail((250, 250))
        tk_img = ImageTk.PhotoImage(img)
        canvas._img = tk_img  # prevent garbage collection
        canvas.delete("all")
        canvas.create_image(125, 125, image=tk_img)
    except Exception as e:
        messagebox.showerror("Image Error", f"Failed to load image: {e}")
def process(entry_file, entry_password, mode, result_canvas):
    file_path = entry_file.get().strip()
    password = entry_password.get().strip()
    if not file_path or not Path(file_path).is_file():
        messagebox.showwarning("Missing File", "Please select a valid image file.")
        return
    if not password:
        messagebox.showwarning("Missing Password", "Please enter a password.")
        return
    img, output_path = encrypt_decrypt_image(file_path, password, mode)
    if img:
        show_image(output_path, result_canvas)
        messagebox.showinfo("Success", f"Image saved to:\n{output_path}")
def main():
    root = tk.Tk()
    root.title("Image Encryptor & Decryptor")
    root.geometry("500x450")
    root.resizable(False, False)
    frame_top = tk.Frame(root, pady=10)
    frame_top.pack()
    tk.Label(frame_top, text="Image File:").grid(row=0, column=0, sticky="e")
    entry_file = tk.Entry(frame_top, width=40)
    entry_file.grid(row=0, column=1)
    tk.Button(frame_top, text="Browse", command=lambda: browse_file(entry_file)).grid(row=0, column=2)
    tk.Label(frame_top, text="Password:").grid(row=1, column=0, sticky="e")
    entry_password = tk.Entry(frame_top, show="*", width=40)
    entry_password.grid(row=1, column=1)
    frame_btn = tk.Frame(root, pady=10)
    frame_btn.pack()
    result_canvas = tk.Canvas(root, width=250, height=250, bg="#ddd")
    result_canvas.pack(pady=10)
    tk.Button(frame_btn, text="Encrypt", command=lambda: process(entry_file, entry_password, "encrypt", result_canvas), width=20).grid(row=0, column=0, padx=10)
    tk.Button(frame_btn, text="Decrypt", command=lambda: process(entry_file, entry_password, "decrypt", result_canvas), width=20).grid(row=0, column=1, padx=10)
    tk.Label(root, text="Result Preview").pack()
    root.mainloop()
if __name__ == "__main__":
    main()