import streamlit as st
from PIL import Image
import numpy as np
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os

# Steganografi LSB
def encode_image(image, message):
    img = np.array(image.convert("RGB"))
    if len(message) == 0:
        return img
    message += b"====="  # Penanda akhir pesan dalam bentuk byte
    message_bytes = ''.join(format(x, '08b') for x in message)
    num_pixels = img.shape[0] * img.shape[1]
    num_bits_needed = len(message_bytes)
    if num_bits_needed > num_pixels * 3:
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")
    index = 0
    for i in range(img.shape[0]):
        for j in range(img.shape[1]):
            for k in range(3):
                if index < num_bits_needed:
                    img[i, j, k] = int(bin(img[i, j, k])[2:-1] + message_bytes[index], 2)
                    index += 1
    return Image.fromarray(img)

def decode_image(image):
    img = np.array(image.convert("RGB"))
    binary_message = ""
    for i in range(img.shape[0]):
        for j in range(img.shape[1]):
            for k in range(3):
                binary_message += bin(img[i, j, k])[-1]

    bytes_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8) if len(binary_message[i:i+8]) == 8]
    decoded_message = b""
    for byte in bytes_message:
        decoded_message += bytes([int(byte, 2)])
    try:
        decoded_message = decoded_message.decode('utf-8')
    except UnicodeDecodeError:
        try:
            decoded_message = decoded_message.decode('latin-1')
        except UnicodeDecodeError:
            return "Tidak ada pesan tersembunyi atau format pesan salah."
    if "=====" in decoded_message:
        return decoded_message.split("=====")[0]
    else:
        return "Tidak ada pesan tersembunyi atau format pesan salah."


# Fungsi untuk mengenkripsi dengan AES-128
def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct

# Fungsi untuk mendekripsi dengan AES-128
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    try:
        pt = decryptor.update(ct) + decryptor.finalize()
        unpadded_data = unpadder.update(pt) + unpadder.finalize()
        return unpadded_data
    except ValueError:
        return b"Padding tidak valid"

# Aplikasi Streamlit
st.title("Steganografi dengan Kriptografi (AES-128)")

uploaded_image = st.file_uploader("Unggah Gambar", type=["png", "jpg", "jpeg"])
message = st.text_area("Masukkan Pesan")
kunci_aes = st.text_input("Masukkan Kunci AES (16 karakter)", type="password")

if st.button("Enkripsi & Sisipkan"):
    if uploaded_image and message and kunci_aes:
        try:
            image = Image.open(uploaded_image)
            key_bytes = kunci_aes.encode('utf-8')
            if len(key_bytes) != 16:
                st.error("Panjang kunci AES harus 16 byte (16 karakter ASCII).")
            else:
                encrypted_message = aes_encrypt(message.encode('utf-8'), key_bytes)
                encoded_image = encode_image(image, encrypted_message)
                st.image(encoded_image, caption="Gambar dengan Pesan Tersembunyi", use_column_width=True)
                buf = io.BytesIO()
                encoded_image.save(buf, format="PNG")
                st.download_button(
                    label="Unduh Gambar Terenkripsi",
                    data=buf.getvalue(),
                    file_name="encoded_image.png",
                    mime="image/png",
                )
        except ValueError as e:
            st.error(str(e))
        except Exception as e:
            st.error(f"Terjadi kesalahan umum saat enkripsi dan penyisipan: {e}")
    else:
        st.warning("Unggah gambar, masukkan pesan, dan kunci AES (16 karakter).")

st.subheader("Dekripsi Pesan")

uploaded_encoded_image = st.file_uploader("Unggah Gambar Terenkripsi", type=["png", "jpg", "jpeg"])
kunci_dekripsi_aes = st.text_input("Masukkan Kunci Dekripsi AES (16 karakter)", type="password")

if st.button("Ekstrak & Dekripsi"):
    if uploaded_encoded_image and kunci_dekripsi_aes:
        try:
            encoded_image = Image.open(uploaded_encoded_image)
            extracted_message = decode_image(encoded_image)

            key_bytes = kunci_dekripsi_aes.encode('utf-8')
            if len(key_bytes) != 16:
                st.error("Panjang kunci AES harus 16 byte (16 karakter ASCII).")
            else:
                if "Tidak ada pesan tersembunyi" not in extracted_message:
                    extracted_bytes = extracted_message.encode('latin-1')
                    decrypted_message_bytes = aes_decrypt(extracted_bytes, key_bytes)
                    try:
                        decrypted_message = decrypted_message_bytes.decode('utf-8')
                        st.write("Pesan yang Didekripsi:", decrypted_message)
                    except UnicodeDecodeError:
                        st.write("Pesan yang Didekripsi (Byte):", decrypted_message_bytes)
                        st.error("Pesan yang diekstrak bukan teks UTF-8 yang valid.")
                else:
                    st.write(extracted_message)
        except ValueError as e:
            st.error(f"Terjadi kesalahan dekripsi (ValueError): {e}")
        except Exception as e:
            st.error(f"Terjadi kesalahan umum saat ekstraksi dan dekripsi: {e}")
    else:
        st.warning("Unggah gambar terenkripsi dan masukkan kunci dekripsi AES (16 karakter).")